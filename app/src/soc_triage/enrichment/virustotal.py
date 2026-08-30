"""VirusTotal v3 enrichment provider (Phase 2A).

Implements the :class:`~soc_triage.enrichment.providers.EnrichmentProvider`
contract on top of the public VirusTotal REST API (``/api/v3``):

* hashes  → ``GET /files/{id}``
* IPv4    → ``GET /ip_addresses/{ip}``
* domain  → ``GET /domains/{domain}``
* URL     → ``GET /urls/{base64url-id}``
* email   → not handled (absent, per the provider contract)

The provider is **disabled by default** — an empty ``VIRUSTOTAL_API_KEY`` means
``enabled=False`` and the chain skips it (disable-by-empty, ARCHITECTURE.md §14).
The key is read from configuration/environment only, is attached to the request
as the ``x-apikey`` header, and is never logged, returned, or stored in
provenance (SECURITY.md §2, §7).

Rate limiting respects the free public tier (4 requests/minute, burst of 4,
ARCHITECTURE.md §7.3) via a non-blocking token bucket; a lookup that would
exceed the quota is recorded ``rate_limited`` and the pipeline continues.

Only allow-listed, sanitized metadata is stored: the ``last_analysis_stats``
counts (``malicious`` / ``suspicious`` / ``harmless`` / ``undetected``) and the
integer ``reputation``. The raw upstream body is never persisted.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import datetime
from typing import Any

import httpx

from ..models.ioc import IOC, IOCType
from .threat_intel import (
    DEFAULT_TIMEOUT_SECONDS,
    BaseHTTPThreatIntelProvider,
    RetryConfig,
    TokenBucket,
)

#: VirusTotal v3 API base URL.
VT_BASE_URL = "https://www.virustotal.com/api/v3"

#: Free public tier: 4 requests/minute, burst of 4 (ARCHITECTURE.md §7.3).
VT_PUBLIC_CAPACITY = 4
VT_PUBLIC_REFILL_PER_SECOND = 4 / 60.0


def _int_or_zero(value: Any) -> int:
    """Coerce a stats count to ``int``, treating missing values as zero."""
    if value is None:
        return 0
    return int(value)


class VirusTotalProvider(BaseHTTPThreatIntelProvider):
    """VirusTotal v3 lookups for hashes, IPv4, domains and URLs."""

    handled_types: frozenset[IOCType] = frozenset(
        {
            IOCType.MD5,
            IOCType.SHA1,
            IOCType.SHA256,
            IOCType.IPV4,
            IOCType.DOMAIN,
            IOCType.URL,
        }
    )

    def __init__(
        self,
        api_key: str | None,
        *,
        client: httpx.Client | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        rate_limiter: TokenBucket | None = None,
        retry: RetryConfig | None = None,
        now: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Build the provider; ``api_key=None``/empty ⇒ disabled (never called)."""
        headers = {"Accept": "application/json"}
        if api_key:
            headers["x-apikey"] = api_key
        built_client = client or httpx.Client(
            base_url=VT_BASE_URL,
            headers=headers,
            timeout=timeout,
        )
        limiter = (
            rate_limiter
            if rate_limiter is not None
            else TokenBucket(VT_PUBLIC_CAPACITY, VT_PUBLIC_REFILL_PER_SECOND)
        )
        super().__init__(
            enabled=bool(api_key),
            client=built_client,
            headers=headers,
            rate_limiter=limiter,
            retry=retry,
            now=now,
            sleep=sleep,
        )

    @property
    def name(self) -> str:
        """Provider identifier (IOC enrichment key)."""
        return "virustotal"

    def _build_request(self, ioc: IOC) -> tuple[str, dict[str, str] | None]:
        if ioc.type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
            return f"/files/{ioc.value}", None
        if ioc.type is IOCType.IPV4:
            return f"/ip_addresses/{ioc.value}", None
        if ioc.type is IOCType.DOMAIN:
            return f"/domains/{ioc.value}", None
        if ioc.type is IOCType.URL:
            # VirusTotal identifies URLs by their unpadded base64url encoding.
            url_id = base64.urlsafe_b64encode(ioc.value.encode("utf-8")).decode("ascii").rstrip("=")
            return f"/urls/{url_id}", None
        # Unreachable: ``handled_types`` filters before this is called.
        raise ValueError(
            f"virustotal cannot look up indicator type {ioc.type.value}"
        )  # pragma: no cover

    def _sanitize(self, _ioc: IOC, body: Any) -> dict[str, Any] | None:
        if not isinstance(body, dict):
            raise ValueError("malformed VirusTotal response: top-level is not an object")
        data = body.get("data")
        if data is None:
            # VT returns `{"data": null}` for an indicator with no report.
            return None
        if not isinstance(data, dict):
            raise ValueError("malformed VirusTotal response: 'data' is not an object")
        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            raise ValueError("malformed VirusTotal response: missing attributes")
        stats = attributes.get("last_analysis_stats")
        if stats is None:
            stats = {}
        if not isinstance(stats, dict):
            raise ValueError("malformed VirusTotal response: bad last_analysis_stats")
        return {
            "malicious": _int_or_zero(stats.get("malicious")),
            "suspicious": _int_or_zero(stats.get("suspicious")),
            "harmless": _int_or_zero(stats.get("harmless")),
            "undetected": _int_or_zero(stats.get("undetected")),
            "reputation": attributes.get("reputation"),
        }


__all__ = [
    "VT_BASE_URL",
    "VT_PUBLIC_CAPACITY",
    "VT_PUBLIC_REFILL_PER_SECOND",
    "VirusTotalProvider",
]
