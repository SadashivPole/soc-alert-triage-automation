"""MISP threat-intelligence enrichment provider (Phase 2A).

Implements the :class:`~soc_triage.enrichment.providers.EnrichmentProvider`
contract on top of a self-hosted MISP's ``/attributes/restSearch`` endpoint
(profile ``intel``, ARCHITECTURE.md §7.3). Each indicator is looked up by its
exact attribute ``value``; a match means the indicator appears in at least one
MISP event.

The provider is **disabled by default** — it requires both ``MISP_URL`` and
``MISP_API_KEY``; either empty ⇒ ``enabled=False`` (disable-by-empty,
ARCHITECTURE.md §14). The key is attached to the request ``Authorization``
header only and is never logged, returned, or stored in provenance
(SECURITY.md §2, §7).

Only allow-listed, sanitized metadata is stored: the number of matching
attributes, the (capped, sorted) set of distinct event ids, and the (capped,
sorted) set of distinct tag names. Raw attribute values, event payloads and
credentials are never persisted.
"""

from __future__ import annotations

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

#: Cap on distinct event ids / tags stored in sanitized provenance.
_MAX_EVENT_IDS = 20
_MAX_TAGS = 50


class MISPProvider(BaseHTTPThreatIntelProvider):
    """Self-hosted MISP attribute lookups for every supported indicator type."""

    handled_types: frozenset[IOCType] = frozenset(IOCType)

    def __init__(
        self,
        url: str,
        api_key: str | None,
        *,
        verify_tls: bool = True,
        client: httpx.Client | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        rate_limiter: TokenBucket | None = None,
        retry: RetryConfig | None = None,
        now: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Build the provider; empty ``url``/``api_key`` ⇒ disabled (never called)."""
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = api_key
        built_client = client or httpx.Client(
            base_url=url.rstrip("/"),
            headers=headers,
            verify=verify_tls,
            timeout=timeout,
        )
        super().__init__(
            enabled=bool(url and api_key),
            client=built_client,
            headers=headers,
            rate_limiter=rate_limiter,  # no public rate limit → None by default
            retry=retry,
            now=now,
            sleep=sleep,
        )

    @property
    def name(self) -> str:
        """Provider identifier (IOC enrichment key)."""
        return "misp"

    def _build_request(self, ioc: IOC) -> tuple[str, dict[str, str] | None]:
        return "/attributes/restSearch", {"value": ioc.value, "returnFormat": "json"}

    def _sanitize(self, _ioc: IOC, body: Any) -> dict[str, Any] | None:
        if not isinstance(body, dict):
            raise ValueError("malformed MISP response: top-level is not an object")
        response = body.get("response")
        # MISP returns either `{"response": []}` or
        # `{"response": {"Attribute": []}}` when nothing matches.
        if response == []:
            return None  # definitive "no match"
        if not isinstance(response, dict):
            raise ValueError("malformed MISP response: 'response' is not an object")
        attributes = response.get("Attribute") or []
        if not isinstance(attributes, list):
            raise ValueError("malformed MISP response: bad 'Attribute' list")
        if not attributes:
            return None  # definitive "no match"

        event_ids: list[Any] = []
        tags: list[str] = []
        match_count = 0
        for attribute in attributes:
            if not isinstance(attribute, dict):
                continue
            match_count += 1
            event_id = attribute.get("event_id")
            if event_id is not None:
                event_ids.append(event_id)
            for tag in attribute.get("tags") or []:
                if isinstance(tag, dict) and tag.get("name"):
                    tags.append(str(tag["name"]))

        return {
            "match_count": match_count,
            "event_ids": sorted({str(eid) for eid in event_ids})[:_MAX_EVENT_IDS],
            "tags": sorted(set(tags))[:_MAX_TAGS],
        }


__all__ = ["MISPProvider"]
