"""Shared machinery for HTTP-backed threat-intelligence providers (Phase 2A).

This module holds everything the VirusTotal and MISP providers share, so the
two implementations stay small and behave identically at the edges that matter
for the pipeline's guarantees:

* **Fail-open** — a lookup never raises out of :meth:`BaseHTTPThreatIntelProvider.enrich`;
  a timeout / HTTP error / rate-limit / malformed body is recorded as a per-indicator
  :class:`LookupRecord` (``error`` / ``timeout`` / ``rate_limited``) instead. The
  orchestrator (:mod:`soc_triage.enrichment.chain`) remains the backstop.
* **Bounded latency** — every request carries a hard timeout (default 3 s,
  ARCHITECTURE.md §16); the token bucket is **non-blocking**, so an exhausted quota
  marks lookups ``rate_limited`` rather than stalling the alert pipeline.
* **Safe retries only** — retry with capped exponential backoff + jitter applies
  *only* to idempotent GETs and *only* to transient failures: network errors,
  timeouts, HTTP 429 (honouring ``Retry-After``) and 500/502/503/504. 4xx client
  errors and malformed responses are never retried.
* **Provenance** — every result carries ``provider``, ``indicator_type``,
  ``lookup_status``, ``timestamp`` and a *sanitized* ``result`` (explicit allow-listed
  fields only; never the raw upstream body and never the API key).
* **Secrets** — the API key lives only in the httpx client headers; it is never
  logged, never returned, never stored in IOC enrichment, and never appears in a
  provider's ``repr`` (the default object repr shows no attributes).
"""

from __future__ import annotations

import random
import threading
import time
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel, Field

from ..core.logging import get_logger
from ..models.ioc import IOC, IOCType
from .providers import EnrichmentContext, EnrichmentStatus, ProviderEnrichment

logger = get_logger("soc_triage.enrichment.threat_intel")

#: Default per-request timeout (ARCHITECTURE.md §16: "timeout (3 s)").
DEFAULT_TIMEOUT_SECONDS = 3.0

#: HTTP statuses safe to retry for an idempotent GET (transient conditions only).
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

#: Network-level exceptions safe to retry. ``httpx.TimeoutException`` is the
#: common base of ``ConnectTimeout`` / ``ReadTimeout`` / ``WriteTimeout`` /
#: ``PoolTimeout``.
_RETRYABLE_EXCEPTIONS: tuple[type[httpx.HTTPError], ...] = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
)


class LookupStatus(StrEnum):
    """Per-indicator outcome of a threat-intel lookup (provenance vocabulary)."""

    #: The upstream source returned a report/verdict for the indicator.
    FOUND = "found"
    #: The upstream source answered and has no record of the indicator.
    NOT_FOUND = "not_found"
    #: The upstream source failed (HTTP error / malformed response).
    ERROR = "error"
    #: The provider rate limit (or a 429) blocked the lookup.
    RATE_LIMITED = "rate_limited"
    #: The request timed out.
    TIMEOUT = "timeout"


#: Statuses that count as a *successful answer* (the provider was consulted and
#: returned a definitive result — even "not found").
_SUCCESSFUL_LOOKUPS: frozenset[LookupStatus] = frozenset(
    {LookupStatus.FOUND, LookupStatus.NOT_FOUND}
)


class LookupRecord(BaseModel):
    """Sanitized enrichment provenance for one indicator (ARCHITECTURE §7.3, §16).

    This is the shape stored under ``IOC.enrichment[provider]``. ``result``
    carries only explicit allow-listed metadata — never the raw upstream
    response and never credentials (SECURITY.md §2, §7).
    """

    model_config = {"frozen": True}

    provider: str = Field(min_length=1)
    indicator_type: str = Field(min_length=1)
    lookup_status: LookupStatus
    #: ISO-8601 UTC lookup time.
    timestamp: str
    #: Sanitized result metadata (empty for ``not_found`` / failures).
    result: dict[str, Any] = Field(default_factory=dict)


class TokenBucket:
    """Thread-safe, non-blocking token bucket for provider rate limits.

    ``try_acquire`` never sleeps: it returns immediately, so an exhausted quota
    cannot stall the alert pipeline (the caller marks the indicator
    ``rate_limited`` and moves on — fail-open, ARCHITECTURE.md §7.3).
    """

    def __init__(self, capacity: int, refill_per_second: float) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")
        self._capacity = capacity
        self._refill = refill_per_second
        self._tokens = float(capacity)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        """Consume one token if available; return ``False`` without blocking."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._updated
            self._tokens = min(self._capacity, self._tokens + elapsed * self._refill)
            self._updated = now
            if self._tokens < 1.0:
                return False
            self._tokens -= 1.0
            return True


class RetryConfig(BaseModel):
    """Retry policy (safe/idempotent requests only)."""

    model_config = {"frozen": True}

    #: Total attempts (1 initial + ``max_attempts - 1`` retries).
    #: Default 3 = "2x exponential + jitter" (ARCHITECTURE.md §16).
    max_attempts: int = Field(default=3, ge=1, le=10)
    #: Initial backoff, seconds (doubles per retry).
    base_delay: float = Field(default=0.5, ge=0.0)
    #: Backoff cap, seconds (also caps ``Retry-After``).
    max_delay: float = Field(default=8.0, ge=0.0)


def _utc_now() -> datetime:
    """Process clock; injectable in tests for deterministic timestamps."""
    return datetime.now(UTC)


def _jittered(delay: float) -> float:
    """Full-ish jitter in ``[delay/2, delay]`` to de-synchronize retries."""
    return delay * random.uniform(0.5, 1.0)


def _retry_after_or(response: httpx.Response, fallback: float, cap: float) -> float:
    """Honour ``Retry-After`` on 429/503 when it is an integer second count."""
    raw = response.headers.get("retry-after")
    if raw is not None:
        try:
            return min(float(int(raw)), cap)
        except ValueError:
            pass
    return min(_jittered(fallback), cap)


class BaseHTTPThreatIntelProvider(ABC):
    """Base class for VirusTotal/MISP: rate limiting, retry, sanitized provenance.

    Subclasses implement :meth:`_build_request` and :meth:`_sanitize` and set a
    ``name`` and :attr:`handled_types`. The orchestration of lookups, retries,
    timeouts, rate limiting and provenance recording is shared here.
    """

    #: Indicator types this provider can look up (others are simply absent).
    handled_types: frozenset[IOCType] = frozenset()

    def __init__(
        self,
        *,
        enabled: bool,
        client: httpx.Client,
        headers: dict[str, str] | None = None,
        rate_limiter: TokenBucket | None = None,
        retry: RetryConfig | None = None,
        now: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._enabled = enabled
        self._client = client
        # Auth headers are applied *per request* (not only as client defaults)
        # so the API key is always attached — including when a caller injects a
        # bare ``httpx.Client`` for testing.
        self._headers = dict(headers or {})
        self._rate_limiter = rate_limiter
        self._retry = retry or RetryConfig()
        self._now = now or _utc_now
        self._sleep = sleep or time.sleep

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier used as the IOC enrichment key."""

    @property
    def enabled(self) -> bool:
        """Whether this provider is active (empty key/URL → disabled)."""
        return self._enabled

    def enrich(
        self,
        iocs: Sequence[IOC],
        *,
        context: EnrichmentContext,  # noqa: ARG002 - part of the contract
    ) -> ProviderEnrichment:
        """Look up every indicator this provider handles, fail-open.

        Returns a :class:`ProviderEnrichment` whose ``results`` maps
        ``ioc_key → LookupRecord`` (sanitized). Indicators of an unhandled type
        are absent. Never raises for a lookup miss or upstream failure.
        """
        if not self._enabled:
            return ProviderEnrichment(
                provider=self.name,
                status=EnrichmentStatus.SKIPPED,
                notes=[f"{self.name}: provider disabled"],
            )

        handled = [ioc for ioc in iocs if ioc.type in self.handled_types]
        if not handled:
            return ProviderEnrichment(
                provider=self.name,
                status=EnrichmentStatus.SKIPPED,
                notes=[f"{self.name}: no indicators of a handled type"],
            )

        records = {ioc.key: self._lookup_one(ioc) for ioc in handled}
        record_list = list(records.values())
        status = _aggregate_status(record_list)
        notes = _build_notes(self.name, record_list)

        logger.info(
            "threat_intel_lookup_complete",
            component="enrichment",
            provider=self.name,
            handled_count=len(handled),
            enrichment_status=status.value,
            outcome_counts=_outcome_counts(record_list),
        )
        return ProviderEnrichment(
            provider=self.name,
            status=status,
            results={key: record.model_dump(mode="json") for key, record in records.items()},
            notes=notes,
        )

    # --- request plumbing --------------------------------------------------

    @abstractmethod
    def _build_request(self, ioc: IOC) -> tuple[str, dict[str, str] | None]:
        """Return ``(path, query_params)`` relative to the client ``base_url``."""

    @abstractmethod
    def _sanitize(self, ioc: IOC, body: Any) -> dict[str, Any] | None:
        """Extract allow-listed metadata from a 2xx JSON body.

        Returns ``None`` for a definitive "no record" answer, a ``dict`` of
        sanitized metadata on a hit, and raises ``ValueError`` / ``KeyError`` /
        ``TypeError`` on a malformed body (mapped to ``error`` by the caller).
        """

    def _lookup_one(self, ioc: IOC) -> LookupRecord:
        base: dict[str, Any] = dict(
            provider=self.name,
            indicator_type=ioc.type.value,
            timestamp=self._now().isoformat(),
        )
        if self._rate_limiter is not None and not self._rate_limiter.try_acquire():
            return LookupRecord(**base, lookup_status=LookupStatus.RATE_LIMITED)

        try:
            path, params = self._build_request(ioc)
            response = self._get(path, params=params)
        except httpx.TimeoutException:
            return LookupRecord(**base, lookup_status=LookupStatus.TIMEOUT)
        except httpx.HTTPError:
            return LookupRecord(**base, lookup_status=LookupStatus.ERROR)

        if response.status_code == 429:
            return LookupRecord(**base, lookup_status=LookupStatus.RATE_LIMITED)
        if response.status_code == 404:
            return LookupRecord(**base, lookup_status=LookupStatus.NOT_FOUND)
        if response.status_code >= 400:
            return LookupRecord(**base, lookup_status=LookupStatus.ERROR)

        try:
            body = response.json()
        except ValueError:
            return LookupRecord(**base, lookup_status=LookupStatus.ERROR)
        try:
            metadata = self._sanitize(ioc, body)
        except (ValueError, KeyError, TypeError):
            return LookupRecord(**base, lookup_status=LookupStatus.ERROR)

        if metadata is None:
            return LookupRecord(**base, lookup_status=LookupStatus.NOT_FOUND)
        return LookupRecord(**base, lookup_status=LookupStatus.FOUND, result=metadata)

    def _get(self, path: str, *, params: dict[str, str] | None = None) -> httpx.Response:
        """Perform an idempotent GET with safe retry/backoff.

        Retries only transient failures (network errors, timeouts, 429, 5xx)
        with capped exponential backoff + jitter; a final error status is
        *returned* (so the caller can classify it), while a final network error
        is re-raised.
        """
        delay = self._retry.base_delay
        for attempt in range(self._retry.max_attempts):
            try:
                response = self._client.get(path, params=params, headers=self._headers)
            except _RETRYABLE_EXCEPTIONS:
                if attempt == self._retry.max_attempts - 1:
                    raise
                self._sleep(_jittered(delay))
                delay = min(delay * 2, self._retry.max_delay)
                continue

            is_retryable_status = response.status_code in _RETRYABLE_STATUS_CODES
            if is_retryable_status and attempt < self._retry.max_attempts - 1:
                self._sleep(_retry_after_or(response, delay, self._retry.max_delay))
                delay = min(delay * 2, self._retry.max_delay)
                continue
            return response
        raise AssertionError("unreachable")  # pragma: no cover


def _aggregate_status(records: Sequence[LookupRecord]) -> EnrichmentStatus:
    """Fold per-indicator lookup statuses into one provider-level status."""
    statuses = [record.lookup_status for record in records]
    if not statuses:
        return EnrichmentStatus.SKIPPED
    if all(status in _SUCCESSFUL_LOOKUPS for status in statuses):
        return EnrichmentStatus.COMPLETE
    if all(status not in _SUCCESSFUL_LOOKUPS for status in statuses):
        return EnrichmentStatus.FAILED
    return EnrichmentStatus.PARTIAL


def _outcome_counts(records: Sequence[LookupRecord]) -> dict[str, int]:
    """Sanitized, log-safe summary: counts per status (never values/keys)."""
    return dict(Counter(record.lookup_status.value for record in records))


def _build_notes(provider: str, records: Sequence[LookupRecord]) -> list[str]:
    """Human-facing notes: counts per outcome only — no secrets, no values."""
    notes = [f"{provider}: looked up {len(records)} indicator(s)"]
    counts = _outcome_counts(records)
    if counts.get(LookupStatus.RATE_LIMITED.value):
        notes.append(f"{provider}: {counts[LookupStatus.RATE_LIMITED.value]} rate-limited")
    if counts.get(LookupStatus.TIMEOUT.value):
        notes.append(f"{provider}: {counts[LookupStatus.TIMEOUT.value]} timed out")
    if counts.get(LookupStatus.ERROR.value):
        notes.append(f"{provider}: {counts[LookupStatus.ERROR.value]} failed")
    if counts.get(LookupStatus.NOT_FOUND.value):
        notes.append(f"{provider}: {counts[LookupStatus.NOT_FOUND.value]} not found")
    return notes


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "BaseHTTPThreatIntelProvider",
    "LookupRecord",
    "LookupStatus",
    "RetryConfig",
    "TokenBucket",
]
