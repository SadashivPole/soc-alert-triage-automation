"""Enrichment response TTL cache (Phase 2.3).

SQLite-backed response cache for threat-intel lookups (ARCHITECTURE.md §7.2,
step 2: "Local cache — TTL 6 h hashes / 1 h IPs — SQLite-backed — avoids
quota burn — fail-open").

Semantics
---------

* **Cacheable verdicts only** — only *definitive* answers
  (:data:`~soc_triage.enrichment.threat_intel.LookupStatus.FOUND` and
  :data:`~soc_triage.enrichment.threat_intel.LookupStatus.NOT_FOUND`) are
  stored. Transient failures (``error`` / ``timeout`` / ``rate_limited``)
  are never cached, so a failed lookup is always retried on the next alert.
* **Freshness is measured from the original lookup**, not from storage
  time: ``expires_at = LookupRecord.timestamp + ttl_for(type)``. A restored
  or copied database therefore never extends a verdict's validity.
* **Byte-identical replay** — a cache hit replays the stored sanitized
  :class:`~soc_triage.enrichment.threat_intel.LookupRecord` unchanged
  (including its original ``timestamp``). The cache never alters payloads,
  so scoring, decisions, explanations and notifications see exactly the
  data the live lookup produced.
* **Provider-scoped keys** — entries are keyed by
  ``(provider, indicator_type, indicator_value)``; a VirusTotal verdict is
  never served for a MISP lookup (or vice versa). Indicator values are the
  normalized representation (lowercased hashes/domains, canonical URL/IPv4),
  so equality is stable.
* **Fail-open** — the cache never raises: any database failure is counted
  (``stats.failures``), logged by exception *type* only (SECURITY.md §7),
  and degrades to a normal lookup. A malformed stored payload is treated as
  a miss and its row discarded (self-healing).
* **Bounded** — at most ``policy.max_entries`` rows; on overflow the entries
  expiring soonest are evicted (deterministic: ``expires_at``, then ``id``).

Privacy / secrets
-----------------

Rows store the indicator value (the same data the ``alerts`` table already
persists) and the *sanitized* lookup record — the explicit allow-listed
metadata the pipeline stores on the IOC anyway. Raw upstream bodies and API
keys are never cached (SECURITY.md §2, §5, §7).

The cache is a quota/latency optimization only: it never feeds
``scoring.v1`` / ``decisions.v1`` on its own and is **disabled by default**
(``TRIAGE_ENRICHMENT_CACHE_ENABLED``), matching the Phase 2.2
disabled-by-default convention.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.ioc import IOC, IOCType
from ..models.orm import EnrichmentCacheEntry
from .threat_intel import LookupRecord, LookupStatus

logger = get_logger("soc_triage.enrichment.cache")

#: ARCHITECTURE.md §7.2: "TTL 6 h hashes / 1 h IPs".
DEFAULT_HASH_TTL_SECONDS = 6 * 3600
DEFAULT_IPV4_TTL_SECONDS = 3600
#: Types ARCHITECTURE.md §7.2 does not pin explicitly (domain/url/email).
DEFAULT_OTHER_TTL_SECONDS = 3600
#: Conservative bound: a lab never needs an unbounded verdict table.
DEFAULT_MAX_ENTRIES = 4096

#: Lookup outcomes that are safe to cache (definitive answers only).
CACHEABLE_STATUSES: frozenset[LookupStatus] = frozenset(
    {LookupStatus.FOUND, LookupStatus.NOT_FOUND}
)


class EnrichmentCachePolicy(BaseModel):
    """Versioned, deterministic configuration of the response cache."""

    model_config = {"frozen": True}

    #: Hard cap on cached rows; overflow evicts soonest-expiring entries.
    max_entries: int = Field(default=DEFAULT_MAX_ENTRIES, ge=1)
    #: TTL for MD5/SHA1/SHA256 verdicts (ARCHITECTURE.md §7.2: 6 h).
    hash_ttl_seconds: int = Field(default=DEFAULT_HASH_TTL_SECONDS, ge=1)
    #: TTL for IPv4 verdicts (ARCHITECTURE.md §7.2: 1 h).
    ipv4_ttl_seconds: int = Field(default=DEFAULT_IPV4_TTL_SECONDS, ge=1)
    #: TTL for types §7.2 does not pin (domain, URL, email).
    default_ttl_seconds: int = Field(default=DEFAULT_OTHER_TTL_SECONDS, ge=1)

    def ttl_for(self, ioc_type: IOCType) -> timedelta:
        """Return the cache lifetime for one indicator type."""
        if ioc_type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
            return timedelta(seconds=self.hash_ttl_seconds)
        if ioc_type is IOCType.IPV4:
            return timedelta(seconds=self.ipv4_ttl_seconds)
        return timedelta(seconds=self.default_ttl_seconds)


class CacheStats(BaseModel):
    """Observable counters for the cache (log/inspection-safe, no payloads)."""

    model_config = {"frozen": True}

    hits: int = Field(default=0, ge=0)
    misses: int = Field(default=0, ge=0)
    #: Definitive records written (insert or refresh of an existing key).
    stores: int = Field(default=0, ge=0)
    #: ``put`` calls ignored because the status is not cacheable.
    rejected: int = Field(default=0, ge=0)
    #: Rows found expired at read time (lazily removed).
    expirations: int = Field(default=0, ge=0)
    #: Rows removed to honour ``max_entries``.
    evictions: int = Field(default=0, ge=0)
    #: Database failures swallowed to stay fail-open.
    failures: int = Field(default=0, ge=0)


def _as_aware(value: datetime) -> datetime:
    """Normalize a datetime to UTC-aware (SQLite may hand back naive rows)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_lookup_time(record: LookupRecord, fallback: datetime) -> datetime:
    """Original lookup instant from the record's own timestamp."""
    try:
        return _as_aware(datetime.fromisoformat(record.timestamp))
    except ValueError:  # pragma: no cover - records always carry ISO-8601
        return fallback


class PersistentEnrichmentCache:
    """SQLite-backed TTL cache for sanitized enrichment responses.

    Implements the structural cache contract consumed by
    :class:`~soc_triage.enrichment.threat_intel.BaseHTTPThreatIntelProvider`
    (``get`` / ``put`` with an explicit ``now``). Every method is fail-open:
    database problems are counted and logged, never raised.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        policy: EnrichmentCachePolicy | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._policy = policy or EnrichmentCachePolicy()
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {
            "hits": 0,
            "misses": 0,
            "stores": 0,
            "rejected": 0,
            "expirations": 0,
            "evictions": 0,
            "failures": 0,
        }

    @property
    def policy(self) -> EnrichmentCachePolicy:
        """The immutable policy this cache runs with."""
        return self._policy

    @property
    def stats(self) -> CacheStats:
        """A snapshot of the observable counters."""
        with self._lock:
            return CacheStats(**self._counters)

    def _bump(self, name: str, count: int = 1) -> None:
        with self._lock:
            self._counters[name] += count

    def _fail_open(self, event: str, exc: Exception) -> None:
        self._bump("failures")
        # Exception *type* only — never messages (SECURITY.md §7).
        logger.warning(
            event,
            component="enrichment_cache",
            error_type=type(exc).__name__,
        )

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def get(self, provider: str, ioc: IOC, *, now: datetime) -> LookupRecord | None:
        """Return the cached record when fresh; ``None`` on miss/expiry/failure."""
        try:
            with session_scope(self._session_factory) as session:
                entry = self._find_entry(session, provider, ioc)
                if entry is None:
                    self._bump("misses")
                    return None
                expires_at = _as_aware(entry.expires_at)
                if expires_at <= now:
                    # Expired: remove lazily and report a miss.
                    session.delete(entry)
                    self._bump("expirations")
                    self._bump("misses")
                    return None
                record = LookupRecord.model_validate_json(entry.payload)
        except (SQLAlchemyError, ValueError) as exc:
            # ValueError covers malformed stored payloads: self-heal by
            # treating them as misses (the row is removed best-effort below).
            self._fail_open("enrichment_cache_get_failed", exc)
            self._discard_best_effort(provider, ioc)
            self._bump("misses")
            return None
        self._bump("hits")
        return record

    # ------------------------------------------------------------------
    # Write path
    # ------------------------------------------------------------------

    def put(self, provider: str, ioc: IOC, record: LookupRecord, *, now: datetime) -> None:
        """Store a definitive lookup verdict; ignore non-cacheable statuses."""
        if record.lookup_status not in CACHEABLE_STATUSES:
            self._bump("rejected")
            return
        try:
            looked_at = _parse_lookup_time(record, now)
            expires_at = looked_at + self._policy.ttl_for(ioc.type)
            payload = record.model_dump_json()
            with self._lock, session_scope(self._session_factory) as session:
                entry = self._find_entry(session, provider, ioc)
                if entry is not None:
                    entry.lookup_status = record.lookup_status.value
                    entry.payload = payload
                    entry.looked_at = looked_at
                    entry.expires_at = expires_at
                else:
                    session.add(
                        EnrichmentCacheEntry(
                            provider=provider,
                            indicator_type=ioc.type.value,
                            indicator_value=ioc.value,
                            lookup_status=record.lookup_status.value,
                            payload=payload,
                            looked_at=looked_at,
                            expires_at=expires_at,
                        )
                    )
                evicted = self._evict_overflow(session)
            self._bump("stores")
            if evicted:
                self._bump("evictions", evicted)
        except SQLAlchemyError as exc:
            self._fail_open("enrichment_cache_put_failed", exc)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def purge_expired(self, *, now: datetime) -> int:
        """Delete every expired row; return how many were removed."""
        try:
            with session_scope(self._session_factory) as session:
                rows = session.scalars(
                    select(EnrichmentCacheEntry).where(EnrichmentCacheEntry.expires_at <= now)
                ).all()
                count = len(rows)
                for row in rows:
                    session.delete(row)
            if count:
                self._bump("expirations", count)
            return count
        except SQLAlchemyError as exc:
            self._fail_open("enrichment_cache_purge_failed", exc)
            return 0

    def clear(self) -> int:
        """Remove every cached row; return how many were removed."""
        try:
            with session_scope(self._session_factory) as session:
                count = session.scalar(select(func.count()).select_from(EnrichmentCacheEntry))
                session.execute(delete(EnrichmentCacheEntry))
            return int(count or 0)
        except SQLAlchemyError as exc:
            self._fail_open("enrichment_cache_clear_failed", exc)
            return 0

    def __len__(self) -> int:
        """Number of cached rows (0 on any database failure — fail-open)."""
        try:
            with session_scope(self._session_factory) as session:
                count = session.scalar(select(func.count()).select_from(EnrichmentCacheEntry))
            return int(count or 0)
        except SQLAlchemyError as exc:
            self._fail_open("enrichment_cache_count_failed", exc)
            return 0

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _find_entry(self, session: Session, provider: str, ioc: IOC) -> EnrichmentCacheEntry | None:
        return session.scalar(
            select(EnrichmentCacheEntry)
            .where(EnrichmentCacheEntry.provider == provider)
            .where(EnrichmentCacheEntry.indicator_type == ioc.type.value)
            .where(EnrichmentCacheEntry.indicator_value == ioc.value)
        )

    def _evict_overflow(self, session: Session) -> int:
        """Evict soonest-expiring rows beyond ``max_entries`` (session-local)."""
        total = session.scalar(select(func.count()).select_from(EnrichmentCacheEntry)) or 0
        overflow = int(total) - self._policy.max_entries
        if overflow <= 0:
            return 0
        victims = session.scalars(
            select(EnrichmentCacheEntry)
            .order_by(EnrichmentCacheEntry.expires_at.asc(), EnrichmentCacheEntry.id.asc())
            .limit(overflow)
        ).all()
        for victim in victims:
            session.delete(victim)
        return len(victims)

    def _discard_best_effort(self, provider: str, ioc: IOC) -> None:
        """Remove a row that failed to load (self-heal); never raises."""
        try:
            with session_scope(self._session_factory) as session:
                entry = self._find_entry(session, provider, ioc)
                if entry is not None:
                    session.delete(entry)
        except SQLAlchemyError as exc:
            self._fail_open("enrichment_cache_discard_failed", exc)

    def __repr__(self) -> str:
        """Deliberately attribute-free: never echo configuration or data."""
        return f"<{type(self).__name__}>"


__all__ = [
    "CACHEABLE_STATUSES",
    "DEFAULT_HASH_TTL_SECONDS",
    "DEFAULT_IPV4_TTL_SECONDS",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_OTHER_TTL_SECONDS",
    "CacheStats",
    "EnrichmentCachePolicy",
    "PersistentEnrichmentCache",
]
