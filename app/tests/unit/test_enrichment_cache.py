"""Phase 2.3 unit tests: the enrichment response TTL cache.

The cache is exercised against a real temporary SQLite database (one per
test) with only the ``enrichment_cache`` table created — migrations are
covered by the integration suite. No network access anywhere: these tests
verify the storage/freshness/fail-open contract of
:class:`~soc_triage.enrichment.cache.PersistentEnrichmentCache` in
isolation, independent of any provider.

Pinned semantics:

* only definitive verdicts (``found`` / ``not_found``) are cached;
* freshness is measured from the record's own timestamp (a restored
  database never extends a verdict's validity);
* a hit replays the stored sanitized record byte-identically;
* entries are scoped per provider and per indicator type;
* expiry is lazy at read time plus explicit via ``purge_expired``;
* ``max_entries`` overflow evicts soonest-expiring rows deterministically;
* every database failure degrades to a miss / no-op (fail-open), counted
  under ``stats.failures``, never raised;
* malformed stored payloads self-heal (treated as a miss, row discarded).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from soc_triage.enrichment.cache import (
    DEFAULT_HASH_TTL_SECONDS,
    DEFAULT_IPV4_TTL_SECONDS,
    DEFAULT_MAX_ENTRIES,
    DEFAULT_OTHER_TTL_SECONDS,
    CacheStats,
    EnrichmentCachePolicy,
    PersistentEnrichmentCache,
)
from soc_triage.enrichment.threat_intel import LookupRecord, LookupStatus
from soc_triage.models.ioc import IOC, IOCType
from soc_triage.models.orm import EnrichmentCacheEntry

MD5 = "bc478d7a48bfab117da4b9bdcb5aee36"
SHA256 = "23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f"
DOC_IP = "203.0.113.50"
DOC_DOMAIN = "example.test"

FIXED_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def cache_factory(tmp_path: Path) -> sessionmaker:
    """A session factory bound to a fresh SQLite DB with only the cache table."""
    engine = create_engine(f"sqlite:///{tmp_path / 'cache.db'}")
    EnrichmentCacheEntry.__table__.create(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def cache(cache_factory: sessionmaker) -> PersistentEnrichmentCache:
    return PersistentEnrichmentCache(cache_factory)


def make_ioc(
    value: str = MD5, *, type: IOCType = IOCType.MD5, provider_enrichment: dict | None = None
) -> IOC:
    return IOC(type=type, value=value, enrichment=provider_enrichment or {})


def make_record(
    *,
    provider: str = "virustotal",
    indicator_type: str = "md5",
    status: LookupStatus = LookupStatus.FOUND,
    timestamp: datetime = FIXED_NOW,
    result: dict | None = None,
) -> LookupRecord:
    return LookupRecord(
        provider=provider,
        indicator_type=indicator_type,
        lookup_status=status,
        timestamp=timestamp.isoformat(),
        result=result if result is not None else {"malicious": 3, "reputation": -42},
    )


def put_found(cache: PersistentEnrichmentCache, ioc: IOC, record: LookupRecord) -> None:
    cache.put("virustotal", ioc, record, now=FIXED_NOW)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def test_policy_defaults_match_architecture_section_7_2() -> None:
    policy = EnrichmentCachePolicy()
    assert policy.max_entries == DEFAULT_MAX_ENTRIES == 4096
    assert policy.hash_ttl_seconds == DEFAULT_HASH_TTL_SECONDS == 6 * 3600
    assert policy.ipv4_ttl_seconds == DEFAULT_IPV4_TTL_SECONDS == 3600
    assert policy.default_ttl_seconds == DEFAULT_OTHER_TTL_SECONDS == 3600


def test_policy_ttl_mapping_by_indicator_type() -> None:
    policy = EnrichmentCachePolicy(
        hash_ttl_seconds=100, ipv4_ttl_seconds=200, default_ttl_seconds=300
    )
    assert policy.ttl_for(IOCType.MD5) == timedelta(seconds=100)
    assert policy.ttl_for(IOCType.SHA1) == timedelta(seconds=100)
    assert policy.ttl_for(IOCType.SHA256) == timedelta(seconds=100)
    assert policy.ttl_for(IOCType.IPV4) == timedelta(seconds=200)
    assert policy.ttl_for(IOCType.DOMAIN) == timedelta(seconds=300)
    assert policy.ttl_for(IOCType.URL) == timedelta(seconds=300)
    assert policy.ttl_for(IOCType.EMAIL) == timedelta(seconds=300)


def test_policy_is_frozen_and_validates_bounds() -> None:
    policy = EnrichmentCachePolicy()
    with pytest.raises(ValidationError):
        policy.max_entries = 1  # frozen model
    with pytest.raises(ValidationError):
        EnrichmentCachePolicy(max_entries=0)
    with pytest.raises(ValidationError):
        EnrichmentCachePolicy(hash_ttl_seconds=0)
    with pytest.raises(ValidationError):
        EnrichmentCachePolicy(ipv4_ttl_seconds=-1)
    with pytest.raises(ValidationError):
        EnrichmentCachePolicy(default_ttl_seconds=0)


def test_default_policy_used_when_omitted(cache_factory: sessionmaker) -> None:
    cache = PersistentEnrichmentCache(cache_factory)
    assert cache.policy == EnrichmentCachePolicy()


# ---------------------------------------------------------------------------
# Round-trip: store and replay
# ---------------------------------------------------------------------------


def test_put_then_get_replays_the_record_byte_identically(
    cache: PersistentEnrichmentCache,
) -> None:
    ioc = make_ioc()
    record = make_record()
    put_found(cache, ioc, record)

    hit = cache.get("virustotal", ioc, now=FIXED_NOW)
    assert hit is not None
    assert hit == record
    assert hit.model_dump_json() == record.model_dump_json()
    assert hit.timestamp == FIXED_NOW.isoformat()  # original timestamp kept
    assert cache.stats.hits == 1
    assert cache.stats.stores == 1
    assert len(cache) == 1


def test_get_on_empty_cache_is_a_counted_miss(cache: PersistentEnrichmentCache) -> None:
    assert cache.get("virustotal", make_ioc(), now=FIXED_NOW) is None
    stats = cache.stats
    assert stats.misses == 1
    assert stats.hits == 0
    assert len(cache) == 0


def test_stats_initial_state_is_all_zero(cache: PersistentEnrichmentCache) -> None:
    assert cache.stats == CacheStats()


def test_not_found_verdicts_are_cached_too(cache: PersistentEnrichmentCache) -> None:
    ioc = make_ioc()
    record = make_record(status=LookupStatus.NOT_FOUND, result={})
    put_found(cache, ioc, record)

    hit = cache.get("virustotal", ioc, now=FIXED_NOW)
    assert hit is not None
    assert hit.lookup_status is LookupStatus.NOT_FOUND
    assert hit.result == {}


@pytest.mark.parametrize(
    "status", [LookupStatus.ERROR, LookupStatus.TIMEOUT, LookupStatus.RATE_LIMITED]
)
def test_transient_failures_are_never_cached(
    cache: PersistentEnrichmentCache, status: LookupStatus
) -> None:
    ioc = make_ioc()
    cache.put("virustotal", ioc, make_record(status=status), now=FIXED_NOW)

    assert cache.get("virustotal", ioc, now=FIXED_NOW) is None
    assert len(cache) == 0
    stats = cache.stats
    assert stats.rejected == 1
    assert stats.stores == 0


def test_entries_are_scoped_per_provider(cache: PersistentEnrichmentCache) -> None:
    ioc = make_ioc(type=IOCType.IPV4, value=DOC_IP)
    record = make_record(provider="virustotal", indicator_type="ipv4")
    cache.put("virustotal", ioc, record, now=FIXED_NOW)

    assert cache.get("virustotal", ioc, now=FIXED_NOW) is not None
    assert cache.get("misp", ioc, now=FIXED_NOW) is None
    stats = cache.stats
    assert stats.hits == 1
    assert stats.misses == 1
    assert len(cache) == 1


def test_entries_are_scoped_per_indicator_type(cache: PersistentEnrichmentCache) -> None:
    md5_ioc = make_ioc(value=MD5, type=IOCType.MD5)
    sha256_ioc = make_ioc(value=SHA256, type=IOCType.SHA256)
    cache.put("virustotal", md5_ioc, make_record(), now=FIXED_NOW)

    assert cache.get("virustotal", md5_ioc, now=FIXED_NOW) is not None
    assert cache.get("virustotal", sha256_ioc, now=FIXED_NOW) is None


def test_second_put_refreshes_the_same_key(cache: PersistentEnrichmentCache) -> None:
    ioc = make_ioc()
    put_found(cache, ioc, make_record(result={"malicious": 1}))
    later = FIXED_NOW + timedelta(minutes=30)
    refreshed = make_record(timestamp=later, result={"malicious": 9})
    cache.put("virustotal", ioc, refreshed, now=later)

    hit = cache.get("virustotal", ioc, now=later)
    assert hit is not None
    assert hit.result == {"malicious": 9}
    assert hit.timestamp == later.isoformat()
    assert len(cache) == 1
    assert cache.stats.stores == 2


# ---------------------------------------------------------------------------
# Freshness & expiry
# ---------------------------------------------------------------------------


def test_fresh_entry_within_ttl_is_a_hit(cache: PersistentEnrichmentCache) -> None:
    ioc = make_ioc()
    put_found(cache, ioc, make_record())
    just_before_expiry = FIXED_NOW + timedelta(seconds=DEFAULT_HASH_TTL_SECONDS - 1)

    assert cache.get("virustotal", ioc, now=just_before_expiry) is not None


def test_entry_is_expired_exactly_at_ttl_boundary(cache: PersistentEnrichmentCache) -> None:
    ioc = make_ioc()
    put_found(cache, ioc, make_record())
    at_expiry = FIXED_NOW + timedelta(seconds=DEFAULT_HASH_TTL_SECONDS)

    assert cache.get("virustotal", ioc, now=at_expiry) is None
    stats = cache.stats
    assert stats.expirations == 1
    assert stats.misses == 1
    assert len(cache) == 0  # expired rows are removed lazily


def test_ipv4_ttl_is_shorter_than_hash_ttl(cache: PersistentEnrichmentCache) -> None:
    ip_ioc = make_ioc(value=DOC_IP, type=IOCType.IPV4)
    hash_ioc = make_ioc(value=SHA256, type=IOCType.SHA256)
    cache.put("virustotal", ip_ioc, make_record(indicator_type="ipv4"), now=FIXED_NOW)
    cache.put("virustotal", hash_ioc, make_record(indicator_type="sha256"), now=FIXED_NOW)

    after_one_hour = FIXED_NOW + timedelta(seconds=DEFAULT_IPV4_TTL_SECONDS)
    assert cache.get("virustotal", ip_ioc, now=after_one_hour) is None  # 1 h TTL up
    assert cache.get("virustotal", hash_ioc, now=after_one_hour) is not None  # 6 h TTL


def test_freshness_is_measured_from_the_original_lookup_time(
    cache: PersistentEnrichmentCache,
) -> None:
    """A stale verdict stored late must not gain a fresh lifetime."""
    ioc = make_ioc()
    old_lookup = FIXED_NOW - timedelta(hours=24)
    stale = make_record(timestamp=old_lookup)
    cache.put("virustotal", ioc, stale, now=FIXED_NOW)

    assert len(cache) == 1  # stored (expiry only enforced at read time)
    assert cache.get("virustotal", ioc, now=FIXED_NOW) is None
    assert cache.stats.expirations == 1


def test_purge_expired_removes_only_expired_rows(cache: PersistentEnrichmentCache) -> None:
    fresh_ioc = make_ioc(value=SHA256, type=IOCType.SHA256)
    stale_ioc = make_ioc(value=MD5, type=IOCType.MD5)
    put_found(cache, fresh_ioc, make_record(indicator_type="sha256"))
    cache.put(
        "virustotal",
        stale_ioc,
        make_record(timestamp=FIXED_NOW - timedelta(days=2)),
        now=FIXED_NOW,
    )
    assert len(cache) == 2

    removed = cache.purge_expired(now=FIXED_NOW)
    assert removed == 1
    assert len(cache) == 1
    assert cache.get("virustotal", fresh_ioc, now=FIXED_NOW) is not None


def test_clear_removes_everything_and_reports_the_count(
    cache: PersistentEnrichmentCache,
) -> None:
    put_found(cache, make_ioc(value=MD5), make_record())
    put_found(cache, make_ioc(value=SHA256, type=IOCType.SHA256), make_record())
    assert len(cache) == 2

    assert cache.clear() == 2
    assert len(cache) == 0
    assert cache.get("virustotal", make_ioc(value=MD5), now=FIXED_NOW) is None


# ---------------------------------------------------------------------------
# Bounded size
# ---------------------------------------------------------------------------


def test_overflow_evicts_soonest_expiring_entries(cache_factory: sessionmaker) -> None:
    cache = PersistentEnrichmentCache(cache_factory, policy=EnrichmentCachePolicy(max_entries=3))
    # Four hashes looked up one second apart: the earliest expires first.
    iocs = []
    for i in range(4):
        ioc = make_ioc(value=f"{MD5[:-2]}{i:02x}")
        iocs.append(ioc)
        record = make_record(timestamp=FIXED_NOW + timedelta(seconds=i))
        cache.put("virustotal", ioc, record, now=FIXED_NOW + timedelta(seconds=i))

    assert len(cache) == 3
    stats = cache.stats
    assert stats.evictions == 1
    assert cache.get("virustotal", iocs[0], now=FIXED_NOW) is None  # evicted
    for ioc in iocs[1:]:
        assert cache.get("virustotal", ioc, now=FIXED_NOW) is not None


# ---------------------------------------------------------------------------
# Fail-open behavior
# ---------------------------------------------------------------------------


def _drop_cache_table(cache_factory: sessionmaker) -> None:
    """Break the database so every statement fails with a SQLAlchemyError."""
    session = cache_factory()
    try:
        session.execute(text("DROP TABLE enrichment_cache"))
        session.commit()
    finally:
        session.close()


def _restore_cache_table(cache_factory: sessionmaker) -> None:
    session = cache_factory()
    try:
        session.execute(
            text(
                """
                CREATE TABLE enrichment_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider VARCHAR(32) NOT NULL,
                    indicator_type VARCHAR(16) NOT NULL,
                    indicator_value TEXT NOT NULL,
                    lookup_status VARCHAR(16) NOT NULL,
                    payload TEXT NOT NULL,
                    looked_at DATETIME NOT NULL,
                    expires_at DATETIME NOT NULL
                )
                """
            )
        )
        session.commit()
    finally:
        session.close()


def test_get_fail_open_on_database_failure(cache: PersistentEnrichmentCache) -> None:
    ioc = make_ioc()
    put_found(cache, ioc, make_record())
    _drop_cache_table(cache._session_factory)

    assert cache.get("virustotal", ioc, now=FIXED_NOW) is None
    # Two counted failures: the read itself, and the best-effort discard of
    # the (presumed) malformed row. Both are swallowed — never raised.
    assert cache.stats.failures == 2


def test_put_fail_open_on_database_failure(cache: PersistentEnrichmentCache) -> None:
    _drop_cache_table(cache._session_factory)
    cache.put("virustotal", make_ioc(), make_record(), now=FIXED_NOW)
    assert cache.stats.failures == 1
    assert cache.stats.stores == 0


def test_cache_recovers_after_database_failure(cache: PersistentEnrichmentCache) -> None:
    factory = cache._session_factory
    _drop_cache_table(factory)
    assert cache.get("virustotal", make_ioc(), now=FIXED_NOW) is None
    _restore_cache_table(factory)

    ioc = make_ioc()
    put_found(cache, ioc, make_record())
    assert cache.get("virustotal", ioc, now=FIXED_NOW) is not None


def test_len_and_clear_are_fail_open(cache: PersistentEnrichmentCache) -> None:
    _drop_cache_table(cache._session_factory)
    assert len(cache) == 0
    assert cache.clear() == 0
    assert cache.purge_expired(now=FIXED_NOW) == 0
    assert cache.stats.failures >= 3


def test_malformed_payload_self_heals_to_a_miss(cache_factory: sessionmaker) -> None:
    session = cache_factory()
    try:
        session.add(
            EnrichmentCacheEntry(
                provider="virustotal",
                indicator_type="md5",
                indicator_value=MD5,
                lookup_status="found",
                payload="this-is-not-a-lookup-record",
                looked_at=FIXED_NOW,
                expires_at=FIXED_NOW + timedelta(hours=6),
            )
        )
        session.commit()
    finally:
        session.close()

    cache = PersistentEnrichmentCache(cache_factory)
    assert cache.get("virustotal", make_ioc(), now=FIXED_NOW) is None
    stats = cache.stats
    assert stats.misses == 1
    assert stats.failures == 1
    assert len(cache) == 0  # the corrupt row was discarded


# ---------------------------------------------------------------------------
# Hygiene
# ---------------------------------------------------------------------------


def test_repr_never_echoes_configuration_or_data(cache: PersistentEnrichmentCache) -> None:
    rendered = repr(cache)
    assert rendered == "<PersistentEnrichmentCache>"
    assert "sqlite" not in rendered.lower()
