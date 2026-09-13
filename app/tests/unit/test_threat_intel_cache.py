"""Phase 2.3 unit tests: response TTL cache wired into the threat-intel base.

Exercises :class:`~soc_triage.enrichment.threat_intel.BaseHTTPThreatIntelProvider`
with a real :class:`~soc_triage.enrichment.cache.PersistentEnrichmentCache`
(temporary SQLite) and ``httpx.MockTransport`` fakes — **no network access**.

Pinned behavior:

* a fresh cache hit replays the stored verdict byte-identically, issues
  **zero** outbound requests, and consumes **zero** rate-limiter tokens
  (the quota-savings guarantee of ARCHITECTURE.md §7.2 step 2);
* only definitive verdicts (``found`` / ``not_found``) are cached —
  ``error`` / ``timeout`` / ``rate_limited`` stay retryable;
* freshness is measured from the original lookup timestamp, so an expired
  entry triggers a real re-lookup;
* entries are provider-scoped (a VirusTotal verdict is never served for a
  MISP lookup sharing the same cache);
* a disabled provider never touches the cache;
* a broken cache degrades to a normal lookup (fail-open twice over: the
  persistent cache never raises, and the provider guards the contract);
* ``cache=None`` preserves the pre-2.3 path byte-for-byte.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from soc_triage.enrichment import (
    IOC,
    EnrichmentContext,
    EnrichmentStatus,
    IOCType,
    LookupStatus,
    MISPProvider,
    PersistentEnrichmentCache,
    TokenBucket,
    VirusTotalProvider,
)
from soc_triage.enrichment.threat_intel import LookupRecord, RetryConfig
from soc_triage.enrichment.virustotal import VT_BASE_URL
from soc_triage.models.orm import EnrichmentCacheEntry

FAKE_VT_KEY = "vt-fake-key-0123456789abcdef"
FAKE_MISP_KEY = "misp-fake-key-0123456789abcdef"
MISP_URL = "https://misp.example.test"

MD5 = "bc478d7a48bfab117da4b9bdcb5aee36"
DOC_IP = "203.0.113.50"

FIXED_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)


def _noop_sleep(_seconds: float) -> None:
    """Replace ``time.sleep`` so retry/backoff paths run instantly in tests."""


class RequestCounter:
    """Counts outbound requests a MockTransport handler receives."""

    def __init__(self) -> None:
        self.count = 0

    def vt_found(self, request: httpx.Request) -> httpx.Response:  # noqa: ARG002
        self.count += 1
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 0,
                            "harmless": 50,
                            "undetected": 5,
                        },
                        "reputation": -42,
                    }
                }
            },
        )

    def vt_not_found(self, request: httpx.Request) -> httpx.Response:  # noqa: ARG002
        self.count += 1
        return httpx.Response(404, json={})

    def vt_server_error(self, request: httpx.Request) -> httpx.Response:  # noqa: ARG002
        self.count += 1
        return httpx.Response(500, json={})

    def vt_rate_limited(self, request: httpx.Request) -> httpx.Response:  # noqa: ARG002
        self.count += 1
        return httpx.Response(429, json={})

    def vt_timeout(self, request: httpx.Request) -> httpx.Response:
        self.count += 1
        raise httpx.ReadTimeout("simulated timeout", request=request)

    def misp_found(self, request: httpx.Request) -> httpx.Response:  # noqa: ARG002
        self.count += 1
        return httpx.Response(
            200,
            json={"response": {"Attribute": [{"event_id": "7", "tags": []}]}},
        )


@pytest.fixture
def cache(tmp_path: Path) -> PersistentEnrichmentCache:
    engine = create_engine(f"sqlite:///{tmp_path / 'cache.db'}")
    EnrichmentCacheEntry.__table__.create(engine)
    return PersistentEnrichmentCache(sessionmaker(bind=engine, expire_on_commit=False))


def make_vt(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    cache: PersistentEnrichmentCache | None,
    clock: list[datetime] | None = None,
    rate_limiter: TokenBucket | None = None,
) -> VirusTotalProvider:
    client = httpx.Client(base_url=VT_BASE_URL, transport=httpx.MockTransport(handler))
    return VirusTotalProvider(
        FAKE_VT_KEY,
        client=client,
        rate_limiter=rate_limiter,
        cache=cache,
        now=(lambda: clock[0]) if clock else (lambda: FIXED_NOW),
        sleep=_noop_sleep,
        retry=RetryConfig(max_attempts=1),
    )


def make_misp(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    cache: PersistentEnrichmentCache | None,
) -> MISPProvider:
    client = httpx.Client(base_url=MISP_URL, transport=httpx.MockTransport(handler))
    return MISPProvider(
        MISP_URL,
        FAKE_MISP_KEY,
        client=client,
        cache=cache,
        now=lambda: FIXED_NOW,
        sleep=_noop_sleep,
        retry=RetryConfig(max_attempts=1),
    )


def md5_ioc() -> IOC:
    return IOC(type=IOCType.MD5, value=MD5)


CONTEXT = EnrichmentContext(source="test")


# ---------------------------------------------------------------------------
# Hits: no outbound request, no token, byte-identical replay
# ---------------------------------------------------------------------------


def test_second_lookup_is_served_from_cache_without_any_request(
    cache: PersistentEnrichmentCache,
) -> None:
    counter = RequestCounter()
    provider = make_vt(counter.vt_found, cache=cache)

    first = provider.enrich([md5_ioc()], context=CONTEXT)
    second = provider.enrich([md5_ioc()], context=CONTEXT)

    assert counter.count == 1  # exactly one outbound request, ever
    assert first.results == second.results  # byte-identical payloads
    assert second.status is EnrichmentStatus.COMPLETE
    assert "virustotal: 1 served from cache" in second.notes
    assert cache.stats.hits == 1
    assert cache.stats.stores == 1
    assert len(cache) == 1


def test_cache_hit_consumes_no_rate_limiter_token(cache: PersistentEnrichmentCache) -> None:
    counter = RequestCounter()
    # One token, effectively no refill: the first lookup exhausts the quota.
    provider = make_vt(
        counter.vt_found,
        cache=cache,
        rate_limiter=TokenBucket(1, 1 / 3600),
    )

    first = provider.enrich([md5_ioc()], context=CONTEXT)
    assert first.status is EnrichmentStatus.COMPLETE

    # Same indicator: served from cache despite the exhausted quota.
    cached = provider.enrich([md5_ioc()], context=CONTEXT)
    assert cached.status is EnrichmentStatus.COMPLETE
    assert cached.results == first.results

    # A *different* indicator still hits the quota wall (cache is no excuse).
    other = IOC(type=IOCType.IPV4, value=DOC_IP)
    limited = provider.enrich([other], context=CONTEXT)
    assert limited.status is EnrichmentStatus.FAILED
    assert limited.results[other.key]["lookup_status"] == LookupStatus.RATE_LIMITED.value
    assert counter.count == 1


def test_cached_payload_preserves_the_original_timestamp(
    cache: PersistentEnrichmentCache,
) -> None:
    counter = RequestCounter()
    clock = [FIXED_NOW]
    provider = make_vt(counter.vt_found, cache=cache, clock=clock)

    provider.enrich([md5_ioc()], context=CONTEXT)
    clock[0] = FIXED_NOW + timedelta(hours=1)  # one hour later, still fresh
    second = provider.enrich([md5_ioc()], context=CONTEXT)

    assert counter.count == 1
    assert second.results[md5_ioc().key]["timestamp"] == FIXED_NOW.isoformat()


def test_mixed_cached_and_fresh_indicators(cache: PersistentEnrichmentCache) -> None:
    counter = RequestCounter()
    provider = make_vt(counter.vt_found, cache=cache)

    provider.enrich([md5_ioc()], context=CONTEXT)  # seeds the cache
    mixed = provider.enrich([md5_ioc(), IOC(type=IOCType.IPV4, value=DOC_IP)], context=CONTEXT)

    assert counter.count == 2  # only the IP required an outbound request
    assert len(mixed.results) == 2
    assert mixed.status is EnrichmentStatus.COMPLETE
    assert "virustotal: 1 served from cache" in mixed.notes


def test_not_found_verdicts_are_cached_and_replayed(
    cache: PersistentEnrichmentCache,
) -> None:
    counter = RequestCounter()
    provider = make_vt(counter.vt_not_found, cache=cache)

    first = provider.enrich([md5_ioc()], context=CONTEXT)
    second = provider.enrich([md5_ioc()], context=CONTEXT)

    assert counter.count == 1
    assert first.results == second.results
    assert second.results[md5_ioc().key]["lookup_status"] == LookupStatus.NOT_FOUND.value
    assert len(cache) == 1


# ---------------------------------------------------------------------------
# Misses: transient failures stay retryable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "handler_name",
    ["vt_server_error", "vt_rate_limited", "vt_timeout"],
)
def test_transient_failures_are_never_cached(
    cache: PersistentEnrichmentCache, handler_name: str
) -> None:
    counter = RequestCounter()
    provider = make_vt(getattr(counter, handler_name), cache=cache)

    first = provider.enrich([md5_ioc()], context=CONTEXT)
    second = provider.enrich([md5_ioc()], context=CONTEXT)

    assert counter.count == 2  # the second lookup really went outbound again
    assert first.results == second.results
    assert first.status is EnrichmentStatus.FAILED
    assert len(cache) == 0
    assert cache.stats.stores == 0


def test_expired_entry_triggers_a_real_relookup(cache: PersistentEnrichmentCache) -> None:
    counter = RequestCounter()
    clock = [FIXED_NOW]
    provider = make_vt(counter.vt_found, cache=cache, clock=clock)

    provider.enrich([md5_ioc()], context=CONTEXT)
    clock[0] = FIXED_NOW + timedelta(seconds=6 * 3600)  # hash TTL (6 h) is up
    provider.enrich([md5_ioc()], context=CONTEXT)

    assert counter.count == 2
    assert cache.stats.expirations == 1
    # The refreshed verdict is stored again.
    assert cache.stats.stores == 2


# ---------------------------------------------------------------------------
# Scoping, disablement, fail-open
# ---------------------------------------------------------------------------


def test_cache_entries_are_provider_scoped(cache: PersistentEnrichmentCache) -> None:
    vt_counter = RequestCounter()
    misp_counter = RequestCounter()
    ioc = IOC(type=IOCType.IPV4, value=DOC_IP)

    vt = make_vt(vt_counter.vt_found, cache=cache)
    misp = make_misp(misp_counter.misp_found, cache=cache)

    vt.enrich([ioc], context=CONTEXT)
    result = misp.enrich([ioc], context=CONTEXT)

    assert vt_counter.count == 1
    assert misp_counter.count == 1  # MISP did NOT reuse the VT verdict
    assert result.results[ioc.key]["provider"] == "misp"
    assert len(cache) == 2


def test_disabled_provider_never_touches_the_cache(
    cache: PersistentEnrichmentCache,
) -> None:
    counter = RequestCounter()
    client = httpx.Client(base_url=VT_BASE_URL, transport=httpx.MockTransport(counter.vt_found))
    provider = VirusTotalProvider(None, client=client, cache=cache)

    result = provider.enrich([md5_ioc()], context=CONTEXT)

    assert result.status is EnrichmentStatus.SKIPPED
    assert counter.count == 0
    assert len(cache) == 0
    stats = cache.stats  # no hits/misses/stores recorded at all
    assert stats.hits == 0
    assert stats.misses == 0
    assert stats.stores == 0


class BrokenCache:
    """A cache that violates the fail-open contract — the provider must cope."""

    # Argument names kept for protocol-shape readability; all calls raise.

    def get(self, provider: str, ioc: IOC, *, now: datetime) -> LookupRecord | None:  # noqa: ARG002
        raise RuntimeError("cache backend exploded")

    def put(self, provider: str, ioc: IOC, record: LookupRecord, *, now: datetime) -> None:  # noqa: ARG002
        raise RuntimeError("cache backend exploded")


def test_broken_cache_degrades_to_normal_lookups() -> None:
    counter = RequestCounter()
    client = httpx.Client(base_url=VT_BASE_URL, transport=httpx.MockTransport(counter.vt_found))
    provider = VirusTotalProvider(FAKE_VT_KEY, client=client, cache=BrokenCache())

    result = provider.enrich([md5_ioc()], context=CONTEXT)

    assert result.status is EnrichmentStatus.COMPLETE
    assert counter.count == 1
    assert result.results[md5_ioc().key]["lookup_status"] == LookupStatus.FOUND.value


def test_no_cache_preserves_the_pre_2_3_path_byte_for_byte() -> None:
    counter = RequestCounter()
    provider = make_vt(counter.vt_found, cache=None)

    first = provider.enrich([md5_ioc()], context=CONTEXT)
    second = provider.enrich([md5_ioc()], context=CONTEXT)

    assert counter.count == 2  # every lookup goes outbound
    assert first.results == second.results
    assert not any("served from cache" in note for note in first.notes)
    assert not any("served from cache" in note for note in second.notes)


def test_cache_note_absent_when_nothing_was_cached(cache: PersistentEnrichmentCache) -> None:
    counter = RequestCounter()
    provider = make_vt(counter.vt_found, cache=cache)

    first = provider.enrich([md5_ioc()], context=CONTEXT)
    assert not any("served from cache" in note for note in first.notes)
    assert first.notes[0] == "virustotal: looked up 1 indicator(s)"


def test_cache_is_never_consulted_for_unhandled_types(
    cache: PersistentEnrichmentCache,
) -> None:
    counter = RequestCounter()
    provider = make_vt(counter.vt_found, cache=cache)
    email = IOC(type=IOCType.EMAIL, value="user@example.test")

    result = provider.enrich([email], context=CONTEXT)

    assert result.status is EnrichmentStatus.SKIPPED
    assert counter.count == 0
    assert len(cache) == 0
    assert cache.stats.hits == 0
    assert cache.stats.misses == 0


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_repeated_cached_runs_are_deterministic(cache: PersistentEnrichmentCache) -> None:
    counter = RequestCounter()
    provider = make_vt(counter.vt_found, cache=cache)
    provider.enrich([md5_ioc()], context=CONTEXT)

    runs = [provider.enrich([md5_ioc()], context=CONTEXT) for _ in range(3)]
    assert all(run.results == runs[0].results for run in runs)
    assert all(run.status is EnrichmentStatus.COMPLETE for run in runs)
    assert counter.count == 1
