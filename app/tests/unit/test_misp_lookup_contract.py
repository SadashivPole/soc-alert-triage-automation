"""Phase 2.4 contract tests: the MISP lookup path, end to end at the provider.

The `intel` compose profile only becomes useful if the lookup contract is exact,
so this suite pins it against ``httpx.MockTransport`` fakes (no network — the
development sandbox has no Docker and no MISP instance):

* **read-only request shape** — exactly one ``GET /attributes/restSearch`` per
  indicator, ``value``/``returnFormat`` parameters, no request body, and the API
  key attached only as the ``Authorization`` header;
* **sanitization is an allow-list** — only ``match_count``, capped/sorted
  ``event_ids`` and capped/sorted ``tags`` survive; raw attribute values, event
  payloads and unrelated fields never do, even when upstream echoes them;
* **failure behavior** — 4xx/5xx/429, timeouts, connection errors and malformed
  bodies are recorded as ``error``/``timeout``/``rate_limited``/``not_found``
  and never raise or block the pipeline (fail-open, ARCHITECTURE.md §7.3);
* **cache wiring (Phase 2.3 preserved)** — definitive MISP verdicts replay
  byte-identically with zero outbound requests and zero rate-limiter tokens,
  failures are never cached, and verdicts stay provider-scoped;
* **secret safety** — the key never appears in results, notes, provenance, the
  request URL/params, or the provider's ``repr``;
* **zero-external fallback** — the compose defaults (empty ``MISP_URL`` /
  ``MISP_API_KEY``) construct a disabled provider that issues no requests.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from soc_triage.enrichment import (
    IOC,
    EnrichmentContext,
    EnrichmentStatus,
    IOCType,
    MISPProvider,
    PersistentEnrichmentCache,
    TokenBucket,
)
from soc_triage.enrichment.threat_intel import RetryConfig
from soc_triage.models.orm import EnrichmentCacheEntry

# Synthetic, non-secret canary key (SECURITY.md §5: never real credentials).
FAKE_MISP_KEY = "misp-fake-key-0123456789abcdef"
MISP_URL = "https://misp.example.test"

DOC_IP = "203.0.113.50"
MD5 = "bc478d7a48bfab117da4b9bdcb5aee36"

FIXED_NOW = datetime(2026, 9, 13, 12, 0, 0, tzinfo=UTC)

CONTEXT = EnrichmentContext(source="test")

Handler = Callable[[httpx.Request], httpx.Response]


def _noop_sleep(_seconds: float) -> None:
    """Retry/backoff paths run instantly in tests."""


def _fixture_event(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    attribute: dict[str, Any] = {
        "id": "1",
        "event_id": "1024",
        "value": DOC_IP,
        "type": "ip-src",
        "tags": [{"name": "synthetic:true"}, {"name": "lab:documentation-ranges"}],
    }
    if overrides:
        attribute.update(overrides)
    return {"response": {"Attribute": [attribute]}}


def make_misp(
    handler: Handler,
    *,
    api_key: str | None = FAKE_MISP_KEY,
    url: str = MISP_URL,
    cache: PersistentEnrichmentCache | None = None,
    rate_limiter: TokenBucket | None = None,
    max_attempts: int = 1,
) -> MISPProvider:
    client = httpx.Client(base_url=url, transport=httpx.MockTransport(handler))
    return MISPProvider(
        url,
        api_key,
        client=client,
        cache=cache,
        rate_limiter=rate_limiter,
        now=lambda: FIXED_NOW,
        sleep=_noop_sleep,
        retry=RetryConfig(max_attempts=max_attempts),
    )


def ip_ioc() -> IOC:
    return IOC(type=IOCType.IPV4, value=DOC_IP)


@pytest.fixture
def cache(tmp_path: Path) -> PersistentEnrichmentCache:
    engine = create_engine(f"sqlite:///{tmp_path / 'cache.db'}")
    EnrichmentCacheEntry.__table__.create(engine)
    return PersistentEnrichmentCache(sessionmaker(bind=engine, expire_on_commit=False))


# ---------------------------------------------------------------------------
# Request contract: GET /attributes/restSearch, no body, header-only key
# ---------------------------------------------------------------------------


def test_lookup_is_a_get_request_with_the_exact_restsearch_contract() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=_fixture_event())

    result = make_misp(handler).enrich([ip_ioc()], context=CONTEXT)

    assert len(captured) == 1
    request = captured[0]
    assert request.method == "GET"
    assert request.url.path == "/attributes/restSearch"
    assert dict(request.url.params) == {"value": DOC_IP, "returnFormat": "json"}
    assert request.content == b""  # lookup-only: never a write payload
    assert request.headers["Authorization"] == FAKE_MISP_KEY
    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "found"


def test_every_indicator_is_looked_up_individually_via_restsearch() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json=_fixture_event())

    iocs = [ip_ioc(), IOC(type=IOCType.MD5, value=MD5)]
    result = make_misp(handler).enrich(iocs, context=CONTEXT)

    assert paths == ["/attributes/restSearch", "/attributes/restSearch"]
    assert set(result.results) == {f"ipv4:{DOC_IP}", f"md5:{MD5}"}


def test_key_is_not_smuggled_into_the_url_or_query() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json=_fixture_event())

    make_misp(handler).enrich([ip_ioc()], context=CONTEXT)

    request = captured[0]
    assert FAKE_MISP_KEY not in str(request.url)
    assert FAKE_MISP_KEY not in str(request.url.params)


# ---------------------------------------------------------------------------
# Sanitization: allow-list only, capped and sorted
# ---------------------------------------------------------------------------


def test_sanitized_result_is_an_allow_list() -> None:
    """Only match_count/event_ids/tags survive — never raw upstream payloads."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "id": "1",
                            "event_id": "1024",
                            "value": DOC_IP,
                            "type": "ip-src",
                            "category": "Network activity",
                            "to_ids": True,
                            "timestamp": "1788220800",
                            "comment": "raw comment that must not be stored",
                            "tags": [{"name": "synthetic:true"}],
                        }
                    ]
                },
                "Event": {"info": "raw event payload that must not be stored"},
                "requested": {"value": DOC_IP},
            },
        )

    result = make_misp(handler).enrich([ip_ioc()], context=CONTEXT)
    record = result.results[f"ipv4:{DOC_IP}"]

    assert record["result"] == {
        "match_count": 1,
        "event_ids": ["1024"],
        "tags": ["synthetic:true"],
    }
    serialized = result.model_dump_json()
    assert "raw comment" not in serialized
    assert "raw event payload" not in serialized
    assert "Network activity" not in serialized


def test_sanitized_event_ids_and_tags_are_deduplicated_sorted_and_capped() -> None:
    attributes = [
        {"event_id": str(2000 - index), "tags": [{"name": f"tag:{index:02d}"}]}
        for index in range(25)
    ]
    # Duplicate tags across attributes must collapse; >caps must truncate.
    attributes.append({"event_id": "2000", "tags": [{"name": "tag:00"}, {"name": "zz:last"}]})

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": {"Attribute": attributes}})

    result = make_misp(handler).enrich([ip_ioc()], context=CONTEXT)
    sanitized = result.results[f"ipv4:{DOC_IP}"]["result"]

    new_events = sorted({str(2000 - index) for index in range(25)})
    assert sanitized["match_count"] == 26
    assert sanitized["event_ids"] == new_events[:20]  # deduplicated, sorted, capped
    assert sanitized["tags"] == sorted(sanitized["tags"])
    assert len(sanitized["tags"]) == 26  # 25 distinct + zz:last, under the 50 cap
    assert len(sanitized["tags"]) == len(set(sanitized["tags"]))


def test_malformed_tag_entries_are_ignored_not_fatal() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_fixture_event(
                {
                    "tags": [
                        "not-a-dict",
                        None,
                        {"name": ""},
                        {"no_name": True},
                        {"name": "synthetic:true"},
                    ]
                }
            ),
        )

    result = make_misp(handler).enrich([ip_ioc()], context=CONTEXT)

    assert result.results[f"ipv4:{DOC_IP}"]["result"]["tags"] == ["synthetic:true"]


def test_attribute_without_event_id_still_counts_as_a_match() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_fixture_event({"event_id": None, "tags": []}))

    result = make_misp(handler).enrich([ip_ioc()], context=CONTEXT)
    sanitized = result.results[f"ipv4:{DOC_IP}"]["result"]

    assert sanitized == {"match_count": 1, "event_ids": [], "tags": []}


# ---------------------------------------------------------------------------
# Failure behavior: fail-open, always recorded, never cached
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (404, "not_found"),
        (401, "error"),
        (403, "error"),
        (500, "error"),
        (502, "error"),
        (429, "rate_limited"),
    ],
)
def test_http_failures_are_recorded_not_raised(status: int, expected: str) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, json={"error": "upstream"})

    result = make_misp(handler).enrich([ip_ioc()], context=CONTEXT)
    record = result.results[f"ipv4:{DOC_IP}"]

    assert record["lookup_status"] == expected
    assert record["result"] == {}
    assert result.status in {EnrichmentStatus.COMPLETE, EnrichmentStatus.FAILED}
    assert calls >= 1


def test_connection_error_and_timeout_are_recorded() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    def timed_out(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    refused_result = make_misp(refused).enrich([ip_ioc()], context=CONTEXT)
    timeout_result = make_misp(timed_out).enrich([ip_ioc()], context=CONTEXT)

    assert refused_result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "error"
    assert timeout_result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "timeout"
    assert timeout_result.status is EnrichmentStatus.FAILED


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"not json {"),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={"response": "not-an-object"}),
        httpx.Response(200, json={"response": {"Attribute": "not-a-list"}}),
    ],
    ids=["invalid-json", "top-level-list", "bad-response", "bad-attribute-list"],
)
def test_malformed_bodies_are_recorded_as_error(response: httpx.Response) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return response

    result = make_misp(handler).enrich([ip_ioc()], context=CONTEXT)

    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "error"


def test_transient_status_is_retried_then_recorded() -> None:
    """5xx is retried with backoff; the final failure is recorded, not raised."""
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    result = make_misp(handler, max_attempts=3).enrich([ip_ioc()], context=CONTEXT)

    assert calls == 3
    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "error"


def test_failures_are_never_cached(cache: PersistentEnrichmentCache) -> None:
    """Transient failures stay retryable: nothing is written to the cache."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    make_misp(handler, cache=cache).enrich([ip_ioc()], context=CONTEXT)

    assert cache.stats.stores == 0
    assert cache.get("misp", ip_ioc(), now=FIXED_NOW) is None
    assert len(cache) == 0


def test_exhausted_token_bucket_skips_the_outbound_call() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_fixture_event())

    bucket = TokenBucket(capacity=1, refill_per_second=0.001)
    provider = make_misp(handler, rate_limiter=bucket)
    first = provider.enrich([ip_ioc()], context=CONTEXT)
    second = provider.enrich([ip_ioc()], context=CONTEXT)

    assert calls == 1
    assert first.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "found"
    assert second.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "rate_limited"


# ---------------------------------------------------------------------------
# Cache wiring (Phase 2.3 preserved for the MISP provider)
# ---------------------------------------------------------------------------


def test_found_verdict_replays_from_cache_without_another_request(
    cache: PersistentEnrichmentCache,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_fixture_event())

    provider = make_misp(handler, cache=cache)
    first = provider.enrich([ip_ioc()], context=CONTEXT)
    second = provider.enrich([ip_ioc()], context=CONTEXT)

    assert calls == 1  # the second lookup never left the process
    assert first.results == second.results  # byte-identical replay
    assert "misp: 1 served from cache" in second.notes
    assert cache.stats.hits == 1


def test_not_found_verdict_is_cached_too(cache: PersistentEnrichmentCache) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"response": []})

    provider = make_misp(handler, cache=cache)
    provider.enrich([ip_ioc()], context=CONTEXT)
    replay = provider.enrich([ip_ioc()], context=CONTEXT)

    assert calls == 1
    assert replay.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "not_found"
    assert cache.stats.hits == 1


def test_cache_entries_are_provider_scoped(cache: PersistentEnrichmentCache) -> None:
    """A MISP verdict is never replayed for another provider (and vice versa)."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_fixture_event())

    make_misp(handler, cache=cache).enrich([ip_ioc()], context=CONTEXT)

    assert cache.get("misp", ip_ioc(), now=FIXED_NOW) is not None
    assert cache.get("virustotal", ip_ioc(), now=FIXED_NOW) is None


def test_cache_hit_consumes_no_rate_limiter_token(cache: PersistentEnrichmentCache) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_fixture_event())

    bucket = TokenBucket(capacity=1, refill_per_second=0.001)
    provider = make_misp(handler, cache=cache, rate_limiter=bucket)
    provider.enrich([ip_ioc()], context=CONTEXT)

    # Quota is exhausted, yet the cached verdict is still served.
    replay = provider.enrich([ip_ioc()], context=CONTEXT)

    assert calls == 1
    assert replay.status is EnrichmentStatus.COMPLETE
    assert replay.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "found"


# ---------------------------------------------------------------------------
# Secret safety and the zero-external fallback
# ---------------------------------------------------------------------------


def test_api_key_never_leaks_into_the_result_or_provenance() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_fixture_event({"comment": f"key={FAKE_MISP_KEY}", "tags": [{"name": "apt"}]}),
        )

    provider = make_misp(handler)
    result = provider.enrich([ip_ioc()], context=CONTEXT)

    for blob in (result.model_dump_json(), "\n".join(result.notes), repr(provider)):
        assert FAKE_MISP_KEY not in blob


def test_compose_defaults_keep_the_provider_disabled_offline() -> None:
    """Empty MISP_URL/MISP_API_KEY (the compose defaults) ⇒ zero outbound calls."""
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_fixture_event())

    for url, key in (("", FAKE_MISP_KEY), (MISP_URL, None), ("", None)):
        provider = make_misp(handler, url=url, api_key=key)
        assert provider.enabled is False
        result = provider.enrich([ip_ioc()], context=CONTEXT)
        assert result.status is EnrichmentStatus.SKIPPED
        assert result.results == {}

    assert calls == 0
