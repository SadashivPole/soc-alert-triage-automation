"""Phase 2A unit tests: VirusTotal & MISP threat-intel providers.

All upstream behaviour is exercised through ``httpx.MockTransport`` — **no
network access** (ARCHITECTURE.md §17). The suite pins the provider contract:

* positive / negative / not-found lookups;
* timeout, HTTP error, rate limit (429 and token-bucket), malformed response;
* disabled-by-default (empty key/URL) and disable-by-empty wiring;
* multiple providers merging under distinct names;
* provenance shape (provider, indicator type, lookup status, timestamp,
  sanitized metadata) with no secrets anywhere in the result.

A canary API key is used throughout; the leak tests assert it never appears in
results, notes, provenance, or a provider's ``repr``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from soc_triage.enrichment import (
    IOC,
    EnrichmentChain,
    EnrichmentContext,
    EnrichmentProvider,
    EnrichmentStatus,
    IOCType,
    LookupStatus,
    MISPProvider,
    TokenBucket,
    VirusTotalProvider,
)
from soc_triage.enrichment.virustotal import VT_BASE_URL

# Synthetic, non-secret canary keys (SECURITY.md §5: never real credentials).
FAKE_VT_KEY = "vt-fake-key-0123456789abcdef"
FAKE_MISP_KEY = "misp-fake-key-0123456789abcdef"
MISP_URL = "https://misp.example.test"

MD5 = "bc478d7a48bfab117da4b9bdcb5aee36"
DOC_IP = "203.0.113.50"

FIXED_NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC)
FIXED_NOW_ISO = FIXED_NOW.isoformat()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _noop_sleep(_seconds: float) -> None:
    """Replace ``time.sleep`` so retry/backoff paths run instantly in tests."""


def make_iocs() -> list[IOC]:
    return [
        IOC(type=IOCType.MD5, value=MD5),
        IOC(type=IOCType.IPV4, value=DOC_IP),
        IOC(type=IOCType.EMAIL, value="user@example.test"),
    ]


def make_vt(
    handler: Any,
    *,
    api_key: str | None = FAKE_VT_KEY,
    rate_limiter: TokenBucket | None = None,
) -> VirusTotalProvider:
    client = httpx.Client(base_url=VT_BASE_URL, transport=httpx.MockTransport(handler))
    return VirusTotalProvider(
        api_key,
        client=client,
        rate_limiter=rate_limiter,
        now=lambda: FIXED_NOW,
        sleep=_noop_sleep,
    )


def make_misp(
    handler: Any,
    *,
    api_key: str | None = FAKE_MISP_KEY,
    url: str = MISP_URL,
    rate_limiter: TokenBucket | None = None,
) -> MISPProvider:
    client = httpx.Client(base_url=url, transport=httpx.MockTransport(handler))
    return MISPProvider(
        url,
        api_key,
        client=client,
        rate_limiter=rate_limiter,
        now=lambda: FIXED_NOW,
        sleep=_noop_sleep,
    )


def vt_file_attributes(**overrides: Any) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "last_analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 50,
            "undetected": 5,
            "timeout": 1,
        },
        "reputation": 0,
    }
    attrs.update(overrides)
    return attrs


# ---------------------------------------------------------------------------
# VirusTotal: lookups
# ---------------------------------------------------------------------------


def test_vt_positive_lookup_records_sanitized_verdict() -> None:
    """A malicious file yields ``found`` with allow-listed stats only."""
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["apikey"] = request.headers["x-apikey"]
        stats = {"malicious": 38, "suspicious": 3, "harmless": 2, "undetected": 0, "timeout": 0}
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": MD5,
                    "type": "file",
                    "attributes": {
                        "last_analysis_stats": stats,
                        "reputation": -12,
                    },
                }
            },
        )

    provider = make_vt(handler)
    result = provider.enrich([IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext())

    assert captured["path"] == f"/api/v3/files/{MD5}"
    assert captured["apikey"] == FAKE_VT_KEY
    assert result.status is EnrichmentStatus.COMPLETE
    record = result.results[f"md5:{MD5}"]
    assert record == {
        "provider": "virustotal",
        "indicator_type": "md5",
        "lookup_status": "found",
        "timestamp": FIXED_NOW_ISO,
        "result": {
            "malicious": 38,
            "suspicious": 3,
            "harmless": 2,
            "undetected": 0,
            "reputation": -12,
        },
    }
    # The raw upstream body (including the extra "timeout" stat) is not stored.
    assert "timeout" not in record["result"]


def test_vt_negative_lookup_is_a_clean_found_verdict() -> None:
    """A clean file (malicious=0) is still a definitive ``found`` result."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": {"id": MD5, "type": "file", "attributes": (vt_file_attributes())}}
        )

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    record = result.results[f"md5:{MD5}"]
    assert record["lookup_status"] == "found"
    assert record["result"]["malicious"] == 0


def test_vt_not_found_is_a_miss_not_an_error() -> None:
    """A 404 (unknown indicator) maps to ``not_found``, not a failure."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404, json={"error": {"code": "NotFoundError", "message": "not found"}}
        )

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.status is EnrichmentStatus.COMPLETE
    assert result.results[f"md5:{MD5}"]["lookup_status"] == "not_found"
    assert result.results[f"md5:{MD5}"]["result"] == {}


def test_vt_url_lookup_uses_base64url_identifier() -> None:
    """URLs are looked up by their unpadded base64url id (VT spec)."""
    url = "https://example.test/path?q=1"
    import base64

    expected_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(
            200,
            json={"data": {"id": expected_id, "type": "url", "attributes": (vt_file_attributes())}},
        )

    make_vt(handler).enrich([IOC(type=IOCType.URL, value=url)], context=EnrichmentContext())

    assert seen == [f"/api/v3/urls/{expected_id}"]


def test_vt_does_not_handle_email_indicators() -> None:
    """Email is not a VT lookup type → absent from results."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={})

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.EMAIL, value="user@example.test")], context=EnrichmentContext()
    )

    assert result.status is EnrichmentStatus.SKIPPED
    assert result.results == {}
    assert calls == []


# ---------------------------------------------------------------------------
# VirusTotal: failure modes
# ---------------------------------------------------------------------------


def test_vt_timeout_is_recorded_not_raised() -> None:
    """A timed-out request is ``timeout``; the provider never raises."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.status is EnrichmentStatus.FAILED
    assert result.results[f"md5:{MD5}"]["lookup_status"] == "timeout"


def test_vt_http_error_is_recorded_not_raised() -> None:
    """A 5xx (after safe retries) maps to ``error``, not an exception."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"code": "ServerError"}})

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.status is EnrichmentStatus.FAILED
    assert result.results[f"md5:{MD5}"]["lookup_status"] == "error"


def test_vt_rate_limit_429_is_recorded() -> None:
    """A 429 (after retries) maps to ``rate_limited``."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429, json={"error": {"code": "QuotaExceededError"}}, headers={"Retry-After": "60"}
        )

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.status is EnrichmentStatus.FAILED
    assert result.results[f"md5:{MD5}"]["lookup_status"] == "rate_limited"


def test_vt_token_bucket_exhaustion_skips_lookups_without_http() -> None:
    """An exhausted quota never blocks: lookups are marked rate-limited."""
    empty_bucket = TokenBucket(capacity=1, refill_per_second=0.001)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(
            200, json={"data": {"id": MD5, "type": "file", "attributes": (vt_file_attributes())}}
        )

    # First token is consumed by the first indicator; the rest are rate-limited.
    result = make_vt(handler, rate_limiter=empty_bucket).enrich(
        make_iocs(), context=EnrichmentContext()
    )

    # email is unhandled; md5 + ipv4 are handled → one HTTP call, one rate-limited.
    assert calls == [f"/api/v3/files/{MD5}"]
    assert result.status is EnrichmentStatus.PARTIAL
    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "rate_limited"


def test_vt_malformed_json_is_recorded_as_error() -> None:
    """Invalid JSON in a 200 body maps to ``error`` (never retried)."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"this is not json {")

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.results[f"md5:{MD5}"]["lookup_status"] == "error"


def test_vt_malformed_shape_is_recorded_as_error() -> None:
    """A 200 with a non-object ``data`` field is a malformed response."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "not-an-object"})

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.results[f"md5:{MD5}"]["lookup_status"] == "error"


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------


def test_misp_positive_lookup_records_sanitized_metadata() -> None:
    """A matching attribute yields ``found`` with event ids + tags (sanitized)."""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        captured["auth"] = request.headers["Authorization"]
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
                            "tags": [{"name": "tlp:amber"}, {"name": "apt"}],
                        },
                        {
                            "id": "2",
                            "event_id": "1025",
                            "value": DOC_IP,
                            "type": "ip-dst",
                            "tags": [{"name": "apt"}],
                        },
                    ]
                }
            },
        )

    provider = make_misp(handler)
    result = provider.enrich([IOC(type=IOCType.IPV4, value=DOC_IP)], context=EnrichmentContext())

    assert captured["params"] == {"value": DOC_IP, "returnFormat": "json"}
    assert captured["auth"] == FAKE_MISP_KEY
    assert result.status is EnrichmentStatus.COMPLETE
    record = result.results[f"ipv4:{DOC_IP}"]
    assert record["lookup_status"] == "found"
    assert record["result"] == {
        "match_count": 2,
        "event_ids": ["1024", "1025"],
        "tags": ["apt", "tlp:amber"],
    }
    # Raw attribute values / payloads are never stored.
    assert "value" not in record["result"]


def test_misp_not_found_is_a_miss_not_an_error() -> None:
    """An empty attribute list is a definitive ``not_found``."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": []})

    result = make_misp(handler).enrich(
        [IOC(type=IOCType.IPV4, value=DOC_IP)], context=EnrichmentContext()
    )

    assert result.status is EnrichmentStatus.COMPLETE
    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "not_found"


def test_misp_handles_every_supported_indicator_type() -> None:
    """MISP searches by value, so all IOC types are handled (no email drop)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "id": "1",
                            "event_id": "9",
                            "value": request.url.params["value"],
                            "type": "other",
                            "tags": [],
                        },
                    ]
                }
            },
        )

    iocs = [
        IOC(type=IOCType.EMAIL, value="user@example.test"),
        IOC(type=IOCType.SHA256, value="a" * 64),
    ]
    result = make_misp(handler).enrich(iocs, context=EnrichmentContext())

    assert result.status is EnrichmentStatus.COMPLETE
    assert set(result.results) == {"email:user@example.test", f"sha256:{'a' * 64}"}


def test_misp_timeout_and_http_error_are_recorded() -> None:
    """MISP shares the base failure-mode behaviour."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    result = make_misp(handler).enrich(
        [IOC(type=IOCType.IPV4, value=DOC_IP)], context=EnrichmentContext()
    )

    assert result.status is EnrichmentStatus.FAILED
    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "error"


def test_misp_malformed_response_is_recorded_as_error() -> None:
    """A 200 without a ``response`` object is malformed → ``error``."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": True})

    result = make_misp(handler).enrich(
        [IOC(type=IOCType.IPV4, value=DOC_IP)], context=EnrichmentContext()
    )

    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "error"


# ---------------------------------------------------------------------------
# Disabled-by-default / disable-by-empty
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "provider",
    [
        VirusTotalProvider(
            None,
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={}))
            ),
        ),
        VirusTotalProvider(
            "",
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={}))
            ),
        ),
        MISPProvider(
            "",
            None,
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={}))
            ),
        ),
        MISPProvider(
            MISP_URL,
            None,
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={}))
            ),
        ),
    ],
    ids=["vt-none-key", "vt-empty-key", "misp-empty-url", "misp-empty-key"],
)
def test_provider_is_disabled_without_key_or_url(provider: Any) -> None:
    """Empty key (and, for MISP, empty URL) ⇒ disabled and never called."""
    assert provider.enabled is False

    result = provider.enrich([IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext())
    assert result.status is EnrichmentStatus.SKIPPED
    assert result.results == {}


def test_providers_conform_to_the_enrichment_provider_protocol() -> None:
    """Both providers satisfy the runtime-checkable protocol."""
    vt = VirusTotalProvider(
        FAKE_VT_KEY,
        client=httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={}))),
    )
    misp = MISPProvider(
        MISP_URL,
        FAKE_MISP_KEY,
        client=httpx.Client(transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={}))),
    )
    assert isinstance(vt, EnrichmentProvider)
    assert isinstance(misp, EnrichmentProvider)


# ---------------------------------------------------------------------------
# Chain integration: multiple providers, failure isolation, no mutation
# ---------------------------------------------------------------------------


def test_chain_merges_vt_and_misp_under_distinct_names() -> None:
    """Both providers run in registration order and merge under their names."""

    def vt_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {"id": MD5, "type": "file", "attributes": (vt_file_attributes(malicious=9))}
            },
        )

    def misp_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {
                            "id": "1",
                            "event_id": "7",
                            "value": MD5,
                            "type": "md5",
                            "tags": [{"name": "apt"}],
                        },
                    ]
                }
            },
        )

    vt = make_vt(vt_handler)
    misp = make_misp(misp_handler)
    chain = EnrichmentChain([vt, misp])

    outcome = chain.enrich([IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext())

    assert outcome.status is EnrichmentStatus.COMPLETE
    enriched = outcome.iocs[0].enrichment
    assert set(enriched) == {"virustotal", "misp"}
    assert enriched["virustotal"]["lookup_status"] == "found"
    assert enriched["misp"]["lookup_status"] == "found"


def test_chain_continues_when_a_provider_fails_and_reports_partial() -> None:
    """A failing VT does not stop MISP; aggregate status is ``partial``."""

    def vt_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    def misp_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {"id": "1", "event_id": "7", "value": MD5, "type": "md5", "tags": []},
                    ]
                }
            },
        )

    chain = EnrichmentChain([make_vt(vt_handler), make_misp(misp_handler)])

    outcome = chain.enrich([IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext())

    assert outcome.status is EnrichmentStatus.PARTIAL
    assert [p.status for p in outcome.providers] == [
        EnrichmentStatus.FAILED,
        EnrichmentStatus.COMPLETE,
    ]
    assert outcome.iocs[0].enrichment["misp"]["lookup_status"] == "found"


def test_providers_do_not_mutate_input_indicators() -> None:
    """Providers return data; inputs stay frozen and unmodified."""
    iocs = make_iocs()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": {"id": MD5, "type": "file", "attributes": (vt_file_attributes())}}
        )

    make_vt(handler).enrich(iocs, context=EnrichmentContext())

    assert all(ioc.enrichment == {} for ioc in iocs)


# ---------------------------------------------------------------------------
# Provenance vocabulary
# ---------------------------------------------------------------------------


def test_lookup_status_vocabulary_matches_architecture() -> None:
    """``found | not_found | error | rate_limited | timeout``."""
    assert {status.value for status in LookupStatus} == {
        "found",
        "not_found",
        "error",
        "rate_limited",
        "timeout",
    }


def test_every_record_carries_full_provenance() -> None:
    """provider + indicator type + lookup status + timestamp + sanitized result."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": {"id": MD5, "type": "file", "attributes": (vt_file_attributes())}}
        )

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )
    record = result.results[f"md5:{MD5}"]

    assert set(record) == {"provider", "indicator_type", "lookup_status", "timestamp", "result"}


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------


def _every_string_blob(provider: Any, result: Any) -> list[str]:
    """Collect every string surface that must be free of the API key."""
    return [
        repr(provider),
        result.model_dump_json(),
        "\n".join(result.notes),
        "\n".join(f"{k}:{v}" for k, v in result.results.items()),
    ]


def test_vt_api_key_never_leaks_into_results_notes_or_repr() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": MD5,
                    "type": "file",
                    "attributes": (vt_file_attributes(malicious=11)),
                }
            },
        )

    provider = make_vt(handler)
    result = provider.enrich([IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext())

    for blob in _every_string_blob(provider, result):
        assert FAKE_VT_KEY not in blob


def test_misp_api_key_never_leaks_into_results_notes_or_repr() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {"id": "1", "event_id": "7", "value": MD5, "type": "md5", "tags": []},
                    ]
                }
            },
        )

    provider = make_misp(handler)
    result = provider.enrich([IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext())

    for blob in _every_string_blob(provider, result):
        assert FAKE_MISP_KEY not in blob


def test_api_key_never_leaks_even_when_upstream_echoes_it() -> None:
    """Even if the upstream body echoed the key, sanitization drops it."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": MD5,
                    "type": "file",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1,
                            "suspicious": 0,
                            "harmless": 0,
                            "undetected": 0,
                        },
                        "reputation": 0,
                        "x-apikey": FAKE_VT_KEY,  # adversarial echo
                        "raw": {"token": FAKE_VT_KEY},
                    },
                }
            },
        )

    provider = make_vt(handler)
    result = provider.enrich([IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext())

    assert FAKE_VT_KEY not in result.model_dump_json()


# ---------------------------------------------------------------------------
# Endpoint routing & sanitize edge cases
# ---------------------------------------------------------------------------


def test_vt_domain_lookup_uses_the_domain_endpoint() -> None:
    """Domains are routed to ``/domains/{domain}``."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(
            200, json={"data": {"id": "x", "type": "domain", "attributes": (vt_file_attributes())}}
        )

    make_vt(handler).enrich(
        [IOC(type=IOCType.DOMAIN, value="example.com")], context=EnrichmentContext()
    )

    assert seen == ["/api/v3/domains/example.com"]


def test_vt_null_data_is_a_not_found() -> None:
    """``{"data": null}`` is a definitive no-report answer, not an error."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": None})

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.results[f"md5:{MD5}"]["lookup_status"] == "not_found"


@pytest.mark.parametrize(
    "payload",
    [
        [],  # top-level list, not an object
        {"data": {}},  # missing `attributes`
        {"data": {"attributes": {"last_analysis_stats": "not-a-dict"}}},  # bad stats
    ],
    ids=["top-level-list", "missing-attributes", "bad-stats"],
)
def test_vt_malformed_shapes_are_recorded_as_error(payload: Any) -> None:
    """Structurally invalid 200 bodies map to ``error`` (never retried)."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.results[f"md5:{MD5}"]["lookup_status"] == "error"


def test_vt_missing_stats_yields_zero_counts() -> None:
    """A valid report with no ``last_analysis_stats`` is found with zero counts."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"id": MD5, "type": "file", "attributes": {}}})

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    record = result.results[f"md5:{MD5}"]
    assert record["lookup_status"] == "found"
    assert record["result"]["malicious"] == 0
    assert record["result"]["suspicious"] == 0
    assert record["result"]["harmless"] == 0
    assert record["result"]["undetected"] == 0


def test_misp_empty_attribute_list_is_a_not_found() -> None:
    """``{"response": {"Attribute": []}}`` is a definitive no-match."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": {"Attribute": []}})

    result = make_misp(handler).enrich(
        [IOC(type=IOCType.IPV4, value=DOC_IP)], context=EnrichmentContext()
    )

    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "not_found"


@pytest.mark.parametrize(
    "payload",
    [
        [],  # top-level list, not an object
        {"response": {"Attribute": "not-a-list"}},  # bad attribute list
    ],
    ids=["top-level-list", "bad-attribute-list"],
)
def test_misp_malformed_shapes_are_recorded_as_error(payload: Any) -> None:
    """Structurally invalid 200 bodies map to ``error``."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = make_misp(handler).enrich(
        [IOC(type=IOCType.IPV4, value=DOC_IP)], context=EnrichmentContext()
    )

    assert result.results[f"ipv4:{DOC_IP}"]["lookup_status"] == "error"


def test_misp_skips_non_dict_attributes_when_sanitizing() -> None:
    """Non-object entries in the attribute list are ignored, not fatal."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "response": {
                    "Attribute": [
                        {"id": "1", "event_id": "9", "value": DOC_IP, "type": "ip-src", "tags": []},
                        "junk-entry",
                        None,
                    ]
                }
            },
        )

    result = make_misp(handler).enrich(
        [IOC(type=IOCType.IPV4, value=DOC_IP)], context=EnrichmentContext()
    )

    record = result.results[f"ipv4:{DOC_IP}"]
    assert record["lookup_status"] == "found"
    assert record["result"]["match_count"] == 1
    assert record["result"]["event_ids"] == ["9"]


def test_token_bucket_rejects_invalid_parameters() -> None:
    """A rate limiter must have a positive capacity and refill rate."""
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, refill_per_second=1.0)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, refill_per_second=0.0)


def test_retry_after_non_integer_falls_back_to_backoff() -> None:
    """A non-integer ``Retry-After`` is ignored (backoff used) — not fatal."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429, json={"error": {"code": "QuotaExceededError"}}, headers={"Retry-After": "soon"}
        )

    result = make_vt(handler).enrich(
        [IOC(type=IOCType.MD5, value=MD5)], context=EnrichmentContext()
    )

    assert result.results[f"md5:{MD5}"]["lookup_status"] == "rate_limited"
