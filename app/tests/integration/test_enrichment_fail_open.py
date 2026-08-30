"""Phase 2A integration tests: enrichment providers inside the ingest API.

Exercises the real pipeline (normalize → extract → enrich → dedupe → score →
decide) with an *enabled* mock-backed provider injected into the enrichment
chain, proving the key architectural guarantee (ARCHITECTURE.md §16):

* a provider failure (timeout / HTTP error) must **never** block alert
  processing — the alert still ingests, scores, and decides;
* a successful enrichment attaches sanitized provenance to the indicator and
  does not leak the API key into the response.

All network behaviour is mocked via ``httpx.MockTransport`` — no external calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient
from tests.conftest import TEST_INGEST_KEY

from soc_triage.enrichment import EnrichmentChain
from soc_triage.enrichment.virustotal import VT_BASE_URL, VirusTotalProvider

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
FAKE_VT_KEY = "vt-fake-key-0123456789abcdef"


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _install_chain(client: TestClient, providers: list[Any]) -> None:
    client.app.state.enrichment_chain = EnrichmentChain(providers)


def _vt_client(handler: Any) -> httpx.Client:
    return httpx.Client(base_url=VT_BASE_URL, transport=httpx.MockTransport(handler))


def _ingest(client: TestClient, name: str) -> dict[str, Any]:
    response = client.post("/api/v1/alerts/ingest", json=_load_sample(name), headers=AUTH_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def test_provider_timeout_does_not_block_alert_processing(client: TestClient) -> None:
    """A fully-timing-out provider still yields a scored, decided alert."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    _install_chain(
        client,
        [VirusTotalProvider(FAKE_VT_KEY, client=_vt_client(handler), sleep=lambda _s: None)],
    )

    body = _ingest(client, "04_wazuh_malware_hash_virustotal.json")

    assert body["enrichment_status"] == "failed"
    # Scoring & decisioning proceed unchanged (deterministic behaviour intact).
    assert body["risk"]["score"] == 73
    assert body["risk"]["tier"] == "high"
    assert body["decision"]["action"] == "open_incident"
    assert body["decision"]["severity"] == "SEV2"


def test_provider_success_enriches_and_does_not_leak_the_key(client: TestClient) -> None:
    """A hit attaches sanitized provenance; the API key is absent everywhere."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": "hash",
                    "type": "file",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 20,
                            "suspicious": 0,
                            "harmless": 0,
                            "undetected": 0,
                        },
                        "reputation": -3,
                    },
                }
            },
        )

    _install_chain(
        client,
        [VirusTotalProvider(FAKE_VT_KEY, client=_vt_client(handler), sleep=lambda _s: None)],
    )

    body = _ingest(client, "04_wazuh_malware_hash_virustotal.json")

    assert body["enrichment_status"] == "complete"
    enriched = [ioc for ioc in body["iocs"] if ioc["enrichment"]]
    assert enriched, "expected at least one enriched indicator"
    for ioc in enriched:
        record = ioc["enrichment"]["virustotal"]
        assert record["lookup_status"] == "found"
        assert set(record["result"]) == {
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "reputation",
        }

    # The canary key must never reach the response, logs of record, or audit.
    assert FAKE_VT_KEY not in json.dumps(body)
