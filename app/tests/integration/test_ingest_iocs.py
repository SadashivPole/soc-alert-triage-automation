"""Phase 1E integration tests: IOC extraction & enrichment at the ingest API.

The endpoint runs the real pipeline (normalize → extract → enrich → dedupe →
persist) against a temporary SQLite database, with the offline no-op provider
registered — so **no external service is contacted** and every response must
report ``enrichment_status: skipped`` (ARCHITECTURE.md §7.3).

Covered:

* extracted indicators and their provenance in the ingest response;
* persistence of indicators with the canonical alert of record;
* idempotent duplicate deliveries keep the original indicators;
* ``full_log`` is never an extraction source and never leaks into the IOC data
  (SECURITY.md §5, §7);
* the registered enrichment provider is present and disabled by default.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from tests.conftest import TEST_INGEST_KEY

from soc_triage.db.session import session_scope
from soc_triage.models.repositories import AlertRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

SHA256 = "23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _ingest(client: TestClient, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _stored_iocs(client: TestClient, alert_id: str) -> list[dict[str, Any]]:
    """Read the indicators persisted with the alert of record."""
    factory: sessionmaker = client.app.state.session_factory
    with session_scope(factory) as session:
        alert = AlertRepository(session).get(UUID(alert_id))
    assert alert is not None
    return [ioc.model_dump(mode="json") for ioc in alert.iocs]


# ---------------------------------------------------------------------------
# Response contract
# ---------------------------------------------------------------------------


def test_ingest_response_carries_extracted_iocs(client: TestClient) -> None:
    """An SSH brute-force alert yields its source IP with provenance."""
    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))

    assert body["iocs"] == [
        {
            "type": "ipv4",
            "value": "203.0.113.50",
            "provenance": [
                {
                    "field": "source_event.data.srcip",
                    "extractor": "typed_field",
                    "raw_value": "203.0.113.50",
                    "offset": None,
                    "location": "/var/log/auth.log",
                }
            ],
            "enrichment": {},
        }
    ]
    assert body["enrichment_status"] == "skipped"


def test_ingest_response_carries_hashes_and_url(client: TestClient) -> None:
    """The VirusTotal sample yields md5/sha1/sha256 + the permalink URL."""
    body = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))

    pairs = {(ioc["type"], ioc["value"]) for ioc in body["iocs"]}

    assert pairs == {
        ("md5", "bc478d7a48bfab117da4b9bdcb5aee36"),
        ("sha1", "87c151c211facd64c46da2004bccfc31f52128bd"),
        ("sha256", SHA256),
        ("url", f"https://www.virustotal.com/gui/file/{SHA256}/detection"),
    }
    assert {ioc["type"] for ioc in body["iocs"] if ioc["enrichment"]} == set()


def test_ingest_normalizes_indicator_values(client: TestClient) -> None:
    """Mixed-case hashes are stored/returned in normalized (lowercase) form."""
    payload = {
        "id": "1770000000.200001",
        "rule": {"level": 12, "description": "Malware hash", "id": "87105"},
        "agent": {"id": "003", "name": "hr-wks-04"},
        "data": {"virustotal": {"sha256": SHA256.upper()}},
        "location": "syscheck",
        "full_log": "synthetic lab data",
    }

    body = _ingest(client, payload)

    assert [(ioc["type"], ioc["value"]) for ioc in body["iocs"]] == [("sha256", SHA256)]
    assert body["iocs"][0]["provenance"][0]["raw_value"] == SHA256.upper()


def test_ingest_without_indicators_reports_empty_set(client: TestClient) -> None:
    """An alert without evidence fields simply has no indicators."""
    payload = {
        "id": "1770000000.200002",
        "rule": {"level": 5, "description": "Windows: user created", "id": "60180"},
        "agent": {"id": "004", "name": "fin-srv-02"},
        "data": {"dstuser": "svc_temp_backup"},
        "location": "EventChannel",
        "full_log": "A user account was created (synthetic lab data)",
    }

    body = _ingest(client, payload)

    assert body["iocs"] == []
    assert body["enrichment_status"] == "skipped"


def test_every_sample_alert_ingests_with_indicators(client: TestClient) -> None:
    """Contract: all sample fixtures ingest and expose an indicator list."""
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        body = _ingest(client, _load_sample(path.name))

        assert isinstance(body["iocs"], list), path.name
        assert body["enrichment_status"] == "skipped", path.name
        for ioc in body["iocs"]:
            assert set(ioc) == {"type", "value", "provenance", "enrichment"}
            assert ioc["provenance"], f"{path.name}: indicator without provenance"


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_indicators_are_persisted_with_the_alert_of_record(client: TestClient) -> None:
    """IOCs ride along in the existing canonical payload — no schema change."""
    body = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))

    stored = _stored_iocs(client, body["alert_id"])

    assert stored == body["iocs"]
    assert {ioc["type"] for ioc in stored} == {"md5", "sha1", "sha256", "url"}


def test_duplicate_delivery_returns_the_original_indicators(client: TestClient) -> None:
    """Idempotency holds for IOCs: a re-delivery echoes the stored alert."""
    payload = _load_sample("01_wazuh_ssh_brute_force.json")

    first = _ingest(client, payload)
    second = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)

    assert second.status_code == 200
    assert second.json()["iocs"] == first["iocs"]
    assert second.json()["normalized"] == first["normalized"]


# ---------------------------------------------------------------------------
# Log/data hygiene
# ---------------------------------------------------------------------------


def test_indicator_data_never_carries_raw_log_text(client: TestClient) -> None:
    """Provenance holds the matched substring only — never ``full_log``."""
    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    body = _ingest(client, payload)

    blob = json.dumps(body["iocs"])

    assert payload["full_log"] not in blob
    assert "full_log" not in blob
    assert {p["field"] for ioc in body["iocs"] for p in ioc["provenance"]} == {
        "source_event.data.srcip"
    }
    # The indicator itself (a substring of full_log) is legitimate evidence.
    assert "203.0.113.50" in blob


def test_indicators_keep_private_agent_addresses_out(client: TestClient) -> None:
    """RFC 1918 agent addresses are excluded from the persisted indicators."""
    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    assert payload["agent"]["ip"] == "10.0.1.10"

    body = _ingest(client, payload)

    assert {ioc["value"] for ioc in body["iocs"]} == {"203.0.113.50"}
    assert "10.0.1.10" not in json.dumps(body["iocs"])


# ---------------------------------------------------------------------------
# Enrichment wiring
# ---------------------------------------------------------------------------


def test_application_registers_a_disabled_offline_provider(client: TestClient) -> None:
    """Phase 1E ships the no-op provider only — disabled by default."""
    chain = client.app.state.enrichment_chain

    assert [provider.name for provider in chain.providers] == ["noop"]
    assert [provider.enabled for provider in chain.providers] == [False]


def test_no_external_enrichment_provider_is_enabled(client: TestClient) -> None:
    """No VirusTotal/MISP provider exists yet (Phase 2 work)."""
    chain = client.app.state.enrichment_chain

    assert {provider.name for provider in chain.providers if provider.enabled} == set()
