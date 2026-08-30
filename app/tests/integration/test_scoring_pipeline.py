"""Phase 1F integration tests: scoring & decisioning through the ingest API.

Runs the real pipeline (normalize → extract → enrich → dedupe → score →
decide → persist) against a temp SQLite database and asserts:

* the ingest response carries a deterministic ``risk`` (score/tier/factors)
  and ``decision`` (action/severity/reasons);
* the assessment is persisted with the alert of record;
* ``alert.scored`` / ``alert.decided`` audit rows are appended;
* exact duplicates echo the original assessment (idempotent, never re-scored);
* recurrence escalation raises the score across repeated deliveries;
* scoring is fully offline (no external providers enabled).
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
from soc_triage.models.repositories import AlertRepository, AuditRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _ingest(client: TestClient, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _stored(client: TestClient, alert_id: str):
    factory: sessionmaker = client.app.state.session_factory
    with session_scope(factory) as session:
        return AlertRepository(session).get(UUID(alert_id))


def _audit_actions(client: TestClient, alert_id: str) -> list[str]:
    factory: sessionmaker = client.app.state.session_factory
    with session_scope(factory) as session:
        rows = AuditRepository(session).all()
    return [row.action for row in rows if row.entity_id == alert_id]


# ---------------------------------------------------------------------------
# Response contract
# ---------------------------------------------------------------------------


def test_ingest_response_carries_score_and_decision(client: TestClient) -> None:
    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))

    risk = body["risk"]
    assert risk["score"] == 43
    assert risk["tier"] == "low"
    assert risk["engine_version"] == "scoring.v1"
    assert risk["degraded"] is False
    assert {f["name"] for f in risk["factors"]} == {
        "rule_severity",
        "rule_groups_mitre",
        "asset_criticality",
        "recurrence_velocity",
        "ioc_evidence",
        "enrichment_status",
        "allowlist_modifier",
    }
    assert risk["summary"]

    decision = body["decision"]
    assert decision["action"] == "monitor"
    assert decision["severity"] is None
    assert decision["reasons"]

    # The assessment also rides inside the normalized canonical alert.
    assert body["normalized"]["risk"]["score"] == 43
    assert body["normalized"]["decision"]["action"] == "monitor"
    assert body["normalized"]["asset"]["tier"] == "tier-1"
    assert body["normalized"]["enrichment_status"] == "skipped"


def test_malware_alert_scores_high_and_opens_sev2(client: TestClient) -> None:
    body = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))

    assert body["risk"]["score"] == 73
    assert body["risk"]["tier"] == "high"
    assert body["decision"]["action"] == "open_incident"
    assert body["decision"]["severity"] == "SEV2"


def test_fim_critical_asset_scores_medium_and_queues_l1(client: TestClient) -> None:
    body = _ingest(client, _load_sample("03_wazuh_fim_etc_passwd_change.json"))

    assert body["risk"]["score"] == 63
    assert body["risk"]["tier"] == "medium"
    assert body["decision"]["action"] == "queue_l1"


def test_every_sample_alert_scores_within_0_100(client: TestClient) -> None:
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        body = _ingest(client, _load_sample(path.name))
        assert 0 <= body["risk"]["score"] <= 100, path.name
        assert body["risk"]["tier"] in {
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        }, path.name
        assert body["decision"]["action"] in {
            "suppress",
            "monitor",
            "queue_l1",
            "open_incident",
        }, path.name


# ---------------------------------------------------------------------------
# Persistence + audit
# ---------------------------------------------------------------------------


def test_assessment_is_persisted_with_the_alert_of_record(client: TestClient) -> None:
    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))

    stored = _stored(client, body["alert_id"])
    assert stored is not None
    assert stored.risk is not None
    assert stored.risk.score == body["risk"]["score"]
    assert stored.decision is not None
    assert stored.decision.action.value == body["decision"]["action"]


def test_scored_and_decided_audit_events_are_written(client: TestClient) -> None:
    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))

    actions = _audit_actions(client, body["alert_id"])
    assert "alert.scored" in actions
    assert "alert.decided" in actions

    factory: sessionmaker = client.app.state.session_factory
    with session_scope(factory) as session:
        rows = AuditRepository(session).all()
    scored = [r for r in rows if r.action == "alert.scored" and r.entity_id == body["alert_id"]]
    decided = [r for r in rows if r.action == "alert.decided" and r.entity_id == body["alert_id"]]
    assert scored and scored[0].actor == "scoring"
    assert decided and decided[0].actor == "decisions"
    assert scored[0].after["score"] == body["risk"]["score"]
    assert scored[0].before is None
    assert decided[0].after["action"] == body["decision"]["action"]


# ---------------------------------------------------------------------------
# Idempotency + recurrence
# ---------------------------------------------------------------------------


def test_exact_duplicate_echoes_the_original_assessment(client: TestClient) -> None:
    payload = _load_sample("01_wazuh_ssh_brute_force.json")

    first = _ingest(client, payload)
    duplicate = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert duplicate.status_code == 200

    assert duplicate.json()["risk"] == first["risk"]
    assert duplicate.json()["decision"] == first["decision"]
    assert duplicate.json()["normalized"] == first["normalized"]


def test_recurrence_escalation_raises_the_score(client: TestClient) -> None:
    """Three distinct events of the same rule+agent cross the rapid-burst
    threshold, raising the score and moving the decision to queue_l1."""
    base = _load_sample("01_wazuh_ssh_brute_force.json")

    first = _ingest(client, base)
    assert first["risk"]["score"] == 43
    assert first["decision"]["action"] == "monitor"

    second = _ingest(client, dict(base, id="1770000000.100002"))
    assert second["dedupe"]["occurrences"] == 2

    third = _ingest(client, dict(base, id="1770000000.100003"))
    assert third["dedupe"]["occurrences"] == 3
    assert third["risk"]["score"] == first["risk"]["score"] + 12
    assert third["decision"]["action"] == "queue_l1"

    recurrence = next(f for f in third["risk"]["factors"] if f["name"] == "recurrence_velocity")
    assert recurrence["points"] == 12
    assert "rapid_burst" in recurrence["detail"]


def test_pipeline_is_fully_offline(client: TestClient) -> None:
    """Phase 1F performs no external enrichment (no VirusTotal/MISP)."""
    chain = client.app.state.enrichment_chain
    assert {provider.name for provider in chain.providers if provider.enabled} == set()

    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert body["enrichment_status"] == "skipped"
