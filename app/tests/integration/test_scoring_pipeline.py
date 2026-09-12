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


def test_second_occurrence_below_rapid_burst_does_not_escalate(client: TestClient) -> None:
    """Two distinct events of the same rule+agent stay one delivery below the
    configured rapid-burst minimum: the recurrence factor contributes nothing,
    so the score and routing action are unchanged (Phase 6.3 boundary)."""
    base = _load_sample("01_wazuh_ssh_brute_force.json")

    first = _ingest(client, base)
    second = _ingest(client, dict(base, id="1770000000.100001.r2"))

    assert second["dedupe"]["occurrences"] == 2
    assert second["risk"]["score"] == first["risk"]["score"]
    assert second["risk"]["tier"] == first["risk"]["tier"]
    assert second["decision"]["action"] == first["decision"]["action"]

    recurrence = next(f for f in second["risk"]["factors"] if f["name"] == "recurrence_velocity")
    assert recurrence["points"] == 0


def test_benign_informational_event_stays_informational(client: TestClient) -> None:
    """A benign session event with no suspicious groups, no MITRE metadata, no
    indicators, and no asset-tier label stays in the informational band and is
    only monitored (Phase 6.3: fixture 08, second corpus negative)."""
    body = _ingest(client, _load_sample("08_wazuh_ssh_session_opened.json"))

    assert body["risk"]["score"] == 14
    assert body["risk"]["tier"] == "informational"
    assert body["decision"]["action"] == "monitor"
    assert body["decision"]["severity"] is None
    assert body["iocs"] == []

    asset = next(f for f in body["risk"]["factors"] if f["name"] == "asset_criticality")
    assert asset["points"] == client.app.state.scorer.policy.asset_criticality.unknown_points
    groups = next(f for f in body["risk"]["factors"] if f["name"] == "rule_groups_mitre")
    assert groups["points"] == 0


def test_malware_on_critical_asset_scores_critical_and_opens_sev1(client: TestClient) -> None:
    """Fixture 09 pins the critical band and SEV1 severity at pipeline level:
    the same malware-intelligence behavior as fixture 04 on a critical asset
    crosses the critical threshold and opens a SEV1 incident."""
    body = _ingest(client, _load_sample("09_wazuh_malware_hash_critical_server.json"))

    assert body["risk"]["score"] == 88
    assert body["risk"]["tier"] == "critical"
    assert body["decision"]["action"] == "open_incident"
    assert body["decision"]["severity"] == "SEV1"
    assert body["incident_id"]


def test_low_criticality_asset_holds_medium(client: TestClient) -> None:
    """Fixture 10 pins the `low` asset-criticality band (unexercised before
    Phase 6.3): the same web-attack behavior as fixture 05 on a tier-3 asset
    contributes the policy's low band and stays medium, not lower."""
    body = _ingest(client, _load_sample("10_wazuh_web_sql_injection_staging.json"))

    asset = next(f for f in body["risk"]["factors"] if f["name"] == "asset_criticality")
    assert asset["points"] == client.app.state.scorer.policy.asset_criticality.bands["low"]

    assert body["risk"]["score"] == 46
    assert body["risk"]["tier"] == "medium"
    assert body["decision"]["action"] == "queue_l1"


def test_authorized_fim_modification_stays_monitor(client: TestClient) -> None:
    """SCN-17: authorized FIM of /etc/motd on a low-criticality host stays
    in the low/monitor band (Phase 6.3 per-scenario FIM negative)."""
    body = _ingest(client, _load_sample("17_wazuh_fim_authorized_motd.json"))

    assert body["risk"]["score"] == 43
    assert body["risk"]["tier"] == "low"
    assert body["decision"]["action"] == "monitor"
    assert body["decision"]["severity"] is None


def test_expected_account_creation_stays_monitor(client: TestClient) -> None:
    """SCN-18: expected onboarding account creation on a standard-tier
    workstation stays monitor (Phase 6.3 per-scenario account negative)."""
    body = _ingest(client, _load_sample("18_wazuh_windows_user_created_expected.json"))

    assert body["risk"]["score"] == 32
    assert body["risk"]["tier"] == "low"
    assert body["decision"]["action"] == "monitor"
    assert body["decision"]["severity"] is None


def test_non_malicious_hash_event_stays_monitor(client: TestClient) -> None:
    """SCN-19: VirusTotal no-match hash event has no malware group and no
    MITRE metadata, so it stays at the low/monitor floor."""
    body = _ingest(client, _load_sample("19_wazuh_virustotal_no_match.json"))

    assert body["risk"]["score"] == 25
    assert body["risk"]["tier"] == "low"
    assert body["decision"]["action"] == "monitor"
    assert body["decision"]["severity"] is None
    groups = next(f for f in body["risk"]["factors"] if f["name"] == "rule_groups_mitre")
    assert groups["points"] == 0


def test_custom_ssh_near_miss_stays_monitor(client: TestClient) -> None:
    """SCN-20: four parent-rule 5712 failures remain below custom rule
    100100 frequency=5 and stay monitor. Synthetic near-miss shape."""
    body = _ingest(client, _load_sample("20_custom_ssh_near_miss.json"))

    assert body["normalized"]["source_event"]["rule"]["id"] == "5712"
    assert body["risk"]["score"] == 43
    assert body["risk"]["tier"] == "low"
    assert body["decision"]["action"] == "monitor"


def test_custom_fim_near_miss_stays_monitor(client: TestClient) -> None:
    """SCN-21: FIM deletion of an unmonitored scratch file (rule 553, not
    parent 550) stays monitor. Custom rule 100110 would not fire."""
    body = _ingest(client, _load_sample("21_custom_fim_near_miss.json"))

    assert body["normalized"]["source_event"]["rule"]["id"] == "553"
    assert body["risk"]["score"] == 38
    assert body["risk"]["tier"] == "low"
    assert body["decision"]["action"] == "monitor"
    groups = next(f for f in body["risk"]["factors"] if f["name"] == "rule_groups_mitre")
    assert groups["points"] == 0


def test_custom_web_near_miss_stays_monitor(client: TestClient) -> None:
    """SCN-22: WordPress-adjacent /wp-content path is outside custom rule
    100120 match alternatives and stays monitor."""
    body = _ingest(client, _load_sample("22_custom_web_near_miss.json"))

    assert body["normalized"]["source_event"]["rule"]["id"] == "31100"
    assert body["risk"]["score"] == 27
    assert body["risk"]["tier"] == "low"
    assert body["decision"]["action"] == "monitor"


def test_suspicious_non_triggering_web_request_stays_monitor(client: TestClient) -> None:
    """SCN-23: a trailing-quote query string looks suspicious but carries
    no attack group, no MITRE, and not rule 31103 — stays monitor."""
    body = _ingest(client, _load_sample("23_suspicious_web_non_triggering.json"))

    assert body["normalized"]["source_event"]["rule"]["id"] == "31101"
    assert body["risk"]["score"] == 27
    assert body["risk"]["tier"] == "low"
    assert body["decision"]["action"] == "monitor"
    groups = next(f for f in body["risk"]["factors"] if f["name"] == "rule_groups_mitre")
    assert groups["points"] == 0


def test_recurrence_boundary_two_deliveries_do_not_escalate(client: TestClient) -> None:
    """SCN-24: two distinct deliveries of the same rule+agent stay one
    occurrence below rapid-burst (min_occurrences=3); score and action are
    unchanged (Phase 6.3 recurrence-boundary negative)."""
    base = _load_sample("24_ssh_recurrence_below_burst.json")

    first = _ingest(client, base)
    second = _ingest(client, dict(base, id=f"{base.get('id')}.r2"))

    assert first["risk"]["score"] == 43
    assert first["decision"]["action"] == "monitor"
    assert second["dedupe"]["occurrences"] == 2
    assert second["risk"]["score"] == first["risk"]["score"]
    assert second["risk"]["tier"] == first["risk"]["tier"]
    assert second["decision"]["action"] == first["decision"]["action"] == "monitor"

    recurrence = next(f for f in second["risk"]["factors"] if f["name"] == "recurrence_velocity")
    assert recurrence["points"] == 0


def test_pipeline_is_fully_offline(client: TestClient) -> None:
    """Phase 1F performs no external enrichment (no VirusTotal/MISP)."""
    chain = client.app.state.enrichment_chain
    assert {provider.name for provider in chain.providers if provider.enabled} == set()

    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert body["enrichment_status"] == "skipped"
