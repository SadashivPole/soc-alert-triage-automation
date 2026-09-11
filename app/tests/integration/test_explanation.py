"""Phase 6.5 integration tests: analyst explainability end-to-end.

Drives the real pipeline (ingest -> dedupe -> score -> decide -> persist ->
correlate) against a temp SQLite database through the application's normal
startup path, then reads ``GET /api/v1/alerts/{alert_id}/explanation`` and
asserts the explanation is a deterministic projection of the authoritative
persisted facts — never a re-scoring, re-decision, or fabrication.

Coverage (Phase 6.5 test contract):

* complete explanation for a fully populated alert
* score factor ordering is deterministic
* score arithmetic reconciles to the stored score
* decision explanation reflects the authoritative stored decision
* duplicate explanation
* recurrence explanation
* correlation explanation
* incident linkage
* IOC/enrichment explanation
* missing optional fields are explicit nulls
* unknown/unsupported fields are not fabricated
* authentication behavior (401 missing / invalid token)
* not-found behavior (structured 404)
* deterministic repeated requests
* explainability does not mutate persisted state
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
READ_HEADERS = {"X-N8N-Token": TEST_CALLBACK_TOKEN}

TOP_LEVEL_KEYS = {
    "explanation_version",
    "alert_id",
    "alert",
    "detection",
    "score",
    "decision",
    "dedupe",
    "correlation",
    "investigation",
}


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _ingest(client: TestClient, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _explanation(client: TestClient, alert_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/alerts/{alert_id}/explanation", headers=READ_HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def _critical_malware_payload() -> dict[str, Any]:
    """Sample 04 (malware hash) on a critical-tier asset → SEV1 incident."""
    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    payload["agent"] = {
        "id": "003",
        "name": "hr-wks-04",
        "labels": {"asset_tier": "critical"},
    }
    return payload


def _synthetic(*, event_id: str, rule_id: str, agent_id: str, level: int = 5) -> dict[str, Any]:
    """A minimal valid Wazuh alert without MITRE, asset labels, or IOCs."""
    return {
        "id": event_id,
        "rule": {"id": rule_id, "level": level, "description": f"synthetic rule {rule_id}"},
        "agent": {"id": agent_id, "name": "synthetic-host"},
        "location": "/var/log/synthetic.log",
    }


def _db_snapshot(client: TestClient) -> dict[str, Any]:
    """Raw persisted-state snapshot used to prove explanations never mutate."""
    with client.app.state.db_engine.connect() as conn:
        return {
            "alerts": conn.execute(
                text(
                    "SELECT CAST(alert_id AS TEXT), normalized_payload FROM alerts ORDER BY alert_id"
                )
            ).fetchall(),
            "audit_count": conn.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one(),
            "audit_max_id": conn.execute(
                text("SELECT COALESCE(MAX(id), 0) FROM audit_log")
            ).scalar_one(),
            "contexts": conn.execute(
                text("SELECT COUNT(*) FROM correlation_contexts")
            ).scalar_one(),
            "members": conn.execute(text("SELECT COUNT(*) FROM correlation_members")).scalar_one(),
            "dedupe_groups": conn.execute(
                text(
                    "SELECT group_key, occurrences, generation, duplicate_deliveries "
                    "FROM alert_dedupe_groups ORDER BY group_key"
                )
            ).fetchall(),
            "events": conn.execute(
                text(
                    "SELECT event_identity, delivery_count, content_variants "
                    "FROM alert_events ORDER BY event_identity"
                )
            ).fetchall(),
            "incidents": conn.execute(
                text("SELECT incident_id, status FROM incidents ORDER BY incident_id")
            ).fetchall(),
        }


# ---------------------------------------------------------------------------
# Complete explanation (fully populated alert)
# ---------------------------------------------------------------------------


def test_explanation_complete_for_fully_populated_alert(client: TestClient) -> None:
    ingested = _ingest(client, _critical_malware_payload())
    alert_id = ingested["alert_id"]

    body = _explanation(client, alert_id)

    assert body["explanation_version"] == "explanation.v1"
    assert body["alert_id"] == alert_id
    assert set(body.keys()) == TOP_LEVEL_KEYS

    # A. Alert summary — persisted identity facts.
    alert = body["alert"]
    assert alert["alert_id"] == alert_id
    assert alert["source"] == "wazuh"
    assert alert["rule"]["id"] == body["detection"]["rule_id"]
    assert alert["agent"]["id"] == "003"
    assert alert["asset"] == {"name": "hr-wks-04", "tier": "critical", "owner": None}

    # B. Detection — stored rule metadata (sample 04 carries MITRE).
    detection = body["detection"]
    assert detection["rule_description"]
    assert detection["groups"] == alert["rule"]["groups"]

    # C. Score — the authoritative stored assessment, reconciled.
    score = body["score"]
    assert score is not None
    assert score["policy_version"] == "scoring.v1"
    assert score["score"] == ingested["risk"]["score"]
    assert score["tier"] == ingested["risk"]["tier"]
    assert score["reconciles"] is True
    assert [factor["name"] for factor in score["factors"]] == [
        "rule_severity",
        "rule_groups_mitre",
        "asset_criticality",
        "recurrence_velocity",
        "ioc_evidence",
        "enrichment_status",
        "allowlist_modifier",
    ]

    # D. Decision — the authoritative stored routing decision.
    decision = body["decision"]
    assert decision is not None
    assert decision["action"] == "open_incident"
    assert decision["severity"] == "SEV1"
    assert score["severity"] == "SEV1"
    assert decision["policy_version"] is None  # documented v1 limitation
    assert decision["reasons"]

    # E. Dedupe — stored recurrence facts for a first-generation alert.
    dedupe = body["dedupe"]
    assert dedupe is not None
    assert dedupe["dedupe_status"] == "new_generation"
    assert dedupe["is_exact_duplicate"] is False
    assert dedupe["occurrences"] == 1
    assert dedupe["generation"] == 1
    assert dedupe["delivery_count"] == 1

    # F/G — no correlation for a lone alert; incident linkage present.
    assert body["correlation"] is None
    assert body["investigation"]["incident"] is not None
    assert body["investigation"]["incident"]["incident_id"] == ingested["incident_id"]

    # Audit history carries the alert lifecycle, deterministically ordered.
    # (``dedupe.generation_started`` targets the dedupe group and is written
    # in the same clock tick before ``alert.created``; assert the alert's own
    # lifecycle appears in order rather than at fixed indexes.)
    actions = [event["action"] for event in body["investigation"]["audit_events"]]
    assert "dedupe.generation_started" in actions
    for expected in ("alert.created", "alert.scored", "alert.decided", "incident.created"):
        assert expected in actions
    created = actions.index("alert.created")
    assert created < actions.index("alert.scored") < actions.index("alert.decided")


# ---------------------------------------------------------------------------
# Score explanation: deterministic ordering + arithmetic reconciliation
# ---------------------------------------------------------------------------


def test_score_factor_ordering_is_deterministic_and_reconciles(client: TestClient) -> None:
    first = _ingest(client, _critical_malware_payload())
    second = _ingest(
        client,
        dict(
            _critical_malware_payload(),
            id="1770000000.900002",
            agent={"id": "004", "name": "hr-wks-05"},
        ),
    )

    body_a = _explanation(client, first["alert_id"])
    body_b = _explanation(client, second["alert_id"])

    for body in (body_a, body_b):
        factors = body["score"]["factors"]
        assert [f["name"] for f in factors] == [
            "rule_severity",
            "rule_groups_mitre",
            "asset_criticality",
            "recurrence_velocity",
            "ioc_evidence",
            "enrichment_status",
            "allowlist_modifier",
        ]
        assert all(f["kind"] in {"positive", "zero", "negative"} for f in factors)
        assert body["score"]["factor_points_total"] == sum(f["points"] for f in factors)
        assert body["score"]["reconciles"] is True

    # Identical persisted state → identical explanation (same alert, two reads).
    repeat = _explanation(client, first["alert_id"])
    assert repeat == body_a

    # Cross-check against the authoritative alert detail endpoint.
    detail = client.get(f"/api/v1/alerts/{first['alert_id']}", headers=READ_HEADERS).json()
    assert body_a["score"]["score"] == detail["risk"]["score"]
    assert body_a["score"]["tier"] == detail["risk"]["tier"]
    assert body_a["score"]["factors"] == [
        {**factor, "kind": kind}
        for factor, kind in zip(
            detail["risk"]["factors"],
            [f["kind"] for f in body_a["score"]["factors"]],
            strict=True,
        )
    ]


# ---------------------------------------------------------------------------
# Decision explanation reflects the authoritative stored decision
# ---------------------------------------------------------------------------


def test_decision_explanation_reflects_stored_decision(client: TestClient) -> None:
    ingested = _ingest(client, _critical_malware_payload())
    body = _explanation(client, ingested["alert_id"])

    detail = client.get(f"/api/v1/alerts/{ingested['alert_id']}", headers=READ_HEADERS).json()
    decision = body["decision"]
    assert decision["action"] == detail["decision"]["action"] == "open_incident"
    assert decision["severity"] == detail["decision"]["severity"] == "SEV1"
    assert decision["reasons"] == detail["decision"]["reasons"]
    assert decision["decided_at"] == detail["decision"]["decided_at"]
    # No fabricated history: the policy version is not persisted with the alert.
    assert decision["policy_version"] is None


# ---------------------------------------------------------------------------
# Duplicate / recurrence explanations (never reinterpreted as correlation)
# ---------------------------------------------------------------------------


def test_duplicate_explanation_counts_the_absorbed_delivery(client: TestClient) -> None:
    original = _ingest(client, _critical_malware_payload())
    duplicate = _ingest(client, _critical_malware_payload())
    assert duplicate["duplicate"] is True
    assert duplicate["alert_id"] == original["alert_id"]

    body = _explanation(client, original["alert_id"])
    dedupe = body["dedupe"]
    assert dedupe["is_exact_duplicate"] is False  # this row was recorded, not absorbed
    assert dedupe["delivery_count"] == 2  # the event was delivered twice
    assert dedupe["duplicate_deliveries"] == 1  # one absorbed re-delivery
    assert dedupe["occurrences"] == 1  # duplicates never increment occurrences

    actions = [event["action"] for event in body["investigation"]["audit_events"]]
    assert "alert.duplicate_absorbed" in actions
    # Exact duplicates are dedupe semantics — no correlation is implied.
    assert body["correlation"] is None


def test_recurrence_explanation_reports_repeated_status(client: TestClient) -> None:
    first = _ingest(
        client, _synthetic(event_id="1770000001.100001", rule_id="5501", agent_id="011")
    )
    second = _ingest(
        client, _synthetic(event_id="1770000001.100002", rule_id="5501", agent_id="011")
    )
    assert second["duplicate"] is False
    assert second["alert_id"] != first["alert_id"]

    body = _explanation(client, second["alert_id"])
    dedupe = body["dedupe"]
    assert dedupe["dedupe_status"] == "repeated"
    assert dedupe["is_exact_duplicate"] is False
    assert dedupe["occurrences"] == 2
    assert dedupe["generation"] == 1
    assert dedupe["group_key"] == first["dedupe"]["group_key"]
    # Recurrence is its own relationship: no correlation context involved.
    assert body["correlation"] is None


# ---------------------------------------------------------------------------
# Correlation explanation (stored correlation.v1 semantics, verbatim)
# ---------------------------------------------------------------------------


def test_correlation_explanation_uses_stored_context_and_evidence(client: TestClient) -> None:
    first = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    context_id = second["correlation_context_id"]
    assert context_id is not None

    body = _explanation(client, second["alert_id"])
    correlation = body["correlation"]
    assert correlation is not None
    assert correlation["context_id"] == context_id
    assert correlation["linked_alert_ids"] == [first["alert_id"]]
    assert correlation["evidence"]
    for item in correlation["evidence"]:
        assert set(item.keys()) == {"evidence_type", "value", "reason", "peer_alert_id"}
        assert item["peer_alert_id"] == first["alert_id"]

    # Same result as the dedicated correlation read API (no second engine).
    context = client.get(
        f"/api/v1/alerts/{second['alert_id']}/correlation", headers=READ_HEADERS
    ).json()
    assert context["context_id"] == context_id

    # Correlation and dedupe stay visibly distinct relationships.
    assert body["dedupe"]["group_key"] != body["dedupe"]["event_identity"]
    assert body["dedupe"]["dedupe_status"] in {"new_generation", "repeated"}


# ---------------------------------------------------------------------------
# Incident linkage + IOC / enrichment context
# ---------------------------------------------------------------------------


def test_incident_linkage_and_investigation_context(client: TestClient) -> None:
    ingested = _ingest(client, _critical_malware_payload())
    body = _explanation(client, ingested["alert_id"])

    incident = body["investigation"]["incident"]
    assert incident == {
        "incident_id": ingested["incident_id"],
        "status": "open",
        "severity": "SEV1",
    }

    # IOCs: the malware hash is extracted and projected analyst-safe.
    iocs = body["investigation"]["iocs"]
    assert iocs
    assert all(set(ioc.keys()) == {"type", "value", "enrichment", "provenance"} for ioc in iocs)
    assert any(ioc["type"] == "sha256" for ioc in iocs)

    # Enrichment providers are unconfigured in tests → stored status verbatim.
    assert body["investigation"]["enrichment_status"] in {"skipped", "failed"}


# ---------------------------------------------------------------------------
# Missing data, no fabrication, security
# ---------------------------------------------------------------------------


def test_missing_optional_fields_are_explicit_nulls(client: TestClient) -> None:
    ingested = _ingest(
        client, _synthetic(event_id="1770000002.200001", rule_id="100", agent_id="021")
    )
    body = _explanation(client, ingested["alert_id"])

    # No MITRE stored on the rule → null, never invented.
    assert body["detection"]["mitre"] is None
    # No asset labels → the stored asset block carries no tier/owner.
    assert body["alert"]["asset"] is not None
    assert body["alert"]["asset"]["tier"] is None
    assert body["alert"]["asset"]["owner"] is None
    # Low synthetic alert: no incident, no correlation.
    assert body["decision"]["action"] in {"monitor", "suppress", "queue_l1"}
    assert body["investigation"]["incident"] is None
    assert body["correlation"] is None
    assert body["investigation"]["iocs"] == []


def test_unknown_fields_are_not_fabricated(client: TestClient) -> None:
    ingested = _ingest(
        client, _synthetic(event_id="1770000002.300001", rule_id="100", agent_id="022")
    )
    body = _explanation(client, ingested["alert_id"])

    # Exact contract surface — no extra invented fields anywhere at top level.
    assert set(body.keys()) == TOP_LEVEL_KEYS
    # Scoring/decision always run at ingest, so those sections exist; their
    # contents must reconcile with the alert of record, not a new engine.
    detail = client.get(f"/api/v1/alerts/{ingested['alert_id']}", headers=READ_HEADERS).json()
    assert body["score"]["score"] == detail["risk"]["score"]
    assert body["decision"]["action"] == detail["decision"]["action"]
    # Explanation never fabricates a decision policy version.
    assert body["decision"]["policy_version"] is None


def test_explanation_never_leaks_secrets_or_raw_logs(client: TestClient) -> None:
    payload = _synthetic(event_id="1770000002.400001", rule_id="100", agent_id="023")
    payload["full_log"] = "canary-full-log-line password=hunter2 api_key=CANARY-SECRET"
    _ingest(client, payload)

    listed = client.get("/api/v1/alerts", headers=READ_HEADERS).json()
    alert_id = listed["items"][0]["alert_id"]
    response = client.get(f"/api/v1/alerts/{alert_id}/explanation", headers=READ_HEADERS)
    text_body = response.text

    assert "canary-full-log-line" not in text_body
    assert "CANARY-SECRET" not in text_body
    assert "hunter2" not in text_body
    assert TEST_CALLBACK_TOKEN not in text_body
    assert TEST_INGEST_KEY not in text_body


# ---------------------------------------------------------------------------
# Auth, 404, determinism, read-only discipline
# ---------------------------------------------------------------------------


def test_explanation_requires_authentication(client: TestClient) -> None:
    ingested = _ingest(client, _critical_malware_payload())
    url = f"/api/v1/alerts/{ingested['alert_id']}/explanation"

    assert client.get(url).status_code == 401
    assert client.get(url, headers={"X-N8N-Token": "wrong-token"}).status_code == 401
    assert client.get(url, headers=READ_HEADERS).status_code == 200


def test_explanation_unknown_alert_returns_structured_404(client: TestClient) -> None:
    response = client.get(f"/api/v1/alerts/{uuid4()}/explanation", headers=READ_HEADERS)
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "not_found"
    assert "not found" in error["message"]


def test_explanation_repeated_requests_are_identical(client: TestClient) -> None:
    ingested = _ingest(client, _critical_malware_payload())
    url = f"/api/v1/alerts/{ingested['alert_id']}/explanation"

    first = client.get(url, headers=READ_HEADERS)
    second = client.get(url, headers=READ_HEADERS)
    assert first.status_code == second.status_code == 200
    assert first.text == second.text  # byte-identical: content and ordering


def test_explanation_does_not_mutate_persisted_state(client: TestClient) -> None:
    first = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    assert second["correlation_context_id"] is not None

    before = _db_snapshot(client)
    for _ in range(3):
        assert _explanation(client, first["alert_id"])["explanation_version"] == "explanation.v1"
        assert _explanation(client, second["alert_id"])["explanation_version"] == "explanation.v1"
        client.get(f"/api/v1/alerts/{uuid4()}/explanation", headers=READ_HEADERS)
    after = _db_snapshot(client)

    assert before == after


def test_explanation_validates_alert_id_shape(client: TestClient) -> None:
    response = client.get("/api/v1/alerts/not-a-uuid/explanation", headers=READ_HEADERS)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
