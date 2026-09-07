"""Phase 3.2 integration tests: incident lifecycle + feedback synchronization.

Covers the milestone contract on a real (temp) SQLite database through the
same startup path the service uses (engine + Alembic migrations):

* PATCH /api/v1/incidents/{id}/status — valid and illegal transitions,
  structured 404/409, lifecycle timestamps, ``incident.status_updated`` /
  ``incident.escalated`` audit rows;
* POST /api/v1/alerts/{id}/feedback — the request/response contract is
  unchanged, but the linked incident now synchronizes with the verdict via
  the documented conservative mapping (never auto-resolves on a verdict;
  ``contain_requested`` is approval-required and non-destructive);
* restart persistence of lifecycle state + audit;
* idempotency where applicable (repeated identical feedback).
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.session import session_scope
from soc_triage.main import create_app
from soc_triage.models.repositories import AuditRepository, FeedbackRepository, IncidentRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
TOKEN_HEADERS = {"X-N8N-Token": TEST_CALLBACK_TOKEN}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _ingest_incident(client: TestClient, *, event_id: str | None = None) -> dict[str, Any]:
    """Ingest a high-tier alert → automatic SEV2 open incident."""
    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    if event_id is not None:
        payload = dict(payload, id=event_id)
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["incident_id"] is not None
    return body


def _patch_status(
    client: TestClient,
    incident_id: str,
    target: str,
    *,
    actor: str | None = None,
    notes: str | None = None,
) -> Any:
    body: dict[str, Any] = {"status": target}
    if actor is not None:
        body["actor"] = actor
    if notes is not None:
        body["notes"] = notes
    return client.patch(f"/api/v1/incidents/{incident_id}/status", json=body, headers=TOKEN_HEADERS)


def _submit_feedback(
    client: TestClient,
    alert_id: str,
    verdict: str,
    *,
    actor: str | None = None,
    notes: str | None = None,
) -> Any:
    body: dict[str, Any] = {"verdict": verdict}
    if actor is not None:
        body["actor"] = actor
    if notes is not None:
        body["notes"] = notes
    return client.post(f"/api/v1/alerts/{alert_id}/feedback", json=body, headers=TOKEN_HEADERS)


def _incident(client: TestClient, incident_id: str) -> Any:
    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        return IncidentRepository(session).get(incident_id)


def _incident_status(client: TestClient, incident_id: str) -> str:
    """The raw status string from the incidents table (system of record)."""
    with client.app.state.db_engine.connect() as conn:
        return conn.execute(
            text("SELECT status FROM incidents WHERE incident_id = :iid"),
            {"iid": incident_id},
        ).scalar_one()


def _audit(client: TestClient) -> list[Any]:
    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        return AuditRepository(session).all()


def _audit_actions(client: TestClient) -> list[str]:
    return [entry.action for entry in _audit(client)]


def _feedback_rows(client: TestClient, alert_id: str) -> list[Any]:
    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        return FeedbackRepository(session).for_alert(UUID(alert_id))


def _lifecycle_audit_rows(client: TestClient) -> list[Any]:
    """incident.status_updated + incident.escalated + containment entries."""
    return [
        entry
        for entry in _audit(client)
        if entry.action
        in {
            "incident.status_updated",
            "incident.escalated",
            "incident.containment_requested",
        }
    ]


def _app_client(db_url: str):
    settings = Settings(
        soc_env="test",
        soc_log_level="WARNING",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=db_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        n8n_webhook_token="",
    )
    return TestClient(create_app(settings=settings))


# ---------------------------------------------------------------------------
# 1-5. Valid transitions through the state machine
# ---------------------------------------------------------------------------


def test_open_to_investigating_is_valid(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    assert _incident_status(client, incident_id) == "open"

    response = _patch_status(
        client, incident_id, "investigating", actor="analyst@example.com", notes="on it"
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["incident_id"] == incident_id
    assert data["previous_status"] == "open"
    assert data["status"] == "investigating"
    assert data["acknowledged_at"] is None
    assert data["resolved_at"] is None

    incident = _incident(client, incident_id)
    assert incident.status.value == "investigating"
    assert incident.acknowledged_at is None
    assert incident.resolved_at is None
    assert incident.updated_at >= incident.created_at


def test_investigating_to_acknowledged_is_valid(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    assert _patch_status(client, incident_id, "investigating").status_code == 200

    response = _patch_status(client, incident_id, "acknowledged", actor="analyst@example.com")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["previous_status"] == "investigating"
    assert data["status"] == "acknowledged"
    assert data["acknowledged_at"] is not None
    assert data["resolved_at"] is None

    incident = _incident(client, incident_id)
    assert incident.status.value == "acknowledged"
    assert incident.acknowledged_at is not None


def test_acknowledged_to_resolved_is_valid(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    assert _patch_status(client, incident_id, "acknowledged").status_code == 200

    response = _patch_status(client, incident_id, "resolved", notes="host isolated")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["previous_status"] == "acknowledged"
    assert data["status"] == "resolved"
    assert data["acknowledged_at"] is not None
    assert data["resolved_at"] is not None

    incident = _incident(client, incident_id)
    assert incident.status.value == "resolved"
    assert incident.resolved_at is not None


def test_transition_to_false_positive_is_valid(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    # open → false_positive is a legal direct transition.
    response = _patch_status(client, incident_id, "false_positive", notes="allowlisted source")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "false_positive"

    incident = _incident(client, incident_id)
    assert incident.status.value == "false_positive"
    # Terminal states carry a resolution timestamp too (closed as FP).
    assert incident.resolved_at is not None
    assert incident.acknowledged_at is None


def test_transition_to_escalated_is_valid(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]

    response = _patch_status(client, incident_id, "escalated", actor="l2@example.com")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "escalated"

    rows = _lifecycle_audit_rows(client)
    updated = [e for e in rows if e.action == "incident.status_updated"]
    escalated = [e for e in rows if e.action == "incident.escalated"]
    assert len(updated) == 1
    assert len(escalated) == 1
    assert escalated[0].entity_id == incident_id
    assert escalated[0].before == {"status": "open"}
    assert escalated[0].after["status"] == "escalated"


# ---------------------------------------------------------------------------
# 6-8. Illegal transitions, unknown ids
# ---------------------------------------------------------------------------


def test_illegal_transition_from_resolved_is_rejected(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    assert _patch_status(client, incident_id, "acknowledged").status_code == 200
    assert _patch_status(client, incident_id, "resolved").status_code == 200

    before = _incident(client, incident_id)
    response = _patch_status(client, incident_id, "investigating")
    assert response.status_code == 409, response.text
    data = response.json()
    assert data["error"]["code"] == "conflict"
    assert "resolved -> investigating" in data["error"]["message"]
    details = data["error"]["details"]
    assert details["incident_id"] == incident_id
    assert details["current_status"] == "resolved"
    assert details["requested_status"] == "investigating"
    assert details["allowed_transitions"] == []  # terminal state

    # Nothing was mutated: row and audit trail unchanged.
    after = _incident(client, incident_id)
    assert before == after
    assert _audit_actions(client).count("incident.status_updated") == 2


def test_illegal_transition_from_false_positive_is_rejected(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    assert _patch_status(client, incident_id, "false_positive").status_code == 200
    before = _incident(client, incident_id)

    for target in ("investigating", "acknowledged", "resolved", "escalated", "open"):
        response = _patch_status(client, incident_id, target)
        assert response.status_code == 409, f"{target}: {response.text}"
        assert response.json()["error"]["code"] == "conflict"

    assert _incident(client, incident_id) == before
    assert _audit_actions(client).count("incident.status_updated") == 1


def test_open_to_resolved_is_not_a_legal_transition(client: TestClient) -> None:
    """The state machine requires investigation/acknowledgement before close."""
    body = _ingest_incident(client)
    incident_id = body["incident_id"]

    response = _patch_status(client, incident_id, "resolved")
    assert response.status_code == 409, response.text
    details = response.json()["error"]["details"]
    assert details["current_status"] == "open"
    assert details["allowed_transitions"] == sorted(
        ["investigating", "acknowledged", "false_positive", "escalated"]
    )
    assert _incident_status(client, incident_id) == "open"


def test_unknown_incident_returns_structured_404(client: TestClient) -> None:
    response = _patch_status(client, "INC-2099-01-01-0001", "investigating")
    assert response.status_code == 404, response.text
    data = response.json()
    assert data["error"]["code"] == "not_found"
    assert "INC-2099-01-01-0001" in data["error"]["message"]
    # No audit row for a no-op.
    assert _lifecycle_audit_rows(client) == []


def test_unknown_target_status_is_a_validation_error(client: TestClient) -> None:
    body = _ingest_incident(client)
    response = _patch_status(client, body["incident_id"], "closed")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert _incident_status(client, body["incident_id"]) == "open"


def test_status_update_requires_n8n_token(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    body_json: dict[str, Any] = {"status": "investigating"}

    assert (
        client.patch(f"/api/v1/incidents/{incident_id}/status", json=body_json).status_code == 401
    )
    assert (
        client.patch(
            f"/api/v1/incidents/{incident_id}/status",
            json=body_json,
            headers={"X-N8N-Token": "wrong"},
        ).status_code
        == 401
    )
    assert _incident_status(client, incident_id) == "open"


# ---------------------------------------------------------------------------
# 9. Audit
# ---------------------------------------------------------------------------


def test_status_update_creates_status_updated_audit_row(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]

    _patch_status(
        client,
        incident_id,
        "investigating",
        actor="analyst@example.com",
        notes="checking host",
    )

    rows = [e for e in _audit(client) if e.action == "incident.status_updated"]
    assert len(rows) == 1
    entry = rows[0]
    assert entry.actor == "analyst@example.com"
    assert entry.entity_type == "incident"
    assert entry.entity_id == incident_id
    assert entry.before == {"status": "open"}
    assert entry.after == {
        "incident_id": incident_id,
        "status": "investigating",
        "acknowledged_at": None,
        "resolved_at": None,
        "notes": "checking host",
    }
    # Append-only: the incident.created entry still precedes it.
    actions = _audit_actions(client)
    assert actions.index("incident.created") < actions.index("incident.status_updated")


def test_rejected_transition_writes_no_audit_row(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    assert _patch_status(client, incident_id, "resolved").status_code == 409
    # The only entry for this entity is the creation one — the rejected
    # transition wrote no lifecycle audit row.
    entries = [e for e in _audit(client) if e.entity_id == incident_id]
    assert [e.action for e in entries] == ["incident.created"]


# ---------------------------------------------------------------------------
# 10-11. Timestamp semantics
# ---------------------------------------------------------------------------


def test_acknowledged_at_set_exactly_when_acknowledged_is_reached(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]

    # open: not set.
    assert _incident(client, incident_id).acknowledged_at is None

    # investigating: still not set.
    assert _patch_status(client, incident_id, "investigating").status_code == 200
    assert _incident(client, incident_id).acknowledged_at is None

    # acknowledged: set now.
    assert _patch_status(client, incident_id, "acknowledged").status_code == 200
    first_ack = _incident(client, incident_id).acknowledged_at
    assert first_ack is not None

    # Leaving the state does not clear or change the timestamp.
    assert _patch_status(client, incident_id, "investigating").status_code == 200
    assert _incident(client, incident_id).acknowledged_at == first_ack

    # Re-reaching the state updates it to the new transition time.
    assert _patch_status(client, incident_id, "acknowledged").status_code == 200
    second_ack = _incident(client, incident_id).acknowledged_at
    assert second_ack is not None
    assert second_ack >= first_ack


def test_resolved_at_set_exactly_when_a_terminal_state_is_reached(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]

    # Non-terminal states never set resolved_at.
    assert _patch_status(client, incident_id, "investigating").status_code == 200
    assert _incident(client, incident_id).resolved_at is None
    assert _patch_status(client, incident_id, "escalated").status_code == 200
    assert _incident(client, incident_id).resolved_at is None

    # resolved: set exactly here.
    assert _patch_status(client, incident_id, "resolved").status_code == 200
    assert _incident(client, incident_id).resolved_at is not None


def test_false_positive_sets_resolved_at_but_not_acknowledged_at(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    assert _patch_status(client, incident_id, "false_positive").status_code == 200
    incident = _incident(client, incident_id)
    assert incident.resolved_at is not None
    assert incident.acknowledged_at is None
    # updated_at tracks the latest lifecycle change.
    assert incident.updated_at >= incident.created_at


def test_utc_timestamps_are_preserved(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    assert _patch_status(client, incident_id, "acknowledged").status_code == 200
    incident = _incident(client, incident_id)
    assert incident.acknowledged_at is not None
    for value in (incident.created_at, incident.updated_at, incident.acknowledged_at):
        assert value.tzinfo is not None
        assert value.utcoffset() == timedelta(0)  # stored/read as UTC


# ---------------------------------------------------------------------------
# 12-17. Feedback → incident synchronization
# ---------------------------------------------------------------------------


def test_feedback_acknowledged_updates_linked_incident(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]

    response = _submit_feedback(client, alert_id, "acknowledged", actor="analyst@example.com")
    assert response.status_code == 200
    # Response contract is EXACTLY the pre-3.2 envelope.
    assert set(response.json()) == {"status", "alert_id", "verdict", "received_at"}
    assert response.json()["status"] == "accepted"

    assert _incident_status(client, incident_id) == "acknowledged"
    incident = _incident(client, incident_id)
    assert incident.acknowledged_at is not None
    entries = [e for e in _audit(client) if e.action == "incident.status_updated"]
    assert len(entries) == 1
    assert entries[0].actor == "analyst@example.com"
    assert entries[0].before == {"status": "open"}
    assert entries[0].after["status"] == "acknowledged"
    # The feedback itself was recorded as before.
    assert [row.verdict for row in _feedback_rows(client, alert_id)] == ["acknowledged"]


def test_feedback_resolved_updates_linked_incident(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]

    # The state machine requires investigation before resolution — the
    # incident is first moved to investigating, then the verdict applies.
    assert _patch_status(client, incident_id, "investigating").status_code == 200

    response = _submit_feedback(client, alert_id, "resolved", actor="l2@example.com")
    assert response.status_code == 200

    incident = _incident(client, incident_id)
    assert incident.status.value == "resolved"
    assert incident.resolved_at is not None
    entries = [e for e in _audit(client) if e.action == "incident.status_updated"]
    assert len(entries) == 2  # PATCH + feedback
    assert entries[-1].before == {"status": "investigating"}
    assert entries[-1].after["status"] == "resolved"
    assert entries[-1].actor == "l2@example.com"


def test_feedback_resolved_on_open_incident_is_a_noop_for_the_incident(client: TestClient) -> None:
    """open → resolved is illegal: the verdict is recorded, the incident stays."""
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]
    before = _incident(client, incident_id)

    response = _submit_feedback(client, alert_id, "resolved")
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"

    assert _incident(client, incident_id) == before  # untouched
    assert _incident_status(client, incident_id) == "open"
    assert [e for e in _audit(client) if e.action == "incident.status_updated"] == []
    # But the feedback row + feedback.received audit exist (existing contract).
    assert [row.verdict for row in _feedback_rows(client, alert_id)] == ["resolved"]
    assert "feedback.received" in _audit_actions(client)


def test_feedback_false_positive_updates_linked_incident(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]

    response = _submit_feedback(client, alert_id, "false_positive")
    assert response.status_code == 200

    incident = _incident(client, incident_id)
    assert incident.status.value == "false_positive"
    assert incident.resolved_at is not None
    entries = [e for e in _audit(client) if e.action == "incident.status_updated"]
    assert len(entries) == 1
    assert entries[0].after["status"] == "false_positive"


def test_feedback_escalate_updates_linked_incident(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]

    response = _submit_feedback(client, alert_id, "escalate", actor="l2@example.com")
    assert response.status_code == 200

    assert _incident_status(client, incident_id) == "escalated"
    actions = _audit_actions(client)
    assert "incident.escalated" in actions
    escalated = [e for e in _audit(client) if e.action == "incident.escalated"]
    assert len(escalated) == 1
    assert escalated[0].actor == "l2@example.com"
    assert escalated[0].after["status"] == "escalated"


def test_true_positive_does_not_automatically_mark_resolved(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]

    # TP on an open incident: confirmation only — the incident may move to
    # acknowledged, but NEVER to resolved.
    response = _submit_feedback(
        client, alert_id, "true_positive", actor="analyst@example.com", notes="confirmed beacon"
    )
    assert response.status_code == 200
    incident = _incident(client, incident_id)
    assert incident.status.value == "acknowledged"
    assert incident.status.value != "resolved"
    assert incident.resolved_at is None
    assert incident.acknowledged_at is not None

    # A second TP (incident already acknowledged): idempotent, still not
    # resolved, no extra lifecycle audit row.
    assert _submit_feedback(client, alert_id, "true_positive").status_code == 200
    after = _incident(client, incident_id)
    assert after.status.value == "acknowledged"
    assert after.resolved_at is None
    assert len([e for e in _audit(client) if e.action == "incident.status_updated"]) == 1

    # Even an explicit later "resolved" verdict is the only path to resolved.
    assert _submit_feedback(client, alert_id, "resolved").status_code == 200
    assert _incident_status(client, incident_id) == "resolved"


def test_true_positive_on_terminal_incident_is_a_noop(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]
    assert _patch_status(client, incident_id, "false_positive").status_code == 200
    before = _incident(client, incident_id)
    audit_count = len(_lifecycle_audit_rows(client))

    assert _submit_feedback(client, alert_id, "true_positive").status_code == 200
    assert _incident(client, incident_id) == before
    assert len(_lifecycle_audit_rows(client)) == audit_count


def test_benign_maps_to_false_positive_never_resolved(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]

    assert _submit_feedback(client, alert_id, "benign").status_code == 200
    incident = _incident(client, incident_id)
    assert incident.status.value == "false_positive"
    assert incident.status.value != "resolved"
    assert incident.resolved_at is not None


def test_contain_requested_remains_approval_required_and_non_destructive(
    client: TestClient,
) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]
    before = _incident(client, incident_id)

    response = _submit_feedback(client, alert_id, "contain_requested", actor="analyst@example.com")
    # Feedback contract unchanged.
    assert response.status_code == 200
    assert set(response.json()) == {"status", "alert_id", "verdict", "received_at"}

    # The incident is completely untouched: no state change, no timestamps.
    after = _incident(client, incident_id)
    assert after == before
    assert after.status.value == "open"
    assert after.acknowledged_at is None
    assert after.resolved_at is None

    # No lifecycle transition audit — but the approval-required request IS
    # recorded against the incident (and nothing was executed).
    assert [e for e in _audit(client) if e.action == "incident.status_updated"] == []
    contained = [e for e in _audit(client) if e.action == "incident.containment_requested"]
    assert len(contained) == 1
    entry = contained[0]
    assert entry.actor == "analyst@example.com"
    assert entry.entity_type == "incident"
    assert entry.entity_id == incident_id
    assert entry.after == {
        "incident_id": incident_id,
        "alert_id": alert_id,
        "requested_by": "analyst@example.com",
        "state": "approval_required",
        "containment_executed": False,
    }


def test_feedback_for_alert_without_incident_is_unaffected(client: TestClient) -> None:
    """Low-tier alerts have no incident: feedback works exactly as before."""
    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 202
    body = response.json()
    assert body["incident_id"] is None

    feedback = _submit_feedback(client, body["alert_id"], "acknowledged")
    assert feedback.status_code == 200
    assert [row.verdict for row in _feedback_rows(client, body["alert_id"])] == ["acknowledged"]

    with client.app.state.db_engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM incidents")).scalar_one() == 0
    assert _lifecycle_audit_rows(client) == []


# ---------------------------------------------------------------------------
# 18. Restart persistence
# ---------------------------------------------------------------------------


def test_incident_lifecycle_persists_across_application_restart(db_url: str) -> None:
    with _app_client(db_url) as client_a:
        body = _ingest_incident(client_a)
        incident_id = body["incident_id"]
        alert_id = body["alert_id"]
        assert _patch_status(client_a, incident_id, "investigating").status_code == 200
        assert _patch_status(client_a, incident_id, "acknowledged").status_code == 200

    # "Restart triage-api": a brand-new process over the same SQLite file.
    with _app_client(db_url) as client_b:
        incident = _incident(client_b, incident_id)
        assert incident is not None
        assert incident.status.value == "acknowledged"
        assert incident.acknowledged_at is not None
        assert incident.resolved_at is None
        assert _incident_status(client_b, incident_id) == "acknowledged"

        # Lifecycle continues after the restart: feedback drives resolution.
        assert (
            _submit_feedback(client_b, alert_id, "resolved", actor="l2@example.com").status_code
            == 200
        )
        restarted = _incident(client_b, incident_id)
        assert restarted.status.value == "resolved"
        assert restarted.resolved_at is not None
        assert restarted.acknowledged_at == incident.acknowledged_at  # preserved

        # The full lifecycle audit trail survived.
        actions = _audit_actions(client_b)
        assert actions.count("incident.status_updated") == 3
        assert "incident.created" in actions
        assert "feedback.received" in actions
        assert actions.index("incident.created") < actions.index("feedback.received")


# ---------------------------------------------------------------------------
# 19. Idempotency
# ---------------------------------------------------------------------------


def test_repeated_identical_feedback_is_idempotent_for_the_incident(client: TestClient) -> None:
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]

    # Two identical "acknowledged" verdicts: both are recorded as feedback
    # (append-only, existing contract), but the incident transitions once.
    assert _submit_feedback(client, alert_id, "acknowledged").status_code == 200
    assert _submit_feedback(client, alert_id, "acknowledged").status_code == 200

    assert _incident_status(client, incident_id) == "acknowledged"
    assert len(_feedback_rows(client, alert_id)) == 2
    updated = [e for e in _audit(client) if e.action == "incident.status_updated"]
    assert len(updated) == 1
    assert updated[0].after["status"] == "acknowledged"

    # Repeated escalation: one transition, second one is a no-op.
    assert _submit_feedback(client, alert_id, "escalate").status_code == 200
    assert _submit_feedback(client, alert_id, "escalate").status_code == 200
    assert _incident_status(client, incident_id) == "escalated"
    assert len([e for e in _audit(client) if e.action == "incident.escalated"]) == 1


def test_contain_requested_repeated_records_each_request(client: TestClient) -> None:
    """Each approval request is recorded; the incident never moves."""
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]
    before = _incident(client, incident_id)

    assert _submit_feedback(client, alert_id, "contain_requested").status_code == 200
    assert _submit_feedback(client, alert_id, "contain_requested").status_code == 200

    assert _incident(client, incident_id) == before
    assert len(_feedback_rows(client, alert_id)) == 2
    contained = [e for e in _audit(client) if e.action == "incident.containment_requested"]
    assert len(contained) == 2  # each request is audited (approval is per-request)
