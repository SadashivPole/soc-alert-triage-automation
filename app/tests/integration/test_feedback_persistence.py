"""Phase 2E integration tests: analyst feedback survives an application restart.

Covers the persistence contract for the Phase 2B feedback endpoints against a
real (temp) SQLite database, with emphasis on the restart/reload guarantee
that the existing unit tests cannot prove:

* GET /feedback/status before any feedback reports ``acknowledged=false``,
  ``has_feedback=false``, ``feedback_count=0``;
* POST /feedback stores the verdict (200 + response envelope), and status
  flips to acknowledged with ``latest_verdict`` / ``feedback_count``;
* feedback rows survive a full application restart/reload (new engine, same
  SQLite file — app A closed, app B queries the same ``db_url``);
* the append-only ``feedback.received`` audit entry survives the restart;
* security: missing / invalid n8n token is rejected (401) and stores nothing;
* non-true-positive verdicts (``false_positive``, ``escalate``) are accepted,
  persisted across restarts, and count as acknowledgement (the documented
  "any feedback counts as acknowledgement for SLA" contract).

The outage/restart simulation never touches filesystem permissions — it uses
the application factory's normal startup path twice over the same SQLite
file, so it is deterministic on Windows and Linux (no ``chmod`` semantics).
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.engine import create_app_engine, create_session_factory
from soc_triage.db.session import session_scope
from soc_triage.main import create_app
from soc_triage.models.repositories import AuditRepository, FeedbackRepository

# Same audit contract as the production module (Phase 2B): feedback receipts
# are recorded as ``feedback.received`` by the analyst actor on the
# ``feedback`` entity.
ACTION_FEEDBACK_RECEIVED = "feedback.received"
ENTITY_FEEDBACK = "feedback"
ACTOR_ANALYST = "analyst"

SAMPLE_FULL_LOG = "Failed password for admin from 203.0.113.50"


def _settings(db_url: str) -> Settings:
    """Non-placeholder settings for a specific database file."""
    return Settings(
        soc_env="test",
        soc_log_level="WARNING",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=db_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
    )


@contextmanager
def _app_client(db_url: str) -> Iterator[TestClient]:
    """A TestClient over a fresh app instance (lifespan: engine + migrations).

    Closing the context runs the lifespan shutdown, which disposes the
    engine — the "application stopped" boundary of a restart/reload.
    """
    with TestClient(create_app(settings=_settings(db_url))) as client:
        yield client


def _sample_payload() -> dict[str, Any]:
    return {
        "id": "1770000000.100001",
        "timestamp": "2026-08-29T10:15:29.000+0000",
        "rule": {
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "id": "5710",
        },
        "agent": {"id": "001", "name": "web-prod-01"},
        "data": {"srcip": "203.0.113.50", "dstuser": "admin"},
        "location": "/var/log/auth.log",
        "full_log": SAMPLE_FULL_LOG,
    }


def _auth() -> dict[str, str]:
    return {"X-API-Key": TEST_INGEST_KEY}


def _token() -> dict[str, str]:
    return {"X-N8N-Token": TEST_CALLBACK_TOKEN}


def _ingest_alert(client: TestClient) -> str:
    resp = client.post("/api/v1/alerts/ingest", json=_sample_payload(), headers=_auth())
    assert resp.status_code == 202, f"ingest failed: {resp.status_code} {resp.text}"
    return resp.json()["alert_id"]


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
    return client.post(f"/api/v1/alerts/{alert_id}/feedback", json=body, headers=_token())


def _status(client: TestClient, alert_id: str) -> Any:
    resp = client.get(f"/api/v1/alerts/{alert_id}/feedback/status", headers=_token())
    assert resp.status_code == 200, f"status failed: {resp.status_code} {resp.text}"
    return resp.json()


def _stored_feedback(db_url: str, alert_id: str) -> list[Any]:
    """All analyst_feedback rows for an alert, via a fresh engine."""
    engine = create_app_engine(db_url)
    try:
        with session_scope(create_session_factory(engine)) as session:
            return FeedbackRepository(session).for_alert(UUID(alert_id))
    finally:
        engine.dispose()


def _stored_audit(db_url: str) -> list[Any]:
    """All audit rows, via a fresh engine (append-only system of record)."""
    engine = create_app_engine(db_url)
    try:
        with session_scope(create_session_factory(engine)) as session:
            return AuditRepository(session).all()
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Status before feedback
# ---------------------------------------------------------------------------


def test_status_before_any_feedback_reports_unacknowledged(db_url: str) -> None:
    """GET /feedback/status on a fresh alert: no feedback recorded yet."""
    with _app_client(db_url) as client:
        alert_id = _ingest_alert(client)
        body = _status(client, alert_id)
        assert body["alert_id"] == alert_id
        assert body["acknowledged"] is False
        assert body["has_feedback"] is False
        assert body["feedback_count"] == 0
        assert body["latest_verdict"] is None
        assert body["acknowledged_at"] is None
        assert "checked_at" in body

    # Nothing was persisted by a read-only status check.
    assert _stored_feedback(db_url, alert_id) == []


# ---------------------------------------------------------------------------
# Submission + immediate status update
# ---------------------------------------------------------------------------


def test_true_positive_feedback_submission_updates_status(db_url: str) -> None:
    """POST true_positive -> 200 envelope, status flips to acknowledged."""
    with _app_client(db_url) as client:
        alert_id = _ingest_alert(client)

        resp = _submit_feedback(
            client,
            alert_id,
            "true_positive",
            actor="analyst@example.com",
            notes="confirmed C2 beacon",
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "accepted"
        assert body["alert_id"] == alert_id
        assert body["verdict"] == "true_positive"
        assert body["received_at"]  # ISO timestamp present

        status = _status(client, alert_id)
        assert status["acknowledged"] is True
        assert status["has_feedback"] is True
        assert status["feedback_count"] == 1
        assert status["latest_verdict"] == "true_positive"
        assert status["acknowledged_at"] is not None

    stored = _stored_feedback(db_url, alert_id)
    assert len(stored) == 1
    assert stored[0].verdict == "true_positive"
    assert stored[0].actor == "analyst@example.com"
    assert stored[0].notes == "confirmed C2 beacon"


# ---------------------------------------------------------------------------
# Restart / reload persistence
# ---------------------------------------------------------------------------


def test_feedback_persists_across_application_restart(db_url: str) -> None:
    """Feedback submitted against app A is served by app B on the same file."""
    with _app_client(db_url) as client_a:
        alert_id = _ingest_alert(client_a)
        resp = _submit_feedback(
            client_a,
            alert_id,
            "true_positive",
            actor="analyst@example.com",
            notes="confirmed C2 beacon",
        )
        assert resp.status_code == 200
    # app A lifespan ended -> engine disposed.

    with _app_client(db_url) as client_b:
        status = _status(client_b, alert_id)
        assert status["acknowledged"] is True
        assert status["has_feedback"] is True
        assert status["feedback_count"] == 1
        assert status["latest_verdict"] == "true_positive"
        assert status["acknowledged_at"] is not None

    # Direct DB proof via a fresh engine: the row is durable.
    stored = _stored_feedback(db_url, alert_id)
    assert len(stored) == 1
    assert stored[0].verdict == "true_positive"
    assert stored[0].actor == "analyst@example.com"
    assert stored[0].notes == "confirmed C2 beacon"
    assert stored[0].alert_id == UUID(alert_id)


def test_feedback_received_audit_entry_survives_restart(db_url: str) -> None:
    """The append-only feedback.received audit entry outlives the app."""
    with _app_client(db_url) as client_a:
        alert_id = _ingest_alert(client_a)
        assert (
            _submit_feedback(
                client_a,
                alert_id,
                "true_positive",
                actor="analyst@example.com",
            ).status_code
            == 200
        )

    entries = _stored_audit(db_url)
    received = [e for e in entries if e.action == ACTION_FEEDBACK_RECEIVED]
    assert len(received) == 1
    entry = received[0]
    assert entry.entity_type == ENTITY_FEEDBACK
    assert entry.entity_id == alert_id
    assert entry.actor == ACTOR_ANALYST
    assert entry.after == {
        "alert_id": alert_id,
        "verdict": "true_positive",
        "actor": "analyst@example.com",
    }


# ---------------------------------------------------------------------------
# Security: token required
# ---------------------------------------------------------------------------


def test_feedback_endpoints_reject_missing_or_invalid_token(db_url: str) -> None:
    """Missing/invalid n8n token -> 401, and nothing is persisted."""
    with _app_client(db_url) as client:
        alert_id = _ingest_alert(client)

        # Missing token on both endpoints.
        assert (
            client.post(
                f"/api/v1/alerts/{alert_id}/feedback", json={"verdict": "true_positive"}
            ).status_code
            == 401
        )
        assert client.get(f"/api/v1/alerts/{alert_id}/feedback/status").status_code == 401

        # Invalid token on both endpoints.
        for header in ({"X-N8N-Token": "wrong-token"}, {"Authorization": "Bearer wrong-token"}):
            resp = client.post(
                f"/api/v1/alerts/{alert_id}/feedback",
                json={"verdict": "true_positive"},
                headers=header,
            )
            assert resp.status_code == 401
            assert (
                client.get(f"/api/v1/alerts/{alert_id}/feedback/status", headers=header).status_code
                == 401
            )

    # Rejected attempts must not have created feedback rows or audit entries.
    assert _stored_feedback(db_url, alert_id) == []
    entries = _stored_audit(db_url)
    assert [e.action for e in entries if e.action == ACTION_FEEDBACK_RECEIVED] == []


# ---------------------------------------------------------------------------
# Verdict acceptance (false_positive / escalate) + restart
# ---------------------------------------------------------------------------


def test_false_positive_verdict_accepted_and_persisted_across_restart(
    db_url: str,
) -> None:
    """false_positive is accepted, counts as acknowledgement, survives restart."""
    with _app_client(db_url) as client_a:
        alert_id = _ingest_alert(client_a)
        resp = _submit_feedback(client_a, alert_id, "false_positive", actor="analyst@example.com")
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "false_positive"

        status = _status(client_a, alert_id)
        assert status["acknowledged"] is True  # any verdict counts for SLA
        assert status["latest_verdict"] == "false_positive"

    with _app_client(db_url) as client_b:
        status = _status(client_b, alert_id)
        assert status["acknowledged"] is True
        assert status["has_feedback"] is True
        assert status["feedback_count"] == 1
        assert status["latest_verdict"] == "false_positive"

    stored = _stored_feedback(db_url, alert_id)
    assert [row.verdict for row in stored] == ["false_positive"]


def test_escalate_verdict_accepted_and_persisted_across_restart(db_url: str) -> None:
    """escalate is accepted, counts as acknowledgement, survives restart."""
    with _app_client(db_url) as client_a:
        alert_id = _ingest_alert(client_a)
        resp = _submit_feedback(
            client_a, alert_id, "escalate", actor="l2@example.com", notes="needs L2"
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "escalate"

        status = _status(client_a, alert_id)
        assert status["acknowledged"] is True
        assert status["latest_verdict"] == "escalate"

    with _app_client(db_url) as client_b:
        status = _status(client_b, alert_id)
        assert status["acknowledged"] is True
        assert status["feedback_count"] == 1
        assert status["latest_verdict"] == "escalate"
        assert status["acknowledged_at"] is not None

    stored = _stored_feedback(db_url, alert_id)
    assert [(row.verdict, row.notes) for row in stored] == [("escalate", "needs L2")]


def test_multiple_feedback_entries_count_and_keep_latest_after_restart(
    db_url: str,
) -> None:
    """Two submissions -> feedback_count=2, latest_verdict=second verdict."""
    with _app_client(db_url) as client_a:
        alert_id = _ingest_alert(client_a)
        assert _submit_feedback(client_a, alert_id, "true_positive").status_code == 200
        # Ensure strictly increasing received_at so "latest" is deterministic
        # (for_alert orders by received_at).
        time.sleep(0.05)
        assert _submit_feedback(client_a, alert_id, "escalate").status_code == 200

        status = _status(client_a, alert_id)
        assert status["feedback_count"] == 2
        assert status["latest_verdict"] == "escalate"
        assert status["acknowledged"] is True

    with _app_client(db_url) as client_b:
        status = _status(client_b, alert_id)
        assert status["feedback_count"] == 2
        assert status["latest_verdict"] == "escalate"
        assert status["acknowledged"] is True

    stored = _stored_feedback(db_url, alert_id)
    assert [row.verdict for row in stored] == ["true_positive", "escalate"]
