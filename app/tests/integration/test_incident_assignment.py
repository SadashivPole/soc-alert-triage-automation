"""Phase 4.1 integration tests: incident analyst assignment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.conftest import TEST_INGEST_KEY

from soc_triage.api.dependencies import get_scorer
from soc_triage.db.session import session_scope
from soc_triage.models.assessment import RiskAssessment, RiskTier, ScoreFactor
from soc_triage.models.repositories import AuditRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
INCIDENT_HEADERS = {"X-N8N-Token": "test-callback-token-not-a-real-secret"}


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


class _AssignmentTestScorer:
    """Deterministic HIGH/SEV2 scorer for assignment integration tests."""

    def __init__(self) -> None:
        self._risk = RiskAssessment(
            score=73,
            tier=RiskTier.HIGH,
            engine_version="scoring.v2",
            factors=(
                ScoreFactor(
                    name="assignment_test",
                    points=73,
                    max=100,
                    detail="deterministic incident-assignment integration test",
                ),
            ),
            summary="Incident assignment integration test score 73 (high).",
            degraded=False,
        )

    def score(self, _alert: Any) -> RiskAssessment:
        return self._risk


def _create_incident(client: TestClient) -> str:
    """Create one real persisted incident through the ingest API."""
    client.app.dependency_overrides[get_scorer] = lambda: _AssignmentTestScorer()

    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    payload["id"] = "1770000000.940001"
    payload["agent"] = {
        **payload.get("agent", {}),
        "id": "assignment-001",
        "name": "assignment-test-host",
    }

    response = client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 202, response.text

    body = response.json()
    assert body["incident_id"] is not None
    assert body["risk"]["score"] == 73
    assert body["risk"]["tier"] == "high"
    assert body["decision"]["action"] == "open_incident"

    return body["incident_id"]


@pytest.fixture
def incident_id(client: TestClient) -> str:
    """Create one incident for each assignment test."""
    return _create_incident(client)


def _audit_entries(client: TestClient) -> list[Any]:
    with session_scope(client.app.state.session_factory) as session:
        return AuditRepository(session).all()


def test_assignment_starts_unassigned(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.get(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "incident_id": incident_id,
        "assignee": None,
    }


def test_assign_incident_and_read_assignment(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
        json={
            "assignee": "analyst@example.com",
            "actor": "lead-analyst",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()

    assert body["incident_id"] == incident_id
    assert body["previous_assignee"] is None
    assert body["assignee"] == "analyst@example.com"
    assert body["changed"] is True

    read_response = client.get(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
    )

    assert read_response.status_code == 200
    assert read_response.json()["assignee"] == "analyst@example.com"


def test_reassign_and_unassign_incident(
    client: TestClient,
    incident_id: str,
) -> None:
    first = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
        json={
            "assignee": "analyst-one",
            "actor": "team-lead",
        },
    )
    assert first.status_code == 200

    second = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
        json={
            "assignee": "analyst-two",
            "actor": "team-lead",
        },
    )
    assert second.status_code == 200
    assert second.json()["previous_assignee"] == "analyst-one"
    assert second.json()["assignee"] == "analyst-two"
    assert second.json()["changed"] is True

    third = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
        json={
            "assignee": None,
            "actor": "team-lead",
        },
    )
    assert third.status_code == 200
    assert third.json()["previous_assignee"] == "analyst-two"
    assert third.json()["assignee"] is None
    assert third.json()["changed"] is True

    read_response = client.get(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
    )
    assert read_response.status_code == 200
    assert read_response.json()["assignee"] is None


def test_repeated_same_assignment_is_idempotent(
    client: TestClient,
    incident_id: str,
) -> None:
    payload = {
        "assignee": "analyst@example.com",
        "actor": "lead-analyst",
    }

    first = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
        json=payload,
    )
    assert first.status_code == 200
    assert first.json()["changed"] is True

    second = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
        json=payload,
    )
    assert second.status_code == 200
    assert second.json()["previous_assignee"] == "analyst@example.com"
    assert second.json()["assignee"] == "analyst@example.com"
    assert second.json()["changed"] is False

    assignment_events = [
        entry
        for entry in _audit_entries(client)
        if entry.action == "incident.assigned" and entry.entity_id == incident_id
    ]
    assert len(assignment_events) == 1


def test_assignment_is_written_to_audit_and_timeline(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
        json={
            "assignee": "investigator-01",
            "actor": "soc-lead",
        },
    )
    assert response.status_code == 200

    assignment_events = [
        entry
        for entry in _audit_entries(client)
        if entry.action == "incident.assigned" and entry.entity_id == incident_id
    ]

    assert len(assignment_events) == 1
    entry = assignment_events[0]
    assert entry.actor == "soc-lead"
    assert entry.entity_type == "incident"
    assert entry.before == {"assignee": None}
    assert entry.after == {"assignee": "investigator-01"}

    timeline = client.get(
        f"/api/v1/incidents/{incident_id}/timeline",
        headers=INCIDENT_HEADERS,
    )
    assert timeline.status_code == 200, timeline.text

    events = timeline.json()["events"]
    matching = [event for event in events if event["action"] == "incident.assigned"]
    assert matching
    assert matching[-1]["after"]["assignee"] == "investigator-01"


def test_assignment_unknown_incident_returns_404(
    client: TestClient,
) -> None:
    incident_id = "INC-2099-01-01-9999"

    get_response = client.get(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
    )
    assert get_response.status_code == 404

    patch_response = client.patch(
        f"/api/v1/incidents/{incident_id}/assignment",
        headers=INCIDENT_HEADERS,
        json={
            "assignee": "analyst@example.com",
            "actor": "lead-analyst",
        },
    )
    assert patch_response.status_code == 404


def test_assignment_requires_authentication(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.get(
        f"/api/v1/incidents/{incident_id}/assignment",
    )
    assert response.status_code == 401
