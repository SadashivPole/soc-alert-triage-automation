"""Phase 4.2 integration tests: incident investigation notes."""

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


class _NotesTestScorer:
    def __init__(self) -> None:
        self._risk = RiskAssessment(
            score=73,
            tier=RiskTier.HIGH,
            engine_version="scoring.v2",
            factors=(
                ScoreFactor(
                    name="notes_test",
                    points=73,
                    max=100,
                    detail="deterministic incident-notes integration test",
                ),
            ),
            summary="Incident notes integration test score 73 (high).",
            degraded=False,
        )

    def score(self, _alert: Any) -> RiskAssessment:
        return self._risk


@pytest.fixture
def incident_id(client: TestClient) -> str:
    client.app.dependency_overrides[get_scorer] = lambda: _NotesTestScorer()

    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    payload["id"] = "1770000000.950001"
    payload["agent"] = {
        **payload.get("agent", {}),
        "id": "notes-001",
        "name": "notes-test-host",
    }

    response = client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers=AUTH_HEADERS,
    )
    assert response.status_code == 202, response.text

    body = response.json()
    assert body["incident_id"] is not None
    return body["incident_id"]


def _audit_entries(client: TestClient) -> list[Any]:
    with session_scope(client.app.state.session_factory) as session:
        return AuditRepository(session).all()


def test_notes_start_empty(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "incident_id": incident_id,
        "notes": [],
    }


def test_add_and_list_investigation_notes(
    client: TestClient,
    incident_id: str,
) -> None:
    first = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
        json={
            "note": "Confirmed suspicious PowerShell activity.",
            "actor": "analyst-one",
        },
    )

    assert first.status_code == 201, first.text
    first_body = first.json()
    assert first_body["incident_id"] == incident_id
    assert first_body["actor"] == "analyst-one"
    assert first_body["note"] == "Confirmed suspicious PowerShell activity."
    assert first_body["created_at"]

    second = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
        json={
            "note": "Host isolated pending endpoint review.",
            "actor": "analyst-two",
        },
    )

    assert second.status_code == 201, second.text

    listed = client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
    )
    assert listed.status_code == 200

    notes = listed.json()["notes"]
    assert len(notes) == 2
    assert notes[0]["actor"] == "analyst-one"
    assert notes[0]["note"] == "Confirmed suspicious PowerShell activity."
    assert notes[1]["actor"] == "analyst-two"
    assert notes[1]["note"] == "Host isolated pending endpoint review."


def test_note_is_append_only_and_audited(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
        json={
            "note": "IOC matched known malicious infrastructure.",
            "actor": "soc-lead",
        },
    )
    assert response.status_code == 201

    matching = [
        entry
        for entry in _audit_entries(client)
        if entry.action == "incident.note_added" and entry.entity_id == incident_id
    ]

    assert len(matching) == 1
    entry = matching[0]
    assert entry.actor == "soc-lead"
    assert entry.entity_type == "incident"
    assert entry.before is None
    assert entry.after == {"note": "IOC matched known malicious infrastructure."}


def test_note_appears_in_incident_timeline(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
        json={
            "note": "Timeline evidence supports credential access activity.",
            "actor": "investigator-01",
        },
    )
    assert response.status_code == 201

    timeline = client.get(
        f"/api/v1/incidents/{incident_id}/timeline",
        headers=INCIDENT_HEADERS,
    )
    assert timeline.status_code == 200, timeline.text

    events = timeline.json()["events"]
    matching = [event for event in events if event["action"] == "incident.note_added"]

    assert matching
    assert matching[-1]["actor"] == "investigator-01"
    assert matching[-1]["after"]["note"] == (
        "Timeline evidence supports credential access activity."
    )


def test_empty_note_is_rejected(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
        json={
            "note": "   ",
            "actor": "analyst",
        },
    )

    assert response.status_code == 422


def test_unknown_incident_returns_404(
    client: TestClient,
) -> None:
    incident_id = "INC-2099-01-01-9999"

    get_response = client.get(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
    )
    assert get_response.status_code == 404

    post_response = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        headers=INCIDENT_HEADERS,
        json={
            "note": "This incident does not exist.",
            "actor": "analyst",
        },
    )
    assert post_response.status_code == 404


def test_notes_require_authentication(
    client: TestClient,
    incident_id: str,
) -> None:
    response = client.get(
        f"/api/v1/incidents/{incident_id}/notes",
    )
    assert response.status_code == 401
