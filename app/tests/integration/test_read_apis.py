"""Phase 3.3 integration tests: alert/incident read APIs + incident timeline.

Covers the required read-surface contract on a real (temp) SQLite database
through the same startup path the service uses (engine + Alembic migrations):

ALERTS
1. list returns persisted alerts
2. detail returns the expected alert
3. unknown alert → structured 404
4. pagination
5. filtering
6. sensitive fields excluded

INCIDENTS
7. list returns persisted incidents
8. detail returns the expected incident
9. unknown incident → structured 404
10. status filter
11. severity filter
12. pagination

TIMELINE
13. returns events
14. incident.created appears
15. status transitions appear in chronological order
16. feedback-related event appears when linked
17. deterministic for equal timestamps
18. read-only (GET never mutates)

REGRESSION / SECURITY
20. GET endpoints do not mutate state
21. no secrets / raw credentials / full_log in responses
auth: shared N8N token (ingest key is rejected)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage.db.session import session_scope
from soc_triage.models.repositories import AuditRepository, IncidentRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
INGEST_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
TOKEN_HEADERS = {"X-N8N-Token": TEST_CALLBACK_TOKEN}

SECRET = "SuperSecret123"
CREDENTIAL_URL = f"https://analyst:{SECRET}@example.com/login"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _ingest(client: TestClient, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=INGEST_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _ingest_high(
    client: TestClient, *, agent_id: str = "003", event_id: str | None = None
) -> dict[str, Any]:
    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    payload = dict(payload)
    payload["agent"] = {**payload["agent"], "id": agent_id, "name": f"host-{agent_id}"}
    if event_id is not None:
        payload["id"] = event_id
    return _ingest(client, payload)


def _ingest_low(client: TestClient) -> dict[str, Any]:
    return _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))


def _get(client: TestClient, path: str, **params: Any) -> Any:
    return client.get(path, params=params or None, headers=TOKEN_HEADERS)


def _patch_status(client: TestClient, incident_id: str, target: str) -> Any:
    return client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": target, "actor": "analyst@example.com"},
        headers=TOKEN_HEADERS,
    )


def _feedback(client: TestClient, alert_id: str, verdict: str) -> Any:
    return client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": verdict, "actor": "analyst@example.com"},
        headers=TOKEN_HEADERS,
    )


def _counts(client: TestClient) -> dict[str, int]:
    with client.app.state.db_engine.connect() as conn:
        return {
            "alerts": int(conn.execute(text("SELECT COUNT(*) FROM alerts")).scalar_one()),
            "incidents": int(conn.execute(text("SELECT COUNT(*) FROM incidents")).scalar_one()),
            "audit": int(conn.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one()),
            "feedback": int(
                conn.execute(text("SELECT COUNT(*) FROM analyst_feedback")).scalar_one()
            ),
        }


def _incident_row(client: TestClient, incident_id: str) -> tuple[str, str | None, str | None]:
    with client.app.state.db_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT status, acknowledged_at, resolved_at FROM incidents WHERE incident_id = :iid"
            ),
            {"iid": incident_id},
        ).one()
        return str(row[0]), row[1], row[2]


class FakeClock:
    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, *, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_read_endpoints_require_n8n_token(client: TestClient) -> None:
    body = _ingest_high(client)
    paths = [
        "/api/v1/alerts",
        f"/api/v1/alerts/{body['alert_id']}",
        "/api/v1/incidents",
        f"/api/v1/incidents/{body['incident_id']}",
        f"/api/v1/incidents/{body['incident_id']}/timeline",
    ]
    for path in paths:
        missing = client.get(path)
        assert missing.status_code == 401, path
        assert missing.json()["error"]["code"] == "unauthorized"
        ingest_key = client.get(path, headers=INGEST_HEADERS)
        assert ingest_key.status_code == 401, path


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def test_alert_list_returns_persisted_alerts(client: TestClient) -> None:
    low = _ingest_low(client)
    high = _ingest_high(client)

    response = _get(client, "/api/v1/alerts")
    assert response.status_code == 200, response.text
    body = response.json()
    assert "items" in body and "pagination" in body
    ids = {item["alert_id"] for item in body["items"]}
    assert low["alert_id"] in ids
    assert high["alert_id"] in ids
    assert body["pagination"]["total"] == 2
    assert body["pagination"]["limit"] == 50
    assert body["pagination"]["offset"] == 0
    assert body["pagination"]["has_more"] is False
    # Newest first (high ingested after low).
    assert body["items"][0]["alert_id"] == high["alert_id"]
    high_row = next(item for item in body["items"] if item["alert_id"] == high["alert_id"])
    assert high_row["incident_id"] == high["incident_id"]
    assert high_row["rule"]["id"] == "87105"
    assert high_row["agent"]["id"] == "003"
    assert high_row["risk"]["tier"] == "high"
    assert high_row["decision"]["action"] == "open_incident"


def test_alert_detail_returns_expected_alert(client: TestClient) -> None:
    ingested = _ingest_high(client)
    response = _get(client, f"/api/v1/alerts/{ingested['alert_id']}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["alert_id"] == ingested["alert_id"]
    assert body["incident_id"] == ingested["incident_id"]
    assert body["rule"]["id"] == "87105"
    assert body["agent"]["name"]
    assert body["risk"]["score"] == ingested["risk"]["score"]
    assert body["risk"]["factors"]
    assert body["decision"]["action"] == "open_incident"
    assert body["dedupe"]["group_key"] == "wazuh:87105:003"
    assert isinstance(body["iocs"], list)
    assert "source_event" in body
    assert "full_log" not in body["source_event"]


def test_unknown_alert_returns_structured_404(client: TestClient) -> None:
    missing = uuid4()
    response = _get(client, f"/api/v1/alerts/{missing}")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "not_found"
    assert str(missing) in data["error"]["message"]


def test_alert_list_pagination(client: TestClient) -> None:
    ids = []
    for index, agent_id in enumerate(("003", "013", "023")):
        body = _ingest_high(client, agent_id=agent_id, event_id=f"1770000000.{200000 + index}")
        ids.append(body["alert_id"])

    first = _get(client, "/api/v1/alerts", limit=1, offset=0)
    second = _get(client, "/api/v1/alerts", limit=1, offset=1)
    third = _get(client, "/api/v1/alerts", limit=1, offset=2)
    overflow = _get(client, "/api/v1/alerts", limit=1, offset=3)
    assert first.status_code == 200
    assert first.json()["pagination"] == {"limit": 1, "offset": 0, "total": 3, "has_more": True}
    assert second.json()["pagination"]["has_more"] is True
    assert third.json()["pagination"]["has_more"] is False
    assert overflow.json()["items"] == []
    page_ids = [
        first.json()["items"][0]["alert_id"],
        second.json()["items"][0]["alert_id"],
        third.json()["items"][0]["alert_id"],
    ]
    assert len(set(page_ids)) == 3
    assert set(page_ids) == set(ids)
    # Bound: oversize limit is a validation error (not an unbounded scan).
    assert _get(client, "/api/v1/alerts", limit=201).status_code == 422


def test_alert_list_filtering(client: TestClient) -> None:
    low = _ingest_low(client)
    high = _ingest_high(client)
    # Absorb an exact duplicate so duplicate=true has a row.
    _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))

    by_tier = _get(client, "/api/v1/alerts", tier="high")
    assert {item["alert_id"] for item in by_tier.json()["items"]} == {high["alert_id"]}

    by_sev = _get(client, "/api/v1/alerts", severity="SEV2")
    assert {item["alert_id"] for item in by_sev.json()["items"]} == {high["alert_id"]}

    by_rule = _get(client, "/api/v1/alerts", rule_id="5710")
    assert {item["alert_id"] for item in by_rule.json()["items"]} == {low["alert_id"]}

    by_agent = _get(client, "/api/v1/alerts", agent_id="003")
    assert {item["alert_id"] for item in by_agent.json()["items"]} == {high["alert_id"]}

    by_source = _get(client, "/api/v1/alerts", source="wazuh")
    assert by_source.json()["pagination"]["total"] == 2

    by_incident = _get(client, "/api/v1/alerts", incident_id=high["incident_id"])
    assert {item["alert_id"] for item in by_incident.json()["items"]} == {high["alert_id"]}

    by_group = _get(client, "/api/v1/alerts", dedupe_group_key="wazuh:87105:003")
    assert {item["alert_id"] for item in by_group.json()["items"]} == {high["alert_id"]}

    duplicated = _get(client, "/api/v1/alerts", duplicate=True)
    assert {item["alert_id"] for item in duplicated.json()["items"]} == {high["alert_id"]}

    not_duplicated = _get(client, "/api/v1/alerts", duplicate=False)
    assert {item["alert_id"] for item in not_duplicated.json()["items"]} == {low["alert_id"]}


def test_alert_responses_exclude_sensitive_fields(client: TestClient) -> None:
    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    assert payload.get("full_log")
    ingested = _ingest(client, payload)

    listed = _get(client, "/api/v1/alerts")
    detail = _get(client, f"/api/v1/alerts/{ingested['alert_id']}")
    listed_text = json.dumps(listed.json())
    detail_text = json.dumps(detail.json())
    assert "full_log" not in listed_text
    assert "full_log" not in detail_text
    assert TEST_INGEST_KEY not in listed_text
    assert TEST_CALLBACK_TOKEN not in listed_text
    assert TEST_INGEST_KEY not in detail_text
    assert TEST_CALLBACK_TOKEN not in detail_text
    # The raw log line from the sample must not be echoed.
    if payload["full_log"]:
        assert payload["full_log"] not in detail_text


def test_alert_detail_strips_url_credentials(client: TestClient) -> None:
    payload = {
        "id": "1770000000.910099",
        "rule": {
            "level": 12,
            "description": "credential URL",
            "id": "99997",
            "groups": ["malware"],
        },
        "agent": {"id": "010", "name": "host-010"},
        "data": {"url": CREDENTIAL_URL},
    }
    ingested = _ingest(client, payload)
    detail = _get(client, f"/api/v1/alerts/{ingested['alert_id']}")
    body = json.dumps(detail.json())
    assert SECRET not in body
    assert "analyst:" not in body


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


def test_incident_list_returns_persisted_incidents(client: TestClient) -> None:
    first = _ingest_high(client, agent_id="003")
    second = _ingest_high(client, agent_id="013", event_id="1770000000.300001")
    _ingest_low(client)  # no incident

    response = _get(client, "/api/v1/incidents")
    assert response.status_code == 200, response.text
    body = response.json()
    ids = {item["incident_id"] for item in body["items"]}
    assert first["incident_id"] in ids
    assert second["incident_id"] in ids
    assert body["pagination"]["total"] == 2
    row = next(item for item in body["items"] if item["incident_id"] == first["incident_id"])
    assert row["status"] == "open"
    assert row["severity"] == "SEV2"
    assert row["primary_alert_id"] == first["alert_id"]
    assert row["dedupe_group_key"] == "wazuh:87105:003"
    assert row["acknowledged_at"] is None
    assert row["resolved_at"] is None


def test_incident_detail_returns_expected_incident(client: TestClient) -> None:
    ingested = _ingest_high(client)
    # Recurring alert attaches to the same incident.
    repeated = dict(_load_sample("04_wazuh_malware_hash_virustotal.json"), id="1770000000.100099")
    attached = _ingest(client, repeated)
    assert attached["incident_id"] == ingested["incident_id"]

    response = _get(client, f"/api/v1/incidents/{ingested['incident_id']}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["incident_id"] == ingested["incident_id"]
    assert body["status"] == "open"
    assert body["severity"] == "SEV2"
    assert body["primary_alert_id"] == ingested["alert_id"]
    assert body["linked_alert_count"] == 2
    assert body["primary_alert"]["alert_id"] == ingested["alert_id"]
    assert body["primary_alert"]["is_primary"] is True
    assert {item["alert_id"] for item in body["linked_alerts"]} == {
        ingested["alert_id"],
        attached["alert_id"],
    }
    # No raw payloads.
    assert "full_log" not in json.dumps(body)
    assert "normalized_payload" not in json.dumps(body)


def test_unknown_incident_returns_structured_404(client: TestClient) -> None:
    response = _get(client, "/api/v1/incidents/INC-2099-01-01-0001")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "not_found"
    assert "INC-2099-01-01-0001" in data["error"]["message"]


def test_incident_status_filter(client: TestClient) -> None:
    open_inc = _ingest_high(client, agent_id="003")
    investigating = _ingest_high(client, agent_id="013", event_id="1770000000.300002")
    assert _patch_status(client, investigating["incident_id"], "investigating").status_code == 200

    opened = _get(client, "/api/v1/incidents", status="open")
    assert {item["incident_id"] for item in opened.json()["items"]} == {open_inc["incident_id"]}
    inv = _get(client, "/api/v1/incidents", status="investigating")
    assert {item["incident_id"] for item in inv.json()["items"]} == {investigating["incident_id"]}


def test_incident_severity_filter(client: TestClient) -> None:
    high = _ingest_high(client)
    critical_payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    critical_payload = dict(critical_payload)
    critical_payload["agent"] = {
        "id": "033",
        "name": "hr-wks-33",
        "labels": {"asset_tier": "critical"},
    }
    critical_payload["id"] = "1770000000.300003"
    critical = _ingest(client, critical_payload)
    assert critical["decision"]["severity"] == "SEV1"

    sev1 = _get(client, "/api/v1/incidents", severity="SEV1")
    assert {item["incident_id"] for item in sev1.json()["items"]} == {critical["incident_id"]}
    sev2 = _get(client, "/api/v1/incidents", severity="SEV2")
    assert {item["incident_id"] for item in sev2.json()["items"]} == {high["incident_id"]}


def test_incident_list_pagination(client: TestClient) -> None:
    ids = []
    for index, agent_id in enumerate(("003", "013", "023")):
        body = _ingest_high(client, agent_id=agent_id, event_id=f"1770000000.{400000 + index}")
        ids.append(body["incident_id"])

    first = _get(client, "/api/v1/incidents", limit=1, offset=0)
    second = _get(client, "/api/v1/incidents", limit=1, offset=1)
    third = _get(client, "/api/v1/incidents", limit=1, offset=2)
    assert first.json()["pagination"]["total"] == 3
    assert first.json()["pagination"]["has_more"] is True
    page_ids = [
        first.json()["items"][0]["incident_id"],
        second.json()["items"][0]["incident_id"],
        third.json()["items"][0]["incident_id"],
    ]
    assert len(set(page_ids)) == 3
    assert set(page_ids) == set(ids)


def test_incident_created_from_to_filter(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(datetime(2026, 8, 29, 10, 0, 0, tzinfo=UTC))
    monkeypatch.setattr("soc_triage.api.alerts._utc_now", clock.now)

    first = _ingest_high(client, agent_id="003")
    clock.advance(seconds=3600)
    second = _ingest_high(client, agent_id="013", event_id="1770000000.500001")

    early = _get(
        client,
        "/api/v1/incidents",
        created_from="2026-08-29T10:00:00+00:00",
        created_to="2026-08-29T10:30:00+00:00",
    )
    assert {item["incident_id"] for item in early.json()["items"]} == {first["incident_id"]}
    later = _get(client, "/api/v1/incidents", created_from="2026-08-29T10:30:00+00:00")
    assert {item["incident_id"] for item in later.json()["items"]} == {second["incident_id"]}


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def test_incident_timeline_events_and_created(client: TestClient) -> None:
    ingested = _ingest_high(client)
    response = _get(client, f"/api/v1/incidents/{ingested['incident_id']}/timeline")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["incident_id"] == ingested["incident_id"]
    actions = [event["action"] for event in body["events"]]
    assert "incident.created" in actions
    assert "alert.created" in actions
    assert "alert.scored" in actions
    assert "alert.decided" in actions
    created = next(event for event in body["events"] if event["action"] == "incident.created")
    assert created["entity_type"] == "incident"
    assert created["entity_id"] == ingested["incident_id"]
    assert created["after"]["status"] == "open"


def test_timeline_status_transitions_are_chronological(client: TestClient) -> None:
    ingested = _ingest_high(client)
    incident_id = ingested["incident_id"]
    assert _patch_status(client, incident_id, "investigating").status_code == 200
    assert _patch_status(client, incident_id, "acknowledged").status_code == 200

    body = _get(client, f"/api/v1/incidents/{incident_id}/timeline").json()
    events = body["events"]
    timestamps = [event["timestamp"] for event in events]
    assert timestamps == sorted(timestamps)

    updates = [event for event in events if event["action"] == "incident.status_updated"]
    assert [event["after"]["status"] for event in updates] == ["investigating", "acknowledged"]
    assert [event["metadata"]["after_status"] for event in updates] == [
        "investigating",
        "acknowledged",
    ]
    created_index = next(
        i for i, event in enumerate(events) if event["action"] == "incident.created"
    )
    first_update = next(
        i for i, event in enumerate(events) if event["action"] == "incident.status_updated"
    )
    assert created_index < first_update


def test_timeline_includes_feedback_event(client: TestClient) -> None:
    ingested = _ingest_high(client)
    assert _feedback(client, ingested["alert_id"], "acknowledged").status_code == 200

    body = _get(client, f"/api/v1/incidents/{ingested['incident_id']}/timeline").json()
    actions = [event["action"] for event in body["events"]]
    assert "feedback.received" in actions
    feedback = next(event for event in body["events"] if event["action"] == "feedback.received")
    assert feedback["entity_id"] == ingested["alert_id"]
    assert feedback["after"]["verdict"] == "acknowledged"
    assert feedback["metadata"]["verdict"] == "acknowledged"


def test_timeline_is_deterministic_for_equal_timestamps(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ingest + status change share one frozen clock tick; order stays stable."""
    clock = FakeClock(datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC))
    monkeypatch.setattr("soc_triage.api.alerts._utc_now", clock.now)
    monkeypatch.setattr("soc_triage.api.incidents._utc_now", clock.now)

    ingested = _ingest_high(client)
    incident_id = ingested["incident_id"]
    assert _patch_status(client, incident_id, "investigating").status_code == 200

    first = _get(client, f"/api/v1/incidents/{incident_id}/timeline").json()
    second = _get(client, f"/api/v1/incidents/{incident_id}/timeline").json()
    assert first == second
    # Every event in this test shares the frozen timestamp; the tie-breaker
    # must still produce a total order that starts with alert.created and
    # places incident.created before the later status_updated (higher audit id).
    stamps = {event["timestamp"] for event in first["events"]}
    assert len(stamps) == 1
    actions = [event["action"] for event in first["events"]]
    assert actions.index("alert.created") < actions.index("alert.scored")
    assert actions.index("alert.scored") < actions.index("alert.decided")
    assert actions.index("incident.created") < actions.index("incident.status_updated")


def test_timeline_unknown_incident_is_404(client: TestClient) -> None:
    response = _get(client, "/api/v1/incidents/INC-2099-01-01-0001/timeline")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_timeline_and_reads_are_read_only(client: TestClient) -> None:
    ingested = _ingest_high(client)
    incident_id = ingested["incident_id"]
    alert_id = ingested["alert_id"]
    assert _patch_status(client, incident_id, "investigating").status_code == 200
    before_counts = _counts(client)
    before_row = _incident_row(client, incident_id)

    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        before_incident = IncidentRepository(session).get(incident_id)
        before_audit = [
            (entry.id, entry.action, entry.entity_id) for entry in AuditRepository(session).all()
        ]

    for path in (
        "/api/v1/alerts",
        f"/api/v1/alerts/{alert_id}",
        "/api/v1/incidents",
        f"/api/v1/incidents/{incident_id}",
        f"/api/v1/incidents/{incident_id}/timeline",
    ):
        assert _get(client, path).status_code == 200

    assert _counts(client) == before_counts
    assert _incident_row(client, incident_id) == before_row
    with session_scope(factory) as session:
        after_incident = IncidentRepository(session).get(incident_id)
        after_audit = [
            (entry.id, entry.action, entry.entity_id) for entry in AuditRepository(session).all()
        ]
    assert after_incident == before_incident
    assert after_audit == before_audit


def test_read_responses_never_include_secrets(client: TestClient) -> None:
    ingested = _ingest_high(client)
    paths = [
        "/api/v1/alerts",
        f"/api/v1/alerts/{ingested['alert_id']}",
        "/api/v1/incidents",
        f"/api/v1/incidents/{ingested['incident_id']}",
        f"/api/v1/incidents/{ingested['incident_id']}/timeline",
    ]
    for path in paths:
        text_body = json.dumps(_get(client, path).json()).lower()
        assert "full_log" not in text_body
        assert TEST_INGEST_KEY.lower() not in text_body
        assert TEST_CALLBACK_TOKEN.lower() not in text_body
        assert "authorization" not in text_body or "bearer" not in text_body
