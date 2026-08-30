"""Integration tests for the POST /api/v1/alerts/ingest endpoint."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load_sample(name: str) -> dict:
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


# --- Authentication tests ---


def test_ingest_requires_api_key(client: TestClient) -> None:
    """Missing X-API-Key should return 401."""
    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
    )
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "unauthorized"


def test_ingest_rejects_invalid_api_key(client: TestClient) -> None:
    """Wrong X-API-Key should return 401."""
    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": "wrong-key-definitely-not-valid"},
    )
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "unauthorized"


def test_ingest_accepts_valid_api_key(client: TestClient) -> None:
    """Valid X-API-Key should allow the request through."""
    from tests.conftest import TEST_INGEST_KEY

    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 202


# --- Successful ingestion tests ---


def test_ingest_ssh_brute_force(client: TestClient) -> None:
    """Ingest the SSH brute-force sample alert successfully."""
    from tests.conftest import TEST_INGEST_KEY

    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert "alert_id" in body
    # Validate it's a valid UUID
    UUID(body["alert_id"])
    assert "received_at" in body
    assert "normalized" in body
    normalized = body["normalized"]
    assert normalized["source_event"]["rule"]["id"] == "5710"
    assert normalized["source_event"]["rule"]["level"] == 5
    assert normalized["source_event"]["agent"]["name"] == "web-prod-01"


def test_ingest_all_sample_alerts(client: TestClient) -> None:
    """All sample alerts should ingest successfully."""
    from tests.conftest import TEST_INGEST_KEY

    for path in sorted(FIXTURES_DIR.glob("*.json")):
        with path.open() as f:
            payload = json.load(f)
        response = client.post(
            "/api/v1/alerts/ingest",
            json=payload,
            headers={"X-API-Key": TEST_INGEST_KEY},
        )
        assert response.status_code == 202, f"Failed for {path.name}: {response.text}"
        body = response.json()
        assert body["status"] == "accepted"
        UUID(body["alert_id"])


def test_ingest_resolves_duplicate_deliveries_idempotently(client: TestClient) -> None:
    """Phase 1C contract: distinct events get distinct alert_ids, but an exact
    re-delivery of the same event resolves to the *original* alert_id.

    (Supersedes the Phase 1B assertion that identical deliveries produce
    unique ids — idempotency is the Phase 1C requirement, ARCHITECTURE.md §16.)
    """
    from tests.conftest import TEST_INGEST_KEY

    same = _load_sample("01_wazuh_ssh_brute_force.json")
    distinct = dict(same, id="1770000000.100099")

    first = client.post("/api/v1/alerts/ingest", json=same, headers={"X-API-Key": TEST_INGEST_KEY})
    redelivery = client.post(
        "/api/v1/alerts/ingest", json=same, headers={"X-API-Key": TEST_INGEST_KEY}
    )
    other = client.post(
        "/api/v1/alerts/ingest", json=distinct, headers={"X-API-Key": TEST_INGEST_KEY}
    )

    assert first.status_code == 202
    assert redelivery.status_code == 200  # duplicate: idempotent response
    assert other.status_code == 202
    ids = {first.json()["alert_id"], redelivery.json()["alert_id"], other.json()["alert_id"]}
    assert len(ids) == 2
    assert redelivery.json()["alert_id"] == first.json()["alert_id"]


# --- Validation error tests ---


def test_ingest_rejects_missing_rule(client: TestClient) -> None:
    """Payload without a rule block should return 422."""
    from tests.conftest import TEST_INGEST_KEY

    response = client.post(
        "/api/v1/alerts/ingest",
        json={"agent": {"id": "001", "name": "test"}},
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error"
    assert "details" in body["error"]


def test_ingest_rejects_missing_agent(client: TestClient) -> None:
    """Payload without an agent block should return 422."""
    from tests.conftest import TEST_INGEST_KEY

    response = client.post(
        "/api/v1/alerts/ingest",
        json={"rule": {"id": "5710", "level": 5, "description": "test"}},
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 422


def test_ingest_rejects_invalid_rule_level(client: TestClient) -> None:
    """Rule level outside 0-15 should return 422."""
    from tests.conftest import TEST_INGEST_KEY

    response = client.post(
        "/api/v1/alerts/ingest",
        json={
            "rule": {"id": "5710", "level": 99, "description": "bad level"},
            "agent": {"id": "001", "name": "test"},
        },
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 422


def test_ingest_rejects_invalid_json(client: TestClient) -> None:
    """Non-JSON body should return 422."""
    from tests.conftest import TEST_INGEST_KEY

    response = client.post(
        "/api/v1/alerts/ingest",
        content=b"not json at all",
        headers={
            "X-API-Key": TEST_INGEST_KEY,
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error"


def test_ingest_rejects_empty_body(client: TestClient) -> None:
    """Empty body should return 422."""
    from tests.conftest import TEST_INGEST_KEY

    response = client.post(
        "/api/v1/alerts/ingest",
        content=b"",
        headers={
            "X-API-Key": TEST_INGEST_KEY,
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 422


# --- Size protection tests ---


def test_ingest_rejects_oversized_body_content_length(client: TestClient) -> None:
    """Body exceeding 256 KiB (via Content-Length) should return 413."""
    from tests.conftest import TEST_INGEST_KEY

    oversized = "x" * (256 * 1024 + 1)
    response = client.post(
        "/api/v1/alerts/ingest",
        content=json.dumps({"rule": {"id": "1", "level": 1, "description": oversized}}),
        headers={
            "X-API-Key": TEST_INGEST_KEY,
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 413
    body = response.json()
    assert body["error"]["code"] == "payload_too_large"


def test_ingest_accepts_body_within_limit(client: TestClient) -> None:
    """Body within 256 KiB should be accepted."""
    from tests.conftest import TEST_INGEST_KEY

    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    response = client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 202


# --- Error response safety tests ---


def test_error_responses_do_not_leak_internals(client: TestClient) -> None:
    """Error responses should not contain stack traces or internal details."""
    from tests.conftest import TEST_INGEST_KEY

    # Invalid JSON
    response = client.post(
        "/api/v1/alerts/ingest",
        content=b"{{{invalid",
        headers={
            "X-API-Key": TEST_INGEST_KEY,
            "Content-Type": "application/json",
        },
    )
    body = response.json()
    assert "traceback" not in json.dumps(body).lower()
    assert "exception" not in json.dumps(body).lower()


def test_error_envelope_structure(client: TestClient) -> None:
    """All error responses should follow the standard envelope."""
    response = client.post("/api/v1/alerts/ingest", json={})
    body = response.json()
    assert "error" in body
    assert "code" in body["error"]
    assert "message" in body["error"]


def test_ingest_deduplication_first_delivery(client: TestClient) -> None:
    """First delivery: 202, new_generation, dedupe info embedded in the alert."""
    from tests.conftest import TEST_INGEST_KEY

    response = client.post(
        "/api/v1/alerts/ingest",
        headers={"X-API-Key": TEST_INGEST_KEY},
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert body["duplicate"] is False
    assert body["dedupe_status"] == "new_generation"
    assert body["dedupe"]["occurrences"] == 1
    assert body["dedupe"]["group_key"] == "wazuh:5710:001"
    assert body["dedupe"]["event_identity"].startswith("wazuh:")
    assert body["dedupe"]["generation"] == 1
    assert body["normalized"]["dedupe"]["occurrences"] == 1
    assert body["normalized"]["alert_id"] == body["alert_id"]


def test_ingest_exact_duplicate_is_idempotent(client: TestClient) -> None:
    """Exact re-delivery: 200 + duplicate=true + original alert preserved."""
    from tests.conftest import TEST_INGEST_KEY

    payload = _load_sample("01_wazuh_ssh_brute_force.json")

    first = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
    )
    duplicate = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
    )
    assert first.status_code == 202
    assert duplicate.status_code == 200

    body = duplicate.json()
    original = first.json()
    assert body["status"] == "duplicate"
    assert body["duplicate"] is True
    assert body["dedupe_status"] == "exact_duplicate"
    assert body["alert_id"] == original["alert_id"]
    # The preserved canonical alert is returned unchanged.
    assert body["normalized"] == original["normalized"]
    assert body["normalized"]["source_event"]["full_log"] == payload["full_log"]
    # Recurrence state untouched; the duplicate delivery is still counted.
    assert body["dedupe"]["occurrences"] == 1
    assert body["dedupe"]["duplicate_deliveries"] == 1
    assert body["dedupe"]["last_seen"] == original["dedupe"]["last_seen"]


def test_ingest_repeated_alert_increments_occurrences(client: TestClient) -> None:
    """Distinct event, same rule+agent, within the window: occurrences bump."""
    from tests.conftest import TEST_INGEST_KEY

    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    repeated = dict(payload, id="1770000000.100002")

    first = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
    )
    response = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=repeated
    )

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert body["dedupe_status"] == "repeated"
    assert body["dedupe"]["occurrences"] == 2
    assert body["normalized"]["dedupe"]["occurrences"] == 2
    # A recurrence is a new distinct event with its own alert id.
    assert body["alert_id"] != first.json()["alert_id"]


def test_ingest_alert_after_window_starts_new_generation(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A distinct event beyond the window resets the generation."""
    from tests.conftest import TEST_INGEST_KEY

    fake_clock = FakeClock()
    monkeypatch.setattr("soc_triage.api.alerts._utc_now", fake_clock.now)

    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    later = dict(payload, id="1770000000.100002")

    client.post("/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload)
    fake_clock.advance(seconds=901)  # default window is 900 s
    response = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=later
    )

    assert response.status_code == 202
    body = response.json()
    assert body["dedupe_status"] == "new_generation"
    assert body["dedupe"]["occurrences"] == 1
    assert body["dedupe"]["generation"] == 2


def test_ingest_exact_duplicate_within_configured_window(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exact duplicates stay idempotent across intervening distinct events."""
    from tests.conftest import TEST_INGEST_KEY

    fake_clock = FakeClock()
    monkeypatch.setattr("soc_triage.api.alerts._utc_now", fake_clock.now)

    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    other = dict(payload, id="1770000000.100003")

    original = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
    )
    fake_clock.advance(seconds=120)
    client.post("/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=other)
    fake_clock.advance(seconds=120)
    duplicate = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
    )

    assert duplicate.status_code == 200
    body = duplicate.json()
    assert body["dedupe_status"] == "exact_duplicate"
    assert body["alert_id"] == original.json()["alert_id"]
    assert body["dedupe"]["occurrences"] == 2  # two distinct events, not three
    assert body["dedupe"]["duplicate_deliveries"] == 1


def test_ingest_rejects_invalid_identity_inputs(client: TestClient) -> None:
    """Blank rule/agent ids cannot yield an identity: 422, never a guess."""
    from tests.conftest import TEST_INGEST_KEY

    for payload in (
        dict(_load_sample("01_wazuh_ssh_brute_force.json"), agent={"id": "", "name": "x"}),
        {
            **_load_sample("01_wazuh_ssh_brute_force.json"),
            "rule": {"id": "  ", "level": 5, "description": "blank rule id"},
        },
    ):
        response = client.post(
            "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
        )
        assert response.status_code == 422
        body = response.json()
        assert body["error"]["code"] == "validation_error"
        assert "identity" in body["error"]["message"]


def test_ingest_redelivery_flood_keeps_one_alert(client: TestClient) -> None:
    """Ten identical deliveries: one alert, nine counted duplicates."""
    from tests.conftest import TEST_INGEST_KEY

    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    statuses = []
    alert_ids = set()
    for _ in range(10):
        response = client.post(
            "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
        )
        statuses.append(response.status_code)
        alert_ids.add(response.json()["alert_id"])

    assert statuses == [202] + [200] * 9
    assert len(alert_ids) == 1
    final = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
    )
    dedupe = final.json()["dedupe"]
    assert dedupe["occurrences"] == 1
    assert dedupe["duplicate_deliveries"] == 10


def test_ingest_different_agents_and_rules_do_not_collapse(client: TestClient) -> None:
    """Same event id on other agents/rules forms its own groups."""
    from tests.conftest import TEST_INGEST_KEY

    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    other_agent = dict(payload, agent={"id": "002", "name": "web-prod-02"})
    other_rule = {
        **payload,
        "rule": {**payload["rule"], "id": "5402", "level": 7},
    }

    first = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=payload
    )
    agent_resp = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=other_agent
    )
    rule_resp = client.post(
        "/api/v1/alerts/ingest", headers={"X-API-Key": TEST_INGEST_KEY}, json=other_rule
    )

    assert agent_resp.json()["dedupe_status"] == "new_generation"
    assert rule_resp.json()["dedupe_status"] == "new_generation"
    ids = {first.json()["alert_id"], agent_resp.json()["alert_id"], rule_resp.json()["alert_id"]}
    assert len(ids) == 3
    assert agent_resp.json()["dedupe"]["group_key"] == "wazuh:5710:002"
    assert rule_resp.json()["dedupe"]["group_key"] == "wazuh:5402:001"


class FakeClock:
    """Deterministic clock for window tests (no real sleeping)."""

    def __init__(self) -> None:
        self._now = datetime.now(UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, *, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)
