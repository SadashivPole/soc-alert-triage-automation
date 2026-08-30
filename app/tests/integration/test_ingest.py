"""Integration tests for the POST /api/v1/alerts/ingest endpoint."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

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


def test_ingest_returns_unique_alert_ids(client: TestClient) -> None:
    """Each ingestion should produce a unique alert_id."""
    from tests.conftest import TEST_INGEST_KEY

    ids = set()
    for _ in range(3):
        response = client.post(
            "/api/v1/alerts/ingest",
            json=_load_sample("01_wazuh_ssh_brute_force.json"),
            headers={"X-API-Key": TEST_INGEST_KEY},
        )
        assert response.status_code == 202
        ids.add(response.json()["alert_id"])
    assert len(ids) == 3


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
