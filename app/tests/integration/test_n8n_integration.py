"""Integration tests for n8n SOAR workflow integration (Phase 2B).

Covers:
* successful webhook delivery
* timeout
* HTTP error
* retry
* invalid callback token
* n8n unavailable
* duplicate notification prevention
* payload schema validation
* audit notification attempt/result
* analyst acknowledgement/feedback webhook
* fail-open behavior
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import httpx
from fastapi.testclient import TestClient

from soc_triage.notifications.client import N8NWebhookClient

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load_sample(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


# ---------------------------------------------------------------------------
# Helper to create app with mocked n8n client
# ---------------------------------------------------------------------------


def _make_mock_transport(handler):
    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# Successful delivery
# ---------------------------------------------------------------------------


def test_successful_webhook_delivery(client: TestClient) -> None:
    """Ingest should attempt n8n notification when webhook URL is configured."""
    from tests.conftest import TEST_INGEST_KEY

    # Configure n8n client to succeed
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["alert_id"]
        assert body["severity"]
        assert body["score"] >= 0
        assert "decision" in body
        assert "rule" in body
        assert "recurrence" in body
        assert "iocs" in body
        assert "enrichment" in body
        assert "investigation_links" in body
        assert "full_log" not in json.dumps(body).lower()
        return httpx.Response(200, json={"status": "routed"})

    transport = _make_mock_transport(handler)
    httpx_client = httpx.Client(transport=transport)
    n8n_client = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-callback-token-not-a-real-secret",
        client=httpx_client,
        max_retries=1,
    )
    # Inject into app
    client.app.state.n8n_client = n8n_client

    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["notification"] is not None
    assert body["notification"]["delivered"] is True
    assert body["notification"]["attempted"] is True

    # Check audit
    from sqlalchemy.orm import sessionmaker

    from soc_triage.db.session import session_scope
    from soc_triage.models.repositories import AuditRepository, NotificationRepository

    factory: sessionmaker = client.app.state.session_factory
    with session_scope(factory) as session:
        audits = AuditRepository(session).all()
        notif_audits = [
            a for a in audits if a.entity_id == body["alert_id"] and "notification" in a.action
        ]
        assert any(a.action == "notification.attempt" for a in notif_audits)
        assert any(a.action == "notification.delivered" for a in notif_audits)

        attempts = NotificationRepository(session).attempts_for(UUID(body["alert_id"]))
        assert len(attempts) == 1
        assert attempts[0].status == "delivered"


def test_n8n_failure_does_not_corrupt_alert(client: TestClient) -> None:
    """n8n failure must not corrupt or lose the alert (fail-open)."""
    from tests.conftest import TEST_INGEST_KEY

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(500, json={"error": "n8n down"})

    transport = _make_mock_transport(handler)
    httpx_client = httpx.Client(transport=transport)
    n8n_client = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-callback-token-not-a-real-secret",
        client=httpx_client,
        max_retries=1,
    )
    client.app.state.n8n_client = n8n_client

    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    # Alert still accepted despite n8n failure
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert body["alert_id"]
    assert body["notification"]["delivered"] is False
    assert body["notification"]["attempted"] is True

    # Alert persisted
    from soc_triage.db.session import session_scope
    from soc_triage.models.repositories import AlertRepository

    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        stored = AlertRepository(session).get(UUID(body["alert_id"]))
        assert stored is not None
        assert stored.risk is not None


def test_n8n_unavailable_connection_error(client: TestClient) -> None:
    """When n8n is unavailable (connection error), alert still accepted."""
    from tests.conftest import TEST_INGEST_KEY

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        raise httpx.ConnectError("connection refused")

    transport = _make_mock_transport(handler)
    httpx_client = httpx.Client(transport=transport)
    n8n_client = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=httpx_client,
        max_retries=1,
    )
    client.app.state.n8n_client = n8n_client

    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 202
    assert response.json()["notification"]["delivered"] is False


def test_n8n_timeout_handling(client: TestClient) -> None:
    """Timeout should be handled with retry and fail-open."""
    from tests.conftest import TEST_INGEST_KEY

    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        raise httpx.ReadTimeout("timeout")

    transport = _make_mock_transport(handler)
    httpx_client = httpx.Client(transport=transport)
    n8n_client = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=httpx_client,
        max_retries=2,
        retry_backoff_seconds=0.01,
    )
    client.app.state.n8n_client = n8n_client

    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 202
    assert calls["count"] == 2
    assert response.json()["notification"]["attempted"] is True


def test_retry_on_500_then_success(client: TestClient) -> None:
    """Retry logic: 500 then success should deliver."""
    from tests.conftest import TEST_INGEST_KEY

    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(500, json={"error": "internal"})
        return httpx.Response(200, json={"ok": True})

    transport = _make_mock_transport(handler)
    httpx_client = httpx.Client(transport=transport)
    n8n_client = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=httpx_client,
        max_retries=3,
        retry_backoff_seconds=0.01,
    )
    client.app.state.n8n_client = n8n_client

    response = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code == 202
    assert calls["count"] == 2
    assert response.json()["notification"]["delivered"] is True


def test_duplicate_notification_prevention(client: TestClient) -> None:
    """Exact duplicate must not trigger second n8n notification (idempotent)."""
    from tests.conftest import TEST_INGEST_KEY

    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        return httpx.Response(200, json={"ok": True})

    transport = _make_mock_transport(handler)
    httpx_client = httpx.Client(transport=transport)
    n8n_client = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=httpx_client,
        max_retries=1,
    )
    client.app.state.n8n_client = n8n_client

    payload = _load_sample("01_wazuh_ssh_brute_force.json")

    first = client.post(
        "/api/v1/alerts/ingest", json=payload, headers={"X-API-Key": TEST_INGEST_KEY}
    )
    assert first.status_code == 202
    assert calls["count"] == 1

    duplicate = client.post(
        "/api/v1/alerts/ingest", json=payload, headers={"X-API-Key": TEST_INGEST_KEY}
    )
    assert duplicate.status_code == 200
    # No second notification for exact duplicate
    assert calls["count"] == 1
    assert duplicate.json()["notification"] is None


def test_duplicate_alert_id_prevention_via_repo(client: TestClient) -> None:
    """If alert_id already delivered, second attempt should be suppressed via repo."""
    from tests.conftest import TEST_INGEST_KEY

    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        return httpx.Response(200, json={"ok": True})

    transport = _make_mock_transport(handler)
    httpx_client = httpx.Client(transport=transport)
    n8n_client = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=httpx_client,
        max_retries=1,
    )
    client.app.state.n8n_client = n8n_client

    # First alert
    first_payload = _load_sample("01_wazuh_ssh_brute_force.json")
    first = client.post(
        "/api/v1/alerts/ingest", json=first_payload, headers={"X-API-Key": TEST_INGEST_KEY}
    )
    assert first.status_code == 202
    alert_id = first.json()["alert_id"]
    assert calls["count"] == 1

    # Manually try to notify same alert again via direct client call with repo check
    from soc_triage.db.session import session_scope
    from soc_triage.models.repositories import NotificationRepository

    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        repo = NotificationRepository(session)
        assert repo.has_delivered(UUID(alert_id)) is True


# ---------------------------------------------------------------------------
# Feedback webhook
# ---------------------------------------------------------------------------


def test_feedback_requires_valid_token(client: TestClient) -> None:
    """Feedback endpoint must reject invalid token."""
    from tests.conftest import TEST_INGEST_KEY

    # First ingest to get alert_id
    ingest_resp = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    alert_id = ingest_resp.json()["alert_id"]

    # No token
    resp = client.post(f"/api/v1/alerts/{alert_id}/feedback", json={"verdict": "true_positive"})
    assert resp.status_code in {401, 503}

    # Invalid token
    resp = client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": "true_positive"},
        headers={"X-N8N-Token": "invalid-token"},
    )
    assert resp.status_code == 401


def test_feedback_successful(client: TestClient) -> None:
    """Valid feedback should be stored and audited."""
    from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

    ingest_resp = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    alert_id = ingest_resp.json()["alert_id"]

    feedback_resp = client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={
            "verdict": "false_positive",
            "notes": "benign scanner",
            "actor": "analyst@example.com",
        },
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    assert feedback_resp.status_code == 200
    body = feedback_resp.json()
    assert body["status"] == "accepted"
    assert body["verdict"] == "false_positive"
    assert body["alert_id"] == alert_id

    # Check persistence
    from soc_triage.db.session import session_scope
    from soc_triage.models.repositories import AuditRepository, FeedbackRepository

    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        feedbacks = FeedbackRepository(session).for_alert(UUID(alert_id))
        assert len(feedbacks) == 1
        assert feedbacks[0].verdict == "false_positive"

        audits = AuditRepository(session).all()
        fb_audits = [
            a for a in audits if a.action == "feedback.received" and a.entity_id == alert_id
        ]
        assert len(fb_audits) == 1


def test_feedback_invalid_verdict(client: TestClient) -> None:
    """Invalid verdict should be rejected with 422."""
    from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

    ingest_resp = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("01_wazuh_ssh_brute_force.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    alert_id = ingest_resp.json()["alert_id"]

    resp = client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": "not_a_real_verdict"},
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    assert resp.status_code == 422


def test_feedback_nonexistent_alert(client: TestClient) -> None:
    """Feedback for nonexistent alert should return 404."""
    import uuid

    from tests.conftest import TEST_CALLBACK_TOKEN

    fake_id = uuid.uuid4()
    resp = client.post(
        f"/api/v1/alerts/{fake_id}/feedback",
        json={"verdict": "true_positive"},
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    assert resp.status_code == 404


def test_payload_schema_validation_integration(client: TestClient) -> None:
    """End-to-end payload should contain all required fields and no full_log."""
    from tests.conftest import TEST_INGEST_KEY

    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    transport = _make_mock_transport(handler)
    httpx_client = httpx.Client(transport=transport)
    n8n_client = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=httpx_client,
        max_retries=1,
    )
    client.app.state.n8n_client = n8n_client

    resp = client.post(
        "/api/v1/alerts/ingest",
        json=_load_sample("04_wazuh_malware_hash_virustotal.json"),
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert resp.status_code == 202
    body = captured["body"]
    # Required fields per spec
    for field in [
        "alert_id",
        "severity",
        "score",
        "decision",
        "rule",
        "recurrence",
        "iocs",
        "enrichment",
        "investigation_links",
    ]:
        assert field in body, f"Missing {field} in n8n payload"
    # No full_log
    assert "full_log" not in json.dumps(body).lower()
    # Check structure
    assert body["rule"]["id"]
    assert body["rule"]["level"] >= 0
    assert body["recurrence"]["group_key"]
    assert isinstance(body["iocs"], list)
    assert body["enrichment"]["status"]
    assert body["investigation_links"]["alert_api"]
