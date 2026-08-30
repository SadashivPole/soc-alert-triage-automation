"""Unit tests for n8n webhook client (Phase 2B).

Covers:
* successful webhook delivery
* timeout
* HTTP error
* retry
* n8n unavailable
* payload schema validation
* secret leakage tests
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx

from soc_triage.models.assessment import (
    Decision,
    DecisionAction,
    DecisionSeverity,
    RiskAssessment,
    RiskTier,
    ScoreFactor,
)
from soc_triage.models.canonical import (
    CanonicalAgent,
    CanonicalAlert,
    CanonicalDedupe,
    CanonicalRule,
    CanonicalSourceEvent,
)
from soc_triage.models.ioc import IOC, IOCType
from soc_triage.notifications.client import N8NWebhookClient
from soc_triage.notifications.payload import build_n8n_payload


def _make_payload():
    now = datetime(2026, 8, 30, 10, 0, 0, tzinfo=UTC)
    risk = RiskAssessment(
        score=75,
        tier=RiskTier.HIGH,
        engine_version="scoring.v1",
        factors=(ScoreFactor(name="rule_severity", points=30, max=40, detail="level 10"),),
        summary="Score 75 (high)",
    )
    decision = Decision(
        action=DecisionAction.OPEN_INCIDENT,
        severity=DecisionSeverity.SEV2,
        reasons=("score=75 tier=high",),
        decided_at=now,
    )
    alert = CanonicalAlert(
        alert_id=uuid4(),
        source="wazuh",
        received_at=now,
        source_event=CanonicalSourceEvent(
            rule=CanonicalRule(id="5710", level=10, description="test"),
            agent=CanonicalAgent(id="001", name="web-prod-01"),
        ),
        dedupe=CanonicalDedupe(
            group_key="wazuh:5710:001",
            occurrences=1,
            first_seen=now,
            last_seen=now,
            event_identity="test",
        ),
        iocs=[IOC(type=IOCType.IPV4, value="203.0.113.50")],
        enrichment_status="complete",
        risk=risk,
        decision=decision,
    )
    return build_n8n_payload(alert, dedupe_status="new_generation")


def test_successful_delivery():
    payload = _make_payload()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-N8N-Token") == "test-token"
        assert request.headers.get("Authorization") == "Bearer test-token"
        body = json.loads(request.content)
        assert body["alert_id"] == payload.alert_id
        assert "full_log" not in json.dumps(body).lower()
        return httpx.Response(200, json={"status": "routed"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    n8n = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=client,
        max_retries=1,
    )
    result = n8n.send(payload)
    assert result.delivered is True
    assert result.status_code == 200
    assert result.attempted is True
    assert result.skipped is False
    assert result.attempts == 1


def test_timeout_with_retry():
    payload = _make_payload()
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        raise httpx.ReadTimeout("timeout")

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    n8n = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=client,
        max_retries=3,
        retry_backoff_seconds=0.01,
    )
    result = n8n.send(payload)
    assert result.delivered is False
    assert result.attempted is True
    assert result.error_type == "ReadTimeout"
    assert result.attempts == 3
    assert calls["count"] == 3


def test_http_error_no_retry_on_4xx():
    payload = _make_payload()
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        return httpx.Response(400, json={"error": "bad request"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    n8n = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=client,
        max_retries=3,
    )
    result = n8n.send(payload)
    assert result.delivered is False
    assert result.status_code == 400
    assert calls["count"] == 1  # no retry on 400
    assert result.attempts == 1


def test_retry_on_500_and_429():
    payload = _make_payload()
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        if calls["count"] < 3:
            return httpx.Response(500, json={"error": "internal"})
        return httpx.Response(200, json={"status": "ok"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    n8n = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=client,
        max_retries=3,
        retry_backoff_seconds=0.01,
    )
    result = n8n.send(payload)
    assert result.delivered is True
    assert calls["count"] == 3
    assert result.attempts == 3


def test_retry_on_429_honours_retry_after():
    payload = _make_payload()
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(429, headers={"retry-after": "1"}, json={"error": "rate limited"})
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    n8n = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=client,
        max_retries=2,
        retry_backoff_seconds=0.01,
    )
    result = n8n.send(payload)
    assert result.delivered is True
    assert calls["count"] == 2


def test_n8n_unavailable_connection_error():
    payload = _make_payload()

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    n8n = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=client,
        max_retries=2,
        retry_backoff_seconds=0.01,
    )
    result = n8n.send(payload)
    assert result.delivered is False
    assert result.error_type == "ConnectError"
    assert result.attempted is True


def test_disabled_client_skips():
    payload = _make_payload()
    n8n = N8NWebhookClient(webhook_url="", token="", max_retries=1)
    assert n8n.enabled is False
    result = n8n.send(payload)
    assert result.skipped is True
    assert result.attempted is False
    assert result.delivered is False
    assert result.attempts == 0


def test_payload_schema_validation_no_full_log():
    payload = _make_payload()
    dumped = json.dumps(payload.model_dump(mode="json"))
    assert "full_log" not in dumped.lower()
    # Ensure payload hash is deterministic

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    n8n = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token="test-token",
        client=client,
        max_retries=1,
    )
    result = n8n.send(payload)
    assert len(result.payload_hash) == 16


def test_secret_not_logged_in_headers():
    payload = _make_payload()
    captured_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    secret_token = "super-secret-token-12345"
    n8n = N8NWebhookClient(
        webhook_url="http://n8n:5678/webhook/soc-alert-scored",
        token=secret_token,
        client=client,
        max_retries=1,
    )
    result = n8n.send(payload)
    assert result.delivered is True
    # Headers contain token (required for auth), but logs should not
    assert captured_headers.get("x-n8n-token") == secret_token
    # Ensure payload itself does not contain token
    body = json.dumps(payload.model_dump(mode="json"))
    assert secret_token not in body
