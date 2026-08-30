"""Integration tests for health and readiness endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from soc_triage import __version__


def test_health_returns_ok(client: TestClient, settings) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "triage-api"
    assert body["instance"] == settings.soc_instance_name
    assert body["version"] == __version__
    assert body["timestamp"]


def test_ready_returns_ready(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["config"] == "ok"


def test_unknown_route_returns_structured_404(client: TestClient) -> None:
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "not_found"
    assert "error" in body
