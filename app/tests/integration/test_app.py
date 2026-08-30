"""Tests for application factory setup and startup."""

from __future__ import annotations

from fastapi.testclient import TestClient

from soc_triage.core.config import Settings
from soc_triage.main import create_app


def test_application_factory_binds_settings(app, settings: Settings) -> None:
    assert app.state.settings is settings


def test_application_starts_and_serves_openapi(app) -> None:
    with TestClient(app) as client:
        response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "SOC Alert Triage API"


def test_create_app_without_injected_settings_uses_defaults() -> None:
    default_app = create_app()
    assert default_app.state.settings.soc_env == "development"
