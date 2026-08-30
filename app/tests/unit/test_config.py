"""Tests for environment-driven settings loading and validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from soc_triage.core.config import Settings

_CONFIG_VARIABLES = (
    "SOC_ENV",
    "SOC_LOG_LEVEL",
    "SOC_INSTANCE_NAME",
    "TRIAGE_API_HOST",
    "TRIAGE_API_PORT",
    "TRIAGE_CORS_ORIGINS",
    "TRIAGE_DB_URL",
    "TRIAGE_INGEST_API_KEY",
    "N8N_CALLBACK_TOKEN",
    "N8N_WEBHOOK_URL",
    "N8N_WEBHOOK_TOKEN",
    "N8N_TIMEOUT_SECONDS",
    "N8N_MAX_RETRIES",
    "N8N_RETRY_BACKOFF_SECONDS",
)


def _clear_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in _CONFIG_VARIABLES:
        monkeypatch.delenv(variable, raising=False)


def test_default_development_config(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_environment(monkeypatch)
    settings = Settings()
    assert settings.soc_env == "development"
    assert settings.soc_log_level == "INFO"
    assert settings.soc_instance_name == "soc-lab"
    assert settings.triage_api_host == "0.0.0.0"
    assert settings.triage_api_port == 8000
    assert settings.triage_db_url == "sqlite:////data/soc_triage.db"


def test_environment_variables_override_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_environment(monkeypatch)
    monkeypatch.setenv("SOC_ENV", "test")
    monkeypatch.setenv("SOC_LOG_LEVEL", "debug")
    monkeypatch.setenv("SOC_INSTANCE_NAME", "soc-unit")
    monkeypatch.setenv("TRIAGE_API_PORT", "9123")
    monkeypatch.setenv("TRIAGE_INGEST_API_KEY", "unit-ingest-key")
    monkeypatch.setenv("N8N_CALLBACK_TOKEN", "unit-callback-token")

    settings = Settings()
    assert settings.soc_env == "test"
    assert settings.soc_log_level == "DEBUG"
    assert settings.soc_instance_name == "soc-unit"
    assert settings.triage_api_port == 9123


def test_cors_origins_parse_comma_separated_values() -> None:
    settings = Settings(
        soc_env="test",
        triage_cors_origins="http://one.local, https://two.local, ,https://three.local",
        triage_ingest_api_key="unit-ingest-key",
        n8n_callback_token="unit-callback-token",
    )
    assert settings.cors_origins == ["http://one.local", "https://two.local", "https://three.local"]


def test_rejects_invalid_log_level() -> None:
    with pytest.raises(ValidationError):
        Settings(soc_log_level="CHATTY")


def test_rejects_placeholder_secrets_in_test_environment() -> None:
    with pytest.raises(ValidationError):
        Settings(soc_env="test")


def test_rejects_placeholder_secrets_in_production_environment() -> None:
    with pytest.raises(ValidationError):
        Settings(soc_env="production")
