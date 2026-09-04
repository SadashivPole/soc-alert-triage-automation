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
    "METRICS_ENABLED",
    "METRICS_SCRAPE_TOKEN",
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
    assert settings.metrics_enabled is True
    assert settings.metrics_scrape_token.get_secret_value() == ""


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


def test_postgresql_db_url_is_accepted_without_repr_or_log_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A credential-bearing PostgreSQL URL round-trips but stays diagnostic-safe."""
    _clear_environment(monkeypatch)
    pg_url = "postgresql+psycopg://soc_triage:pg-url-canary-7f3c@postgres:5432/soc_triage"
    monkeypatch.setenv("TRIAGE_DB_URL", pg_url)

    settings = Settings()

    assert settings.triage_db_url == pg_url
    # Settings objects are commonly passed as structured-log context. The DB
    # URL is excluded from both diagnostic representations so its password
    # cannot leak through a settings repr/str rendered in a log line.
    for rendered in (repr(settings), str(settings)):
        assert pg_url not in rendered
        assert "pg-url-canary-7f3c" not in rendered


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


def test_rejects_placeholder_secrets_in_test_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SOC_ENV=test + placeholder secrets must fail, independent of .env.

    Placeholders are passed as explicit init kwargs so a developer's local
    ``.env`` (loaded by SettingsConfigDict) cannot supply real secrets and
    mask the rejection.
    """
    _clear_environment(monkeypatch)
    with pytest.raises(ValidationError):
        Settings(
            soc_env="test",
            triage_ingest_api_key="change-me-generate-a-long-random-value",
            n8n_callback_token="change-me-generate-a-long-random-value",
        )


def test_rejects_placeholder_secrets_in_production_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SOC_ENV=production + placeholder secrets must fail, independent of .env."""
    _clear_environment(monkeypatch)
    with pytest.raises(ValidationError):
        Settings(
            soc_env="production",
            triage_ingest_api_key="change-me-generate-a-long-random-value",
            n8n_callback_token="change-me-generate-a-long-random-value",
        )


def test_explicit_placeholder_kwargs_override_env_file_and_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove ambient non-placeholder secrets cannot make rejection nondeterministic.

    Simulates a developer machine where process env (or .env-loaded values
    mirrored into the environment) carries real secrets: explicit init kwargs
    still supply the placeholders under test, so ValidationError is raised.
    """
    _clear_environment(monkeypatch)
    monkeypatch.setenv("TRIAGE_INGEST_API_KEY", "real-secret-from-developer-dotenv")
    monkeypatch.setenv("N8N_CALLBACK_TOKEN", "real-callback-from-developer-dotenv")

    with pytest.raises(ValidationError):
        Settings(
            soc_env="test",
            triage_ingest_api_key="change-me-generate-a-long-random-value",
            n8n_callback_token="change-me-generate-a-long-random-value",
        )

    with pytest.raises(ValidationError):
        Settings(
            soc_env="production",
            triage_ingest_api_key="change-me-generate-a-long-random-value",
            n8n_callback_token="change-me-generate-a-long-random-value",
        )
