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
    "TRIAGE_ENRICHMENT_CACHE_ENABLED",
    "TRIAGE_ENRICHMENT_CACHE_MAX_ENTRIES",
    "TRIAGE_ENRICHMENT_CACHE_HASH_TTL_SECONDS",
    "TRIAGE_ENRICHMENT_CACHE_IPV4_TTL_SECONDS",
    "TRIAGE_ENRICHMENT_CACHE_DEFAULT_TTL_SECONDS",
    "LATE_ENRICHMENT_SWEEP_ENABLED",
    "LATE_ENRICHMENT_SWEEP_INTERVAL_SECONDS",
    "LATE_ENRICHMENT_LOOKBACK_SECONDS",
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


# ---------------------------------------------------------------------------
# Phase 2.3 — enrichment response TTL cache configuration
# ---------------------------------------------------------------------------


def test_enrichment_cache_defaults_disabled_with_architecture_ttls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disabled by default; TTL defaults pin ARCHITECTURE.md §7.2 (6 h / 1 h)."""
    _clear_environment(monkeypatch)
    settings = Settings(
        soc_env="test",
        triage_ingest_api_key="test-ingest-key-not-a-real-secret",
        n8n_callback_token="test-callback-token-not-a-real-secret",
    )

    assert settings.triage_enrichment_cache_enabled is False
    assert settings.triage_enrichment_cache_max_entries == 4096
    assert settings.triage_enrichment_cache_hash_ttl_seconds == 6 * 3600
    assert settings.triage_enrichment_cache_ipv4_ttl_seconds == 3600
    assert settings.triage_enrichment_cache_default_ttl_seconds == 3600


def test_enrichment_cache_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_environment(monkeypatch)
    monkeypatch.setenv("TRIAGE_ENRICHMENT_CACHE_ENABLED", "1")
    monkeypatch.setenv("TRIAGE_ENRICHMENT_CACHE_MAX_ENTRIES", "128")
    monkeypatch.setenv("TRIAGE_ENRICHMENT_CACHE_HASH_TTL_SECONDS", "7200")
    monkeypatch.setenv("TRIAGE_ENRICHMENT_CACHE_IPV4_TTL_SECONDS", "1800")
    monkeypatch.setenv("TRIAGE_ENRICHMENT_CACHE_DEFAULT_TTL_SECONDS", "900")

    settings = Settings(
        soc_env="test",
        triage_ingest_api_key="test-ingest-key-not-a-real-secret",
        n8n_callback_token="test-callback-token-not-a-real-secret",
    )

    assert settings.triage_enrichment_cache_enabled is True
    assert settings.triage_enrichment_cache_max_entries == 128
    assert settings.triage_enrichment_cache_hash_ttl_seconds == 7200
    assert settings.triage_enrichment_cache_ipv4_ttl_seconds == 1800
    assert settings.triage_enrichment_cache_default_ttl_seconds == 900


@pytest.mark.parametrize(
    "kwargs",
    [
        {"triage_enrichment_cache_max_entries": 0},
        {"triage_enrichment_cache_hash_ttl_seconds": 0},
        {"triage_enrichment_cache_ipv4_ttl_seconds": -1},
        {"triage_enrichment_cache_default_ttl_seconds": 0},
    ],
)
def test_enrichment_cache_rejects_non_positive_bounds(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict
) -> None:
    _clear_environment(monkeypatch)
    with pytest.raises(ValidationError):
        Settings(
            soc_env="test",
            triage_ingest_api_key="test-ingest-key-not-a-real-secret",
            n8n_callback_token="test-callback-token-not-a-real-secret",
            **kwargs,
        )


def test_late_enrichment_sweep_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_environment(monkeypatch)
    settings = Settings(
        soc_env="test",
        triage_ingest_api_key="test-ingest-key-not-a-real-secret",
        n8n_callback_token="test-callback-token-not-a-real-secret",
    )

    assert settings.late_enrichment_sweep_enabled is False
    assert settings.late_enrichment_sweep_interval_seconds == 300
    assert settings.late_enrichment_lookback_seconds == 604800


def test_late_enrichment_sweep_environment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_environment(monkeypatch)
    monkeypatch.setenv("LATE_ENRICHMENT_SWEEP_ENABLED", "1")
    monkeypatch.setenv("LATE_ENRICHMENT_SWEEP_INTERVAL_SECONDS", "60")
    monkeypatch.setenv("LATE_ENRICHMENT_LOOKBACK_SECONDS", "86400")

    settings = Settings(
        soc_env="test",
        triage_ingest_api_key="test-ingest-key-not-a-real-secret",
        n8n_callback_token="test-callback-token-not-a-real-secret",
    )

    assert settings.late_enrichment_sweep_enabled is True
    assert settings.late_enrichment_sweep_interval_seconds == 60
    assert settings.late_enrichment_lookback_seconds == 86400


@pytest.mark.parametrize(
    "kwargs",
    [
        {"late_enrichment_sweep_interval_seconds": 0},
        {"late_enrichment_sweep_interval_seconds": -1},
        {"late_enrichment_lookback_seconds": 0},
    ],
)
def test_late_enrichment_sweep_rejects_non_positive_bounds(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict
) -> None:
    _clear_environment(monkeypatch)
    with pytest.raises(ValidationError):
        Settings(
            soc_env="test",
            triage_ingest_api_key="test-ingest-key-not-a-real-secret",
            n8n_callback_token="test-callback-token-not-a-real-secret",
            **kwargs,
        )
