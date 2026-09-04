"""Phase 3.7 Task D3 — metrics configuration tests.

Covers the environment-driven metrics settings (approved decision D1):

* ``METRICS_ENABLED`` defaults to ``True`` and can be disabled;
* ``METRICS_SCRAPE_TOKEN`` defaults to empty (auth disabled) and is a
  ``SecretStr``;
* a configured token round-trips via ``get_secret_value()`` only;
* empty tokens stay valid in every environment (disabled default);
* ``change-me-*`` placeholders fail fast in ``test`` / ``production``
  exactly like the existing secret fields (SECURITY.md §2);
* the token is never reused from the N8N/ingest secrets (separate field);
* ``.env.example`` documents the metrics settings with placeholders only.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from soc_triage.core.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_EXAMPLE = REPO_ROOT / ".env.example"

#: An explicitly non-placeholder secret for the other auth fields so a
#: validation failure can only come from the metrics token under test.
_INGEST_KEY = "unit-test-ingest-key-not-a-secret"
_TEST_CALLBACK_TOKEN = "unit-test-callback-token-not-a-secret"
_TEST_METRICS_TOKEN = "unit-metrics-scrape-token-not-a-secret"


@pytest.fixture(autouse=True)
def _clean_metrics_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate metrics settings from any ambient developer environment."""
    monkeypatch.delenv("METRICS_ENABLED", raising=False)
    monkeypatch.delenv("METRICS_SCRAPE_TOKEN", raising=False)


def test_metrics_defaults_enabled_and_token_disabled() -> None:
    """Defaults: metrics on, scrape-auth off (empty token)."""
    settings = Settings()
    assert settings.metrics_enabled is True
    assert isinstance(settings.metrics_scrape_token, SecretStr)
    assert settings.metrics_scrape_token.get_secret_value() == ""


def test_metrics_enabled_disable_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """METRICS_ENABLED=false (env) turns the surface off."""
    monkeypatch.setenv("METRICS_ENABLED", "false")
    settings = Settings()
    assert settings.metrics_enabled is False


def test_metrics_enabled_true_accepted_via_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """METRICS_ENABLED accepts explicit truthy env values."""
    monkeypatch.setenv("METRICS_ENABLED", "1")
    assert Settings().metrics_enabled is True


def test_configured_scrape_token_round_trips_as_secret_str() -> None:
    """A configured token is held as SecretStr and read via get_secret_value."""
    settings = Settings(
        soc_env="test",
        metrics_scrape_token=_TEST_METRICS_TOKEN,
        triage_ingest_api_key=_INGEST_KEY,
        n8n_callback_token=_TEST_CALLBACK_TOKEN,
    )
    assert isinstance(settings.metrics_scrape_token, SecretStr)
    assert settings.metrics_scrape_token.get_secret_value() == _TEST_METRICS_TOKEN
    # Distinct secret field: the metrics token is never the N8N/ingest secret.
    assert (
        settings.metrics_scrape_token.get_secret_value()
        != settings.triage_ingest_api_key.get_secret_value()
    )
    assert (
        settings.metrics_scrape_token.get_secret_value()
        != settings.n8n_callback_token.get_secret_value()
    )


def test_empty_token_is_valid_in_every_environment() -> None:
    """Empty token = auth disabled; valid in test and production alike."""
    for env in ("test", "production"):
        settings = Settings(
            soc_env=env,
            metrics_scrape_token="",
            triage_ingest_api_key=_INGEST_KEY,
            n8n_callback_token=_TEST_CALLBACK_TOKEN,
        )
        assert settings.metrics_scrape_token.get_secret_value() == ""


def test_placeholder_token_rejected_in_test_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A change-me metrics token must fail fast in test (SECURITY.md §2)."""
    monkeypatch.delenv("METRICS_SCRAPE_TOKEN", raising=False)
    with pytest.raises(ValidationError):
        Settings(
            soc_env="test",
            metrics_scrape_token="change-me-generate-a-long-random-value",
            triage_ingest_api_key=_INGEST_KEY,
            n8n_callback_token=_TEST_CALLBACK_TOKEN,
        )


def test_placeholder_token_rejected_in_production_environment() -> None:
    """A change-me metrics token must fail fast in production."""
    with pytest.raises(ValidationError):
        Settings(
            soc_env="production",
            metrics_scrape_token="change-me-generate-a-long-random-value",
            triage_ingest_api_key=_INGEST_KEY,
            n8n_callback_token=_TEST_CALLBACK_TOKEN,
        )


def test_placeholder_token_rejection_ignores_ambient_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real token in the ambient env cannot mask an explicit placeholder."""
    monkeypatch.setenv("METRICS_SCRAPE_TOKEN", "real-token-from-developer-dotenv")
    with pytest.raises(ValidationError):
        Settings(
            soc_env="test",
            metrics_scrape_token="change-me-generate-a-long-random-value",
            triage_ingest_api_key=_INGEST_KEY,
            n8n_callback_token=_TEST_CALLBACK_TOKEN,
        )


def test_secret_str_repr_never_exposes_the_token() -> None:
    """The SecretStr representation must never leak the configured token."""
    settings = Settings(
        soc_env="test",
        metrics_scrape_token=_TEST_METRICS_TOKEN,
        triage_ingest_api_key=_INGEST_KEY,
        n8n_callback_token=_TEST_CALLBACK_TOKEN,
    )
    assert _TEST_METRICS_TOKEN not in repr(settings.metrics_scrape_token)
    assert _TEST_METRICS_TOKEN not in str(settings.metrics_scrape_token)


def test_metrics_token_not_used_to_resolve_n8n_or_ingest_auth() -> None:
    """Metrics and N8N/API token channels remain fully independent."""
    settings = Settings(
        soc_env="test",
        metrics_enabled=True,
        metrics_scrape_token=_TEST_METRICS_TOKEN,
        triage_ingest_api_key=_INGEST_KEY,
        n8n_callback_token=_TEST_CALLBACK_TOKEN,
    )
    assert settings.effective_n8n_token != _TEST_METRICS_TOKEN
    assert settings.triage_ingest_api_key.get_secret_value() != _TEST_METRICS_TOKEN


def test_env_example_documents_metrics_settings_placeholder_only() -> None:
    """.env.example documents both metrics settings; token stays empty."""
    assert ENV_EXAMPLE.exists(), ".env.example must exist"
    content = ENV_EXAMPLE.read_text(encoding="utf-8")
    lines = {line.strip() for line in content.splitlines() if line.strip()}

    # Documented, and the enabled flag defaults to true.
    assert "METRICS_ENABLED=1" in lines
    assert "# Enable the metrics recording surface" in content

    # Token documented as empty / disabled — never a real or placeholder value.
    token_lines = [
        line for line in content.splitlines() if line.strip().startswith("METRICS_SCRAPE_TOKEN=")
    ]
    assert len(token_lines) == 1
    assert token_lines[0].strip() == "METRICS_SCRAPE_TOKEN="
    assert "METRICS_SCRAPE_TOKEN" in content
    # Never reuse the ingest key or N8N tokens for scraping (decision D1).
    assert "never reuse" in content.lower()
    # No real credential-looking value for the metrics token anywhere.
    assert "METRICS_SCRAPE_TOKEN=change-me" not in content
