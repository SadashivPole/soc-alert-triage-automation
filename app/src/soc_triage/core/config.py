"""Typed, environment-driven application settings.

All runtime configuration comes from environment variables (and optionally a
git-ignored `.env` file). Secrets are stored as ``SecretStr``; the credential-
bearing database URL is kept out of settings ``repr``/``str`` output; and the
settings object fails fast when placeholder values are used outside development.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]

_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_PLACEHOLDER_PREFIX = "change-me"


class Settings(BaseSettings):
    """Validated application settings loaded from the environment.

    Field names mirror the environment variables documented in ``.env.example``.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )

    soc_env: Environment = Field(default="development", alias="SOC_ENV")
    soc_log_level: str = Field(default="INFO", alias="SOC_LOG_LEVEL")
    soc_instance_name: str = Field(default="soc-lab", alias="SOC_INSTANCE_NAME")

    triage_api_host: str = Field(default="0.0.0.0", alias="TRIAGE_API_HOST")
    triage_api_port: int = Field(default=8000, alias="TRIAGE_API_PORT", ge=1, le=65535)
    triage_cors_origins: str = Field(default="http://localhost:8080", alias="TRIAGE_CORS_ORIGINS")
    # A PostgreSQL SQLAlchemy URL can contain credentials. Keep the value as a
    # string for SQLAlchemy, but exclude it from Settings repr/str output so a
    # settings object can be safely included in diagnostic log context.
    triage_db_url: str = Field(
        default="sqlite:////data/soc_triage.db", alias="TRIAGE_DB_URL", repr=False
    )
    triage_dedupe_window_seconds: int = Field(
        default=900, alias="TRIAGE_DEDUPE_WINDOW_SECONDS", ge=1
    )

    # ------------------------------------------------------------------
    # Phase 3.4 — incident auto-close TTL sweeper
    # ------------------------------------------------------------------
    # Non-terminal incidents (open / investigating / acknowledged / escalated)
    # whose ``updated_at`` has not changed within this TTL are automatically
    # transitioned to ``resolved`` by a periodic background sweeper. Terminal
    # states (``resolved``, ``false_positive``) are never touched.
    # Conservative lab default: 7 days (604800 s) — long enough for the
    # analyst workflow in a lab/portfolio setting, short enough to keep the
    # incident board from accumulating unbounded stale rows. Must be >= 1.
    incident_auto_close_ttl_seconds: int = Field(
        default=604800, alias="INCIDENT_AUTO_CLOSE_TTL_SECONDS", ge=1
    )
    # Period between sweeper passes. The sweeper runs an idempotent pass,
    # so a shorter interval is safe; default 5 minutes keeps DB load minimal.
    # Must be >= 1. Set to 0 via code (not env) only in tests that drive
    # the sweeper manually.
    incident_sweeper_interval_seconds: int = Field(
        default=300, alias="INCIDENT_SWEEPER_INTERVAL_SECONDS", ge=1
    )

    # ------------------------------------------------------------------
    # Phase 3.7 — Prometheus metrics (optional scrape authentication)
    # ------------------------------------------------------------------
    # Enables the metrics recording surface and (Task D4) the `/metrics`
    # endpoint. Default true: observability is on by default, but metrics
    # are non-load-bearing and can be switched off entirely.
    metrics_enabled: bool = Field(default=True, alias="METRICS_ENABLED")
    # Optional bearer token protecting the `/metrics` exposition. Empty =
    # metrics authentication disabled (development-compatible default);
    # when set, a scrape must present `Authorization: Bearer <token>`.
    # This is a DEDICATED token: the ingest API key and N8N tokens are never
    # reused for scraping (SECURITY.md §2, approved decision D1). Held as
    # SecretStr; `change-me-*` placeholders fail fast outside development.
    metrics_scrape_token: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        alias="METRICS_SCRAPE_TOKEN",
    )

    triage_ingest_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr("change-me-generate-a-long-random-value"),
        alias="TRIAGE_INGEST_API_KEY",
    )
    n8n_callback_token: SecretStr = Field(
        default_factory=lambda: SecretStr("change-me-generate-a-long-random-value"),
        alias="N8N_CALLBACK_TOKEN",
    )

    # ------------------------------------------------------------------
    # n8n SOAR webhook integration (Phase 2B)
    # ------------------------------------------------------------------
    # Outbound webhook from the triage service to n8n (WF1 router).
    # Empty URL = disabled (fail-open, no notification attempted). When set,
    # the service POSTs the structured alert payload with timeout/retry and
    # audits the result — n8n failure never corrupts the alert (ARCH §16).
    n8n_webhook_url: str = Field(default="", alias="N8N_WEBHOOK_URL")
    # Shared authentication token for service ↔ n8n. If N8N_WEBHOOK_TOKEN is
    # empty but N8N_CALLBACK_TOKEN is configured, the callback token is used
    # as the shared secret (single-token deployment). Empty = no auth header
    # sent (n8n workflow should still validate when token is configured).
    n8n_webhook_token: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        alias="N8N_WEBHOOK_TOKEN",
    )
    n8n_timeout_seconds: float = Field(default=3.0, alias="N8N_TIMEOUT_SECONDS", ge=0.5, le=30.0)
    n8n_max_retries: int = Field(default=3, alias="N8N_MAX_RETRIES", ge=1, le=10)
    n8n_retry_backoff_seconds: float = Field(
        default=0.5, alias="N8N_RETRY_BACKOFF_SECONDS", ge=0.0, le=10.0
    )

    # Threat-intelligence enrichment (Phase 2A). Both providers are optional
    # and **disabled by default**: an empty key (and, for MISP, an empty URL)
    # means the provider is never called (disable-by-empty, ARCHITECTURE.md §14).
    # Keys come only from the environment / secret store — never hardcoded.
    virustotal_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        alias="VIRUSTOTAL_API_KEY",
    )
    misp_url: str = Field(default="", alias="MISP_URL")
    misp_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        alias="MISP_API_KEY",
    )
    misp_verify_tls: bool = Field(default=True, alias="MISP_VERIFY_TLS")

    @property
    def cors_origins(self) -> list[str]:
        """Parse the comma-separated CORS origins into a clean list."""
        return [origin.strip() for origin in self.triage_cors_origins.split(",") if origin.strip()]

    @property
    def n8n_enabled(self) -> bool:
        """Whether outbound n8n notification is enabled (URL non-empty)."""
        return bool(self.n8n_webhook_url.strip())

    @property
    def effective_n8n_token(self) -> str:
        """Resolve the shared token used for service ↔ n8n authentication.

        Preference: explicit N8N_WEBHOOK_TOKEN, else N8N_CALLBACK_TOKEN (shared
        token deployment). Empty string means no auth header is sent.
        """
        webhook = self.n8n_webhook_token.get_secret_value().strip()
        if webhook:
            return webhook
        callback = self.n8n_callback_token.get_secret_value().strip()
        if callback and not callback.lower().startswith(_PLACEHOLDER_PREFIX):
            return callback
        return webhook

    @field_validator("soc_log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        """Normalize and validate the configured log level."""
        normalized = value.upper()
        if normalized not in _LOG_LEVELS:
            raise ValueError(
                f"unsupported SOC_LOG_LEVEL {value!r}; expected one of {sorted(_LOG_LEVELS)}"
            )
        return normalized

    @model_validator(mode="after")
    def _reject_placeholder_secrets(self) -> Self:
        """Refuse placeholder secrets outside development so misconfig fails fast."""
        if self.soc_env == "development":
            return self

        secret_fields = {
            "triage_ingest_api_key": self.triage_ingest_api_key.get_secret_value(),
            "n8n_callback_token": self.n8n_callback_token.get_secret_value(),
            "n8n_webhook_token": self.n8n_webhook_token.get_secret_value(),
            "virustotal_api_key": self.virustotal_api_key.get_secret_value(),
            "misp_api_key": self.misp_api_key.get_secret_value(),
            "metrics_scrape_token": self.metrics_scrape_token.get_secret_value(),
        }
        for name, raw in secret_fields.items():
            # Empty values are the documented "disabled" default and are valid
            # in every environment; only non-empty placeholder values are rejected.
            if raw and raw.lower().startswith(_PLACEHOLDER_PREFIX):
                raise ValueError(
                    f"{name} must not use the {_PLACEHOLDER_PREFIX}* placeholder when SOC_ENV={self.soc_env}"
                )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide cached settings instance.

    Use ``create_app(settings=...)`` in tests to inject a controlled settings
    object instead of relying on the ambient environment.
    """
    return Settings()


__all__ = ["Environment", "Settings", "ValidationError", "get_settings"]
