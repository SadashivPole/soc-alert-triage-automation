"""Typed, environment-driven application settings.

All runtime configuration comes from environment variables (and optionally a
git-ignored `.env` file). Secrets are stored as ``SecretStr`` and the settings
object fails fast when placeholder values are used outside development.
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
    triage_db_url: str = Field(default="sqlite:////data/soc_triage.db", alias="TRIAGE_DB_URL")
    triage_dedupe_window_seconds: int = Field(
        default=900, alias="TRIAGE_DEDUPE_WINDOW_SECONDS", ge=1
    )

    triage_ingest_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr("change-me-generate-a-long-random-value"),
        alias="TRIAGE_INGEST_API_KEY",
    )
    n8n_callback_token: SecretStr = Field(
        default_factory=lambda: SecretStr("change-me-generate-a-long-random-value"),
        alias="N8N_CALLBACK_TOKEN",
    )

    @property
    def cors_origins(self) -> list[str]:
        """Parse the comma-separated CORS origins into a clean list."""
        return [origin.strip() for origin in self.triage_cors_origins.split(",") if origin.strip()]

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
        }
        for name, raw in secret_fields.items():
            if raw.lower().startswith(_PLACEHOLDER_PREFIX):
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
