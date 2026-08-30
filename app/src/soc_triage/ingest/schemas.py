"""Wazuh alert schema validation.

Pydantic models that validate the shape of incoming Wazuh 4.x alert JSON.
The schema is *tolerant*: unknown fields are preserved under ``source_event``
and never rejected, since Wazuh rulesets evolve over time.

Based on ARCHITECTURE.md §6 and the sample alerts in ``docs/sample-alerts/``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WazuhMitre(BaseModel):
    """MITRE ATT&CK metadata attached to a rule."""

    model_config = ConfigDict(extra="allow")

    id: list[str] = Field(default_factory=list)
    tactic: list[str] = Field(default_factory=list)
    technique: list[str] = Field(default_factory=list)


class WazuhRule(BaseModel):
    """Wazuh rule block. Required fields: id, level, description."""

    model_config = ConfigDict(extra="allow")

    id: str
    level: int = Field(ge=0, le=15)
    description: str = Field(min_length=1)
    groups: list[str] = Field(default_factory=list)
    mitre: WazuhMitre | None = None
    firedtimes: int = Field(default=0, ge=0)
    mail: bool = False

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id_to_string(cls, value: Any) -> str:
        """Accept numeric rule IDs (Wazuh sometimes emits ints)."""
        return str(value)


class WazuhAgent(BaseModel):
    """Wazuh agent block."""

    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    ip: str | None = None
    #: Optional inventory labels (``asset_tier`` / ``owner``) — carried into
    #: the canonical asset context for scoring (Phase 1F, ARCHITECTURE §5.2).
    labels: dict[str, Any] | None = None

    @field_validator("id", mode="before")
    @classmethod
    def _coerce_id_to_string(cls, value: Any) -> str:
        """Accept numeric agent IDs."""
        return str(value)


class WazuhData(BaseModel):
    """Wazuh data block. All fields are optional — content varies by rule."""

    model_config = ConfigDict(extra="allow")

    srcip: str | None = None
    srcport: int | str | None = None
    dstip: str | None = None
    srcuser: str | None = None
    dstuser: str | None = None
    protocol: str | None = None


class WazuhAlert(BaseModel):
    """Top-level Wazuh alert payload.

    The schema validates the structural shape of the alert but is tolerant of
    extra fields (Wazuh rulesets vary). Required fields: ``rule``, ``agent``.
    """

    model_config = ConfigDict(extra="allow")

    id: str | None = None
    timestamp: str | None = None
    rule: WazuhRule
    agent: WazuhAgent
    data: WazuhData | None = None
    manager: dict[str, Any] | None = None
    decoder: dict[str, Any] | None = None
    location: str | None = None
    full_log: str | None = None
    syscheck: dict[str, Any] | None = None

    @property
    def parsed_timestamp(self) -> datetime | None:
        """Attempt to parse the Wazuh timestamp into a datetime."""
        if not self.timestamp:
            return None
        # Wazuh timestamps: "2026-08-29T10:15:29.000+0000"
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(self.timestamp, fmt)
            except ValueError:
                continue
        return None


__all__ = [
    "WazuhAgent",
    "WazuhAlert",
    "WazuhData",
    "WazuhMitre",
    "WazuhRule",
]
