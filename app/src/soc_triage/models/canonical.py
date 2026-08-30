"""Canonical alert schema for normalized Wazuh alerts.

This model represents the normalized form of an alert after ingestion and
validation. It is the internal representation used throughout the triage
pipeline. Based on ARCHITECTURE.md §5.2.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class CanonicalRule(BaseModel):
    """Normalized rule information from the source alert."""

    id: str
    level: int
    description: str
    groups: list[str] = Field(default_factory=list)
    mitre: dict[str, Any] = Field(default_factory=dict)


class CanonicalAgent(BaseModel):
    """Normalized agent information from the source alert."""

    id: str
    name: str
    ip: str | None = None


class CanonicalSourceEvent(BaseModel):
    """Trimmed original payload with key fields preserved."""

    rule: CanonicalRule
    agent: CanonicalAgent
    location: str | None = None
    full_log: str | None = None


class CanonicalDedupe(BaseModel):
    """Deduplication information for the alert."""

    group_key: str
    occurrences: int
    first_seen: datetime
    last_seen: datetime


class CanonicalAlert(BaseModel):
    """Canonical alert record after normalization.

    This is the internal representation used throughout the triage pipeline.
    Phase 1B implements: alert_id, source, received_at, source_event.
    Phase 1C adds: dedupe.
    Future phases will add: iocs, asset, risk, decision, etc.
    """

    alert_id: UUID
    source: str = "wazuh"
    received_at: datetime
    source_event: CanonicalSourceEvent
    dedupe: CanonicalDedupe | None = None

    model_config = {"frozen": True}


__all__ = [
    "CanonicalAgent",
    "CanonicalAlert",
    "CanonicalDedupe",
    "CanonicalRule",
    "CanonicalSourceEvent",
]
