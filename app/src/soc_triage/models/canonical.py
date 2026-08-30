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

from .assessment import Decision, RiskAssessment
from .ioc import IOC


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


class CanonicalAsset(BaseModel):
    """Asset context for scoring (ARCHITECTURE.md §5.2, §8.1).

    Populated from the agent's ``labels`` (``asset_tier`` / ``owner``) when the
    source supplies them; ``tier`` drives the ``asset_criticality`` scoring
    factor. ``tier`` is ``None`` when the source carries no tier label, which
    the scoring engine treats as *unknown* (a policy-configured neutral
    contribution) rather than an error.
    """

    model_config = {"frozen": True}

    name: str | None = None
    #: Raw tier label as supplied by the source (e.g. ``tier-1``, ``critical``).
    tier: str | None = None
    owner: str | None = None


class CanonicalSourceEvent(BaseModel):
    """Trimmed original payload with key fields preserved.

    ``data`` and ``syscheck`` keep the structured evidence blocks of a Wazuh
    alert (FIM hashes live in ``syscheck``, network/context fields in
    ``data``) so IOC extraction (Phase 1E) can work from typed fields instead
    of scraping ``full_log`` (ARCHITECTURE.md §7.1).
    """

    rule: CanonicalRule
    agent: CanonicalAgent
    location: str | None = None
    full_log: str | None = None
    #: Wazuh ``data`` block (unknown fields preserved verbatim by the schema).
    data: dict[str, Any] = Field(default_factory=dict)
    #: Wazuh ``syscheck`` (FIM) block: paths plus before/after file hashes.
    syscheck: dict[str, Any] = Field(default_factory=dict)


class CanonicalDedupe(BaseModel):
    """Deduplication and recurrence information for the alert.

    ``occurrences`` counts *distinct events* in the current generation (an
    exact duplicate re-delivery never increments it). ``first_seen`` /
    ``last_seen`` bound the generation's recurrence span; together with
    ``duplicate_deliveries`` they are the recurrence signals later consumed by
    risk scoring. ``event_identity`` is the deterministic source-event identity
    (see ``ingest.deduplication``) and ``generation`` counts window-expiry
    resets of the group.
    """

    group_key: str
    occurrences: int = Field(default=1, ge=1)
    first_seen: datetime
    last_seen: datetime
    event_identity: str | None = None
    generation: int = Field(default=1, ge=1)
    duplicate_deliveries: int = Field(default=0, ge=0)

    model_config = {"frozen": True}


class CanonicalAlert(BaseModel):
    """Canonical alert record after normalization.

    This is the internal representation used throughout the triage pipeline.
    Phase 1B implemented: alert_id, source, received_at, source_event.
    Phase 1C populates: dedupe (identity, recurrence, idempotency info).
    Phase 1E populates: iocs (indicators + provenance, enrichment payloads).
    Phase 1F populates: asset (tier/owner for scoring), enrichment_status,
    risk (the deterministic score) and decision (the routing outcome).
    """

    alert_id: UUID
    source: str = "wazuh"
    received_at: datetime
    source_event: CanonicalSourceEvent
    dedupe: CanonicalDedupe | None = None
    #: Indicators extracted from this alert (ARCHITECTURE.md §5.2, §7.1).
    #: Normalized, provenance-carrying, and deduplicated by (type, value).
    iocs: list[IOC] = Field(default_factory=list)
    #: Asset context (name/tier/owner) derived from agent labels, when present.
    asset: CanonicalAsset | None = None
    #: Enrichment run outcome (``complete`` | ``partial`` | ``failed`` |
    #: ``skipped``) — consumed by the scoring ``enrichment_status`` factor.
    enrichment_status: str | None = None
    #: Deterministic risk assessment (Phase 1F scoring engine output).
    risk: RiskAssessment | None = None
    #: Routing decision derived from the risk tier and alert context.
    decision: Decision | None = None

    model_config = {"frozen": True}


__all__ = [
    "CanonicalAgent",
    "CanonicalAlert",
    "CanonicalAsset",
    "CanonicalDedupe",
    "CanonicalRule",
    "CanonicalSourceEvent",
]
