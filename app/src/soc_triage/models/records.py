"""Read-side domain records (Phase 3.3).

These are the repository return types for the alert/incident read APIs and
the incident timeline. They wrap persisted columns plus the canonical alert
without exposing SQLAlchemy ORM objects to the API layer (ARCHITECTURE.md
§12). Pagination bounds live here so repositories and routers share one
definition without the models package importing ``api/``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from .canonical import CanonicalAlert

#: Default page size for list endpoints (SOC console, newest-first).
DEFAULT_PAGE_LIMIT = 50

#: Hard ceiling on ``limit`` so a client cannot unbounded-scan the table.
MAX_PAGE_LIMIT = 200


class PersistedAlert(BaseModel):
    """One alert of record plus the denormalized columns used for listing."""

    model_config = {"frozen": True}

    alert_id: UUID
    source: str
    received_at: datetime
    created_at: datetime
    incident_id: str | None
    rule_id: str
    rule_level: int
    agent_id: str
    agent_name: str
    dedupe_group_key: str
    event_identity: str
    canonical: CanonicalAlert


class AuditRecord(BaseModel):
    """One append-only audit row, as a domain object (never an ORM instance)."""

    model_config = {"frozen": True}

    id: int
    occurred_at: datetime
    actor: str
    action: str
    entity_type: str
    entity_id: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None


class CorrelationEvidenceItem(BaseModel):
    """One stored pairwise evidence item on a correlation membership.

    ``peer_alert_id`` is the *other* alert of the pair the evidence was
    computed against — the reason a membership exists is always a
    relationship between exactly two distinct alerts.
    """

    model_config = {"frozen": True}

    evidence_type: str
    value: str
    peer_alert_id: str


class CorrelationMemberRecord(BaseModel):
    """Membership of one alert in one correlation context (persistence view)."""

    model_config = {"frozen": True}

    context_id: str
    alert_id: UUID
    joined_at: datetime
    evidence: list[CorrelationEvidenceItem]


class CorrelationContextRecord(BaseModel):
    """One correlation context plus its (query-derived) member count."""

    model_config = {"frozen": True}

    context_id: str
    created_at: datetime
    updated_at: datetime
    first_seen: datetime
    last_seen: datetime
    member_count: int = Field(default=0, ge=0)


class CorrelationMemberSummary(BaseModel):
    """One member alert of a correlation context, as shown on the read API.

    Carries the alert's own ``dedupe_group_key`` and ``incident_id`` so the
    three relationships an alert can have (recurrence group, incident,
    correlation context) stay visibly distinct (DEVELOPMENT_PLAN.md 6.4).
    """

    model_config = {"frozen": True}

    alert_id: UUID
    received_at: datetime
    joined_at: datetime
    rule_id: str
    rule_level: int
    agent_id: str
    agent_name: str
    dedupe_group_key: str
    incident_id: str | None = None
    risk_tier: str | None = None
    decision_action: str | None = None
    evidence: list[CorrelationEvidenceItem] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    """One chronological, read-only timeline entry for an incident.

    Built exclusively from existing ``audit_log`` rows — constructing a
    timeline never writes, notifies, or calls an external system.
    """

    model_config = {"frozen": True}

    timestamp: datetime
    action: str
    entity_type: str
    entity_id: str
    actor: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "DEFAULT_PAGE_LIMIT",
    "MAX_PAGE_LIMIT",
    "AuditRecord",
    "CorrelationContextRecord",
    "CorrelationEvidenceItem",
    "CorrelationMemberRecord",
    "CorrelationMemberSummary",
    "PersistedAlert",
    "TimelineEvent",
]
