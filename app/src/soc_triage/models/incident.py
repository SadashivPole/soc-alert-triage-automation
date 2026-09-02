"""Incident domain/schema models (Phase 3.1).

The domain representation of a persisted incident, deliberately dependency-free
(pydantic + enum + datetime + uuid only) so repositories and orchestration code
work with domain objects — never ORM rows (ARCHITECTURE.md §12).

Incidents are opened automatically by the ingest pipeline when an alert
decision is ``open_incident`` (critical → SEV1, high → SEV2). The
human-readable id follows the platform convention ``INC-YYYY-MM-DD-NNNN``
(sequential per UTC date, unique); severity reuses the decision engine's
:class:`soc_triage.models.assessment.DecisionSeverity` vocabulary so the
decision and its incident can never disagree.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from .assessment import DecisionSeverity


class IncidentStatus(StrEnum):
    """Incident lifecycle status.

    Phase 3.1 only creates incidents in state ``open``; later milestones
    (analyst resolution, SLA sweeps) extend this enum.
    """

    OPEN = "open"


class Incident(BaseModel):
    """One persisted incident (domain view, frozen)."""

    model_config = {"frozen": True}

    #: Human-readable, sequential-per-UTC-date id (``INC-YYYY-MM-DD-NNNN``).
    incident_id: str = Field(min_length=1)
    status: IncidentStatus
    severity: DecisionSeverity
    #: The alert whose ``open_incident`` decision created this incident.
    primary_alert_id: UUID
    #: Rule+agent dedupe group the incident belongs to (recurrence linking).
    dedupe_group_key: str = Field(min_length=1)
    created_at: datetime
    updated_at: datetime


__all__ = ["Incident", "IncidentStatus"]
