"""Incident domain/schema models (Phase 3.1 + 3.2).

The domain representation of a persisted incident, deliberately dependency-free
(pydantic + enum + datetime + uuid only) so repositories and orchestration code
work with domain objects — never ORM rows (ARCHITECTURE.md §12).

Incidents are opened automatically by the ingest pipeline when an alert
decision is ``open_incident`` (critical → SEV1, high → SEV2). The
human-readable id follows the platform convention ``INC-YYYY-MM-DD-NNNN``
(sequential per UTC date, unique); severity reuses the decision engine's
:class:`soc_triage.models.assessment.DecisionSeverity` vocabulary so the
decision and its incident can never disagree.

Phase 3.2 — incident lifecycle
------------------------------

Incidents move through a strict status model with **explicit valid
transitions** (no other transition is legal, terminal states allow none):

    open          -> investigating | acknowledged | false_positive | escalated
    investigating -> acknowledged | resolved | escalated | false_positive
    acknowledged  -> investigating | resolved | escalated
    escalated     -> investigating | acknowledged | resolved | false_positive
    resolved        (terminal — no further transitions)
    false_positive  (terminal — no further transitions)

Two lifecycle timestamps are maintained alongside ``created_at`` /
``updated_at`` and are populated **only when the corresponding state is
actually reached**:

* ``acknowledged_at`` — set when the incident transitions to
  ``acknowledged`` (the most recent time that state was reached).
* ``resolved_at`` — set when the incident reaches a terminal state
  (``resolved`` or ``false_positive``).

A feedback verdict is **not** proof that remediation is complete, so nothing
auto-resolves an incident on a verdict alone (see the Phase 3.2 feedback
mapping in :mod:`soc_triage.api.feedback`).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from .assessment import DecisionSeverity


class IncidentStatus(StrEnum):
    """Incident lifecycle status (Phase 3.2).

    Incidents are created in state ``open`` (Phase 3.1); the analyst — via the
    status update API or through analyst feedback on a linked alert — moves
    the incident along the explicit transitions in
    :data:`VALID_TRANSITIONS`.
    """

    OPEN = "open"
    INVESTIGATING = "investigating"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


#: Explicit valid transitions of the incident lifecycle (Phase 3.2).
#:
#: Terminal states (``resolved``, ``false_positive``) map to the empty set:
#: a closed incident never changes state again. No transitions are implied —
#: the API and the feedback synchronizer are both guarded by this table, so
#: the state machine can never be bypassed.
VALID_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.ACKNOWLEDGED,
            IncidentStatus.FALSE_POSITIVE,
            IncidentStatus.ESCALATED,
        }
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.ACKNOWLEDGED,
            IncidentStatus.RESOLVED,
            IncidentStatus.ESCALATED,
            IncidentStatus.FALSE_POSITIVE,
        }
    ),
    IncidentStatus.ACKNOWLEDGED: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.RESOLVED,
            IncidentStatus.ESCALATED,
        }
    ),
    IncidentStatus.ESCALATED: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.ACKNOWLEDGED,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        }
    ),
    IncidentStatus.RESOLVED: frozenset(),
    IncidentStatus.FALSE_POSITIVE: frozenset(),
}

#: States an incident can never leave (no outgoing transitions).
TERMINAL_STATUSES: frozenset[IncidentStatus] = frozenset(
    {IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}
)


def can_transition(current: IncidentStatus, target: IncidentStatus) -> bool:
    """Whether the lifecycle allows ``current`` → ``target``.

    A transition into the same state is never allowed (it is not in
    :data:`VALID_TRANSITIONS`), which is what makes repeated feedback with
    the same verdict idempotent: the first one moves the incident, later
    ones find no legal transition and leave it untouched.
    """
    return target in VALID_TRANSITIONS.get(current, frozenset())


class InvalidIncidentTransitionError(ValueError):
    """A requested incident status transition is not in the state machine.

    Carries both states so API layers can render a structured conflict
    response (current status, requested status, allowed targets) instead of
    silently dropping the request.
    """

    def __init__(self, current: IncidentStatus, target: IncidentStatus) -> None:
        self.current = current
        self.target = target
        allowed = sorted(s.value for s in VALID_TRANSITIONS.get(current, frozenset()))
        super().__init__(
            f"invalid incident status transition: {current.value} -> {target.value} "
            f"(allowed from {current.value}: {allowed if allowed else 'none — terminal state'})"
        )


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
    #: Set exactly when the incident transitions to ``acknowledged``
    #: (Phase 3.2); ``None`` until that state is reached.
    acknowledged_at: datetime | None = None
    #: Set exactly when the incident reaches a terminal state
    #: (``resolved`` or ``false_positive``); ``None`` otherwise.
    resolved_at: datetime | None = None


__all__ = [
    "TERMINAL_STATUSES",
    "VALID_TRANSITIONS",
    "Incident",
    "IncidentStatus",
    "InvalidIncidentTransitionError",
    "can_transition",
]
