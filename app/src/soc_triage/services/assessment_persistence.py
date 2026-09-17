"""Atomic persistence for alert assessments and incident linkage."""

from __future__ import annotations

from datetime import datetime
from typing import NamedTuple
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from ..audit import audit_entries_for_assessment, audit_entries_for_incident
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.assessment import Decision, DecisionAction, RiskAssessment
from ..models.canonical import CanonicalAlert
from ..models.repositories import AlertRepository, AuditRepository, IncidentRepository

logger = get_logger(__name__)


class AssessmentPersistResult(NamedTuple):
    """Outcome of one atomic assessment persistence attempt."""

    incident_id: str | None
    persisted: bool


def persist_assessment(
    session_factory: sessionmaker,
    *,
    alert_id: UUID,
    canonical: CanonicalAlert,
    risk: RiskAssessment,
    decision: Decision,
    dedupe_group_key: str,
    occurred_at: datetime,
    previous_risk: RiskAssessment | None = None,
    previous_decision: Decision | None = None,
) -> AssessmentPersistResult:
    """Persist assessment, audit entries, and incident linkage atomically.

    When the decision is ``open_incident``:

    * no open incident for the dedupe group → create one;
    * an existing open incident → attach the alert to it.

    A database failure rolls the complete transaction back and returns
    ``persisted=False``.
    """

    incident_id: str | None = None
    incident_action: str | None = None
    severity: str | None = None

    try:
        with session_scope(session_factory) as session:
            AlertRepository(session).update_normalized_payload(
                alert_id,
                canonical,
            )
            AuditRepository(session).append(
                audit_entries_for_assessment(
                    alert_id,
                    risk=risk,
                    decision=decision,
                    previous_risk=previous_risk,
                    previous_decision=previous_decision,
                ),
                occurred_at=occurred_at,
            )

            if decision.action is DecisionAction.OPEN_INCIDENT:
                incident_repo = IncidentRepository(session)
                existing = incident_repo.open_for_group(dedupe_group_key)

                if existing is None:
                    if decision.severity is None:  # pragma: no cover
                        raise ValueError("open_incident decision is missing a severity")

                    incident = incident_repo.create(
                        alert_id=alert_id,
                        severity=decision.severity,
                        dedupe_group_key=dedupe_group_key,
                        occurred_at=occurred_at,
                    )

                    incident_id = incident.incident_id
                    severity = incident.severity.value
                    incident_action = "created"

                    AuditRepository(session).append(
                        audit_entries_for_incident(incident),
                        occurred_at=occurred_at,
                    )
                else:
                    incident_repo.attach(
                        alert_id=alert_id,
                        incident_id=existing.incident_id,
                    )
                    incident_id = existing.incident_id
                    severity = existing.severity.value
                    incident_action = "attached_existing"

        if incident_id is not None:
            logger.info(
                "incident_created"
                if incident_action == "created"
                else "incident_attached_existing",
                component="incidents",
                incident_id=incident_id,
                alert_id=str(alert_id),
                severity=severity,
                dedupe_group_key=dedupe_group_key,
            )

    except SQLAlchemyError as exc:
        logger.error(
            "assessment_persistence_failed",
            component="scoring",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return AssessmentPersistResult(
            incident_id=None,
            persisted=False,
        )

    return AssessmentPersistResult(
        incident_id=incident_id,
        persisted=True,
    )


__all__ = [
    "AssessmentPersistResult",
    "persist_assessment",
]
