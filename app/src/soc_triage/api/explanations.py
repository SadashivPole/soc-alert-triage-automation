"""Alert explanation read API (Phase 6.5).

Read-only explainability over already-persisted facts: the alert of record
(with its authoritative scoring.v1 assessment and decisions.v1 decision),
the dedupe group state, incident linkage, the correlation.v1 context, and
the audit history. One ``GET`` is served as a **single read-only request**:
every lookup happens inside one database session that performs no writes —
no audit rows, no state transitions, no notifications, no n8n/Wazuh/intel/
LLM calls (ARCHITECTURE.md §10, §15).

Security (same conventions as the other read APIs):

* Requires the shared N8N token (X-N8N-Token / X-Callback-Token / Bearer).
* Never exposes ``full_log``, credentials, tokens, or raw payloads; IOC
  enrichment and MITRE metadata pass through the shared secret redaction.
* Unknown ids return a structured 404; the response is deterministic —
  identical persisted state yields identical content and ordering.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse

from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..explanation import ExplanationRead, build_explanation
from ..models.repositories import (
    AlertRepository,
    AuditRepository,
    CorrelationRepository,
    DedupeStateRepository,
    IncidentRepository,
)
from .dependencies import SessionFactoryDependency
from .n8n_auth import RequireN8NToken

logger = get_logger("soc_triage.explanations")

router = APIRouter(prefix="/api/v1/alerts", tags=["explanations"])


@router.get(
    "/{alert_id}/explanation",
    response_model=ExplanationRead,
    status_code=status.HTTP_200_OK,
    summary="Get the deterministic explanation for a persisted alert",
    description=(
        "Return a versioned, deterministic explanation assembled exclusively "
        "from already-persisted facts: alert summary, detection metadata, "
        "the stored scoring.v1 assessment with its ordered factor breakdown "
        "(reconciled against the authoritative score), the stored "
        "decisions.v1 routing decision with its exact reasons, dedupe/"
        "recurrence facts, the correlation.v1 context and evidence when "
        "present, incident linkage, IOCs, enrichment status, and the audit "
        "history. Missing facts are explicit nulls — nothing is inferred. "
        "Read-only: never mutates state, never includes full_log, "
        "credentials, or tokens. Unknown ids return a structured 404. "
        "Requires the shared N8N token."
    ),
)
async def get_alert_explanation(
    session_factory: SessionFactoryDependency,
    alert_id: Annotated[UUID, Path(description="Alert ID")],
    _: None = RequireN8NToken,
) -> ExplanationRead | JSONResponse:
    """Return the deterministic explanation for one alert, or a structured 404."""
    try:
        with session_scope(session_factory) as session:
            record = AlertRepository(session).get_alert(alert_id)
            if record is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"alert {alert_id} not found",
                )
            # Read-only lookups only: group_state() never prunes, and no
            # repository call here inserts, updates, or deletes.
            group_state = DedupeStateRepository(session).group_state(record.dedupe_group_key)
            incident = IncidentRepository(session).for_alert(alert_id)
            correlation_repo = CorrelationRepository(session)
            context = correlation_repo.context_for_alert(alert_id)
            members = correlation_repo.members(context.context_id) if context is not None else []
            entity_ids = [str(alert_id), record.dedupe_group_key]
            if incident is not None:
                entity_ids.append(incident.incident_id)
            audit_records = AuditRepository(session).for_entity_ids(entity_ids)
        explanation = build_explanation(
            record=record,
            group_state=group_state,
            incident=incident,
            context=context,
            members=members,
            audit_records=audit_records,
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "alert_explanation_failed",
            component="explanations",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to build alert explanation",
        )
    logger.info("alert_explanation_read", component="explanations", alert_id=str(alert_id))
    return explanation


__all__ = ["router"]
