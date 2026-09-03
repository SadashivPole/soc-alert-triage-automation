"""Incident lifecycle API (Phase 3.2).

Endpoints:
* PATCH /api/v1/incidents/{incident_id}/status — move an incident through its
  lifecycle along the explicit state machine (``open`` → ``investigating`` /
  ``acknowledged`` / ``false_positive`` / ``escalated`` → terminal states).

Security (consistent with the analyst feedback endpoint conventions):
* Requires the shared N8N token (X-N8N-Token / X-Callback-Token / Bearer) —
  the same analyst channel the n8n workflows use for feedback; a separate
  analyst token for read/admin surfaces arrives with the later console
  milestone (ARCHITECTURE.md §19).
* No destructive actions: the endpoint only moves the lifecycle state.
* The state machine is enforced server-side; unknown incidents return a
  structured 404 and illegal transitions a structured 409 (never a silent
  no-op).
* Append-only audit: every change writes ``incident.status_updated`` (and
  ``incident.escalated`` when escalating) with actor, incident id and
  before/after state — small structured snapshots, never raw alert payloads
  and never secrets (SECURITY.md §5, §7).

Read surface (GET /incidents, GET /incidents/{id}, timelines, stats) belongs
to a later milestone and is intentionally not implemented here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..audit import audit_entries_for_incident_status
from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.incident import (
    VALID_TRANSITIONS,
    IncidentStatus,
    InvalidIncidentTransitionError,
)
from ..models.repositories import AuditRepository, IncidentRepository
from .dependencies import SessionFactoryDependency
from .n8n_auth import RequireN8NToken

logger = get_logger("soc_triage.incidents")

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class IncidentStatusUpdateRequest(BaseModel):
    """Request body for an incident status update."""

    status: IncidentStatus = Field(description="Target lifecycle status")
    notes: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional analyst notes (recorded in the audit entry)",
    )
    actor: str | None = Field(
        default=None, max_length=128, description="Analyst identifier (email/name)"
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


@router.patch(
    "/{incident_id}/status",
    status_code=status.HTTP_200_OK,
    summary="Update an incident's lifecycle status",
    description=(
        "Move an incident to a new lifecycle status along the explicit state "
        "machine (open → investigating/acknowledged/false_positive/escalated, "
        "with terminal states resolved/false_positive). Unknown incidents "
        "return a structured 404; illegal transitions return a structured "
        "409 with the current status and the allowed targets. Requires shared "
        "N8N token authentication."
    ),
)
async def update_incident_status(
    session_factory: SessionFactoryDependency,
    incident_id: Annotated[str, Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)")],
    body: IncidentStatusUpdateRequest,
    _: None = RequireN8NToken,
) -> JSONResponse:
    """Update an incident's lifecycle status (Phase 3.2).

    Returns:
        200 with the new lifecycle state on success.
        401 if the N8N token is missing or invalid.
        404 (structured) if the incident id is unknown.
        409 (structured) if the transition is not in the state machine.
        422 if the body fails schema validation (e.g. unknown target status).
    """
    occurred_at = _utc_now()
    actor = (body.actor or "analyst").strip() or "analyst"
    notes = body.notes.strip() if body.notes else None
    if notes and len(notes) > 2000:
        notes = notes[:2000]

    try:
        with session_scope(session_factory) as session:
            repo = IncidentRepository(session)
            current = repo.get(incident_id)
            if current is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"incident {incident_id} not found",
                )
            try:
                updated = repo.update_status(
                    incident_id,
                    target=body.status,
                    occurred_at=occurred_at,
                )
            except InvalidIncidentTransitionError as exc:
                return error_response(
                    status.HTTP_409_CONFLICT,
                    "conflict",
                    str(exc),
                    details={
                        "incident_id": incident_id,
                        "current_status": current.status.value,
                        "requested_status": body.status.value,
                        "allowed_transitions": sorted(
                            s.value for s in VALID_TRANSITIONS.get(current.status, frozenset())
                        ),
                    },
                )
            AuditRepository(session).append(
                audit_entries_for_incident_status(
                    incident=updated,
                    previous_status=current.status,
                    actor=actor,
                    notes=notes,
                ),
                occurred_at=occurred_at,
            )
        response = JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "incident_id": updated.incident_id,
                "previous_status": current.status.value,
                "status": updated.status.value,
                "updated_at": updated.updated_at.isoformat(),
                "acknowledged_at": (
                    updated.acknowledged_at.isoformat()
                    if updated.acknowledged_at is not None
                    else None
                ),
                "resolved_at": (
                    updated.resolved_at.isoformat() if updated.resolved_at is not None else None
                ),
            },
        )
    except Exception as exc:  # pragma: no cover - defensive, should not happen
        logger.error(
            "incident_status_update_failed",
            component="incidents",
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to update incident status",
        )

    logger.info(
        "incident_status_updated",
        component="incidents",
        incident_id=incident_id,
        before=current.status.value,
        after=updated.status.value,
        actor=actor,
    )
    return response


__all__ = ["IncidentStatusUpdateRequest", "router"]
