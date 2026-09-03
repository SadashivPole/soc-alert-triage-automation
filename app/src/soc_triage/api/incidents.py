"""Incident lifecycle + read APIs (Phase 3.2 / 3.3).

Write:
* PATCH /api/v1/incidents/{incident_id}/status — move an incident through its
  lifecycle along the explicit state machine (``open`` → ``investigating`` /
  ``acknowledged`` / ``false_positive`` / ``escalated`` → terminal states).

Read (Phase 3.3, strictly read-only — no audit writes, no transitions, no
notifications, no external calls):
* GET /api/v1/incidents
* GET /api/v1/incidents/{incident_id}
* GET /api/v1/incidents/{incident_id}/timeline

Security (consistent with the analyst feedback endpoint conventions):
* Requires the shared N8N token (X-N8N-Token / X-Callback-Token / Bearer) —
  the same analyst channel the n8n workflows use for feedback; a separate
  analyst token for read/admin surfaces arrives with the later console
  milestone (ARCHITECTURE.md §19).
* No destructive actions: the PATCH endpoint only moves the lifecycle state;
  GET endpoints never mutate.
* The state machine is enforced server-side; unknown incidents return a
  structured 404 and illegal transitions a structured 409 (never a silent
  no-op).
* Append-only audit: every *change* writes ``incident.status_updated`` (and
  ``incident.escalated`` when escalating) with actor, incident id and
  before/after state — small structured snapshots, never raw alert payloads
  and never secrets (SECURITY.md §5, §7). GET never appends audit rows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Path, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..audit import audit_entries_for_incident_status
from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.assessment import DecisionSeverity
from ..models.incident import (
    VALID_TRANSITIONS,
    IncidentStatus,
    InvalidIncidentTransitionError,
)
from ..models.records import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from ..models.repositories import AlertRepository, AuditRepository, IncidentRepository
from ..timeline import build_timeline
from .dependencies import SessionFactoryDependency
from .n8n_auth import RequireN8NToken
from .schemas import (
    IncidentDetail,
    IncidentListResponse,
    IncidentTimelineResponse,
    incident_detail_from_domain,
    incident_summary_from_domain,
    make_pagination,
    redact_mapping,
)

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


@router.get(
    "/",
    response_model=IncidentListResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
@router.get(
    "",
    response_model=IncidentListResponse,
    status_code=status.HTTP_200_OK,
    summary="List persisted incidents",
    description=(
        "Return a newest-first page of incidents suitable for a SOC console. "
        "Filters: status, severity (SEV1/SEV2), dedupe_group_key, created_from "
        "/ created_to (inclusive, UTC). Requires the shared N8N token."
    ),
)
async def list_incidents(
    session_factory: SessionFactoryDependency,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: Annotated[DecisionSeverity | None, Query()] = None,
    dedupe_group_key: Annotated[str | None, Query()] = None,
    created_from: Annotated[datetime | None, Query()] = None,
    created_to: Annotated[datetime | None, Query()] = None,
    _: None = RequireN8NToken,
) -> IncidentListResponse | JSONResponse:
    """List persisted incidents (paginated, filtered)."""
    try:
        with session_scope(session_factory) as session:
            items, total = IncidentRepository(session).list_incidents(
                status=status_filter,
                severity=severity,
                dedupe_group_key=dedupe_group_key,
                created_from=created_from,
                created_to=created_to,
                limit=limit,
                offset=offset,
            )
            response = IncidentListResponse(
                items=[incident_summary_from_domain(item) for item in items],
                pagination=make_pagination(limit=limit, offset=offset, total=total),
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "incident_list_failed",
            component="incidents",
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list incidents",
        )
    logger.info(
        "incidents_listed",
        component="incidents",
        count=len(response.items),
        total=total,
        limit=limit,
        offset=offset,
    )
    return response


@router.get(
    "/{incident_id}",
    response_model=IncidentDetail,
    status_code=status.HTTP_200_OK,
    summary="Get a persisted incident",
    description=(
        "Return incident metadata, lifecycle timestamps, and linked-alert "
        "summaries (never raw event payloads). Unknown ids return a structured "
        "404. Requires the shared N8N token."
    ),
)
async def get_incident(
    session_factory: SessionFactoryDependency,
    incident_id: Annotated[str, Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)")],
    _: None = RequireN8NToken,
) -> IncidentDetail | JSONResponse:
    """Return one persisted incident, or a structured 404."""
    try:
        with session_scope(session_factory) as session:
            incident = IncidentRepository(session).get_incident(incident_id)
            if incident is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"incident {incident_id} not found",
                )
            linked = AlertRepository(session).for_incident(incident_id)
            detail = incident_detail_from_domain(incident, linked_alerts=linked)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "incident_get_failed",
            component="incidents",
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load incident",
        )
    logger.info("incident_read", component="incidents", incident_id=incident_id)
    return detail


@router.get(
    "/{incident_id}/timeline",
    response_model=IncidentTimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get an incident timeline",
    description=(
        "Return a chronological, deterministic timeline assembled from "
        "existing audit rows (incident.created, status_updated, escalated, "
        "linked alert created/scored/decided, feedback). Read-only: does not "
        "write audit events, mutate state, or call n8n/Wazuh/intel/LLM. "
        "Unknown incidents return a structured 404. Requires the shared N8N token."
    ),
)
async def get_incident_timeline(
    session_factory: SessionFactoryDependency,
    incident_id: Annotated[str, Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)")],
    _: None = RequireN8NToken,
) -> IncidentTimelineResponse | JSONResponse:
    """Build a read-only incident timeline from existing audit events."""
    try:
        with session_scope(session_factory) as session:
            incident = IncidentRepository(session).get_incident(incident_id)
            if incident is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"incident {incident_id} not found",
                )
            linked = AlertRepository(session).for_incident(incident_id)
            entity_ids = [incident_id, *[str(record.alert_id) for record in linked]]
            records = AuditRepository(session).for_entity_ids(entity_ids)
            events = build_timeline(records)
            # Defense in depth: never forward secret-bearing snapshot keys.
            sanitized = [
                event.model_copy(
                    update={
                        "before": redact_mapping(event.before)
                        if event.before is not None
                        else None,
                        "after": redact_mapping(event.after) if event.after is not None else None,
                        "metadata": redact_mapping(event.metadata),
                    }
                )
                for event in events
            ]
            response = IncidentTimelineResponse(incident_id=incident_id, events=sanitized)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "incident_timeline_failed",
            component="incidents",
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load incident timeline",
        )
    logger.info(
        "incident_timeline_read",
        component="incidents",
        incident_id=incident_id,
        event_count=len(response.events),
    )
    return response


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
