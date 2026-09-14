"""Incident assignment API (Phase 4.1)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..audit import AuditEntry
from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.repositories import AuditRepository, IncidentRepository
from .dependencies import SessionFactoryDependency
from .n8n_auth import RequireN8NToken

logger = get_logger("soc_triage.incident_assignment")

router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["incident-assignment"],
)

ACTION_INCIDENT_ASSIGNED = "incident.assigned"
ENTITY_INCIDENT = "incident"


class IncidentAssignmentUpdateRequest(BaseModel):
    """Request body for assigning or unassigning an incident."""

    assignee: str | None = Field(
        default=None,
        max_length=128,
        description="Analyst identifier. Null unassigns the incident.",
    )
    actor: str | None = Field(
        default=None,
        max_length=128,
        description="Analyst identifier performing the change.",
    )


class IncidentAssignmentReadResponse(BaseModel):
    """Current assignment for an incident."""

    incident_id: str
    assignee: str | None = None


class IncidentAssignmentUpdateResponse(BaseModel):
    """Result of an assignment change."""

    incident_id: str
    assignee: str | None = None
    previous_assignee: str | None = None
    changed: bool


def _assignment_from_audit(record: Any) -> str | None:
    after = record.after or {}
    value = after.get("assignee")
    return str(value) if value is not None else None


def _current_assignment(records: list[Any]) -> str | None:
    for record in reversed(records):
        if getattr(record, "action", None) == ACTION_INCIDENT_ASSIGNED:
            return _assignment_from_audit(record)
    return None


async def _require_incident(
    session_factory: SessionFactoryDependency,
    incident_id: str,
) -> Any:
    with session_scope(session_factory) as session:
        incident = IncidentRepository(session).get(incident_id)
        if incident is None:
            return None
        return incident


@router.get(
    "/{incident_id}/assignment",
    response_model=IncidentAssignmentReadResponse,
    status_code=status.HTTP_200_OK,
    summary="Get incident assignment",
)
async def get_incident_assignment(
    session_factory: SessionFactoryDependency,
    incident_id: Annotated[
        str,
        Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)"),
    ],
    _: Any = RequireN8NToken,
) -> IncidentAssignmentReadResponse | JSONResponse:
    incident = await _require_incident(session_factory, incident_id)

    if incident is None:
        return error_response(
            code="not_found",
            message="Incident not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    with session_scope(session_factory) as session:
        records = AuditRepository(session).for_entity_ids([incident_id])
        assignee = _current_assignment(records)

    return IncidentAssignmentReadResponse(
        incident_id=incident_id,
        assignee=assignee,
    )


@router.patch(
    "/{incident_id}/assignment",
    response_model=IncidentAssignmentUpdateResponse,
    status_code=status.HTTP_200_OK,
    summary="Assign or unassign an incident",
)
async def update_incident_assignment(
    session_factory: SessionFactoryDependency,
    incident_id: Annotated[
        str,
        Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)"),
    ],
    body: IncidentAssignmentUpdateRequest,
    _: Any = RequireN8NToken,
) -> IncidentAssignmentUpdateResponse | JSONResponse:
    incident = await _require_incident(session_factory, incident_id)

    if incident is None:
        return error_response(
            code="not_found",
            message="Incident not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    with session_scope(session_factory) as session:
        audit_repository = AuditRepository(session)
        records = audit_repository.for_entity_ids([incident_id])
        current = _current_assignment(records)

        changed = current != body.assignee

        if changed:
            audit_repository.append(
                [
                    AuditEntry(
                        action=ACTION_INCIDENT_ASSIGNED,
                        entity_type=ENTITY_INCIDENT,
                        entity_id=incident_id,
                        actor=body.actor,
                        before={"assignee": current},
                        after={"assignee": body.assignee},
                    )
                ],
                occurred_at=datetime.now(UTC),
            )

        return IncidentAssignmentUpdateResponse(
            incident_id=incident_id,
            assignee=body.assignee,
            previous_assignee=current,
            changed=changed,
        )
