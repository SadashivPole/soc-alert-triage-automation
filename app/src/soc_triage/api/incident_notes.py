"""Incident investigation notes API (Phase 4.2)."""

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

logger = get_logger("soc_triage.incident_notes")

router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["incident-notes"],
)

ACTION_INCIDENT_NOTE_ADDED = "incident.note_added"
ENTITY_INCIDENT = "incident"


class IncidentNoteCreateRequest(BaseModel):
    """Request body for adding an investigation note."""

    note: str = Field(
        min_length=1,
        max_length=2000,
        description="Analyst investigation note.",
    )
    actor: str | None = Field(
        default=None,
        max_length=128,
        description="Analyst identifier (email/name).",
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _note_from_audit(record: Any) -> dict[str, Any]:
    after = record.after or {}
    return {
        "actor": record.actor,
        "note": str(after.get("note", "")),
        "created_at": record.occurred_at.isoformat(),
    }


@router.post(
    "/{incident_id}/notes",
    status_code=status.HTTP_201_CREATED,
    summary="Add an investigation note to an incident",
)
async def add_incident_note(
    session_factory: SessionFactoryDependency,
    incident_id: Annotated[
        str,
        Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)"),
    ],
    body: IncidentNoteCreateRequest,
    _: None = RequireN8NToken,
) -> JSONResponse:
    """Append one investigation note to an incident."""

    occurred_at = _utc_now()
    actor = (body.actor or "analyst").strip() or "analyst"
    note = body.note.strip()

    if not note:
        return error_response(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "validation_error",
            "note must not be empty",
        )

    try:
        with session_scope(session_factory) as session:
            incident = IncidentRepository(session).get_incident(incident_id)
            if incident is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"incident {incident_id} not found",
                )

            AuditRepository(session).append(
                [
                    AuditEntry(
                        actor=actor,
                        action=ACTION_INCIDENT_NOTE_ADDED,
                        entity_type=ENTITY_INCIDENT,
                        entity_id=incident_id,
                        before=None,
                        after={"note": note},
                    )
                ],
                occurred_at=occurred_at,
            )

    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "incident_note_add_failed",
            component="incident_notes",
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to add incident note",
        )

    logger.info(
        "incident_note_added",
        component="incident_notes",
        incident_id=incident_id,
        actor=actor,
    )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "incident_id": incident_id,
            "actor": actor,
            "note": note,
            "created_at": occurred_at.isoformat(),
        },
    )


@router.get(
    "/{incident_id}/notes",
    status_code=status.HTTP_200_OK,
    summary="List investigation notes for an incident",
)
async def list_incident_notes(
    session_factory: SessionFactoryDependency,
    incident_id: Annotated[
        str,
        Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)"),
    ],
    _: None = RequireN8NToken,
) -> JSONResponse:
    """Return incident investigation notes in chronological order."""

    try:
        with session_scope(session_factory) as session:
            incident = IncidentRepository(session).get_incident(incident_id)
            if incident is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"incident {incident_id} not found",
                )

            records = AuditRepository(session).for_entity_ids([incident_id])
            notes = [
                _note_from_audit(record)
                for record in records
                if record.action == ACTION_INCIDENT_NOTE_ADDED
            ]

    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "incident_notes_read_failed",
            component="incident_notes",
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load incident notes",
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "incident_id": incident_id,
            "notes": notes,
        },
    )


__all__ = [
    "ACTION_INCIDENT_NOTE_ADDED",
    "IncidentNoteCreateRequest",
    "router",
]
