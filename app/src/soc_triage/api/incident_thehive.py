"""TheHive case export API (Phase 4.6)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse

from ..audit import AuditEntry
from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.repositories import (
    AlertRepository,
    AuditRepository,
    IncidentRepository,
)
from ..thehive import (
    TheHiveAuthenticationError,
    TheHiveClient,
    TheHiveError,
    TheHiveNotConfiguredError,
    TheHiveUnavailableError,
)
from ..thehive.export import build_thehive_case_export
from ..timeline import build_timeline
from .dependencies import SessionFactoryDependency, SettingsDependency
from .n8n_auth import RequireN8NToken
from .schemas import alert_detail_from_record

logger = get_logger("soc_triage.incident_thehive")

router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["incident-thehive"],
)

ACTION_INCIDENT_THEHIVE_EXPORTED = "incident.thehive_exported"
ENTITY_INCIDENT = "incident"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _existing_case_mapping(records: list[Any], incident_id: str) -> str | None:
    """Return an existing successful TheHive case id, if already exported."""

    for record in reversed(records):
        if getattr(record, "action", None) != ACTION_INCIDENT_THEHIVE_EXPORTED:
            continue

        if getattr(record, "entity_id", None) != incident_id:
            continue

        after = record.after or {}
        case_id = after.get("case_id")

        if isinstance(case_id, str) and case_id.strip():
            return case_id.strip()

    return None


@router.post(
    "/{incident_id}/thehive",
    status_code=status.HTTP_201_CREATED,
    summary="Export an incident to TheHive",
    description=(
        "Create a TheHive case from a safe incident representation. "
        "The export includes incident metadata, linked alert identifiers, "
        "safe IOC summaries, assignment, investigation notes, and a timeline "
        "summary. Raw full_log values, secrets, credentials, and tokens are "
        "never exported. Repeated successful exports return the existing "
        "TheHive case instead of creating a duplicate."
    ),
)
async def export_incident_to_thehive(
    session_factory: SessionFactoryDependency,
    settings: SettingsDependency,
    incident_id: Annotated[
        str,
        Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)"),
    ],
    _: None = RequireN8NToken,
) -> JSONResponse:
    """Export one persisted incident to TheHive."""

    if not settings.thehive_url.strip() or not settings.thehive_api_key.get_secret_value().strip():
        return error_response(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "integration_not_configured",
            "TheHive integration is not configured",
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

            audit_repository = AuditRepository(session)
            audit_records = audit_repository.for_entity_ids([incident_id])

            existing_case_id = _existing_case_mapping(
                audit_records,
                incident_id,
            )

            if existing_case_id is not None:
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "incident_id": incident_id,
                        "case_id": existing_case_id,
                        "created": False,
                        "duplicate": True,
                    },
                )

            linked_records = AlertRepository(session).for_incident(incident_id)

            alert_details = [alert_detail_from_record(record) for record in linked_records]

            ioc_map: dict[tuple[str, str], dict[str, Any]] = {}

            for alert in alert_details:
                for ioc in alert.iocs:
                    key = (ioc.type, ioc.value)
                    if key not in ioc_map:
                        ioc_map[key] = ioc.model_dump(mode="json")

            iocs = [ioc_map[key] for key in sorted(ioc_map)]

            assignment_records = audit_repository.for_entity_ids([incident_id])
            assignee: str | None = None

            for record in reversed(assignment_records):
                if getattr(record, "action", None) != "incident.assigned":
                    continue

                after = record.after or {}
                value = after.get("assignee")
                assignee = None if value is None else str(value)

                break

            notes: list[dict[str, Any]] = []

            for record in audit_records:
                if getattr(record, "action", None) != "incident.note_added":
                    continue

                after = record.after or {}
                note = str(after.get("note", "")).strip()

                if note:
                    notes.append(
                        {
                            "actor": record.actor,
                            "note": note,
                            "created_at": record.occurred_at.isoformat(),
                        }
                    )

            entity_ids = [
                incident_id,
                *[str(record.alert_id) for record in linked_records],
            ]

            timeline_records = audit_repository.for_entity_ids(entity_ids)
            timeline_events = build_timeline(timeline_records)

            timeline = [
                {
                    "event": event.action,
                    "timestamp": event.timestamp.isoformat(),
                }
                for event in timeline_events
            ]

            incident_payload = {
                "incident_id": incident.incident_id,
                "status": incident.status.value,
                "severity": incident.severity.value,
                "primary_alert_id": str(incident.primary_alert_id),
                "dedupe_group_key": incident.dedupe_group_key,
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
                "acknowledged_at": (
                    incident.acknowledged_at.isoformat()
                    if incident.acknowledged_at is not None
                    else None
                ),
                "resolved_at": (
                    incident.resolved_at.isoformat() if incident.resolved_at is not None else None
                ),
            }

            export = build_thehive_case_export(
                incident=incident_payload,
                alerts=[
                    {
                        "alert_id": str(record.alert_id),
                    }
                    for record in linked_records
                ],
                iocs=iocs,
                assignment={"assignee": assignee},
                notes=notes,
                timeline=timeline,
            )

            client = TheHiveClient(settings)

            case_result = client.create_case(
                title=export.title,
                description=export.description,
                severity=export.severity,
                tlp=export.tlp,
                pap=export.pap,
            )

            observable_count = 0

            for observable in export.observables:
                client.create_observable(
                    case_id=case_result.case_id,
                    data_type=observable.data_type,
                    data=observable.data,
                    message=observable.message,
                )
                observable_count += 1

            occurred_at = _utc_now()

            audit_repository.append(
                [
                    AuditEntry(
                        actor="system",
                        action=ACTION_INCIDENT_THEHIVE_EXPORTED,
                        entity_type=ENTITY_INCIDENT,
                        entity_id=incident_id,
                        before=None,
                        after={
                            "incident_id": incident_id,
                            "case_id": case_result.case_id,
                            "severity": incident.severity.value,
                            "status": incident.status.value,
                            "observable_count": observable_count,
                        },
                    )
                ],
                occurred_at=occurred_at,
            )

        logger.info(
            "incident_thehive_exported",
            component="incident_thehive",
            incident_id=incident_id,
            observable_count=observable_count,
        )

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "incident_id": incident_id,
                "case_id": case_result.case_id,
                "created": True,
                "duplicate": False,
                "observable_count": observable_count,
            },
        )

    except TheHiveNotConfiguredError:
        return error_response(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "integration_not_configured",
            "TheHive integration is not configured",
        )

    except TheHiveAuthenticationError:
        logger.error(
            "incident_thehive_authentication_failed",
            component="incident_thehive",
            incident_id=incident_id,
        )
        return error_response(
            status.HTTP_502_BAD_GATEWAY,
            "external_authentication_error",
            "TheHive rejected the configured credentials",
        )

    except TheHiveUnavailableError:
        logger.error(
            "incident_thehive_unavailable",
            component="incident_thehive",
            incident_id=incident_id,
        )
        return error_response(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "external_service_unavailable",
            "TheHive server is unavailable",
        )

    except TheHiveError as exc:
        logger.error(
            "incident_thehive_export_failed",
            component="incident_thehive",
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_502_BAD_GATEWAY,
            "external_service_error",
            "TheHive export failed",
        )

    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "incident_thehive_export_unexpected_error",
            component="incident_thehive",
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to export incident to TheHive",
        )


__all__ = [
    "ACTION_INCIDENT_THEHIVE_EXPORTED",
    "router",
]
