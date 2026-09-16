"""Incident investigation evidence API (Phase 4.3)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.repositories import AlertRepository, CorrelationRepository, IncidentRepository
from .dependencies import SessionFactoryDependency
from .n8n_auth import RequireN8NToken
from .schemas import (
    AlertDetail,
    CorrelationContextDetailRead,
    alert_detail_from_record,
    correlation_detail_from_records,
)

logger = get_logger("soc_triage.incident_evidence")

router = APIRouter(
    prefix="/api/v1/incidents",
    tags=["incident-evidence"],
)


class IncidentEvidenceResponse(BaseModel):
    """Analyst-safe evidence aggregated for one incident."""

    model_config = {"frozen": True}

    incident_id: str
    alert_count: int = Field(ge=0)
    ioc_count: int = Field(ge=0)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[AlertDetail] = Field(default_factory=list)
    correlation_contexts: list[CorrelationContextDetailRead] = Field(default_factory=list)


def _ioc_key(ioc: Any) -> tuple[str, str]:
    """Return a deterministic identity key for an IOC."""

    return (
        str(getattr(ioc, "type", "")),
        str(getattr(ioc, "value", "")),
    )


@router.get(
    "/{incident_id}/evidence",
    response_model=IncidentEvidenceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get investigation evidence for an incident",
    description=(
        "Return a deterministic, read-only investigation evidence view for one "
        "incident. The response aggregates linked analyst-safe alert details, "
        "unique IOC summaries, and correlated investigation contexts. It never "
        "returns full_log, raw source-event payloads, credentials, or tokens. "
        "Unknown incidents return a structured 404. Requires the shared N8N token."
    ),
)
async def get_incident_evidence(
    session_factory: SessionFactoryDependency,
    incident_id: Annotated[
        str,
        Path(description="Incident ID (INC-YYYY-MM-DD-NNNN)"),
    ],
    _: None = RequireN8NToken,
) -> IncidentEvidenceResponse | JSONResponse:
    """Return read-only evidence aggregated from the incident's linked alerts."""

    try:
        with session_scope(session_factory) as session:
            incident = IncidentRepository(session).get_incident(incident_id)

            if incident is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"incident {incident_id} not found",
                )

            linked_records = AlertRepository(session).for_incident(incident_id)

            alert_details = [alert_detail_from_record(record) for record in linked_records]

            ioc_map: dict[tuple[str, str], dict[str, Any]] = {}

            for alert in alert_details:
                for ioc in alert.iocs:
                    key = (ioc.type, ioc.value)

                    if key not in ioc_map:
                        ioc_map[key] = ioc.model_dump(mode="json")

            correlation_repo = CorrelationRepository(session)

            correlation_map: dict[str, CorrelationContextDetailRead] = {}

            for record in linked_records:
                context = correlation_repo.context_for_alert(record.alert_id)

                if context is None:
                    continue

                if context.context_id in correlation_map:
                    continue

                members = correlation_repo.members(context.context_id)

                detail = correlation_detail_from_records(
                    context,
                    members,
                )

                correlation_map[context.context_id] = detail

            iocs = [ioc_map[key] for key in sorted(ioc_map)]

            correlations = [correlation_map[key] for key in sorted(correlation_map)]

            response = IncidentEvidenceResponse(
                incident_id=incident_id,
                alert_count=len(alert_details),
                ioc_count=len(iocs),
                iocs=iocs,
                alerts=alert_details,
                correlation_contexts=correlations,
            )

    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "incident_evidence_failed",
            component="incident_evidence",
            incident_id=incident_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load incident investigation evidence",
        )

    logger.info(
        "incident_evidence_read",
        component="incident_evidence",
        incident_id=incident_id,
        alert_count=response.alert_count,
        ioc_count=response.ioc_count,
        correlation_count=len(response.correlation_contexts),
    )

    return response


__all__ = ["router"]
