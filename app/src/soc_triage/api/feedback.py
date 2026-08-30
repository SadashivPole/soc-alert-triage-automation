"""Analyst feedback / acknowledgement webhook (Phase 2B).

Endpoints:
* POST /api/v1/alerts/{alert_id}/feedback — submit verdict
* GET /api/v1/alerts/{alert_id}/feedback/status — read-only acknowledgement status

This is the callback target for n8n workflows (WF2/WF3/WF5). Analysts submit
a verdict via n8n form → n8n POSTs here with the shared token. The feedback
is persisted, audited, and can feed future tuning.

For SLA escalation (WF3), a dedicated read-only status endpoint is required:
GET /feedback/status returns whether the alert has been acknowledged/resolved.
WF3 must NOT misuse POST /feedback to query status (Phase 2B fix).

Security:
* Requires shared N8N token (X-N8N-Token / X-Callback-Token / Bearer)
* No destructive actions — only stores verdict/notes
* Verdict is validated against an allow-list
* Notes truncated to 2000 chars (ORM limit)
* Fail-closed when token not configured (503)

Persistence:
* analyst_feedback table (append-only for this entity)
* audit_log: feedback.received
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Path, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..audit import audit_entries_for_feedback
from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.repositories import AlertRepository, AuditRepository, FeedbackRepository
from .dependencies import SessionFactoryDependency
from .n8n_auth import RequireN8NToken

logger = get_logger("soc_triage.feedback")

router = APIRouter(prefix="/api/v1/alerts", tags=["feedback"])


class FeedbackVerdict(StrEnum):
    """Allowed analyst verdicts (no autonomous containment)."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    ESCALATE = "escalate"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    CONTAIN_REQUESTED = "contain_requested"  # human approval required, not autonomous


class FeedbackRequest(BaseModel):
    """Request body for feedback submission."""

    verdict: FeedbackVerdict = Field(description="Analyst verdict")
    notes: str | None = Field(default=None, max_length=2000, description="Optional analyst notes")
    actor: str | None = Field(
        default=None, max_length=128, description="Analyst identifier (email/name)"
    )


class FeedbackResponse(BaseModel):
    """Response after storing feedback."""

    status: str = "accepted"
    alert_id: str
    verdict: str
    received_at: str


def _utc_now() -> datetime:
    return datetime.now(UTC)


# Verdicts that count as acknowledgement for SLA purposes
ACKNOWLEDGED_VERDICTS: frozenset[str] = frozenset(
    {
        FeedbackVerdict.ACKNOWLEDGED.value,
        FeedbackVerdict.RESOLVED.value,
        FeedbackVerdict.TRUE_POSITIVE.value,
        FeedbackVerdict.FALSE_POSITIVE.value,
        FeedbackVerdict.BENIGN.value,
        FeedbackVerdict.ESCALATE.value,
        FeedbackVerdict.CONTAIN_REQUESTED.value,
    }
)


@router.post(
    "/{alert_id}/feedback",
    status_code=status.HTTP_200_OK,
    summary="Submit analyst feedback for an alert",
    description=(
        "Accept analyst feedback (verdict + notes) for an alert. "
        "Called by n8n workflows after analyst acknowledgement via form/email. "
        "Requires shared N8N token authentication."
    ),
)
async def submit_feedback(
    session_factory: SessionFactoryDependency,
    alert_id: Annotated[UUID, Path(description="Alert ID")],
    body: FeedbackRequest,
    _: None = RequireN8NToken,
) -> JSONResponse:
    received_at = _utc_now()

    # Verify alert exists
    try:
        with session_scope(session_factory) as session:
            repo = AlertRepository(session)
            existing = repo.get(alert_id)
            if existing is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"alert {alert_id} not found",
                )

            # Persist feedback
            feedback_repo = FeedbackRepository(session)
            actor = (body.actor or "analyst").strip() or "analyst"
            notes = body.notes.strip() if body.notes else None
            if notes and len(notes) > 2000:
                notes = notes[:2000]

            feedback_repo.add(
                alert_id=alert_id,
                actor=actor,
                verdict=body.verdict.value,
                notes=notes,
                received_at=received_at,
            )

            # Audit
            audit_repo = AuditRepository(session)
            audit_repo.append(
                audit_entries_for_feedback(
                    alert_id,
                    verdict=body.verdict.value,
                    actor=actor,
                ),
                occurred_at=received_at,
            )

        logger.info(
            "feedback_received",
            component="feedback",
            alert_id=str(alert_id),
            verdict=body.verdict.value,
            actor=actor,
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "accepted",
                "alert_id": str(alert_id),
                "verdict": body.verdict.value,
                "received_at": received_at.isoformat(),
            },
        )

    except Exception as exc:  # pragma: no cover - defensive, should not happen
        logger.error(
            "feedback_storage_failed",
            component="feedback",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to store feedback",
        )


@router.get(
    "/{alert_id}/feedback/status",
    status_code=status.HTTP_200_OK,
    summary="Get acknowledgement status for an alert",
    description=(
        "Read-only status endpoint for SLA escalation checks (WF3). "
        "Returns whether the alert has been acknowledged/resolved via feedback. "
        "Does NOT create feedback — safe to call after SLA wait. "
        "If the endpoint fails, WF3 should escalate (fail-safe for SLA). "
        "Requires shared N8N token authentication."
    ),
)
async def get_feedback_status(
    session_factory: SessionFactoryDependency,
    alert_id: Annotated[UUID, Path(description="Alert ID")],
    _: None = RequireN8NToken,
) -> JSONResponse:
    """Return acknowledgement status for an alert (read-only, Phase 2B fix)."""
    try:
        with session_scope(session_factory) as session:
            # Verify alert exists
            alert_repo = AlertRepository(session)
            existing = alert_repo.get(alert_id)
            if existing is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"alert {alert_id} not found",
                )

            feedback_repo = FeedbackRepository(session)
            feedbacks = feedback_repo.for_alert(alert_id)

            acknowledged = False
            latest_verdict: str | None = None
            acknowledged_at: str | None = None

            if feedbacks:
                # Latest feedback by received_at
                latest = feedbacks[-1]
                latest_verdict = latest.verdict
                # Any feedback counts as acknowledgement for SLA
                # (all verdicts in allow-list indicate analyst action)
                if latest.verdict in ACKNOWLEDGED_VERDICTS:
                    acknowledged = True
                    acknowledged_at = latest.received_at.isoformat()

        logger.info(
            "feedback_status_checked",
            component="feedback",
            alert_id=str(alert_id),
            acknowledged=acknowledged,
            feedback_count=len(feedbacks) if "feedbacks" in locals() else 0,
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "alert_id": str(alert_id),
                "acknowledged": acknowledged,
                "has_feedback": bool(feedbacks) if "feedbacks" in locals() else False,
                "feedback_count": len(feedbacks) if "feedbacks" in locals() else 0,
                "latest_verdict": latest_verdict,
                "acknowledged_at": acknowledged_at,
                "checked_at": _utc_now().isoformat(),
            },
        )

    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "feedback_status_check_failed",
            component="feedback",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to check feedback status",
        )


__all__ = ["FeedbackRequest", "FeedbackResponse", "FeedbackVerdict", "router"]
