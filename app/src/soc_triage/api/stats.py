"""Read-only daily SOC statistics API (Phase 3.9).

The endpoint exposes only bounded aggregates from a previous UTC calendar day
by default. An explicit ``date=YYYY-MM-DD`` is supported for repeatable
reports and backfills. Authentication reuses the existing shared n8n token;
no stats request writes audit rows or changes scoring, decisions, or Wazuh
rules.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated

from fastapi import APIRouter, Query, status
from fastapi.responses import JSONResponse

from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.repositories import StatsRepository
from ..services.stats import StatsService
from .dependencies import SessionFactoryDependency
from .n8n_auth import RequireN8NToken
from .schemas import DailyStatsResponse, daily_stats_from_record

logger = get_logger("soc_triage.stats")

router = APIRouter(prefix="/api/v1/stats", tags=["stats"])


def _utc_now() -> datetime:
    """Clock seam used to select the previous UTC date by default."""
    return datetime.now(UTC)


@router.get(
    "/daily",
    response_model=DailyStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get aggregate daily SOC statistics",
    description=(
        "Return alert, incident, and feedback volumes, false-positive rate, "
        "top rules, and human-review tuning suggestions for a half-open UTC "
        "calendar-day window. Without date, the previous UTC day is used. "
        "Requires the shared n8n token."
    ),
)
async def get_daily_stats(
    session_factory: SessionFactoryDependency,
    report_date: Annotated[
        date | None,
        Query(alias="date", description="UTC reporting date in YYYY-MM-DD format"),
    ] = None,
    _: None = RequireN8NToken,
) -> DailyStatsResponse | JSONResponse:
    """Return aggregate daily statistics without exposing alert payloads."""
    try:
        with session_scope(session_factory) as session:
            record = StatsService(StatsRepository(session)).daily(
                report_date=report_date,
                now=_utc_now(),
            )
            response = daily_stats_from_record(record)
    except Exception as exc:  # pragma: no cover - defensive storage boundary
        logger.error(
            "daily_stats_failed",
            component="stats",
            error_type=type(exc).__name__,
            report_date=report_date.isoformat() if report_date else None,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to build daily statistics",
        )

    logger.info(
        "daily_stats_read",
        component="stats",
        report_date=response.date,
        timezone=response.timezone,
        alert_count=response.volumes.alerts,
        incident_count=response.volumes.incidents,
        feedback_count=response.volumes.feedback,
    )
    return response


__all__ = ["router"]
