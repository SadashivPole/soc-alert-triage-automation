"""Cross-alert correlation read APIs (Phase 6.4).

Read-only (strictly — no audit writes, no incident transitions, no n8n /
Wazuh / intel / LLM calls, no destructive or merge endpoints):

* GET /api/v1/correlations — newest-first page of investigation contexts
* GET /api/v1/correlations/{context_id} — one context with member alerts
  and the aggregated evidence explaining why they correlate

Contexts are *built* by the ingest pipeline (``POST /api/v1/alerts/ingest``
correlates each newly recorded alert, fail-open); this surface only reads
them. Correlation never alters incident lifecycle: an alert's
``incident_id`` and ``dedupe_group_key`` are surfaced on each member row
exactly as stored, and merging or creating incidents through correlation is
not possible by design.

Security (same conventions as the other read APIs):

* Requires the shared N8N token (X-N8N-Token / X-Callback-Token / Bearer).
* Responses carry ids, rule/agent metadata, risk tier, decision action and
  evidence values (normalized indicators, agent/rule/technique ids) — never
  ``full_log``, raw source-event payloads, credentials, or tokens
  (SECURITY.md §5, §7).
* Unknown ids return a structured 404; GET never mutates or appends audit
  rows.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query, status
from fastapi.responses import JSONResponse

from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.records import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from ..models.repositories import CorrelationRepository
from .dependencies import SessionFactoryDependency
from .n8n_auth import RequireN8NToken
from .schemas import (
    CorrelationContextDetailRead,
    CorrelationListResponse,
    correlation_context_summary_from_record,
    correlation_detail_from_records,
    make_pagination,
)

logger = get_logger("soc_triage.correlations")

router = APIRouter(prefix="/api/v1/correlations", tags=["correlations"])


@router.get(
    "/",
    response_model=CorrelationListResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
@router.get(
    "",
    response_model=CorrelationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List correlation contexts",
    description=(
        "Return a newest-first page of cross-alert investigation contexts. "
        "Each context groups distinct alerts (different dedupe groups) that "
        "share deterministic evidence. Read-only. Requires the shared N8N "
        "token."
    ),
)
async def list_correlations(
    session_factory: SessionFactoryDependency,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
    _: None = RequireN8NToken,
) -> CorrelationListResponse | JSONResponse:
    """List correlation contexts (paginated, deterministic order)."""
    try:
        with session_scope(session_factory) as session:
            items, total = CorrelationRepository(session).list_contexts(limit=limit, offset=offset)
            response = CorrelationListResponse(
                items=[correlation_context_summary_from_record(item) for item in items],
                pagination=make_pagination(limit=limit, offset=offset, total=total),
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "correlation_list_failed",
            component="correlations",
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list correlation contexts",
        )
    logger.info(
        "correlations_listed",
        component="correlations",
        count=len(response.items),
        total=total,
        limit=limit,
        offset=offset,
    )
    return response


@router.get(
    "/{context_id}",
    response_model=CorrelationContextDetailRead,
    status_code=status.HTTP_200_OK,
    summary="Get a correlation context",
    description=(
        "Return one investigation context: member alert summaries (each "
        "carrying its own dedupe_group_key and incident_id), the aggregated "
        "evidence explaining why the alerts correlate, and the evidence "
        "time span. Never includes full_log, credentials, or tokens. "
        "Unknown ids return a structured 404. Read-only. Requires the "
        "shared N8N token."
    ),
)
async def get_correlation(
    session_factory: SessionFactoryDependency,
    context_id: Annotated[str, Path(description="Correlation context ID (CORR-YYYY-MM-DD-NNNN)")],
    _: None = RequireN8NToken,
) -> CorrelationContextDetailRead | JSONResponse:
    """Return one correlation context, or a structured 404."""
    try:
        with session_scope(session_factory) as session:
            repo = CorrelationRepository(session)
            context = repo.get_context(context_id)
            if context is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"correlation context {context_id} not found",
                )
            members = repo.members(context_id)
            detail = correlation_detail_from_records(context, members)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "correlation_get_failed",
            component="correlations",
            context_id=context_id,
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load correlation context",
        )
    logger.info(
        "correlation_read",
        component="correlations",
        context_id=context_id,
        member_count=detail.member_count,
    )
    return detail


__all__ = ["router"]
