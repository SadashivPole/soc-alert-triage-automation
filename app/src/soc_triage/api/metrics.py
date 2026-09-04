"""Prometheus text exposition endpoint (Phase 3.7, Task D4).

``GET /metrics`` exposes the app-scoped ``soc_triage_`` metrics in the
Prometheus text exposition format (``text/plain; version=0.0.4;
charset=utf-8``). It is hidden from OpenAPI and only mounted when
``METRICS_ENABLED=true`` — when disabled the route does not exist at all
(environment-gated endpoint convention, ARCHITECTURE.md §14).

Authentication (approved decision D1): optional bearer auth driven by
``METRICS_SCRAPE_TOKEN``.

* Empty token → authentication disabled (development-compatible default).
* Non-empty token → ``Authorization: Bearer <token>`` required, verified
  with constant-time comparison (same pattern as :mod:`.n8n_auth` and
  :mod:`soc_triage.ingest.auth`). The ingest API key and N8N tokens are
  never accepted.

Security invariants: the configured token never appears in response bodies,
headers, logs, or error messages; scraping performs no database *writes*
(only the cheap, read-only liveness/migration pings allowed by decision D3);
rendering is non-load-bearing and never alters pipeline behavior.
"""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from ..core.config import Settings
from ..core.logging import get_logger
from .dependencies import DbEngineDependency, MetricsDependency
from .health import _db_alive, _migrations_applied

logger = get_logger("soc_triage.api.metrics")

router = APIRouter(tags=["metrics"])

#: Exact Prometheus exposition content type (charset included so Starlette
#: does not append a second ``charset`` parameter).
METRICS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time (timing-attack safe)."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _extract_bearer_token(authorization: str | None) -> str | None:
    """Extract the credential from an ``Authorization: Bearer <token>`` header.

    Returns ``None`` for a missing header, a non-Bearer scheme, or a header
    without a credential (malformed).
    """
    if not authorization:
        return None
    auth = authorization.strip()
    if not auth.lower().startswith("bearer "):
        return None
    credential = auth[7:].strip()
    return credential or None


def verify_metrics_token(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> None:
    """Verify the optional Bearer token for GET /metrics.

    Empty ``METRICS_SCRAPE_TOKEN`` = authentication disabled (no-op). When
    configured, a missing/malformed/wrong Bearer credential raises a 401.
    The configured token is compared in constant time and is never logged.

    Raises:
        HTTPException: 401 for missing, malformed, or invalid credentials.
    """
    settings: Settings = request.app.state.settings
    configured = settings.metrics_scrape_token.get_secret_value()
    if not configured:
        return

    supplied = _extract_bearer_token(authorization)
    if supplied is None:
        logger.warning(
            "metrics_auth_failed",
            component="metrics",
            reason="missing_or_malformed_bearer_token",
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )

    if not _constant_time_compare(supplied, configured):
        logger.warning(
            "metrics_auth_failed",
            component="metrics",
            reason="invalid_bearer_token",
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )


#: FastAPI dependency alias for cleaner route signatures.
RequireMetricsToken = Depends(verify_metrics_token)


@router.get(
    "/metrics",
    include_in_schema=False,
    summary="Prometheus metrics",
    description=(
        "Expose app-scoped Prometheus metrics in text exposition format. "
        "Optional Bearer authentication via METRICS_SCRAPE_TOKEN."
    ),
)
async def metrics_exposition(
    metrics: MetricsDependency,
    engine: DbEngineDependency,
    _: None = RequireMetricsToken,
) -> PlainTextResponse:
    """Render the app-scoped ``soc_triage_`` metrics exposition.

    Health gauges are refreshed from the cheap, read-only DB pings (one
    ``SELECT 1`` and one ``alembic_version`` read per scrape, decision D3);
    no other database access and never a write. Rendering is non-load-bearing
    and cannot alter pipeline behavior.
    """
    db_ok = _db_alive(engine)
    metrics.set_database_up(db_ok)
    metrics.set_migrations_applied(db_ok and _migrations_applied(engine))
    return PlainTextResponse(metrics.render_text(), media_type=METRICS_CONTENT_TYPE)


__all__ = [
    "METRICS_CONTENT_TYPE",
    "RequireMetricsToken",
    "metrics_exposition",
    "router",
    "verify_metrics_token",
]
