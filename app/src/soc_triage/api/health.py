"""Liveness and readiness endpoints for the Triage API."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError
from starlette import status
from starlette.responses import JSONResponse

from .. import __version__
from ..core.errors import error_response
from ..core.logging import get_logger
from .dependencies import DbEngineDependency, SettingsDependency

logger = get_logger("soc_triage.health")
router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Liveness payload."""

    status: str
    service: str
    instance: str
    version: str
    timestamp: str
    db: str


class ReadinessResponse(BaseModel):
    """Readiness payload."""

    status: str
    checks: dict[str, str]


def _db_alive(engine: Engine) -> bool:
    """Best-effort database ping (liveness/readiness, ARCHITECTURE.md §15)."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        return False


def _migrations_applied(engine: Engine) -> bool:
    """True when Alembic has stamped at least one revision on the database."""
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1")
            ).first()
        return row is not None
    except SQLAlchemyError:
        return False


@router.get("/health", response_model=HealthResponse, summary="Service liveness")
async def health(
    settings: SettingsDependency, engine: DbEngineDependency
) -> HealthResponse | JSONResponse:
    """Report that the process and its database are alive.

    A database failure makes liveness fail (503) — the pipeline cannot serve
    ingest without storage (ARCHITECTURE.md §16: DB unavailable → 503).
    """
    if _db_alive(engine):
        return HealthResponse(
            status="ok",
            service="triage-api",
            instance=settings.soc_instance_name,
            version=__version__,
            timestamp=datetime.now(UTC).isoformat(),
            db="ok",
        )
    logger.warning("liveness_db_unavailable", component="health")
    return error_response(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "service_unavailable",
        "database unavailable",
    )


@router.get("/ready", response_model=ReadinessResponse, summary="Service readiness")
async def ready(
    settings: SettingsDependency, engine: DbEngineDependency
) -> ReadinessResponse | JSONResponse:
    """Report that the application is ready: config valid, database reachable,
    migrations applied (ARCHITECTURE.md §15)."""
    db_ok = _db_alive(engine)
    checks: dict[str, str] = {
        "config": "ok",
        "instance": settings.soc_instance_name,
        "db": "ok" if db_ok else "error",
        "migrations": "ok" if (db_ok and _migrations_applied(engine)) else "error",
    }
    if checks["db"] == "ok" and checks["migrations"] == "ok":
        return ReadinessResponse(status="ready", checks=checks)
    logger.warning("readiness_degraded", component="health", checks=checks)
    return error_response(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "service_unavailable",
        "service not ready",
    )


__all__ = ["HealthResponse", "ReadinessResponse", "router"]
