"""Liveness and readiness endpoints for the Triage API."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel

from .. import __version__
from .dependencies import SettingsDependency

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Liveness payload."""

    status: str
    service: str
    instance: str
    version: str
    timestamp: str


class ReadinessResponse(BaseModel):
    """Readiness payload."""

    status: str
    checks: dict[str, str]


@router.get("/health", response_model=HealthResponse, summary="Service liveness")
async def health(settings: SettingsDependency) -> HealthResponse:
    """Report that the process is alive and serving requests."""
    return HealthResponse(
        status="ok",
        service="triage-api",
        instance=settings.soc_instance_name,
        version=__version__,
        timestamp=datetime.now(UTC).isoformat(),
    )


@router.get("/ready", response_model=ReadinessResponse, summary="Service readiness")
async def ready(settings: SettingsDependency) -> ReadinessResponse:
    """Report that startup configuration is valid.

    Phase 1A has no database dependency yet, so readiness confirms the
    application configuration was validated successfully at startup.
    """
    return ReadinessResponse(
        status="ready",
        checks={"config": "ok", "instance": settings.soc_instance_name},
    )
