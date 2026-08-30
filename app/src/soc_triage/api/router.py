"""Aggregate the Triage API's top-level router."""

from __future__ import annotations

from fastapi import APIRouter

from .alerts import router as alerts_router
from .health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(alerts_router)


__all__ = ["api_router"]
