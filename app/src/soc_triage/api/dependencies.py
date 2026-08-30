"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from ..core.config import Settings
from ..ingest.deduplication import MemoryDeduplicator


def get_app_settings(request: Request) -> Settings:
    """Return the settings object bound to the running application."""
    return request.app.state.settings


def get_deduplicator(request: Request) -> MemoryDeduplicator:
    """Return the deduplicator object bound to the running application."""
    return request.app.state.deduplicator


SettingsDependency = Annotated[Settings, Depends(get_app_settings)]
DeduplicatorDependency = Annotated[MemoryDeduplicator, Depends(get_deduplicator)]


__all__ = ["DeduplicatorDependency", "SettingsDependency", "get_app_settings", "get_deduplicator"]
