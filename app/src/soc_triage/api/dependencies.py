"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from ..core.config import Settings
from ..ingest.deduplication import Deduplicator


def get_app_settings(request: Request) -> Settings:
    """Return the settings object bound to the running application."""
    return request.app.state.settings


def get_deduplicator(request: Request) -> Deduplicator:
    """Return the deduplicator bound to the running application.

    Typed against the ``Deduplicator`` protocol so routing depends on the
    contract, not on the in-memory implementation.
    """
    deduplicator: Deduplicator = request.app.state.deduplicator
    return deduplicator


SettingsDependency = Annotated[Settings, Depends(get_app_settings)]
DeduplicatorDependency = Annotated[Deduplicator, Depends(get_deduplicator)]


__all__ = ["DeduplicatorDependency", "SettingsDependency", "get_app_settings", "get_deduplicator"]
