"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from ..core.config import Settings


def get_app_settings(request: Request) -> Settings:
    """Return the settings object bound to the running application."""
    return request.app.state.settings


SettingsDependency = Annotated[Settings, Depends(get_app_settings)]


__all__ = ["SettingsDependency", "get_app_settings"]
