"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from ..core.config import Settings
from ..ingest.deduplication import Deduplicator


def get_app_settings(request: Request) -> Settings:
    """Return the settings object bound to the running application."""
    return request.app.state.settings


def get_deduplicator(request: Request) -> Deduplicator:
    """Return the deduplicator bound to the running application.

    Typed against the ``Deduplicator`` protocol so routing depends on the
    contract, not on the persistence-backed implementation.
    """
    deduplicator: Deduplicator = request.app.state.deduplicator
    return deduplicator


def get_db_engine(request: Request) -> Engine:
    """Return the database engine bound to the running application."""
    engine: Engine = request.app.state.db_engine
    return engine


def get_session_factory(request: Request) -> sessionmaker:
    """Return the session factory bound to the running application."""
    factory: sessionmaker = request.app.state.session_factory
    return factory


SettingsDependency = Annotated[Settings, Depends(get_app_settings)]
DeduplicatorDependency = Annotated[Deduplicator, Depends(get_deduplicator)]
DbEngineDependency = Annotated[Engine, Depends(get_db_engine)]
SessionFactoryDependency = Annotated[sessionmaker, Depends(get_session_factory)]


__all__ = [
    "DbEngineDependency",
    "DeduplicatorDependency",
    "SessionFactoryDependency",
    "SettingsDependency",
    "get_app_settings",
    "get_db_engine",
    "get_deduplicator",
    "get_session_factory",
]
