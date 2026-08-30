"""FastAPI application factory for the SOC Triage API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import __version__
from .api.router import api_router
from .core.config import Settings, get_settings
from .core.errors import register_exception_handlers
from .core.logging import configure_logging, get_logger

logger = get_logger("soc_triage.main")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure a Triage API application instance.

    ``settings`` may be injected during tests/liability environments; when
    omitted the settings are loaded from the process environment.
    """
    app_settings = settings or get_settings()
    configure_logging(app_settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "application_started",
            component="main",
            environment=app_settings.soc_env,
            instance=app_settings.soc_instance_name,
            version=__version__,
        )
        yield
        logger.info("application_stopped", component="main")

    app = FastAPI(
        title="SOC Alert Triage API",
        version=__version__,
        description="Defensive SOC alert triage foundation (Phase 1A).",
        lifespan=lifespan,
    )
    app.state.settings = app_settings

    from .ingest.deduplication import MemoryDeduplicator

    app.state.deduplicator = MemoryDeduplicator(
        window_seconds=app_settings.triage_dedupe_window_seconds
    )

    register_exception_handlers(app)
    app.include_router(api_router)
    return app


app = create_app()


__all__ = ["app", "create_app"]
