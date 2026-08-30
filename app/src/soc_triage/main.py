"""FastAPI application factory for the SOC Triage API."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.exc import SQLAlchemyError

from . import __version__
from .api.router import api_router
from .core.config import Settings, get_settings
from .core.errors import register_exception_handlers
from .core.logging import configure_logging, get_logger
from .db.engine import (
    ALEMBIC_SCRIPT_LOCATION,
    create_app_engine,
    create_session_factory,
    run_migrations,
)
from .decisions import DecisionEngine, default_decision_policy
from .enrichment import EnrichmentChain
from .enrichment.misp import MISPProvider
from .enrichment.providers import EnrichmentProvider, NoOpEnrichmentProvider
from .enrichment.virustotal import VirusTotalProvider
from .scoring import RiskScorer, default_scoring_policy

logger = get_logger("soc_triage.main")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure a Triage API application instance.

    ``settings`` may be injected during tests; when omitted the settings are
    loaded from the process environment.
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

        # --- Persistent storage (Phase 1D) ---
        # Engine + migrations first: the app refuses to serve rather than run
        # against a missing/incompatible schema (fail loud, ARCHITECTURE §16).
        engine = create_app_engine(app_settings.triage_db_url)
        try:
            run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
        except SQLAlchemyError as exc:
            engine.dispose()
            # Exception type only — the DB URL may carry credentials.
            logger.critical(
                "database_migrations_failed",
                component="main",
                error_type=type(exc).__name__,
            )
            raise

        session_factory = create_session_factory(engine)
        _app.state.db_engine = engine
        _app.state.session_factory = session_factory

        from .ingest.persistent_deduplication import PersistentDeduplicator

        # Phase 1D deduplication: the same contract as Phase 1C, but with
        # SQLite as the system of record — recurrence state, alerts and audit
        # entries survive restarts (ARCHITECTURE.md §6).
        deduplicator = PersistentDeduplicator(
            session_factory,
            window_seconds=app_settings.triage_dedupe_window_seconds,
        )
        _app.state.deduplicator = deduplicator
        logger.info(
            "database_ready",
            component="main",
            dialect=engine.dialect.name,
            dedupe_window_seconds=app_settings.triage_dedupe_window_seconds,
        )

        # --- IOC extraction & enrichment (Phase 1E / 2A) ---
        # Extraction is pure (no I/O). Enrichment providers are registered in
        # a fixed order: the offline no-op (disabled), then VirusTotal and MISP
        # — both optional and **disabled by default** (empty key/URL ⇒ never
        # called). With no key configured, ingestion performs zero external
        # calls and reports `enrichment_status: skipped` (ARCHITECTURE.md §7.3).
        enrichment_providers: list[EnrichmentProvider] = [
            NoOpEnrichmentProvider(),
            VirusTotalProvider(
                api_key=app_settings.virustotal_api_key.get_secret_value() or None,
            ),
            MISPProvider(
                url=app_settings.misp_url,
                api_key=app_settings.misp_api_key.get_secret_value() or None,
                verify_tls=app_settings.misp_verify_tls,
            ),
        ]
        enrichment_chain = EnrichmentChain(enrichment_providers)
        _app.state.enrichment_chain = enrichment_chain
        logger.info(
            "enrichment_ready",
            component="main",
            providers=[provider.name for provider in enrichment_chain.providers],
            enabled_providers=[
                provider.name for provider in enrichment_chain.providers if provider.enabled
            ],
        )

        # --- Deterministic scoring & decisioning (Phase 1F) ---
        # Policies are versioned, non-secret YAML under app/config/ and are
        # schema-validated at load (fail loud). Both engines are pure —
        # zero I/O, zero external calls (ARCHITECTURE.md §8, §9, §12).
        scoring_policy = default_scoring_policy()
        decision_policy = default_decision_policy()
        _app.state.scorer = RiskScorer(scoring_policy)
        _app.state.decider = DecisionEngine(decision_policy)
        logger.info(
            "scoring_ready",
            component="main",
            engine_version=scoring_policy.engine_version,
            decision_policy=decision_policy.policy_version,
        )

        try:
            yield
        finally:
            engine.dispose()
            logger.info("application_stopped", component="main")

    app = FastAPI(
        title="SOC Alert Triage API",
        version=__version__,
        description=(
            "Defensive SOC alert triage pipeline (Phase 1F: ingest, dedupe, persistent "
            "storage, audit, IOC extraction & enrichment interface, deterministic "
            "risk scoring & decision engine)."
        ),
        lifespan=lifespan,
    )
    app.state.settings = app_settings

    register_exception_handlers(app)
    app.include_router(api_router)
    return app


app = create_app()


__all__ = ["app", "create_app"]
