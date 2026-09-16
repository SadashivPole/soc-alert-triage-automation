"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from ..core.config import Settings
from ..core.metrics import MetricsRegistry
from ..correlation import CorrelationService
from ..decisions import DecisionEngine
from ..enrichment import EnrichmentChain
from ..enrichment.asset_inventory import AssetInventory
from ..ingest.deduplication import Deduplicator
from ..notifications import N8NWebhookClient
from ..scoring import RiskScorer


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


def get_correlator(request: Request) -> CorrelationService:
    """Return the correlation service bound to the running application."""
    correlator: CorrelationService = request.app.state.correlator
    return correlator


def get_enrichment_chain(request: Request) -> EnrichmentChain:
    """Return the enrichment chain bound to the running application.

    Typed against the concrete orchestrator, which in turn depends only on
    the ``EnrichmentProvider`` protocol (ARCHITECTURE.md §12).
    """
    chain: EnrichmentChain = request.app.state.enrichment_chain
    return chain


def get_asset_inventory(request: Request) -> AssetInventory | None:
    """Return the optional static asset inventory bound to the application."""
    inventory: AssetInventory | None = getattr(
        request.app.state,
        "asset_inventory",
        None,
    )
    return inventory


def get_db_engine(request: Request) -> Engine:
    """Return the database engine bound to the running application."""
    engine: Engine = request.app.state.db_engine
    return engine


def get_session_factory(request: Request) -> sessionmaker:
    """Return the session factory bound to the running application."""
    factory: sessionmaker = request.app.state.session_factory
    return factory


def get_scorer(request: Request) -> RiskScorer:
    """Return the deterministic risk scorer bound to the running application."""
    scorer: RiskScorer = request.app.state.scorer
    return scorer


def get_decider(request: Request) -> DecisionEngine:
    """Return the decision engine bound to the running application."""
    decider: DecisionEngine = request.app.state.decider
    return decider


def get_n8n_client(request: Request) -> N8NWebhookClient:
    """Return the n8n webhook client bound to the running application."""
    client: N8NWebhookClient = request.app.state.n8n_client
    return client


def get_metrics_registry(request: Request) -> MetricsRegistry:
    """Return the app-scoped metrics registry bound to the application.

    Only reachable when the metrics surface is enabled (the /metrics route is
    not mounted otherwise), so ``app.state.metrics`` is always present here.
    """
    metrics: MetricsRegistry = request.app.state.metrics
    return metrics


SettingsDependency = Annotated[Settings, Depends(get_app_settings)]
DeduplicatorDependency = Annotated[Deduplicator, Depends(get_deduplicator)]
CorrelatorDependency = Annotated[CorrelationService, Depends(get_correlator)]
EnrichmentChainDependency = Annotated[EnrichmentChain, Depends(get_enrichment_chain)]
AssetInventoryDependency = Annotated[
    AssetInventory | None,
    Depends(get_asset_inventory),
]
DbEngineDependency = Annotated[Engine, Depends(get_db_engine)]
SessionFactoryDependency = Annotated[sessionmaker, Depends(get_session_factory)]
ScorerDependency = Annotated[RiskScorer, Depends(get_scorer)]
DeciderDependency = Annotated[DecisionEngine, Depends(get_decider)]
N8NClientDependency = Annotated[N8NWebhookClient, Depends(get_n8n_client)]
MetricsDependency = Annotated[MetricsRegistry, Depends(get_metrics_registry)]


__all__ = [
    "AssetInventoryDependency",
    "CorrelatorDependency",
    "DbEngineDependency",
    "DeciderDependency",
    "DeduplicatorDependency",
    "EnrichmentChainDependency",
    "MetricsDependency",
    "N8NClientDependency",
    "ScorerDependency",
    "SessionFactoryDependency",
    "SettingsDependency",
    "get_app_settings",
    "get_asset_inventory",
    "get_correlator",
    "get_db_engine",
    "get_decider",
    "get_deduplicator",
    "get_enrichment_chain",
    "get_metrics_registry",
    "get_n8n_client",
    "get_scorer",
    "get_session_factory",
]
