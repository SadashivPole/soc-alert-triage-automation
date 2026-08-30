"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from ..core.config import Settings
from ..decisions import DecisionEngine
from ..enrichment import EnrichmentChain
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


def get_enrichment_chain(request: Request) -> EnrichmentChain:
    """Return the enrichment chain bound to the running application.

    Typed against the concrete orchestrator, which in turn depends only on
    the ``EnrichmentProvider`` protocol (ARCHITECTURE.md §12).
    """
    chain: EnrichmentChain = request.app.state.enrichment_chain
    return chain


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


SettingsDependency = Annotated[Settings, Depends(get_app_settings)]
DeduplicatorDependency = Annotated[Deduplicator, Depends(get_deduplicator)]
EnrichmentChainDependency = Annotated[EnrichmentChain, Depends(get_enrichment_chain)]
DbEngineDependency = Annotated[Engine, Depends(get_db_engine)]
SessionFactoryDependency = Annotated[sessionmaker, Depends(get_session_factory)]
ScorerDependency = Annotated[RiskScorer, Depends(get_scorer)]
DeciderDependency = Annotated[DecisionEngine, Depends(get_decider)]
N8NClientDependency = Annotated[N8NWebhookClient, Depends(get_n8n_client)]


__all__ = [
    "DbEngineDependency",
    "DeciderDependency",
    "DeduplicatorDependency",
    "EnrichmentChainDependency",
    "N8NClientDependency",
    "ScorerDependency",
    "SessionFactoryDependency",
    "SettingsDependency",
    "get_app_settings",
    "get_db_engine",
    "get_decider",
    "get_deduplicator",
    "get_enrichment_chain",
    "get_n8n_client",
    "get_scorer",
    "get_session_factory",
]
