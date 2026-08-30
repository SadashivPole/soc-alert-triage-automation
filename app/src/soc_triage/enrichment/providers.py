"""Enrichment provider interface (Phase 1E).

This module defines the **contract** external threat-intel sources will
implement in Phase 2 (VirusTotal v3, MISP). Nothing here performs network
I/O — Phase 1E deliberately ships the interface plus one offline provider
only (ARCHITECTURE.md §7.3: "the system must run fully functional with zero
external services").

Contract
--------

A provider

* exposes a stable ``name`` (used as the key under which its payload is
  stored on each :class:`~soc_triage.models.ioc.IOC`) and an ``enabled``
  flag — optional integrations are **disabled when unconfigured**
  (ARCHITECTURE.md §14: "disable-by-empty");
* receives *all* extracted indicators plus an immutable
  :class:`EnrichmentContext`, and returns a :class:`ProviderEnrichment`
  carrying payloads keyed by :func:`~soc_triage.models.ioc.ioc_key`;
* must never raise for a *lookup miss*: a miss is an empty payload, not an
  error. Exceptions are treated as provider failures and handled by the
  orchestrator (:mod:`soc_triage.enrichment.chain`), which fails open.
* must not mutate its inputs — indicators are frozen models; providers return
  data, the orchestrator merges it.

The interface is synchronous on purpose: Phase 1E has no I/O, and keeping the
boundary free of an event loop makes providers trivially unit-testable. When
Phase 2 adds HTTP providers, the async client lives *inside* the provider
implementation (behind this stable boundary) — the orchestrator and its tests
do not change.

No VirusTotal, MISP or any other external service is contacted in this phase.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, Field

from ..models.ioc import IOC


class EnrichmentStatus(StrEnum):
    """Outcome of an enrichment run (ARCHITECTURE.md §5.2, §16).

    Surfaceable on the alert as ``enrichment_status``.
    """

    #: Nothing was looked up: no indicators, no enabled provider.
    SKIPPED = "skipped"
    #: Every enabled provider answered for every indicator it handles.
    COMPLETE = "complete"
    #: Some lookups succeeded, others failed (provider error / outage).
    PARTIAL = "partial"
    #: Every enabled provider failed; the alert proceeds without intel.
    FAILED = "failed"


class EnrichmentContext(BaseModel):
    """Read-only context handed to providers (correlation, not control flow)."""

    model_config = {"frozen": True}

    alert_id: UUID | None = None
    #: Source label (``wazuh`` / ``simulator``).
    source: str = "unknown"
    received_at: datetime | None = None
    #: Deduplication group key, when the alert already has one.
    dedupe_group: str | None = None


class ProviderEnrichment(BaseModel):
    """Result of one provider run for one indicator set."""

    model_config = {"frozen": True}

    #: Provider name (matches :attr:`EnrichmentProvider.name`).
    provider: str = Field(min_length=1)
    status: EnrichmentStatus
    #: ``ioc_key → provider payload``. Indicators the provider does not
    #: handle are simply absent — absence is not an error.
    results: dict[str, dict[str, Any]] = Field(default_factory=dict)
    #: Human/analyst-facing notes (e.g. "quota_exceeded", "unavailable").
    notes: list[str] = Field(default_factory=list)


@runtime_checkable
class EnrichmentProvider(Protocol):
    """Contract implemented by every enrichment source (Phase 2+)."""

    @property
    def name(self) -> str:
        """Stable identifier used as the IOC enrichment key."""
        ...

    @property
    def enabled(self) -> bool:
        """Whether this provider is active (False → the chain skips it)."""
        ...

    def enrich(
        self,
        iocs: Sequence[IOC],
        *,
        context: EnrichmentContext,
    ) -> ProviderEnrichment:
        """Return enrichment payloads for the indicators this provider handles.

        Implementations must not raise on lookup misses and must not mutate
        ``iocs``. Any exception is caught by the orchestrator and recorded as a
        provider failure (fail-open, ARCHITECTURE.md §16).
        """
        ...


class NoOpEnrichmentProvider:
    """Offline, no-op provider used for local development and tests.

    Performs **zero** I/O and produces **no** enrichment data; it exists so
    the orchestration path (registration → enabled check → result merge) is
    exercised end-to-end without any external dependency. It is **disabled by
    default** — an unconfigured integration must never be called
    (ARCHITECTURE.md §14, SECURITY.md §2).

    Even when explicitly enabled it returns ``skipped`` with no payloads:
    "no provider configured" must be indistinguishable from "no intel found"
    for scoring, which treats an absent payload as *no signal*
    (ARCHITECTURE.md §7.3: zero-external fallback mode).
    """

    def __init__(self, *, enabled: bool = False) -> None:
        self._enabled = enabled

    @property
    def name(self) -> str:
        """Provider identifier (``"noop"``)."""
        return "noop"

    @property
    def enabled(self) -> bool:
        """Whether the provider is active (default: ``False``)."""
        return self._enabled

    def enrich(
        self,
        iocs: Sequence[IOC],
        *,
        context: EnrichmentContext,  # noqa: ARG002 - part of the contract
    ) -> ProviderEnrichment:
        """Return a ``skipped`` result: the no-op provider looks up nothing."""
        return ProviderEnrichment(
            provider=self.name,
            status=EnrichmentStatus.SKIPPED,
            notes=[
                "noop: offline provider, no external lookup performed"
                f" ({len(iocs)} indicator(s) received, none enriched)"
            ],
        )


__all__ = [
    "EnrichmentContext",
    "EnrichmentProvider",
    "EnrichmentStatus",
    "NoOpEnrichmentProvider",
    "ProviderEnrichment",
]
