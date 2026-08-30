"""Enrichment orchestration (Phase 1E).

:class:`EnrichmentChain` runs the registered
:class:`~soc_triage.enrichment.providers.EnrichmentProvider` implementations
over an alert's indicators and merges their payloads back onto the indicators.

Guarantees (ARCHITECTURE.md §7.3, §16):

* **Fail-open** — a provider that raises (outage, quota, bug) is recorded as
  ``failed`` and skipped; the alert keeps its indicators and continues down
  the pipeline with ``enrichment_status: partial|failed``. Enrichment never
  blocks or breaks ingestion.
* **Deterministic** — providers run in registration order, providers always
  see indicators in the same (type, value) order, and the merged result is
  returned in that same order. Identical inputs produce identical outputs.
* **Self-describing** — the outcome carries a per-provider
  :class:`ProviderOutcome` (status, how many indicators were enriched, error
  type) so operators can see *why* intel is missing without reading logs.
* **No I/O of its own** — the chain calls providers and merges results; all
  network behaviour lives in the provider implementations (Phase 2).

Logging follows SECURITY.md §7: structured, allow-listed fields, indicator
counts and error *types* only — never indicator payloads, never raw logs.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, Field

from ..core.logging import get_logger
from ..models.ioc import IOC, ioc_sort_key
from .providers import (
    EnrichmentContext,
    EnrichmentProvider,
    EnrichmentStatus,
)

logger = get_logger("soc_triage.enrichment.chain")


class ProviderOutcome(BaseModel):
    """What one provider did during a run (observability, not alert state)."""

    model_config = {"frozen": True}

    provider: str
    status: EnrichmentStatus
    #: Number of indicators this provider attached a payload to.
    enriched: int = Field(default=0, ge=0)
    #: Exception type, when the provider raised (never its message/details).
    error_type: str | None = None
    #: Provider notes (e.g. "provider disabled", "quota_exceeded").
    notes: tuple[str, ...] = ()


class EnrichmentOutcome(BaseModel):
    """Result of running the chain over one alert's indicators."""

    model_config = {"frozen": True}

    status: EnrichmentStatus
    #: Indicators (ordered by type/value) with merged ``enrichment`` payloads.
    iocs: tuple[IOC, ...] = ()
    #: One entry per registered provider, in registration order.
    providers: tuple[ProviderOutcome, ...] = ()


def _aggregate(statuses: Sequence[EnrichmentStatus]) -> EnrichmentStatus:
    """Fold per-provider statuses into one alert-level status."""
    meaningful = [status for status in statuses if status is not EnrichmentStatus.SKIPPED]
    if not meaningful:
        return EnrichmentStatus.SKIPPED
    if all(status is EnrichmentStatus.COMPLETE for status in meaningful):
        return EnrichmentStatus.COMPLETE
    if all(status is EnrichmentStatus.FAILED for status in meaningful):
        return EnrichmentStatus.FAILED
    return EnrichmentStatus.PARTIAL


class EnrichmentChain:
    """Ordered, fail-open orchestration of enrichment providers."""

    def __init__(self, providers: Sequence[EnrichmentProvider] = ()) -> None:
        self._providers: tuple[EnrichmentProvider, ...] = tuple(providers)

    @property
    def providers(self) -> tuple[EnrichmentProvider, ...]:
        """Registered providers in execution order."""
        return self._providers

    def enrich(
        self,
        iocs: Sequence[IOC],
        *,
        context: EnrichmentContext | None = None,
    ) -> EnrichmentOutcome:
        """Run every enabled provider over ``iocs`` and merge the results.

        Args:
            iocs: The alert's extracted indicators (never mutated).
            context: Correlation context handed to each provider.

        Returns:
            An :class:`EnrichmentOutcome` whose ``iocs`` are copies of the
            inputs with their ``enrichment`` mapping populated.
        """
        run_context = context or EnrichmentContext()
        # Normalize input order so every provider sees the same sequence.
        ordered = tuple(sorted(iocs, key=ioc_sort_key))

        if not ordered:
            # Nothing to look up: providers are not called at all.
            return EnrichmentOutcome(
                status=EnrichmentStatus.SKIPPED,
                iocs=(),
                providers=tuple(
                    ProviderOutcome(
                        provider=provider.name,
                        status=EnrichmentStatus.SKIPPED,
                        notes=("no indicators to enrich",),
                    )
                    for provider in self._providers
                ),
            )

        enriched: dict[str, IOC] = {ioc.key: ioc for ioc in ordered}
        outcomes: list[ProviderOutcome] = []
        statuses: list[EnrichmentStatus] = []

        for provider in self._providers:
            if not provider.enabled:
                outcomes.append(
                    ProviderOutcome(
                        provider=provider.name,
                        status=EnrichmentStatus.SKIPPED,
                        notes=("provider disabled",),
                    )
                )
                continue

            try:
                result = provider.enrich(ordered, context=run_context)
            except Exception as exc:  # fail-open by design (ARCHITECTURE.md §16)
                # Log the exception *type* only; never provider payloads or
                # message text (SECURITY.md §7).
                logger.warning(
                    "enrichment_provider_failed",
                    component="enrichment",
                    provider=provider.name,
                    error_type=type(exc).__name__,
                )
                outcomes.append(
                    ProviderOutcome(
                        provider=provider.name,
                        status=EnrichmentStatus.FAILED,
                        error_type=type(exc).__name__,
                        notes=(f"provider raised {type(exc).__name__}",),
                    )
                )
                statuses.append(EnrichmentStatus.FAILED)
                continue

            applied = 0
            for key, payload in result.results.items():
                ioc = enriched.get(key)
                if ioc is None:
                    # Defensive: a provider returned an unknown indicator key.
                    continue
                enriched[key] = ioc.model_copy(
                    update={"enrichment": {**ioc.enrichment, provider.name: payload}}
                )
                applied += 1

            outcomes.append(
                ProviderOutcome(
                    provider=provider.name,
                    status=result.status,
                    enriched=applied,
                    notes=tuple(result.notes),
                )
            )
            statuses.append(result.status)

        logger.info(
            "iocs_enriched",
            component="enrichment",
            ioc_count=len(enriched),
            providers=len(outcomes),
            enrichment_status=_aggregate(statuses).value,
        )

        return EnrichmentOutcome(
            status=_aggregate(statuses),
            iocs=tuple(sorted(enriched.values(), key=ioc_sort_key)),
            providers=tuple(outcomes),
        )


__all__ = [
    "EnrichmentChain",
    "EnrichmentOutcome",
    "ProviderOutcome",
]
