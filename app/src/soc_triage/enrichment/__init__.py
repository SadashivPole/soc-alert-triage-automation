"""Enrichment subsystem (Phase 1E).

Scope of this phase: **IOC extraction** and the **enrichment provider
interface**. No external threat-intel service is contacted — VirusTotal and
MISP arrive in Phase 2 behind the provider contract defined here
(ARCHITECTURE.md §7).

Pipeline position (ARCHITECTURE.md §4)::

    normalize → dedupe → extract IOCs → enrich (Phase 2) → score → decide

Public surface:

* :func:`.extractor.extract_iocs` / :func:`.extractor.extract_iocs_from_text`
  — pure, deterministic, side-effect-free extraction of IPv4, domain, URL,
  MD5, SHA1, SHA256 and email indicators, with full provenance;
* :mod:`.policy` — the false-positive policy (private/documentation ranges,
  which fields are read, indicator cap);
* :mod:`.providers` — the :class:`~.providers.EnrichmentProvider` contract plus
  the offline, disabled-by-default
  :class:`~.providers.NoOpEnrichmentProvider`;
* :class:`.chain.EnrichmentChain` — ordered, fail-open orchestration that
  merges provider payloads onto indicators and reports ``enrichment_status``.

Risk scoring and decisioning are **not** part of this package.
"""

from __future__ import annotations

from ..models.ioc import (
    EXTRACTOR_TEXT_SCAN,
    EXTRACTOR_TYPED_FIELD,
    HASH_LENGTHS,
    IOC,
    IOCProvenance,
    IOCType,
    ioc_key,
    ioc_sort_key,
)
from .chain import EnrichmentChain, EnrichmentOutcome, ProviderOutcome
from .extractor import extract_iocs, extract_iocs_from_text
from .policy import (
    DEFAULT_IOC_POLICY,
    DOCUMENTATION_IPV4_NETWORKS,
    IOCExtractionPolicy,
)
from .providers import (
    EnrichmentContext,
    EnrichmentProvider,
    EnrichmentStatus,
    NoOpEnrichmentProvider,
    ProviderEnrichment,
)

__all__ = [
    "DEFAULT_IOC_POLICY",
    "DOCUMENTATION_IPV4_NETWORKS",
    "EXTRACTOR_TEXT_SCAN",
    "EXTRACTOR_TYPED_FIELD",
    "HASH_LENGTHS",
    "IOC",
    "EnrichmentChain",
    "EnrichmentContext",
    "EnrichmentOutcome",
    "EnrichmentProvider",
    "EnrichmentStatus",
    "IOCExtractionPolicy",
    "IOCProvenance",
    "IOCType",
    "NoOpEnrichmentProvider",
    "ProviderEnrichment",
    "ProviderOutcome",
    "extract_iocs",
    "extract_iocs_from_text",
    "ioc_key",
    "ioc_sort_key",
]
