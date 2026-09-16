"""Cross-alert correlation (Phase 6.4).

Deterministic, explainable grouping of *distinct* alerts (different dedupe
groups) into one investigation context, based on evidence the canonical
alert model can derive safely. Two halves, mirroring the deduplication
package layout (ARCHITECTURE.md §12 — domain logic never imports FastAPI):

* :mod:`soc_triage.correlation.evidence` — the pure engine: pairwise
  evidence derivation and the sufficiency policy (``correlation.v1``).
* :mod:`soc_triage.correlation.service` — the orchestrator: candidate
  loading, context creation/extension/merge, persistence and audit.

Conceptual boundaries (see the evidence module docstring for the full
contract):

* **Deduplication** — "is this the same event / recurrence family?"
  (unchanged, Phase 1C/1D);
* **Recurrence** — distinct events of one ``rule.id + agent.id`` group
  within the dedupe window (unchanged);
* **Correlation** — "are these distinct alerts related enough to present as
  one investigation context?" (this package);
* **Incident** — the response object opened by ``open_incident`` decisions
  (unchanged; correlation never touches incidents).
"""

from __future__ import annotations

from .evidence import (
    CORRELATION_POLICY_VERSION,
    EVIDENCE_TYPE_ORDER,
    STRONG_EVIDENCE_TYPES,
    EvidenceItem,
    EvidenceType,
    evidence_reason,
    evidence_reasons,
    is_sufficient,
    pairwise_evidence,
    sort_evidence,
)
from .service import (
    CorrelationResult,
    CorrelationService,
    InvalidCorrelationInputError,
)

__all__ = [
    "CORRELATION_POLICY_VERSION",
    "EVIDENCE_TYPE_ORDER",
    "STRONG_EVIDENCE_TYPES",
    "CorrelationResult",
    "CorrelationService",
    "EvidenceItem",
    "EvidenceType",
    "InvalidCorrelationInputError",
    "evidence_reason",
    "evidence_reasons",
    "is_sufficient",
    "pairwise_evidence",
    "sort_evidence",
]
