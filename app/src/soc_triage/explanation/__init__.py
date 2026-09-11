"""Analyst explainability (Phase 6.5).

A deterministic, read-only explanation layer over facts the pipeline already
computed and persisted (scoring.v1 assessments, decisions.v1 decisions,
dedupe/recurrence state, correlation.v1 contexts, incident linkage, and the
audit log). The layer never re-scores, re-decides, or infers: stored outputs
remain authoritative, and missing facts surface as explicit nulls.
"""

from .builder import EXPLANATION_VERSION, MAX_AUDIT_EVENTS, ExplanationRead, build_explanation

__all__ = [
    "EXPLANATION_VERSION",
    "MAX_AUDIT_EVENTS",
    "ExplanationRead",
    "build_explanation",
]
