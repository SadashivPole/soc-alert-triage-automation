"""Deterministic risk scoring engine (Phase 1F).

Public surface (ARCHITECTURE.md §8, §12 — a pure, zero-I/O package):

* :mod:`.engine` — the pure :func:`~.engine.score_alert`
  ``(CanonicalAlert, ScoringPolicy) → RiskAssessment`` plus the resilient
  :class:`~.engine.RiskScorer` wrapper with the degraded fallback;
* :mod:`.policy` — the validated, immutable :class:`~.policy.ScoringPolicy`
  (factor weights, severity bands, tier mapping, tier bands);
* :mod:`.config` — the YAML loader (:func:`~.config.load_scoring_policy`) and
  its :class:`~.config.ScoringConfigError`.

Scoring never performs I/O or contacts external services; it reads only the
canonical alert and its policy.
"""

from __future__ import annotations

from .config import (
    DEFAULT_SCORING_POLICY_PATH,
    ScoringConfigError,
    default_scoring_policy,
    load_scoring_policy,
    scoring_policy_from_mapping,
)
from .engine import RiskScorer, degraded_score, score_alert
from .policy import (
    ENRICHMENT_STATUSES,
    AllowlistConfig,
    AssetCriticalityConfig,
    EnrichmentStatusConfig,
    IocEvidenceConfig,
    RecurrenceRule,
    RecurrenceVelocityConfig,
    RuleGroupsMitreConfig,
    RuleSeverityConfig,
    ScoringPolicy,
    SeverityBand,
    TierBand,
)

__all__ = [
    "DEFAULT_SCORING_POLICY_PATH",
    "ENRICHMENT_STATUSES",
    "AllowlistConfig",
    "AssetCriticalityConfig",
    "EnrichmentStatusConfig",
    "IocEvidenceConfig",
    "RecurrenceRule",
    "RecurrenceVelocityConfig",
    "RiskScorer",
    "RuleGroupsMitreConfig",
    "RuleSeverityConfig",
    "ScoringConfigError",
    "ScoringPolicy",
    "SeverityBand",
    "TierBand",
    "default_scoring_policy",
    "degraded_score",
    "load_scoring_policy",
    "score_alert",
    "scoring_policy_from_mapping",
]
