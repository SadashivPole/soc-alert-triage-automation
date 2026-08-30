"""Risk and decision result models (Phase 1F).

These are the **domain result objects** produced by the deterministic scoring
engine (:mod:`soc_triage.scoring`) and the decision engine
(:mod:`soc_triage.decisions`), and embedded back onto the canonical alert
(:class:`soc_triage.models.canonical.CanonicalAlert.risk` /
``.decision``) so they persist with the alert of record.

They are deliberately dependency-free (``pydantic`` + ``enum`` + ``datetime``
only), mirroring :mod:`soc_triage.models.ioc`: the canonical model can embed
them and the scoring/decision packages can produce them without an import
cycle. This keeps the *result shape* a stable, reviewed part of the schema
rather than an implementation detail of one package.

Design notes (ARCHITECTURE.md §5.2, §8, §9):

* A :class:`RiskAssessment` always carries a numeric ``score`` (clipped
  0-100), a :class:`RiskTier`, the ``engine_version`` that produced it, and
  an ordered ``factors`` tuple — one :class:`ScoreFactor` per weighted input,
  each with ``points``/``max`` and a human-readable ``detail``. Explainability
  is the contract: no score without a justification.
* A :class:`Decision` is the routing outcome: ``suppress`` | ``monitor`` |
  ``queue_l1`` | ``open_incident`` (with a ``severity`` only for the last).
  ``reasons`` preserves *why*, and ``decided_at`` timestamps the decision.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class RiskTier(StrEnum):
    """Score bands (ARCHITECTURE.md §8.3; boundaries live in the policy)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScoreFactor(BaseModel):
    """One weighted scoring input with its awarded points and explanation."""

    model_config = {"frozen": True}

    #: Stable factor name (also the policy key), e.g. ``rule_severity``.
    name: str = Field(min_length=1)
    #: Points awarded. May be negative for subtractive modifiers
    #: (``allowlist_modifier``).
    points: int
    #: The factor's maximum contribution (its weight).
    max: int = Field(ge=0)
    #: Human-readable justification for this factor's points.
    detail: str


class RiskAssessment(BaseModel):
    """The output of the deterministic scoring engine for one alert."""

    model_config = {"frozen": True}

    score: int = Field(ge=0, le=100)
    tier: RiskTier
    engine_version: str = Field(min_length=1)
    #: Ordered per-factor breakdown (deterministic order, ARCHITECTURE.md §8).
    factors: tuple[ScoreFactor, ...]
    #: Generated one-paragraph human summary (template-based in Phase 1F).
    summary: str
    #: True only when the full engine raised and the result is the
    #: rule-severity-only fallback (ARCHITECTURE.md §16). Never affects the
    #: 0-100 score contract, only marks the degraded path for audit.
    degraded: bool = False


class DecisionAction(StrEnum):
    """Routing outcomes (ARCHITECTURE.md §9)."""

    SUPPRESS = "suppress"
    MONITOR = "monitor"
    QUEUE_L1 = "queue_l1"
    OPEN_INCIDENT = "open_incident"


class DecisionSeverity(StrEnum):
    """Incident severity for ``open_incident`` decisions."""

    SEV1 = "SEV1"
    SEV2 = "SEV2"


class Decision(BaseModel):
    """The output of the decision engine for one scored alert."""

    model_config = {"frozen": True}

    action: DecisionAction
    #: Present only for ``open_incident`` (SEV1 for critical, SEV2 for high).
    severity: DecisionSeverity | None = None
    #: Why this action was chosen (score, tier, allowlist, …).
    reasons: tuple[str, ...] = ()
    #: Optional runbook link (Phase 3 populates from docs/runbooks/).
    runbook: str | None = None
    decided_at: datetime


__all__ = [
    "Decision",
    "DecisionAction",
    "DecisionSeverity",
    "RiskAssessment",
    "RiskTier",
    "ScoreFactor",
]
