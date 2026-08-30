"""Configuration-driven decision policy (Phase 1F).

The decision engine maps a scored alert's :class:`RiskTier` onto a routing
action via a validated, immutable :class:`DecisionPolicy` loaded from the
versioned, non-secret ``app/config/decisions.yaml`` (ARCHITECTURE.md §9, §14).

Validation is strict and fail-loud: every risk tier must have an entry, and
``open_incident`` must carry a severity while the passive actions must not.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from ..models.assessment import DecisionAction, DecisionSeverity, RiskTier


class TierDecision(BaseModel):
    """The action (and optional severity) for one risk tier."""

    model_config = {"frozen": True}

    action: DecisionAction
    severity: DecisionSeverity | None = None

    @model_validator(mode="after")
    def _severity_consistency(self) -> TierDecision:
        if self.action is DecisionAction.OPEN_INCIDENT and self.severity is None:
            raise ValueError("open_incident requires a severity (SEV1 or SEV2)")
        if self.action is not DecisionAction.OPEN_INCIDENT and self.severity is not None:
            raise ValueError(f"severity is only valid for open_incident, not {self.action.value}")
        return self


class DecisionPolicy(BaseModel):
    """The complete decision policy (tier→action map + allowlist override)."""

    model_config = {"frozen": True}

    policy_version: str = Field(min_length=1)
    #: Risk tier → routing decision (must cover every tier).
    tier_actions: dict[RiskTier, TierDecision]
    #: Action applied when an indicator is allowlisted, regardless of score.
    allowlisted_action: DecisionAction = DecisionAction.SUPPRESS

    @model_validator(mode="after")
    def _all_tiers_present(self) -> DecisionPolicy:
        missing = {tier for tier in RiskTier} - set(self.tier_actions)
        if missing:
            names = sorted(t.value for t in missing)
            raise ValueError(f"decision policy is missing tiers: {names}")
        return self


__all__ = ["DecisionPolicy", "TierDecision"]
