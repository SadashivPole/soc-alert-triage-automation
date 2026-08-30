"""Unit tests for the decision & routing engine (Phase 1F).

Covers every tier→action mapping, incident severities, the allowlist
``suppress`` override, reason strings, and determinism. No external services
or response actions are involved.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tests.conftest import make_canonical_alert, make_ioc

from soc_triage.decisions import DecisionEngine, decide, default_decision_policy
from soc_triage.models.assessment import (
    DecisionAction,
    DecisionSeverity,
    RiskAssessment,
    RiskTier,
    ScoreFactor,
)
from soc_triage.scoring import default_scoring_policy, score_alert

POLICY = default_decision_policy()
SCORING_POLICY = default_scoring_policy()
DECIDED_AT = datetime(2026, 8, 29, 10, 15, 0, tzinfo=UTC)


def _assessment(score: int, tier: RiskTier) -> RiskAssessment:
    return RiskAssessment(
        score=score,
        tier=tier,
        engine_version="scoring.v1",
        factors=(ScoreFactor(name="rule_severity", points=score, max=100, detail="t"),),
        summary=f"Score {score} ({tier.value}).",
    )


# ---------------------------------------------------------------------------
# Tier → action mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "tier", "action", "severity"),
    [
        (0, RiskTier.INFORMATIONAL, DecisionAction.MONITOR, None),
        (24, RiskTier.INFORMATIONAL, DecisionAction.MONITOR, None),
        (44, RiskTier.LOW, DecisionAction.MONITOR, None),
        (69, RiskTier.MEDIUM, DecisionAction.QUEUE_L1, None),
        (84, RiskTier.HIGH, DecisionAction.OPEN_INCIDENT, DecisionSeverity.SEV2),
        (100, RiskTier.CRITICAL, DecisionAction.OPEN_INCIDENT, DecisionSeverity.SEV1),
    ],
)
def test_tier_to_action_mapping(
    score: int, tier: RiskTier, action: DecisionAction, severity: DecisionSeverity | None
) -> None:
    alert = make_canonical_alert()
    decision = decide(_assessment(score, tier), alert=alert, policy=POLICY, decided_at=DECIDED_AT)
    assert decision.action is action, tier
    assert decision.severity is severity, tier
    assert decision.decided_at == DECIDED_AT


def test_decision_reasons_include_score_and_tier() -> None:
    alert = make_canonical_alert()
    decision = decide(
        _assessment(73, RiskTier.HIGH), alert=alert, policy=POLICY, decided_at=DECIDED_AT
    )
    assert decision.reasons
    assert any("score=73" in r for r in decision.reasons)
    assert any("tier=high" in r for r in decision.reasons)
    assert any("severity=SEV2" in r for r in decision.reasons)


# ---------------------------------------------------------------------------
# Allowlist override (ARCHITECTURE.md §9)
# ---------------------------------------------------------------------------


def test_allowlisted_alert_is_suppressed_regardless_of_score() -> None:
    alert = make_canonical_alert(iocs=[make_ioc("203.0.113.50", allowlisted=True)])
    decision = decide(
        _assessment(99, RiskTier.CRITICAL),
        alert=alert,
        policy=POLICY,
        decided_at=DECIDED_AT,
    )
    assert decision.action is DecisionAction.SUPPRESS
    assert decision.severity is None
    assert any("allowlisted" in r for r in decision.reasons)


def test_non_allowlisted_alert_is_not_suppressed() -> None:
    alert = make_canonical_alert(iocs=[make_ioc("203.0.113.50")])
    decision = decide(
        _assessment(99, RiskTier.CRITICAL),
        alert=alert,
        policy=POLICY,
        decided_at=DECIDED_AT,
    )
    assert decision.action is DecisionAction.OPEN_INCIDENT


# ---------------------------------------------------------------------------
# Determinism + engine wrapper
# ---------------------------------------------------------------------------


def test_decision_is_deterministic() -> None:
    alert = make_canonical_alert(asset_tier="tier-1")
    risk = score_alert(alert, policy=SCORING_POLICY)
    first = decide(risk, alert=alert, policy=POLICY, decided_at=DECIDED_AT)
    second = decide(risk, alert=alert, policy=POLICY, decided_at=DECIDED_AT)
    assert first == second


def test_decision_engine_wrapper() -> None:
    engine = DecisionEngine(POLICY)
    assert engine.policy is POLICY
    alert = make_canonical_alert()
    decision = engine.decide(_assessment(55, RiskTier.MEDIUM), alert=alert, decided_at=DECIDED_AT)
    assert decision.action is DecisionAction.QUEUE_L1


def test_end_to_end_score_to_decision_is_consistent() -> None:
    """The scoring tier feeds the decision engine without a gap."""
    critical_alert = make_canonical_alert(
        level=15,
        groups=("malware",),
        mitre={"id": ["T1204"], "tactic": ["Execution", "Initial Access"]},
        asset_tier="critical",
        occurrences=3,
        span_seconds=120,
        iocs=[make_ioc(f"203.0.113.{i}") for i in range(6)],
        enrichment_status="complete",
    )
    risk = score_alert(critical_alert, policy=SCORING_POLICY)
    assert risk.tier is RiskTier.CRITICAL
    decision = decide(risk, alert=critical_alert, policy=POLICY, decided_at=DECIDED_AT)
    assert decision.action is DecisionAction.OPEN_INCIDENT
    assert decision.severity is DecisionSeverity.SEV1
