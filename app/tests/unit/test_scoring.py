"""Unit tests for the deterministic risk scoring engine (Phase 1F).

Covers every scoring factor, factor explanations, determinism, boundary
scores, occurrence changes, IOC presence/absence, missing optional fields,
enrichment unavailability, tier thresholds, clipping, and the degraded
fallback. No external services are involved — the engine is pure.
"""

from __future__ import annotations

import pytest
from tests.conftest import make_canonical_alert, make_ioc

from soc_triage.models.assessment import RiskTier, ScoreFactor
from soc_triage.models.canonical import CanonicalAlert
from soc_triage.models.ioc import IOCType
from soc_triage.scoring import (
    RiskScorer,
    default_scoring_policy,
    score_alert,
)
from soc_triage.scoring.policy import ScoringPolicy

POLICY = default_scoring_policy()


def _factor(alert: CanonicalAlert, name: str) -> ScoreFactor:
    return next(f for f in score_alert(alert, policy=POLICY).factors if f.name == name)


# ---------------------------------------------------------------------------
# Factor: rule_severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (0, 0),
        (2, 0),
        (3, 6),
        (4, 6),
        (5, 14),
        (6, 14),
        (7, 22),
        (8, 22),
        (9, 30),
        (10, 30),
        (11, 40),
        (15, 40),
    ],
)
def test_rule_severity_bands(level: int, expected: int) -> None:
    factor = _factor(make_canonical_alert(level=level), "rule_severity")
    assert factor.points == expected
    assert factor.max == 40
    assert str(level) in factor.detail


# ---------------------------------------------------------------------------
# Factor: rule_groups_mitre
# ---------------------------------------------------------------------------


def test_rule_groups_mitre_groups_only() -> None:
    alert = make_canonical_alert(groups=("authentication_failed", "malware"))
    factor = _factor(alert, "rule_groups_mitre")
    assert factor.points == 8  # two matching groups x 4
    assert "authentication_failed" in factor.detail


def test_rule_groups_mitre_technique_and_tactics() -> None:
    alert = make_canonical_alert(
        mitre={"id": ["T1110"], "tactic": ["Credential Access", "Initial Access"]}
    )
    factor = _factor(alert, "rule_groups_mitre")
    assert factor.points == 7  # technique 4 + two tactics 3
    assert "MITRE technique" in factor.detail


def test_rule_groups_mitre_caps_at_max() -> None:
    alert = make_canonical_alert(
        groups=("authentication_failed", "malware", "attack"),
        mitre={"id": ["T1110"], "tactic": ["A", "B", "C"]},
    )
    factor = _factor(alert, "rule_groups_mitre")
    assert factor.points == factor.max == 15


def test_rule_groups_mitre_absent_is_zero() -> None:
    factor = _factor(make_canonical_alert(), "rule_groups_mitre")
    assert factor.points == 0


# ---------------------------------------------------------------------------
# Factor: asset_criticality
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tier", "expected"),
    [
        ("critical", 25),
        ("tier-1", 18),
        ("standard", 10),
        ("low", 5),
        ("bogus-tier", 8),  # unknown fallback
    ],
)
def test_asset_criticality_tiers(tier: str, expected: int) -> None:
    factor = _factor(make_canonical_alert(asset_tier=tier), "asset_criticality")
    assert factor.points == expected


def test_asset_criticality_missing_tier_is_unknown() -> None:
    factor = _factor(make_canonical_alert(asset_tier=None), "asset_criticality")
    assert factor.points == 8
    assert "unknown" in factor.detail


def test_asset_criticality_missing_asset_is_unknown() -> None:
    factor = _factor(make_canonical_alert(with_asset=False), "asset_criticality")
    assert factor.points == 8


# ---------------------------------------------------------------------------
# Factor: recurrence_velocity
# ---------------------------------------------------------------------------


def test_recurrence_single_occurrence_is_zero() -> None:
    factor = _factor(make_canonical_alert(occurrences=1), "recurrence_velocity")
    assert factor.points == 0


def test_recurrence_rapid_burst() -> None:
    alert = make_canonical_alert(occurrences=3, span_seconds=600)
    factor = _factor(alert, "recurrence_velocity")
    assert factor.points == 12
    assert "rapid_burst" in factor.detail


def test_recurrence_rising_burst() -> None:
    alert = make_canonical_alert(occurrences=5, span_seconds=600)
    factor = _factor(alert, "recurrence_velocity")
    assert factor.points == 18  # rapid_burst 12 + rising_burst 6


def test_recurrence_sustained_volume() -> None:
    # 10 occurrences in 1 h: only the 24 h sustained-volume threshold matches.
    alert = make_canonical_alert(occurrences=10, span_seconds=3600)
    factor = _factor(alert, "recurrence_velocity")
    assert factor.points == 8
    assert "sustained_volume" in factor.detail


def test_recurrence_caps_at_max() -> None:
    # 10 occurrences inside 15 min hits every threshold; capped at max.
    alert = make_canonical_alert(occurrences=10, span_seconds=60)
    factor = _factor(alert, "recurrence_velocity")
    assert factor.points == factor.max == 20


def test_recurrence_too_slow_is_zero() -> None:
    # 10 occurrences spread over more than 24 h meets no threshold.
    alert = make_canonical_alert(occurrences=10, span_seconds=90000)
    factor = _factor(alert, "recurrence_velocity")
    assert factor.points == 0


def test_recurrence_missing_dedupe_is_zero() -> None:
    factor = _factor(make_canonical_alert(with_dedupe=False), "recurrence_velocity")
    assert factor.points == 0


# ---------------------------------------------------------------------------
# Factor: ioc_evidence
# ---------------------------------------------------------------------------


def test_ioc_evidence_presence_scales_with_count() -> None:
    iocs = [make_ioc(f"203.0.113.{i}") for i in range(1, 4)]
    factor = _factor(make_canonical_alert(iocs=iocs), "ioc_evidence")
    assert factor.points == 9  # 3 indicators x 3


def test_ioc_evidence_caps_at_max() -> None:
    iocs = [make_ioc(f"203.0.113.{i}") for i in range(1, 10)]
    factor = _factor(make_canonical_alert(iocs=iocs), "ioc_evidence")
    assert factor.points == factor.max == 15


def test_ioc_evidence_absence_is_zero() -> None:
    factor = _factor(make_canonical_alert(iocs=[]), "ioc_evidence")
    assert factor.points == 0
    assert "no indicators" in factor.detail


# ---------------------------------------------------------------------------
# Factor: enrichment_status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("complete", 5),
        ("partial", 2),
        ("skipped", 0),
        ("failed", 0),
        ("unknown-value", 0),
        (None, 0),
    ],
)
def test_enrichment_status_points(status: str | None, expected: int) -> None:
    factor = _factor(make_canonical_alert(enrichment_status=status), "enrichment_status")
    assert factor.points == expected


def test_enrichment_unavailable_fails_safe() -> None:
    """A failed/unavailable enrichment run still yields a valid score."""
    alert = make_canonical_alert(level=7, asset_tier="critical", enrichment_status="failed")
    result = score_alert(alert, policy=POLICY)
    assert 0 <= result.score <= 100
    factor = _factor(alert, "enrichment_status")
    assert factor.points == 0
    assert "unavailable" in factor.detail


# ---------------------------------------------------------------------------
# Factor: allowlist_modifier
# ---------------------------------------------------------------------------


def test_allowlist_modifier_subtracts() -> None:
    alert = make_canonical_alert(
        iocs=[make_ioc("203.0.113.50", allowlisted=True)], asset_tier="critical"
    )
    factor = _factor(alert, "allowlist_modifier")
    assert factor.points == -20
    assert factor.max == 20


def test_allowlist_modifier_no_match_is_zero() -> None:
    factor = _factor(make_canonical_alert(), "allowlist_modifier")
    assert factor.points == 0


# ---------------------------------------------------------------------------
# Whole-engine behaviour
# ---------------------------------------------------------------------------


def test_score_is_clipped_to_100() -> None:
    alert = make_canonical_alert(
        level=15,
        groups=("authentication_failed", "malware", "attack"),
        mitre={"id": ["T1110"], "tactic": ["A", "B"]},
        asset_tier="critical",
        occurrences=10,
        span_seconds=60,
        iocs=[make_ioc(f"203.0.113.{i}") for i in range(8)],
        enrichment_status="complete",
    )
    result = score_alert(alert, policy=POLICY)
    assert result.score == 100
    assert result.tier is RiskTier.CRITICAL


def test_score_is_clipped_to_zero() -> None:
    # Allowlisted source with an otherwise-minimal profile: floor at 0.
    alert = make_canonical_alert(
        level=0, asset_tier=None, iocs=[make_ioc("203.0.113.50", allowlisted=True)]
    )
    result = score_alert(alert, policy=POLICY)
    assert result.score == 0
    assert result.tier is RiskTier.INFORMATIONAL


@pytest.mark.parametrize(
    ("score", "tier"),
    [
        (0, RiskTier.INFORMATIONAL),
        (24, RiskTier.INFORMATIONAL),
        (25, RiskTier.LOW),
        (44, RiskTier.LOW),
        (45, RiskTier.MEDIUM),
        (69, RiskTier.MEDIUM),
        (70, RiskTier.HIGH),
        (84, RiskTier.HIGH),
        (85, RiskTier.CRITICAL),
        (100, RiskTier.CRITICAL),
    ],
)
def test_tier_thresholds(score: int, tier: RiskTier) -> None:
    assert POLICY.tier_for(score) is tier


def test_scoring_is_deterministic() -> None:
    alert = make_canonical_alert(
        level=7,
        groups=("malware",),
        mitre={"id": ["T1204"], "tactic": ["Execution"]},
        asset_tier="tier-1",
        occurrences=4,
        span_seconds=120,
        iocs=[make_ioc("203.0.113.77"), make_ioc("example.com", type=IOCType.DOMAIN)],
        enrichment_status="complete",
    )
    first = score_alert(alert, policy=POLICY)
    second = score_alert(alert, policy=POLICY)
    assert first == second
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_occurrence_change_raises_score() -> None:
    """More occurrences (holding span constant) raises the recurrence factor."""
    base = make_canonical_alert(asset_tier="tier-1")
    escalated = make_canonical_alert(asset_tier="tier-1", occurrences=3, span_seconds=300)

    base_score = score_alert(base, policy=POLICY).score
    escalated_score = score_alert(escalated, policy=POLICY).score
    assert escalated_score > base_score
    assert escalated_score - base_score == 12  # rapid_burst contribution


def test_ioc_presence_raises_score() -> None:
    without = make_canonical_alert(asset_tier="tier-1")
    with_ioc = make_canonical_alert(asset_tier="tier-1", iocs=[make_ioc("203.0.113.50")])
    assert score_alert(with_ioc, policy=POLICY).score > score_alert(without, policy=POLICY).score


def test_every_factor_has_a_non_empty_explanation() -> None:
    alert = make_canonical_alert(
        level=5,
        groups=("authentication_failed",),
        mitre={"id": ["T1110"], "tactic": ["Credential Access"]},
        asset_tier="tier-1",
        occurrences=3,
        span_seconds=120,
        iocs=[make_ioc("203.0.113.50")],
        enrichment_status="partial",
    )
    result = score_alert(alert, policy=POLICY)
    assert {f.name for f in result.factors} == {
        "rule_severity",
        "rule_groups_mitre",
        "asset_criticality",
        "recurrence_velocity",
        "ioc_evidence",
        "enrichment_status",
        "allowlist_modifier",
    }
    for factor in result.factors:
        assert factor.detail.strip(), factor.name
    assert result.summary
    assert f"Score {result.score}" in result.summary
    assert result.engine_version == "scoring.v1"


def test_result_is_frozen() -> None:
    from pydantic import ValidationError

    result = score_alert(make_canonical_alert(), policy=POLICY)
    with pytest.raises((ValidationError, AttributeError, TypeError)):
        result.score = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Degraded fallback (ARCHITECTURE.md §16)
# ---------------------------------------------------------------------------


def test_risk_scorer_falls_back_on_engine_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An engine exception must never crash ingest: degraded rule-severity-only."""
    import soc_triage.scoring.engine as engine_module

    def boom(_alert: CanonicalAlert, *, _policy: ScoringPolicy):
        raise RuntimeError("simulated engine failure")

    monkeypatch.setattr(engine_module, "score_alert", boom)

    scorer = RiskScorer(POLICY)
    alert = make_canonical_alert(level=7)
    result = scorer.score(alert)

    assert result.degraded is True
    assert 0 <= result.score <= 100
    assert result.score == 22  # rule_severity band 7-8 only
    assert [f.name for f in result.factors] == ["rule_severity"]


def test_risk_scorer_returns_normal_result_when_healthy() -> None:
    scorer = RiskScorer(POLICY)
    result = scorer.score(make_canonical_alert(asset_tier="tier-1"))
    assert result.degraded is False
    assert set(f.name for f in result.factors) == {
        "rule_severity",
        "rule_groups_mitre",
        "asset_criticality",
        "recurrence_velocity",
        "ioc_evidence",
        "enrichment_status",
        "allowlist_modifier",
    }
