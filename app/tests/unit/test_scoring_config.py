"""Unit tests for scoring/decision policy loading and validation (Phase 1F).

Covers the bundled YAML loaders and the fail-loud schema validation: invalid
YAML, non-mapping files, non-contiguous tier coverage, missing tiers, unknown
enrichment statuses, bad asset bands, and decision-policy consistency rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from soc_triage.decisions import (
    DecisionConfigError,
    decision_policy_from_mapping,
    default_decision_policy,
    load_decision_policy,
)
from soc_triage.scoring import (
    ScoringConfigError,
    default_scoring_policy,
    load_scoring_policy,
    scoring_policy_from_mapping,
)


def _valid_policy() -> dict:
    return {
        "engine_version": "scoring.v1",
        "rule_severity": {
            "max": 40,
            "bands": [
                {"min": 0, "max": 2, "points": 0},
                {"min": 3, "max": 15, "points": 40},
            ],
        },
        "rule_groups_mitre": {
            "max": 15,
            "group_keywords": ["authentication_failed"],
            "group_points": 4,
            "mitre_points": 4,
            "multi_tactic_points": 3,
            "multi_tactic_threshold": 2,
        },
        "asset_criticality": {
            "max": 25,
            "unknown_points": 8,
            "bands": {"critical": 25, "high": 18, "medium": 10, "low": 5},
            "tier_aliases": {
                "critical": ["critical"],
                "high": ["high", "tier-1"],
                "medium": ["medium", "standard"],
                "low": ["low"],
            },
        },
        "recurrence_velocity": {
            "max": 20,
            "rules": [
                {
                    "name": "rapid_burst",
                    "min_occurrences": 3,
                    "max_window_seconds": 900,
                    "points": 12,
                }
            ],
        },
        "ioc_evidence": {"max": 15, "per_indicator": 3, "max_counted": 5},
        "enrichment_status": {
            "max": 5,
            "points": {"complete": 5, "partial": 2, "skipped": 0, "failed": 0},
        },
        "allowlist": {"subtract": 20},
        "tiers": [
            {"name": "informational", "min": 0, "max": 24},
            {"name": "low", "min": 25, "max": 44},
            {"name": "medium", "min": 45, "max": 69},
            {"name": "high", "min": 70, "max": 84},
            {"name": "critical", "min": 85, "max": 100},
        ],
    }


def _valid_decision() -> dict:
    return {
        "policy_version": "decisions.v1",
        "tier_actions": {
            "informational": {"action": "monitor"},
            "low": {"action": "monitor"},
            "medium": {"action": "queue_l1"},
            "high": {"action": "open_incident", "severity": "SEV2"},
            "critical": {"action": "open_incident", "severity": "SEV1"},
        },
        "allowlisted_action": "suppress",
    }


# ---------------------------------------------------------------------------
# Bundled policies
# ---------------------------------------------------------------------------


def test_bundled_scoring_policy_loads() -> None:
    policy = default_scoring_policy()
    assert policy.engine_version == "scoring.v1"
    assert policy.tiers[-1].max == 100


def test_bundled_decision_policy_loads() -> None:
    policy = default_decision_policy()
    assert policy.policy_version == "decisions.v1"
    assert len(policy.tier_actions) == 5


# ---------------------------------------------------------------------------
# Scoring policy: loader errors
# ---------------------------------------------------------------------------


def test_load_scoring_policy_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ScoringConfigError):
        load_scoring_policy(tmp_path / "missing.yaml")


def test_load_scoring_policy_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("{{{ not: [valid yaml")
    with pytest.raises(ScoringConfigError):
        load_scoring_policy(path)


def test_load_scoring_policy_not_a_mapping(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- just\n- a\n- list\n")
    with pytest.raises(ScoringConfigError):
        load_scoring_policy(path)


def test_load_scoring_policy_invalid_schema(tmp_path: Path) -> None:
    """A well-formed mapping that fails schema validation is also rejected."""
    path = tmp_path / "invalid_schema.yaml"
    path.write_text("engine_version: scoring.v1\n")  # missing all factor config
    with pytest.raises(ScoringConfigError, match="invalid scoring policy"):
        load_scoring_policy(path)


# ---------------------------------------------------------------------------
# Scoring policy: schema validation
# ---------------------------------------------------------------------------


def test_valid_policy_passes() -> None:
    assert scoring_policy_from_mapping(_valid_policy()).engine_version == "scoring.v1"


@pytest.mark.parametrize(
    ("mutate", "message_fragment"),
    [
        # Gap between bands: `high` starts at 70 but the previous band ended at 44.
        (
            lambda p: p.update(
                tiers=[
                    {"name": "informational", "min": 0, "max": 24},
                    {"name": "low", "min": 25, "max": 44},
                    {"name": "high", "min": 70, "max": 84},
                    {"name": "critical", "min": 85, "max": 100},
                ]
            ),
            "expected 45",
        ),
        # Incomplete coverage: tiers end at 84, not 100.
        (
            lambda p: p.update(tiers=p["tiers"][:-1]),
            "contiguous",
        ),
        # Duplicate tier name.
        (
            lambda p: p.update(
                tiers=[
                    {"name": "low", "min": 0, "max": 24},
                    {"name": "low", "min": 25, "max": 44},
                    {"name": "high", "min": 70, "max": 84},
                    {"name": "critical", "min": 85, "max": 100},
                ]
            ),
            "duplicate",
        ),
        (
            lambda p: p["enrichment_status"].update(points={"complete": 5, "bogus": 3}),
            "unknown enrichment status",
        ),
        (
            lambda p: p["asset_criticality"].update(bands={"critical": 25, "nope": 1}),
            "unknown asset band",
        ),
        (
            lambda p: p["rule_severity"].update(bands=[{"min": 5, "max": 2, "points": 10}]),
            "inverted",
        ),
        (
            lambda p: p.update(rule_severity={"max": 40, "bands": []}),
            "must not be empty",
        ),
    ],
)
def test_invalid_policy_rejected(mutate, message_fragment: str) -> None:
    policy = _valid_policy()
    mutate(policy)
    with pytest.raises(ScoringConfigError, match=message_fragment):
        scoring_policy_from_mapping(policy)


# ---------------------------------------------------------------------------
# Decision policy: schema validation
# ---------------------------------------------------------------------------


def test_valid_decision_policy_passes() -> None:
    assert decision_policy_from_mapping(_valid_decision()).policy_version == "decisions.v1"


def test_decision_policy_missing_tier_rejected() -> None:
    policy = _valid_decision()
    del policy["tier_actions"]["medium"]
    with pytest.raises(DecisionConfigError, match="missing"):
        decision_policy_from_mapping(policy)


def test_decision_policy_open_incident_requires_severity() -> None:
    policy = _valid_decision()
    policy["tier_actions"]["high"] = {"action": "open_incident"}
    with pytest.raises(DecisionConfigError, match="severity"):
        decision_policy_from_mapping(policy)


def test_decision_policy_severity_only_for_incident() -> None:
    policy = _valid_decision()
    policy["tier_actions"]["medium"] = {"action": "queue_l1", "severity": "SEV2"}
    with pytest.raises(DecisionConfigError, match="severity"):
        decision_policy_from_mapping(policy)


def test_load_decision_policy_invalid_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("tier_actions: [1, 2, 3]\n")
    with pytest.raises(DecisionConfigError):
        load_decision_policy(path)


def test_load_decision_policy_missing_file(tmp_path: Path) -> None:
    with pytest.raises(DecisionConfigError, match="cannot read"):
        load_decision_policy(tmp_path / "missing.yaml")


def test_load_decision_policy_not_a_mapping(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- just\n- a\n- list\n")
    with pytest.raises(DecisionConfigError, match="mapping"):
        load_decision_policy(path)
