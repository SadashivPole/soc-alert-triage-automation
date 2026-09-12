"""Phase 6.6 detection-quality CI gate.

Static, read-only checks that close gap G8 from ``docs/detection-coverage.md``:
coverage is documented, not measured — no automated coverage metric, no
threshold, and no CI gate. These tests add **no runtime behavior**: they never
import ``soc_triage``, and they do not touch scoring, decisions, dedupe,
recurrence, correlation, incident, or explanation paths.

Status distinction preserved (and not collapsed by this gate):

* ``authored`` — a custom Wazuh rule exists but is not live-validated
  (``DET-100100``-``DET-100121`` stay here; this gate does **not** require them
  to become ``validated``).
* ``locally-validated`` — a synthetic evaluation scenario replay passes
  (every catalog scenario must currently be at this status).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG = REPO_ROOT / "evaluation" / "detection_catalog.yaml"
GROUND_TRUTH = REPO_ROOT / "evaluation" / "ground_truth.json"
CORPUS = REPO_ROOT / "evaluation" / "corpus.json"
ATTACK_MAPPINGS = REPO_ROOT / "evaluation" / "attack_mappings.yaml"

EXPECTED_SCENARIO_COUNT = 24

_CATALOG: dict[str, Any] = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
SCENARIOS: list[dict[str, Any]] = _CATALOG["scenarios"]
_CORPUS: dict[str, Any] = json.loads(CORPUS.read_text(encoding="utf-8-sig"))
_GROUND_TRUTH: dict[str, Any] = json.loads(GROUND_TRUTH.read_text(encoding="utf-8-sig"))
_ATTACK_MAPPINGS: dict[str, Any] = yaml.safe_load(ATTACK_MAPPINGS.read_text(encoding="utf-8"))


def _assert_test_reference_exists(reference: str) -> None:
    path_part, _, test_name = reference.partition("::")
    assert test_name, f"{reference!r} must be 'path::test_name'"
    path = REPO_ROOT / path_part
    assert path.is_file(), f"referenced test file does not exist: {path_part}"
    assert f"def {test_name}(" in path.read_text(encoding="utf-8"), (
        f"{path_part} has no test function named {test_name}"
    )


def _corpus_fixtures() -> set[str]:
    return {case["fixture"] for case in _CORPUS["cases"]}


def _ground_truth_fixtures() -> set[str]:
    return set(_GROUND_TRUTH["fixtures"])


def _catalog_fixtures() -> set[str]:
    return {scenario["fixture"] for scenario in SCENARIOS}


def _is_recurrence_case(case: dict[str, Any]) -> bool:
    record = _GROUND_TRUTH["fixtures"].get(case["fixture"], {})
    return int(case.get("deliveries", 1)) > 1 and "recurrence" in record


def _quality_counts() -> dict[str, int]:
    recurrence_count = sum(1 for case in _CORPUS["cases"] if _is_recurrence_case(case))
    regression_covered_count = sum(1 for scenario in SCENARIOS if scenario.get("regression_tests"))
    return {
        "total scenarios": len(_CORPUS["cases"]),
        "positive count": sum(1 for case in _CORPUS["cases"] if case["label"] == "positive"),
        "negative count": sum(1 for case in _CORPUS["cases"] if case["label"] == "negative"),
        "recurrence count": recurrence_count,
        "regression-covered count": regression_covered_count,
    }


def test_corpus_contains_exactly_twenty_four_scenarios() -> None:
    """The labeled evaluation corpus is pinned at twenty-four scenarios."""
    assert len(_CORPUS["cases"]) == EXPECTED_SCENARIO_COUNT
    assert len(_corpus_fixtures()) == EXPECTED_SCENARIO_COUNT
    assert len(SCENARIOS) == EXPECTED_SCENARIO_COUNT
    assert len(_ground_truth_fixtures()) == EXPECTED_SCENARIO_COUNT


def test_corpus_ground_truth_and_catalog_fixtures_agree() -> None:
    """Corpus fixture names == ground-truth fixture names == catalog scenario fixtures."""
    corpus_fixtures = _corpus_fixtures()
    ground_truth_fixtures = _ground_truth_fixtures()
    catalog_fixtures = _catalog_fixtures()

    assert corpus_fixtures == ground_truth_fixtures, (
        "corpus and ground truth disagree on fixtures: "
        f"only-corpus={sorted(corpus_fixtures - ground_truth_fixtures)} "
        f"only-ground-truth={sorted(ground_truth_fixtures - corpus_fixtures)}"
    )
    assert corpus_fixtures == catalog_fixtures, (
        "corpus and catalog disagree on fixtures: "
        f"only-corpus={sorted(corpus_fixtures - catalog_fixtures)} "
        f"only-catalog={sorted(catalog_fixtures - corpus_fixtures)}"
    )


def test_every_catalog_scenario_has_a_regression_test() -> None:
    """Every catalog scenario has at least one regression_tests reference."""
    for scenario in SCENARIOS:
        references = scenario.get("regression_tests") or []
        assert references, f"{scenario['id']} has no regression_tests reference"


def test_regression_test_references_point_at_existing_functions() -> None:
    """Every catalog-scenario regression_tests reference names an existing test function."""
    for scenario in SCENARIOS:
        for reference in scenario["regression_tests"]:
            _assert_test_reference_exists(reference)


def test_at_least_one_positive_scenario_exists() -> None:
    assert any(case["label"] == "positive" for case in _CORPUS["cases"]), (
        "corpus has no positive scenario"
    )


def test_at_least_one_negative_scenario_exists() -> None:
    assert any(case["label"] == "negative" for case in _CORPUS["cases"]), (
        "corpus has no negative scenario"
    )


def test_at_least_one_multi_delivery_recurrence_scenario_exists() -> None:
    """At least one corpus case is a multi-delivery recurrence scenario.

    A recurrence scenario is a corpus case with ``deliveries > 1`` whose
    ground-truth record carries a ``recurrence`` block. Multi-delivery cases
    without that block (below-threshold repeats) are not counted here.
    """
    assert any(_is_recurrence_case(case) for case in _CORPUS["cases"]), (
        "corpus has no multi-delivery recurrence scenario"
    )


def test_every_scenario_is_locally_validated() -> None:
    """Every catalog scenario is locally-validated; custom detections stay authored."""
    for scenario in SCENARIOS:
        assert scenario["validation_status"] == "locally-validated", (
            f"{scenario['id']} validation_status={scenario['validation_status']!r}"
        )


def test_g5_remains_recorded_unresolved() -> None:
    """G5 stays present in the ATT&CK registry with status recorded-unresolved."""
    discrepancies = _ATTACK_MAPPINGS["known_discrepancies"]
    g5 = next((item for item in discrepancies if item["id"] == "G5"), None)
    assert g5 is not None, "G5 must remain present in evaluation/attack_mappings.yaml"
    assert g5["status"] == "recorded-unresolved"


def test_detection_quality_summary() -> None:
    """Print a deterministic detection-quality summary for CI logs."""
    counts = _quality_counts()
    assert counts["total scenarios"] == EXPECTED_SCENARIO_COUNT
    assert counts["positive count"] >= 1
    assert counts["negative count"] >= 1
    assert counts["recurrence count"] >= 1
    assert counts["regression-covered count"] == EXPECTED_SCENARIO_COUNT

    print("\n=== Detection quality ===")
    for label, value in counts.items():
        print(f"{label}: {value}")


def test_detection_quality_gate_rejects_an_artificially_degraded_metric() -> None:
    """The quality gate must reject a metric regression."""
    from evaluation.metrics import ConfusionMatrix, calculate_metrics
    from tests.evaluation.detection_quality import (
        DETECTION_QUALITY_THRESHOLDS,
        assert_detection_quality_gate,
    )

    thresholds = DETECTION_QUALITY_THRESHOLDS

    baseline = calculate_metrics(
        ConfusionMatrix(
            true_positive=thresholds.minimum_true_positive,
            false_positive=thresholds.maximum_false_positive,
            false_negative=thresholds.maximum_false_negative,
            true_negative=thresholds.minimum_true_negative,
        )
    )

    assert_detection_quality_gate(baseline)

    degraded = dict(baseline)
    degraded["recall"] = thresholds.minimum_recall - 0.0001

    with pytest.raises(AssertionError, match="recall"):
        assert_detection_quality_gate(degraded)
