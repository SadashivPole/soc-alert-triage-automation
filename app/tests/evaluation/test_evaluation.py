from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evaluation.metrics import ConfusionMatrix, calculate_metrics
from fastapi.testclient import TestClient
from tests.conftest import TEST_INGEST_KEY

ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = ROOT / "app" / "tests" / "fixtures"
EVALUATION_DIR = ROOT / "evaluation"

GROUND_TRUTH = EVALUATION_DIR / "ground_truth.json"
CORPUS = EVALUATION_DIR / "corpus.json"

AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}

POSITIVE_ACTIONS = {"queue_l1", "open_incident"}
NEGATIVE_ACTIONS = {"monitor", "suppress"}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_fixture(name: str) -> dict[str, Any]:
    return load_json(FIXTURES_DIR / name)


def test_ground_truth_evaluation(client: TestClient) -> None:
    ground_truth = load_json(GROUND_TRUTH)
    corpus = load_json(CORPUS)

    results: list[dict[str, Any]] = []

    for case in corpus["cases"]:
        fixture_name = case["fixture"]
        label = case["label"]

        assert label in {"positive", "negative"}, (
            fixture_name,
            f"Unsupported label: {label}",
        )

        payload = load_fixture(fixture_name)

        response = client.post(
            "/api/v1/alerts/ingest",
            json=payload,
            headers=AUTH_HEADERS,
        )

        assert response.status_code in {200, 202}, (
            fixture_name,
            response.text,
        )

        body = response.json()
        risk = body["risk"]
        decision = body["decision"]

        action = decision["action"]

        assert action in POSITIVE_ACTIONS | NEGATIVE_ACTIONS, (
            fixture_name,
            f"Unsupported decision action: {action}",
        )

        predicted_positive = action in POSITIVE_ACTIONS
        actual_positive = label == "positive"

        if actual_positive and predicted_positive:
            classification = "TP"
        elif not actual_positive and predicted_positive:
            classification = "FP"
        elif actual_positive and not predicted_positive:
            classification = "FN"
        else:
            classification = "TN"

        expected = ground_truth["fixtures"][fixture_name].get(
            "expected",
            {},
        )

        contract_checks: dict[str, bool] = {}

        for field in ("score", "tier", "action", "severity"):
            if field in expected:
                actual_value = (
                    risk.get(field) if field in {"score", "tier"} else decision.get(field)
                )
                contract_checks[field] = actual_value == expected[field]

        results.append(
            {
                "fixture": fixture_name,
                "label": label,
                "predicted_positive": predicted_positive,
                "actual_positive": actual_positive,
                "classification": classification,
                "score": risk.get("score"),
                "tier": risk.get("tier"),
                "action": action,
                "severity": decision.get("severity"),
                "contract_checks": contract_checks,
            }
        )

    matrix = ConfusionMatrix(
        true_positive=sum(result["classification"] == "TP" for result in results),
        false_positive=sum(result["classification"] == "FP" for result in results),
        false_negative=sum(result["classification"] == "FN" for result in results),
        true_negative=sum(result["classification"] == "TN" for result in results),
    )

    metrics = calculate_metrics(matrix)

    print("\n=== Phase 5 Detection Evaluation ===")

    for result in results:
        print(
            f"{result['classification']:2} "
            f"{result['fixture']} "
            f"label={result['label']} "
            f"action={result['action']} "
            f"score={result['score']}"
        )

    print("\nConfusion Matrix")
    print(f"  TP: {matrix.true_positive}")
    print(f"  FP: {matrix.false_positive}")
    print(f"  FN: {matrix.false_negative}")
    print(f"  TN: {matrix.true_negative}")

    print("\nMetrics")
    print(f"  Precision:          {metrics['precision']:.4f}")
    print(f"  Recall:             {metrics['recall']:.4f}")
    print(f"  F1:                 {metrics['f1']:.4f}")
    print(f"  False Positive Rate:{metrics['false_positive_rate']:.4f}")

    contract_failures = [
        result for result in results if not all(result["contract_checks"].values())
    ]

    assert not contract_failures, f"Ground-truth contract failures: {contract_failures}"


def test_evaluation_corpus_matches_ground_truth() -> None:
    ground_truth = load_json(GROUND_TRUTH)
    corpus = load_json(CORPUS)

    ground_truth_fixtures = set(ground_truth["fixtures"])
    corpus_fixtures = {case["fixture"] for case in corpus["cases"]}

    assert corpus_fixtures == ground_truth_fixtures
