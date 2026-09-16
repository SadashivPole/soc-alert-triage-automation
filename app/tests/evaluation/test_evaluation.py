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

#: Stable factor ordering contract (scoring.v1, ARCHITECTURE.md §8): every
#: healthy ingest response must carry exactly these factors, in this order.
CANONICAL_FACTOR_ORDER = (
    "rule_severity",
    "rule_groups_mitre",
    "asset_criticality",
    "recurrence_velocity",
    "ioc_evidence",
    "enrichment_status",
    "allowlist_modifier",
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_fixture(name: str) -> dict[str, Any]:
    return load_json(FIXTURES_DIR / name)


def _contract_checks(
    expected: dict[str, Any],
    body: dict[str, Any],
) -> dict[str, bool]:
    """Compare a ground-truth ``expected`` block against one ingest response."""
    risk = body["risk"]
    decision = body["decision"]

    checks: dict[str, bool] = {}
    for field in ("score", "tier", "action", "severity"):
        if field in expected:
            actual_value = risk.get(field) if field in {"score", "tier"} else decision.get(field)
            checks[field] = actual_value == expected[field]
    return checks


def _deliveries(case: dict[str, Any]) -> int:
    """Number of distinct ingest deliveries for a corpus case (default 1)."""
    return int(case.get("deliveries", 1))


def _delivery_payloads(payload: dict[str, Any], count: int) -> list[dict[str, Any]]:
    """Build ``count`` distinct deliveries of one fixture.

    The first delivery replays the fixture byte-for-byte; later deliveries
    change only the event id so the deduplicator treats them as distinct
    recurrences of the same rule+agent group (never as exact duplicates).
    """
    payloads = [payload]
    for n in range(2, count + 1):
        payloads.append(dict(payload, id=f"{payload.get('id')}.r{n}"))
    return payloads


def _stable_contract(body: dict[str, Any]) -> dict[str, Any]:
    """The response fields that must be identical across repeated replays.

    Deliberately excludes volatile detail text (occurrence counts and spans
    appear inside factor ``detail`` strings); keeps the stable contract:
    score, tier, action, severity, reasons, and factor names + points.
    """
    return {
        "engine_version": body["risk"]["engine_version"],
        "degraded": body["risk"]["degraded"],
        "score": body["risk"]["score"],
        "tier": body["risk"]["tier"],
        "factor_points": {f["name"]: f["points"] for f in body["risk"]["factors"]},
        "action": body["decision"]["action"],
        "severity": body["decision"]["severity"],
        "reasons": list(body["decision"]["reasons"]),
    }


def _assert_response_contract(fixture_name: str, body: dict[str, Any]) -> None:
    """Assert the stable scoring.v1 / decisions.v1 response contract."""
    risk = body["risk"]
    decision = body["decision"]

    assert risk["engine_version"] == "scoring.v1", fixture_name
    assert risk["degraded"] is False, fixture_name
    assert [f["name"] for f in risk["factors"]] == list(CANONICAL_FACTOR_ORDER), fixture_name

    assert decision["reasons"], fixture_name
    if decision["action"] == "suppress":
        assert any("allowlisted" in reason for reason in decision["reasons"]), fixture_name
    else:
        assert decision["reasons"][0].startswith("score="), fixture_name
        assert "tier=" in decision["reasons"][0], fixture_name

    if decision["action"] == "open_incident":
        assert decision["severity"] in {"SEV1", "SEV2"}, fixture_name
        assert body["incident_id"], fixture_name
    else:
        assert decision["severity"] is None, fixture_name

    # The corpus is a fully-offline, deterministic replay: no external
    # enrichment provider is enabled, so every fixture must be scored with
    # enrichment skipped (never complete/partial/failed).
    assert body["enrichment_status"] == "skipped", fixture_name


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

        payloads = _delivery_payloads(load_fixture(fixture_name), _deliveries(case))

        bodies: list[dict[str, Any]] = []
        for payload in payloads:
            response = client.post(
                "/api/v1/alerts/ingest",
                json=payload,
                headers=AUTH_HEADERS,
            )

            assert response.status_code in {200, 202}, (
                fixture_name,
                response.text,
            )
            bodies.append(response.json())

        first = bodies[0]
        final = bodies[-1]
        action = final["decision"]["action"]

        assert action in POSITIVE_ACTIONS | NEGATIVE_ACTIONS, (
            fixture_name,
            f"Unsupported decision action: {action}",
        )

        # Stable scoring/decision contract on every delivery.
        for body in bodies:
            _assert_response_contract(fixture_name, body)

        # Ground-truth `expected` always pins the FIRST delivery outcome.
        expected = ground_truth["fixtures"][fixture_name].get("expected", {})
        first_checks = _contract_checks(expected, first)

        contract_checks: dict[str, bool] = dict(first_checks)

        # When ground truth carries a `recurrence` block it additionally pins
        # the escalation across the case's deliveries.
        recurrence = ground_truth["fixtures"][fixture_name].get("recurrence")
        if recurrence is not None:
            assert _deliveries(case) == recurrence["deliveries"], fixture_name
            assert final["dedupe"]["occurrences"] == recurrence["occurrences"], fixture_name
            assert final["dedupe_status"] == "repeated", fixture_name
            contract_checks.update(_contract_checks(recurrence["after_final_delivery"], final))

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

        results.append(
            {
                "fixture": fixture_name,
                "label": label,
                "predicted_positive": predicted_positive,
                "actual_positive": actual_positive,
                "classification": classification,
                "score": first["risk"]["score"],
                "tier": first["risk"]["tier"],
                "action": action,
                "severity": final["decision"]["severity"],
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


def test_corpus_labels_match_ground_truth_actions() -> None:
    """Label semantics (Phase 6.3).

    Labels classify the *scenario*, not each pinned outcome:

    * ``negative`` — benign scenario: every pinned outcome (including a
      recurrence escalation, if any) must stay passive (``monitor``/
      ``suppress``). Routing a benign case to L1/incident is a false
      positive and fails here.
    * ``positive`` — attack/malicious scenario: no pinned outcome may ever
      be suppressed. ``queue_l1``/``open_incident`` warrant action; a
      first-occurrence ``monitor`` is the accepted UC-1 under-triage case
      (reported transparently as an FN by the harness above).
    """
    ground_truth = load_json(GROUND_TRUTH)
    corpus = load_json(CORPUS)

    for case in corpus["cases"]:
        record = ground_truth["fixtures"][case["fixture"]]
        outcomes = [record["expected"]]
        if "recurrence" in record:
            outcomes.append(record["recurrence"]["after_final_delivery"])

        actions = {outcome["action"] for outcome in outcomes}
        if case["label"] == "negative":
            assert actions <= NEGATIVE_ACTIONS, (case["fixture"], actions)
        else:
            assert "suppress" not in actions, (case["fixture"], actions)


def test_recurrence_scenario_escalates_according_to_ground_truth(client: TestClient) -> None:
    """The corpus recurrence case (deliveries > 1) escalates exactly as the
    ground-truth ``recurrence`` block pins, and the score delta is attributable
    to the recurrence factor alone.

    Every expectation is read from ``evaluation/ground_truth.json`` — this test
    pins no values of its own, so a policy change that updates ground truth
    keeps the scenario green while any unexplained drift fails here.
    """
    ground_truth = load_json(GROUND_TRUTH)
    corpus = load_json(CORPUS)

    recurrence_cases = [
        case
        for case in corpus["cases"]
        if _deliveries(case) > 1
        and "recurrence" in ground_truth["fixtures"].get(case["fixture"], {})
    ]
    assert recurrence_cases, "expected at least one multi-delivery ground-truth recurrence case"

    for case in recurrence_cases:
        record = ground_truth["fixtures"][case["fixture"]]
        recurrence = record["recurrence"]
        assert _deliveries(case) == recurrence["deliveries"], case["fixture"]

        payloads = _delivery_payloads(load_fixture(case["fixture"]), recurrence["deliveries"])
        bodies = [
            client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS).json()
            for payload in payloads
        ]

        first = bodies[0]
        final = bodies[-1]

        # The escalation is recurrence-driven: only the recurrence factor's points
        # change between first and final delivery.
        first_points = {f["name"]: f["points"] for f in first["risk"]["factors"]}
        final_points = {f["name"]: f["points"] for f in final["risk"]["factors"]}
        changed = {
            name for name, points in first_points.items() if final_points.get(name) != points
        }
        assert changed == {"recurrence_velocity"}, (
            case["fixture"],
            first_points,
            final_points,
        )

        if "occurrences" in recurrence:
            assert final["dedupe"]["occurrences"] == recurrence["occurrences"]
        assert final["dedupe_status"] == "repeated"

        expected_final = recurrence.get("after_final_delivery", {})
        if "score" in expected_final:
            assert final["risk"]["score"] == expected_final["score"]
        if "tier" in expected_final:
            assert final["risk"]["tier"] == expected_final["tier"]
        if "action" in expected_final:
            assert final["decision"]["action"] == expected_final["action"]

        # A recurrence case must pin a changed score attributable to recurrence.
        if "score" in expected_final:
            assert expected_final["score"] != record["expected"].get("score")


def test_repeated_evaluation_is_deterministic(client: TestClient) -> None:
    """Replaying every corpus fixture a second time (as a distinct recurrence
    event) produces the identical stable contract: same score, tier, factor
    points, action, severity, and decision reasons.
    """
    corpus = load_json(CORPUS)

    for case in corpus["cases"]:
        fixture_name = case["fixture"]
        payload = load_fixture(fixture_name)

        first_response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
        repeat_response = client.post(
            "/api/v1/alerts/ingest",
            json=dict(payload, id=f"{payload.get('id')}.replay"),
            headers=AUTH_HEADERS,
        )

        assert first_response.status_code in {200, 202}, first_response.text
        assert repeat_response.status_code in {200, 202}, repeat_response.text

        assert _stable_contract(repeat_response.json()) == _stable_contract(
            first_response.json()
        ), fixture_name
