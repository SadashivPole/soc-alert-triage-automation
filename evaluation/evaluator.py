from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH = ROOT / "evaluation" / "ground_truth.json"


def load_ground_truth() -> dict[str, Any]:
    return json.loads(GROUND_TRUTH.read_text(encoding="utf-8-sig"))


def compare_expected(
    expected: dict[str, Any],
    actual: dict[str, Any],
) -> dict[str, Any]:
    checks: dict[str, bool] = {}

    if "score" in expected:
        checks["score"] = actual.get("score") == expected["score"]

    if "tier" in expected:
        checks["tier"] = actual.get("tier") == expected["tier"]

    if "action" in expected:
        checks["action"] = actual.get("action") == expected["action"]

    if "severity" in expected:
        checks["severity"] = actual.get("severity") == expected["severity"]

    return {
        "checks": checks,
        "verified": all(checks.values()) if checks else False,
    }


def evaluate_fixture(
    fixture_name: str,
    actual: dict[str, Any],
    ground_truth: dict[str, Any],
) -> dict[str, Any]:
    record = ground_truth["fixtures"].get(fixture_name)

    if record is None:
        return {
            "fixture": fixture_name,
            "status": "untracked",
        }

    expected = record.get("expected", {})
    score_contract = record.get("score_contract", "verified")

    risk = actual.get("risk", {})
    decision = actual.get("decision", {})

    observed = {
        "score": risk.get("score"),
        "tier": risk.get("tier"),
        "action": decision.get("action"),
        "severity": decision.get("severity"),
    }

    if score_contract == "unverified":
        return {
            "fixture": fixture_name,
            "status": "partial",
            "observed": observed,
            "expected": expected,
            "checks": {
                "rule_id": actual.get("normalized", {})
                .get("rule", {})
                .get("id"),
                "rule_level": actual.get("normalized", {})
                .get("rule", {})
                .get("level"),
            },
            "notes": record.get("notes"),
        }

    comparison = compare_expected(expected, observed)

    return {
        "fixture": fixture_name,
        "status": "pass" if comparison["verified"] else "fail",
        "observed": observed,
        "expected": expected,
        "checks": comparison["checks"],
        "notes": record.get("notes"),
    }


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        "pass": 0,
        "fail": 0,
        "partial": 0,
        "untracked": 0,
    }

    for result in results:
        status = result["status"]
        counts[status] = counts.get(status, 0) + 1

    verified = counts["pass"] + counts["fail"]

    return {
        "fixtures": len(results),
        "pass": counts["pass"],
        "fail": counts["fail"],
        "partial": counts["partial"],
        "untracked": counts["untracked"],
        "verified_total": verified,
        "pass_rate": (
            counts["pass"] / verified
            if verified
            else None
        ),
    }


def main() -> int:
    ground_truth = load_ground_truth()

    print("Phase 5 Detection Evaluation Framework")
    print("=" * 38)
    print()
    print("Ground-truth fixtures:")

    for fixture_name, record in ground_truth["fixtures"].items():
        contract = record.get("score_contract", "verified")
        print(f"  {fixture_name}: {contract}")

    print()
    print("Framework initialized successfully.")
    print("Runtime scoring evaluation is implemented in the test harness.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())