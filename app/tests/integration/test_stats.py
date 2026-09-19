"""Phase 3.9 daily statistics API integration tests.

These tests use the normal FastAPI startup and temporary SQLite migrations.
The stats surface is aggregate-only, UTC half-open-window based, and protected
by the existing shared n8n token.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage.api import alerts as alerts_api
from soc_triage.api import feedback as feedback_api
from soc_triage.api import stats as stats_api

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
INGEST_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
TOKEN_HEADERS = {"X-N8N-Token": TEST_CALLBACK_TOKEN}


def _load_fixture(name: str = "01_wazuh_ssh_brute_force.json") -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _payload(
    *,
    event_id: str,
    rule_id: str = "5710",
    agent_id: str = "001",
    fixture: str = "01_wazuh_ssh_brute_force.json",
    raw_marker: str | None = None,
) -> dict[str, Any]:
    payload = copy.deepcopy(_load_fixture(fixture))
    payload["id"] = event_id
    payload["rule"]["id"] = rule_id
    payload["agent"]["id"] = agent_id
    payload["agent"]["name"] = f"host-{agent_id}"
    if raw_marker is not None:
        payload["full_log"] = raw_marker
    return payload


def _ingest(
    client: TestClient,
    monkeypatch: Any,
    payload: dict[str, Any],
    received_at: datetime,
) -> dict[str, Any]:
    monkeypatch.setattr(alerts_api, "_utc_now", lambda: received_at)
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=INGEST_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _feedback(
    client: TestClient,
    monkeypatch: Any,
    alert_id: str,
    verdict: str,
    received_at: datetime,
) -> None:
    monkeypatch.setattr(feedback_api, "_utc_now", lambda: received_at)
    response = client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": verdict, "actor": "analyst@example.test"},
        headers=TOKEN_HEADERS,
    )
    assert response.status_code == 200, response.text


def _get_stats(client: TestClient, **params: str) -> Any:
    return client.get("/api/v1/stats/daily", params=params or None, headers=TOKEN_HEADERS)


def test_stats_requires_existing_shared_token(client: TestClient) -> None:
    missing = client.get("/api/v1/stats/daily")
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "unauthorized"

    wrong = client.get("/api/v1/stats/daily", headers={"X-N8N-Token": "wrong-token"})
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "unauthorized"

    ingest_key = client.get("/api/v1/stats/daily", headers=INGEST_HEADERS)
    assert ingest_key.status_code == 401


def test_empty_dataset_and_previous_utc_day_default(client: TestClient, monkeypatch: Any) -> None:
    # Midnight is an important boundary: previous UTC day is the date before
    # midnight, not the calendar date containing the current instant.
    monkeypatch.setattr(
        stats_api,
        "_utc_now",
        lambda: datetime(2026, 9, 19, 0, 0, 0, tzinfo=UTC),
    )
    response = _get_stats(client)
    assert response.status_code == 200, response.text
    assert response.json() == {
        "date": "2026-09-18",
        "timezone": "UTC",
        "volumes": {"alerts": 0, "incidents": 0, "feedback": 0},
        "false_positive_rate": 0.0,
        "false_positive_count": 0,
        "feedback_count": 0,
        "top_rules": [],
        "tuning_suggestions": [],
    }


def test_explicit_date_uses_half_open_utc_boundaries_and_counts_volumes(
    client: TestClient, monkeypatch: Any
) -> None:
    before = datetime(2026, 9, 17, 23, 59, 59, tzinfo=UTC)
    start = datetime(2026, 9, 18, 0, 0, 0, tzinfo=UTC)
    end = datetime(2026, 9, 18, 23, 59, 59, tzinfo=UTC)
    after = datetime(2026, 9, 19, 0, 0, 0, tzinfo=UTC)

    _ingest(client, monkeypatch, _payload(event_id="stats-before"), before)
    _ingest(
        client,
        monkeypatch,
        _payload(
            event_id="stats-start",
            agent_id="003",
            rule_id="87105",
            fixture="04_wazuh_malware_hash_virustotal.json",
        ),
        start,
    )
    _ingest(
        client,
        monkeypatch,
        _payload(
            event_id="stats-end",
            agent_id="004",
            rule_id="87105",
            fixture="04_wazuh_malware_hash_virustotal.json",
        ),
        end,
    )
    _ingest(
        client,
        monkeypatch,
        _payload(
            event_id="stats-after",
            agent_id="005",
            rule_id="87105",
            fixture="04_wazuh_malware_hash_virustotal.json",
        ),
        after,
    )

    response = _get_stats(client, date="2026-09-18")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["date"] == "2026-09-18"
    assert body["timezone"] == "UTC"
    assert body["volumes"]["alerts"] == 2
    assert body["volumes"]["incidents"] == 2
    assert body["volumes"]["feedback"] == 0
    assert [row["rule_id"] for row in body["top_rules"]] == ["87105"]
    assert body["top_rules"][0]["count"] == 2

    invalid = _get_stats(client, date="2026-9-18")
    assert invalid.status_code == 422


def test_feedback_denominator_rate_and_exact_three_pair_suggestion(
    client: TestClient, monkeypatch: Any
) -> None:
    day = datetime(2026, 9, 18, 10, 0, 0, tzinfo=UTC)
    alert = _ingest(
        client,
        monkeypatch,
        _payload(event_id="feedback-main", rule_id="100101", agent_id="007"),
        day,
    )

    _feedback(client, monkeypatch, alert["alert_id"], "false_positive", day)
    _feedback(
        client,
        monkeypatch,
        alert["alert_id"],
        "true_positive",
        day.replace(hour=11),
    )
    _feedback(
        client,
        monkeypatch,
        alert["alert_id"],
        "false_positive",
        day.replace(hour=12),
    )

    two_response = _get_stats(client, date="2026-09-18")
    assert two_response.status_code == 200
    two_body = two_response.json()
    assert two_body["volumes"]["feedback"] == 3
    assert two_body["feedback_count"] == 3
    assert two_body["false_positive_count"] == 2
    assert two_body["false_positive_rate"] == 0.6667
    assert two_body["tuning_suggestions"] == []

    _feedback(
        client,
        monkeypatch,
        alert["alert_id"],
        "false_positive",
        day.replace(hour=13),
    )
    three_body = _get_stats(client, date="2026-09-18").json()
    assert three_body["volumes"]["feedback"] == 4
    assert three_body["false_positive_count"] == 3
    assert three_body["feedback_count"] == 4
    assert three_body["false_positive_rate"] == 0.75
    assert three_body["tuning_suggestions"] == [
        {"rule_id": "100101", "agent_id": "007", "false_positive_count": 3}
    ]


def test_multiple_pairs_top_rule_ties_are_deterministic_and_payloads_do_not_leak(
    client: TestClient, monkeypatch: Any
) -> None:
    received_at = datetime(2026, 9, 18, 14, 0, 0, tzinfo=UTC)
    # Rule 100 and 101 tie at two rows; lexical rule_id ordering must win.
    rows = [
        ("100", "007"),
        ("100", "007"),
        ("101", "008"),
        ("101", "008"),
        ("102", "009"),
        ("103", "010"),
        ("104", "011"),
        ("105", "012"),
        ("106", "013"),
        ("107", "014"),
        ("108", "015"),
        ("109", "016"),
        ("110", "017"),
    ]
    pair_alerts: dict[tuple[str, str], list[str]] = {}
    for index, (rule_id, agent_id) in enumerate(rows):
        alert = _ingest(
            client,
            monkeypatch,
            _payload(
                event_id=f"top-rule-{index}",
                rule_id=rule_id,
                agent_id=agent_id,
                raw_marker="RAW-ALERT-MARKER-MUST-NOT-APPEAR",
            ),
            received_at,
        )
        pair_alerts.setdefault((rule_id, agent_id), []).append(alert["alert_id"])

    # Use the tied top-rule rows for feedback so tuning tests do not add a
    # third alert volume to a new rule and alter the top-ten assertion.
    for index in range(3):
        _feedback(
            client,
            monkeypatch,
            pair_alerts[("100", "007")][index % 2],
            "false_positive",
            received_at,
        )
    for index in range(2):
        _feedback(
            client,
            monkeypatch,
            pair_alerts[("101", "008")][index % 2],
            "false_positive",
            received_at,
        )

    response = _get_stats(client, date="2026-09-18")
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["top_rules"]) == 10
    assert body["top_rules"][:3] == [
        {"rule_id": "100", "count": 2},
        {"rule_id": "101", "count": 2},
        {"rule_id": "102", "count": 1},
    ]
    assert body["tuning_suggestions"] == [
        {"rule_id": "100", "agent_id": "007", "false_positive_count": 3}
    ]
    assert "RAW-ALERT-MARKER-MUST-NOT-APPEAR" not in response.text
    assert "full_log" not in response.text
