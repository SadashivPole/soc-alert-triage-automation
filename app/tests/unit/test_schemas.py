"""Unit tests for Wazuh alert schema validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from soc_triage.ingest.schemas import WazuhAlert

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def sample_alerts() -> list[dict]:
    """Load all sample alert fixtures."""
    alerts = []
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        with path.open() as f:
            alerts.append(json.load(f))
    return alerts


def test_wazuh_alert_accepts_all_sample_fixtures(sample_alerts: list[dict]) -> None:
    """Every sample alert in docs/sample-alerts/ must parse successfully."""
    assert len(sample_alerts) >= 6, "expected at least 6 sample alerts"
    for raw in sample_alerts:
        alert = WazuhAlert.model_validate(raw)
        assert alert.rule.id
        assert alert.agent.id
        assert alert.agent.name


def test_wazuh_alert_rejects_missing_rule() -> None:
    with pytest.raises(ValidationError):
        WazuhAlert.model_validate({"agent": {"id": "001", "name": "test"}})


def test_wazuh_alert_rejects_missing_agent() -> None:
    with pytest.raises(ValidationError):
        WazuhAlert.model_validate({"rule": {"id": "5710", "level": 5, "description": "test"}})


def test_wazuh_alert_rejects_invalid_rule_level() -> None:
    with pytest.raises(ValidationError):
        WazuhAlert.model_validate(
            {
                "rule": {"id": "5710", "level": 99, "description": "bad level"},
                "agent": {"id": "001", "name": "test"},
            }
        )


def test_wazuh_alert_rejects_empty_description() -> None:
    with pytest.raises(ValidationError):
        WazuhAlert.model_validate(
            {
                "rule": {"id": "5710", "level": 5, "description": ""},
                "agent": {"id": "001", "name": "test"},
            }
        )


def test_wazuh_alert_accepts_minimal_payload() -> None:
    """A minimal alert with only required fields should parse."""
    alert = WazuhAlert.model_validate(
        {
            "rule": {"id": "1000", "level": 0, "description": "minimal"},
            "agent": {"id": "000", "name": "agent-zero"},
        }
    )
    assert alert.rule.id == "1000"
    assert alert.rule.level == 0
    assert alert.agent.id == "000"
    assert alert.data is None
    assert alert.full_log is None


def test_wazuh_alert_preserves_extra_fields() -> None:
    """Extra fields from Wazuh should be preserved, not rejected."""
    alert = WazuhAlert.model_validate(
        {
            "rule": {"id": "5710", "level": 5, "description": "test", "custom_field": "value"},
            "agent": {"id": "001", "name": "test", "labels": {"tier": "critical"}},
            "syscheck": {"path": "/etc/passwd"},
            "unknown_future_field": {"nested": True},
        }
    )
    assert alert.syscheck == {"path": "/etc/passwd"}


def test_wazuh_alert_coerces_numeric_rule_id() -> None:
    """Numeric rule IDs should be coerced to strings."""
    alert = WazuhAlert.model_validate(
        {
            "rule": {"id": 5710, "level": 5, "description": "numeric id"},
            "agent": {"id": 1, "name": "test"},
        }
    )
    assert alert.rule.id == "5710"
    assert alert.agent.id == "1"


def test_wazuh_alert_parses_timestamp() -> None:
    raw = {
        "rule": {"id": "5710", "level": 5, "description": "test"},
        "agent": {"id": "001", "name": "test"},
        "timestamp": "2026-08-29T10:15:29.000+0000",
    }
    alert = WazuhAlert.model_validate(raw)
    parsed = alert.parsed_timestamp
    assert parsed is not None
    assert parsed.year == 2026
    assert parsed.month == 8


def test_wazuh_alert_parses_timestamp_without_milliseconds() -> None:
    raw = {
        "rule": {"id": "5710", "level": 5, "description": "test"},
        "agent": {"id": "001", "name": "test"},
        "timestamp": "2026-08-29T10:15:29+0000",
    }
    alert = WazuhAlert.model_validate(raw)
    parsed = alert.parsed_timestamp
    assert parsed is not None


def test_wazuh_alert_handles_invalid_timestamp() -> None:
    raw = {
        "rule": {"id": "5710", "level": 5, "description": "test"},
        "agent": {"id": "001", "name": "test"},
        "timestamp": "not-a-timestamp",
    }
    alert = WazuhAlert.model_validate(raw)
    assert alert.parsed_timestamp is None


def test_wazuh_mitre_fields() -> None:
    raw = {
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "test",
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "agent": {"id": "001", "name": "test"},
    }
    alert = WazuhAlert.model_validate(raw)
    assert alert.rule.mitre is not None
    assert alert.rule.mitre.id == ["T1110"]
    assert alert.rule.mitre.tactic == ["Credential Access"]


def test_wazuh_data_optional_fields() -> None:
    raw = {
        "rule": {"id": "5710", "level": 5, "description": "test"},
        "agent": {"id": "001", "name": "test"},
        "data": {"srcip": "203.0.113.50", "srcport": 41234, "dstuser": "admin"},
    }
    alert = WazuhAlert.model_validate(raw)
    assert alert.data is not None
    assert alert.data.srcip == "203.0.113.50"
    assert alert.data.srcport == 41234
    assert alert.data.dstuser == "admin"
    assert alert.data.dstip is None
