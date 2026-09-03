"""Unit tests for read-API redaction (Phase 3.3)."""

from __future__ import annotations

from soc_triage.api.schemas import redact_mapping


def test_redact_mapping_drops_full_log_and_secret_keys() -> None:
    payload = {
        "rule": {"id": "5710"},
        "full_log": "sshd: Failed password for root from 203.0.113.50",
        "data": {
            "srcip": "203.0.113.50",
            "password": "hunter2",
            "api_key": "lab-placeholder-must-drop",
            "nested": {"authorization": "Bearer abc", "srcuser": "jdoe-lab"},
        },
        "token": "should-go",
    }
    redacted = redact_mapping(payload)
    assert "full_log" not in redacted
    assert "token" not in redacted
    assert redacted["rule"] == {"id": "5710"}
    assert redacted["data"]["srcip"] == "203.0.113.50"
    assert "password" not in redacted["data"]
    assert "api_key" not in redacted["data"]
    assert "authorization" not in redacted["data"]["nested"]
    assert redacted["data"]["nested"]["srcuser"] == "jdoe-lab"


def test_redact_mapping_is_identity_for_primitives() -> None:
    assert redact_mapping("ok") == "ok"
    assert redact_mapping(7) == 7
    assert redact_mapping(None) is None
    assert redact_mapping(["a", {"secret": "x"}]) == ["a", {}]
