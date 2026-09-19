"""Static contract tests for the Phase 3.9 WF6 daily digest export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
WF6_PATH = REPO_ROOT / "n8n" / "workflows" / "WF6_soc-daily-digest.json"
IMPORT_SCRIPT = REPO_ROOT / "scripts" / "n8n-import-workflows.sh"
SMTP_CREDENTIAL_ID = "smtp-lab-mailpit"
SMTP_CREDENTIAL_NAME = "SMTP Lab Mailpit"


def _workflow() -> dict[str, Any]:
    return json.loads(WF6_PATH.read_text(encoding="utf-8"))


def _node(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    return next(node for node in workflow["nodes"] if node["name"] == name)


def _all_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _all_strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _all_strings(item)]
    return []


def test_wf6_json_structure_and_stable_id() -> None:
    assert WF6_PATH.is_file()
    workflow = _workflow()
    assert workflow["name"] == "WF6_soc-daily-digest"
    assert workflow["id"] == "wf6-soc-daily-digest"
    assert workflow["active"] is False
    assert workflow["settings"]["timezone"] == "UTC"
    names = {node["name"] for node in workflow["nodes"]}
    assert {
        "Schedule Trigger - Daily 07:00 UTC",
        "HTTP - Get Daily Stats",
        "Validate Stats Response",
        "Switch - Stats Available?",
        "Format Daily Digest",
        "Email - Daily Digest",
        "Fail Safe - Skip Digest",
    } <= names


def test_wf6_schedule_is_0700_utc() -> None:
    schedule = _node(_workflow(), "Schedule Trigger - Daily 07:00 UTC")
    intervals = schedule["parameters"]["rule"]["interval"]
    assert intervals == [{"field": "cronExpression", "expression": "0 7 * * *"}]
    assert "UTC" in schedule["notes"]


def test_wf6_calls_stats_endpoint_with_existing_shared_token() -> None:
    http = _node(_workflow(), "HTTP - Get Daily Stats")
    assert http["parameters"]["method"] == "GET"
    assert "/api/v1/stats/daily" in http["parameters"]["url"]
    headers = http["parameters"]["headerParameters"]["parameters"]
    assert {header["name"] for header in headers} >= {"X-N8N-Token", "Accept"}
    token_value = next(header["value"] for header in headers if header["name"] == "X-N8N-Token")
    assert "$env.N8N_WEBHOOK_TOKEN" in token_value
    assert "$env.N8N_CALLBACK_TOKEN" in token_value
    assert http["parameters"]["options"]["continueOnFail"] is True
    assert http["continueOnFail"] is True


def test_wf6_has_safe_validation_format_and_failure_path() -> None:
    workflow = _workflow()
    validation = _node(workflow, "Validate Stats Response")
    validation_code = validation["parameters"]["functionCode"]
    assert "stats_endpoint_failed" in validation_code
    assert "timezone === 'UTC'" in validation_code

    switch = _node(workflow, "Switch - Stats Available?")
    assert switch["parameters"]["options"]["fallbackOutput"] == "extra"
    connections = workflow["connections"]["Switch - Stats Available?"]["main"]
    assert connections[0][0]["node"] == "Format Daily Digest"
    assert connections[1][0]["node"] == "Fail Safe - Skip Digest"


def test_wf6_uses_existing_smtp_credential_and_env_email_settings() -> None:
    email = _node(_workflow(), "Email - Daily Digest")
    smtp = email["credentials"]["smtp"]
    assert smtp == {"id": SMTP_CREDENTIAL_ID, "name": SMTP_CREDENTIAL_NAME}
    params = email["parameters"]
    assert "$env.SOC_FROM_EMAIL" in params["fromEmail"]
    assert "$env.SOC_L1_EMAIL" in params["toEmail"]
    assert "$env.SOC_L2_EMAIL" in params["toEmail"]
    assert params["emailType"] == "html"


def test_wf6_contains_no_secrets_or_raw_payload_fields() -> None:
    workflow = _workflow()
    dumped = json.dumps(workflow).lower()
    assert "full_log" not in dumped
    assert "test-callback-token-not-a-real-secret" not in dumped
    assert "test-ingest-key-not-a-real-secret" not in dumped
    assert "change-me" not in dumped

    # The checked-in export may reference env names and credential metadata,
    # but it must not contain a non-empty secret-looking value.
    for text in _all_strings(workflow):
        assert not text.lower().startswith(("password=", "token=", "secret="))


def test_import_helper_includes_wf6() -> None:
    script = IMPORT_SCRIPT.read_text(encoding="utf-8")
    assert "WF6_soc-daily-digest.json" in script
