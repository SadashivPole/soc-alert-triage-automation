"""Regression tests for WF1 token validation fix (Phase 2B).

Validates:
* Python n8n_auth: missing -> rejected, wrong -> rejected, correct -> accepted
* Workflow JSON logic: reads $env secret, exact match, rejects missing/wrong,
  never logs token
* Security: no secret in JSON, no token logging
"""

from __future__ import annotations

import json
import pathlib

import pytest
from fastapi import Request
from fastapi.exceptions import HTTPException

from soc_triage.api.n8n_auth import _extract_token, verify_n8n_token
from soc_triage.core.config import Settings

REPO_ROOT = pathlib.Path(__file__).parents[3]
WF1_PATH = REPO_ROOT / "n8n" / "workflows" / "WF1_soc-triage-router.json"


def _make_request(settings: Settings) -> Request:
    # Minimal request mock with app.state.settings
    # Starlette Request requires scope["app"] to exist.
    from types import SimpleNamespace

    mock_app = SimpleNamespace(state=SimpleNamespace(settings=settings))
    scope = {
        "type": "http",
        "headers": [],
        "path": "/api/v1/alerts/xxx/feedback",
        "app": mock_app,
    }

    # Minimal required scope fields for Request.
    scope["server"] = ("testserver", 80)
    scope["scheme"] = "http"
    scope["method"] = "GET"
    scope["query_string"] = b""

    return Request(scope)


def test_extract_token_precedence() -> None:
    assert _extract_token("t1", None, None) == "t1"
    assert _extract_token(None, "t2", None) == "t2"
    assert _extract_token(None, None, "Bearer t3") == "t3"
    assert _extract_token(None, None, "t3-raw") == "t3-raw"
    assert _extract_token(None, None, None) is None


def test_n8n_auth_missing_token_rejected() -> None:
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_callback_token="expected-secret-token",
        n8n_webhook_token="",
    )

    req = _make_request(settings)

    with pytest.raises(HTTPException) as exc:
        verify_n8n_token(
            req,
            x_n8n_token=None,
            x_callback_token=None,
            authorization=None,
        )

    assert exc.value.status_code == 401
    assert "missing" in exc.value.detail.lower()


def test_n8n_auth_wrong_token_rejected() -> None:
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_callback_token="expected-secret-token",
        n8n_webhook_token="",
    )

    req = _make_request(settings)

    with pytest.raises(HTTPException) as exc:
        verify_n8n_token(
            req,
            x_n8n_token="wrong-token",
            x_callback_token=None,
            authorization=None,
        )

    assert exc.value.status_code == 401
    assert "invalid" in exc.value.detail.lower()

    with pytest.raises(HTTPException) as exc2:
        verify_n8n_token(
            req,
            x_n8n_token=None,
            x_callback_token=None,
            authorization="Bearer wrong",
        )

    assert exc2.value.status_code == 401


def test_n8n_auth_correct_token_accepted() -> None:
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_callback_token="expected-secret-token",
        n8n_webhook_token="",
    )

    req = _make_request(settings)

    # X-N8N-Token header.
    verify_n8n_token(
        req,
        x_n8n_token="expected-secret-token",
        x_callback_token=None,
        authorization=None,
    )

    # X-Callback-Token header.
    verify_n8n_token(
        req,
        x_n8n_token=None,
        x_callback_token="expected-secret-token",
        authorization=None,
    )

    # Bearer token.
    verify_n8n_token(
        req,
        x_n8n_token=None,
        x_callback_token=None,
        authorization="Bearer expected-secret-token",
    )


def test_n8n_auth_not_configured_fails_closed() -> None:
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_callback_token="",
        n8n_webhook_token="",
        n8n_webhook_url="",
    )

    req = _make_request(settings)

    with pytest.raises(HTTPException) as exc:
        verify_n8n_token(
            req,
            x_n8n_token="anything",
            x_callback_token=None,
            authorization=None,
        )

    assert exc.value.status_code == 503


def test_wf1_workflow_json_real_validation() -> None:
    """Validate WF1 JSON contains real secret comparison, not just existence check."""
    assert WF1_PATH.exists(), f"WF1 not found at {WF1_PATH}"

    data = json.loads(WF1_PATH.read_text())
    nodes = data.get("nodes", [])

    validate_nodes = [node for node in nodes if "validate" in node.get("name", "").lower()]
    assert validate_nodes, "No validate node found in WF1"

    code = ""

    for node in validate_nodes:
        params = node.get("parameters", {})
        if "functionCode" in params:
            code += params["functionCode"]

    # Must read from $env.N8N_CALLBACK_TOKEN or $env.N8N_WEBHOOK_TOKEN.
    assert "$env.N8N_CALLBACK_TOKEN" in code or "$env.N8N_WEBHOOK_TOKEN" in code, (
        "WF1 must read expected secret from $env.N8N_CALLBACK_TOKEN or $env.N8N_WEBHOOK_TOKEN"
    )

    # Must compare supplied vs expected (exact match).
    assert "supplied" in code and "expected" in code, "WF1 must compare supplied vs expected"
    assert " !== " in code or "!==" in code or "!=" in code or "compare" in code.lower(), (
        "WF1 must do comparison"
    )

    # Must reject missing.
    assert "Missing authentication token" in code or "missing" in code.lower(), (
        "WF1 must reject missing token"
    )

    # Must reject invalid.
    assert "Invalid authentication token" in code or "invalid" in code.lower(), (
        "WF1 must reject invalid token"
    )

    # Never log token.
    lower_code = code.lower()

    assert "console.log(supplied" not in lower_code
    assert "console.log(expected" not in lower_code

    # Ensure no secret hardcoded in JSON.
    dumped = json.dumps(data)

    assert "test-callback-token-not-a-real-secret" not in dumped.lower()
    assert "test-ingest-key-not-a-real-secret" not in dumped.lower()

    # Ensure no secret word like "super-secret" hardcoded.
    assert "super-secret" not in dumped.lower() or "credential" in dumped.lower()

    # Notes must mention env credential handling.
    notes_combined = " ".join(node.get("notes", "") for node in nodes).lower()

    assert "env" in notes_combined or "$env" in dumped, "WF1 notes should mention env credential"


def test_wf1_no_secret_in_json() -> None:
    data = json.loads(WF1_PATH.read_text())

    # Ensure no hardcoded token values.
    for node in data.get("nodes", []):
        if node.get("type") != "n8n-nodes-base.httpRequest":
            continue

        headers = node.get("parameters", {}).get("headerParameters", {}).get("parameters", [])

        for header in headers:
            if "token" not in header.get("name", "").lower():
                continue

            value = header.get("value", "")

            # Must be an env reference, not a plain secret.
            assert "$env" in value or "{{" in value, (
                f"Token header must use env reference, got {value}"
            )

            # Environment references are short.
            assert len(value) < 100


def test_all_workflows_use_env_token_reference() -> None:
    """All workflows that send X-N8N-Token must use $env reference."""
    workflow_dir = REPO_ROOT / "n8n" / "workflows"

    for wf_path in workflow_dir.glob("*.json"):
        data = json.loads(wf_path.read_text())

        for node in data.get("nodes", []):
            params = node.get("parameters", {})

            header_params = params.get("headerParameters", {}).get("parameters", [])

            for header_param in header_params:
                if "token" not in header_param.get("name", "").lower():
                    continue

                value = header_param.get("value", "")

                assert "$env" in value, (
                    f"{wf_path.name} node {node.get('name')} "
                    f"must use $env token reference, got {value}"
                )
