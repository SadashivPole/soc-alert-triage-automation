"""Regression tests for N8N_WEBHOOK_TOKEN fallback to N8N_CALLBACK_TOKEN consistency.

Fixes integration bug: inbound auth uses N8N_WEBHOOK_TOKEN || N8N_CALLBACK_TOKEN,
but outbound workflow callbacks previously used only N8N_CALLBACK_TOKEN.
Now all outbound callbacks must use same fallback: $env.N8N_WEBHOOK_TOKEN || $env.N8N_CALLBACK_TOKEN.

Tests:
1. only WEBHOOK_TOKEN configured -> callbacks authenticate correctly
2. only CALLBACK_TOKEN configured -> callbacks authenticate correctly
3. both configured -> WEBHOOK takes precedence consistently
4. no token configured -> fail closed safely
5. no token values appear in workflow JSON/logs/tests
"""

from __future__ import annotations

import json
import pathlib

import pytest
from fastapi import Request
from fastapi.exceptions import HTTPException

from soc_triage.api.n8n_auth import verify_n8n_token
from soc_triage.core.config import Settings

REPO_ROOT = pathlib.Path(__file__).parents[3]
WORKFLOW_DIR = REPO_ROOT / "n8n" / "workflows"


def _make_request(settings: Settings) -> Request:
    from types import SimpleNamespace

    mock_app = SimpleNamespace(state=SimpleNamespace(settings=settings))
    scope = {
        "type": "http",
        "headers": [],
        "path": "/api/v1/alerts/xxx/feedback/status",
        "app": mock_app,
        "server": ("testserver", 80),
        "scheme": "http",
        "method": "GET",
        "query_string": b"",
    }
    return Request(scope)


# ---------------------------------------------------------------------------
# Settings.effective_n8n_token fallback logic
# ---------------------------------------------------------------------------


def test_only_webhook_token_configured() -> None:
    """Only N8N_WEBHOOK_TOKEN configured -> effective token is webhook token."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_webhook_token="webhook-only-secret",
        n8n_callback_token="",
        n8n_webhook_url="http://n8n:5678/webhook/test",
    )
    assert settings.effective_n8n_token == "webhook-only-secret"

    # Callback should authenticate with webhook token
    req = _make_request(settings)
    verify_n8n_token(
        req, x_n8n_token="webhook-only-secret", x_callback_token=None, authorization=None
    )

    # Wrong token should fail
    with pytest.raises(HTTPException) as exc:
        verify_n8n_token(req, x_n8n_token="wrong", x_callback_token=None, authorization=None)
    assert exc.value.status_code == 401


def test_only_callback_token_configured() -> None:
    """Only N8N_CALLBACK_TOKEN configured -> effective token is callback token."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_webhook_token="",
        n8n_callback_token="callback-only-secret",
        n8n_webhook_url="http://n8n:5678/webhook/test",
    )
    assert settings.effective_n8n_token == "callback-only-secret"

    req = _make_request(settings)
    verify_n8n_token(
        req, x_n8n_token="callback-only-secret", x_callback_token=None, authorization=None
    )

    with pytest.raises(HTTPException) as exc:
        verify_n8n_token(req, x_n8n_token="wrong", x_callback_token=None, authorization=None)
    assert exc.value.status_code == 401


def test_both_tokens_webhook_precedence() -> None:
    """Both configured -> WEBHOOK token takes precedence consistently."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_webhook_token="webhook-precedence-secret",
        n8n_callback_token="callback-secret",
        n8n_webhook_url="http://n8n:5678/webhook/test",
    )
    # effective_n8n_token must be webhook token, not callback
    assert settings.effective_n8n_token == "webhook-precedence-secret"
    assert settings.effective_n8n_token != "callback-secret"

    req = _make_request(settings)

    # Webhook token should succeed
    verify_n8n_token(
        req, x_n8n_token="webhook-precedence-secret", x_callback_token=None, authorization=None
    )

    # Callback token alone should FAIL when webhook takes precedence (consistent)
    with pytest.raises(HTTPException) as exc:
        verify_n8n_token(
            req, x_n8n_token="callback-secret", x_callback_token=None, authorization=None
        )
    assert exc.value.status_code == 401


def test_no_token_configured_fail_closed() -> None:
    """No token configured -> fail closed safely (503)."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_webhook_token="",
        n8n_callback_token="",
        n8n_webhook_url="",
    )
    assert settings.effective_n8n_token == ""

    req = _make_request(settings)
    with pytest.raises(HTTPException) as exc:
        verify_n8n_token(req, x_n8n_token="anything", x_callback_token=None, authorization=None)
    assert exc.value.status_code == 503
    assert "not configured" in exc.value.detail.lower()


def test_effective_token_trims_whitespace() -> None:
    """Effective token should strip whitespace."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="test",
        triage_cors_origins="http://localhost",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="k",
        n8n_webhook_token="  spaced-token  ",
        n8n_callback_token="",
        n8n_webhook_url="http://example",
    )
    assert settings.effective_n8n_token == "spaced-token"


# ---------------------------------------------------------------------------
# Workflow JSON outbound callbacks use same fallback
# ---------------------------------------------------------------------------


def test_workflows_outbound_use_webhook_fallback() -> None:
    """All outbound X-N8N-Token headers must use $env.N8N_WEBHOOK_TOKEN || $env.N8N_CALLBACK_TOKEN."""
    assert WORKFLOW_DIR.exists()
    for wf_path in WORKFLOW_DIR.glob("*.json"):
        data = json.loads(wf_path.read_text())
        for node in data.get("nodes", []):
            if node.get("type") != "n8n-nodes-base.httpRequest":
                continue
            header_params = (
                node.get("parameters", {}).get("headerParameters", {}).get("parameters", [])
            )
            for hp in header_params:
                if "token" not in hp.get("name", "").lower():
                    continue
                val = hp.get("value", "")
                # Must contain both WEBHOOK and CALLBACK with fallback ||
                assert "$env.N8N_WEBHOOK_TOKEN" in val, (
                    f"{wf_path.name} node {node.get('name')} must reference N8N_WEBHOOK_TOKEN, got {val}"
                )
                assert "$env.N8N_CALLBACK_TOKEN" in val, (
                    f"{wf_path.name} node {node.get('name')} must reference N8N_CALLBACK_TOKEN fallback, got {val}"
                )
                assert "||" in val, (
                    f"{wf_path.name} node {node.get('name')} must use fallback || operator, got {val}"
                )
                # Ensure precedence: WEBHOOK before CALLBACK
                webhook_idx = val.find("N8N_WEBHOOK_TOKEN")
                callback_idx = val.find("N8N_CALLBACK_TOKEN")
                assert webhook_idx < callback_idx, (
                    f"{wf_path.name} must have WEBHOOK_TOKEN precedence before CALLBACK_TOKEN, got {val}"
                )


def test_workflows_inbound_validation_uses_same_fallback() -> None:
    """Inbound validation Function nodes must also use same fallback."""
    for wf_path in WORKFLOW_DIR.glob("*.json"):
        data = json.loads(wf_path.read_text())
        for node in data.get("nodes", []):
            if "validate" not in node.get("name", "").lower():
                continue
            code = node.get("parameters", {}).get("functionCode", "")
            if not code:
                continue
            # Must use fallback for expected token
            if "$env.N8N_WEBHOOK_TOKEN" in code or "$env.N8N_CALLBACK_TOKEN" in code:
                assert "$env.N8N_WEBHOOK_TOKEN" in code, (
                    f"{wf_path.name} validate node must reference WEBHOOK_TOKEN"
                )
                assert "$env.N8N_CALLBACK_TOKEN" in code, (
                    f"{wf_path.name} validate node must reference CALLBACK_TOKEN fallback"
                )
                # Check fallback operator
                assert "||" in code, f"{wf_path.name} validate must use || fallback"


def test_no_token_values_in_workflow_json() -> None:
    """No token values appear in workflow JSON (only env references)."""
    for wf_path in WORKFLOW_DIR.glob("*.json"):
        content = wf_path.read_text()
        lower = content.lower()
        # No hardcoded secrets
        assert "test-callback-token-not-a-real-secret" not in lower
        assert "test-ingest-key-not-a-real-secret" not in lower
        # No literal token values like 'webhook-only-secret' etc from tests
        assert "webhook-only-secret" not in lower
        assert "callback-only-secret" not in lower
        # No plain token pattern like "secret123" hardcoded as header value
        data = json.loads(content)
        for node in data.get("nodes", []):
            hp = node.get("parameters", {}).get("headerParameters", {}).get("parameters", [])
            for h in hp:
                if "token" in h.get("name", "").lower():
                    val = h.get("value", "")
                    # Must be templated env ref, not plain string
                    assert val.startswith("={{") and "$env" in val, (
                        f"{wf_path.name} token header must be env ref, got {val}"
                    )


def test_no_token_in_logs_simulation() -> None:
    """Simulate that token is never logged (code never logs expected/supplied)."""
    for wf_path in WORKFLOW_DIR.glob("*.json"):
        data = json.loads(wf_path.read_text())
        for node in data.get("nodes", []):
            code = node.get("parameters", {}).get("functionCode", "")
            if not code:
                continue
            lower = code.lower()
            # Should never log token values
            assert "console.log(supplied" not in lower
            assert "console.log(expected" not in lower
            assert "console.log(token" not in lower
            # Should have comment about never logging token
            if "expected" in lower and "supplied" in lower:
                assert "never log" in lower or "not logged" in lower or "never" in lower


def test_env_example_documents_fallback() -> None:
    """Ensure .env.example documents both tokens and fallback behavior."""
    env_example = REPO_ROOT / ".env.example"
    assert env_example.exists(), ".env.example must exist"
    content = env_example.read_text()
    assert "N8N_WEBHOOK_TOKEN" in content
    assert "N8N_CALLBACK_TOKEN" in content
    # Should mention fallback or shared token
    lower = content.lower()
    assert "fallback" in lower or "shared" in lower or "callback" in lower
