"""Integration tests: Wazuh integrator → real Triage API (Phase 4.2).

The integrator's HTTP transport is replaced with a thin adapter over the
FastAPI ``TestClient``, so the *real* ingest route, authentication, validation,
dedupe, scoring and persistence run — but **no Wazuh manager and no network**
are involved (DEVELOPMENT_PLAN.md: fakes only in unit/integration tests).

These tests pin the contract that matters for Phase 4: an unmodified Wazuh
alert file, forwarded by the integrator, is accepted by the existing ingest
endpoint under the existing ``X-API-Key`` auth contract — and a temporarily
unavailable API buffers rather than loses the alert.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

REPO_ROOT = Path(__file__).resolve().parents[3]
INTEGRATOR_PY = REPO_ROOT / "wazuh" / "integrator" / "custom-triage.py"
SAMPLE_ALERTS = REPO_ROOT / "docs" / "sample-alerts"

#: The read APIs authenticate with the n8n callback token (unchanged contract).
READ_HEADERS = {"X-N8N-Token": TEST_CALLBACK_TOKEN}


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("wazuh_custom_triage_it", INTEGRATOR_PY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


integrator = _load_module()


class IngestSender:
    """Integrator transport bound to the in-process FastAPI app."""

    def __init__(self, client: TestClient, *, offline: bool = False) -> None:
        self._client = client
        self.offline = offline
        self.requests: list[dict[str, Any]] = []

    def __call__(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,  # noqa: ARG002 - transport signature
        verify_tls: bool,  # noqa: ARG002 - transport signature
    ) -> Any:
        self.requests.append({"url": url, "headers": dict(headers), "body": body})
        if self.offline:
            # Simulate a connection refused / unreachable API.
            return integrator.SenderResponse(status=0, error_type="ConnectError")
        path = url.split("8000", 1)[-1] if "8000" in url else "/api/v1/alerts/ingest"
        response = self._client.post(path, content=body, headers=dict(headers))
        return integrator.SenderResponse(status=response.status_code)


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {
        "TRIAGE_API_BASE_URL": "http://triage-api:8000",
        "TRIAGE_INGEST_API_KEY": TEST_INGEST_KEY,
        "WAZUH_INTEGRATOR_SPOOL_DIR": str(tmp_path / "spool"),
        "WAZUH_INTEGRATOR_MAX_ATTEMPTS": "1",
        "WAZUH_INTEGRATOR_BACKOFF_SECONDS": "0",
    }


def _alert_file(tmp_path: Path, name: str) -> Path:
    payload = (SAMPLE_ALERTS / name).read_text(encoding="utf-8")
    path = tmp_path / name
    path.write_text(payload, encoding="utf-8")
    return path


def _run(alert: Path, env: dict[str, str], sender: IngestSender) -> int:
    return integrator.run(["custom-triage", str(alert)], env, sender=sender, sleep=lambda _: None)


def _stored_alert_count(client: TestClient) -> int:
    """Total persisted alerts, read through the existing (unchanged) read API."""
    response = client.get("/api/v1/alerts", headers=READ_HEADERS)
    assert response.status_code == 200, response.text
    return int(response.json()["pagination"]["total"])


def test_forwarded_alert_is_accepted_by_the_real_ingest_endpoint(
    client: TestClient, tmp_path: Path, env: dict[str, str]
) -> None:
    sender = IngestSender(client)
    alert = _alert_file(tmp_path, "01_wazuh_ssh_brute_force.json")

    assert _run(alert, env, sender) == 0
    assert len(sender.requests) == 1

    # The alert is now visible through the existing read API.
    assert _stored_alert_count(client) == 1


def test_wrong_api_key_is_rejected_by_the_unchanged_auth_contract(
    client: TestClient, tmp_path: Path, env: dict[str, str]
) -> None:
    """The integrator cannot bypass ingest auth; a bad key yields 401 + no data."""
    env = {**env, "TRIAGE_INGEST_API_KEY": "wrong-key-not-a-real-secret"}
    sender = IngestSender(client)
    alert = _alert_file(tmp_path, "01_wazuh_ssh_brute_force.json")

    assert _run(alert, env, sender) == 0
    assert _stored_alert_count(client) == 0
    # 401 is permanent: not retried, not buffered (it can never succeed).
    assert len(sender.requests) == 1
    assert list((tmp_path / "spool").glob("*.json")) == []


def test_duplicate_delivery_stays_idempotent(
    client: TestClient, tmp_path: Path, env: dict[str, str]
) -> None:
    sender = IngestSender(client)
    alert = _alert_file(tmp_path, "01_wazuh_ssh_brute_force.json")
    for _ in range(3):
        assert _run(alert, env, sender) == 0

    assert _stored_alert_count(client) == 1


def test_outage_buffers_and_recovery_replays_without_loss(
    client: TestClient, tmp_path: Path, env: dict[str, str]
) -> None:
    offline = IngestSender(client, offline=True)
    first = _alert_file(tmp_path, "01_wazuh_ssh_brute_force.json")
    third = _alert_file(tmp_path, "03_wazuh_fim_etc_passwd_change.json")

    assert _run(first, env, offline) == 0
    assert _run(third, env, offline) == 0
    assert len(list((tmp_path / "spool").glob("*.json"))) == 2

    assert _stored_alert_count(client) == 0

    # API recovers; the next invocation drains the backlog first.
    online = IngestSender(client)
    fifth = _alert_file(tmp_path, "05_wazuh_web_sql_injection.json")
    assert _run(fifth, env, online) == 0

    assert list((tmp_path / "spool").glob("*.json")) == []
    assert _stored_alert_count(client) == 3


def test_every_forwarded_sample_alert_is_accepted(
    client: TestClient, tmp_path: Path, env: dict[str, str]
) -> None:
    sender = IngestSender(client)
    config = integrator.load_config(env)
    forwarded = 0
    for sample in sorted(SAMPLE_ALERTS.glob("*.json")):
        alert = json.loads(sample.read_text(encoding="utf-8"))
        if not integrator.should_forward(alert, config)[0]:
            continue
        forwarded += 1
        assert _run(_alert_file(tmp_path, sample.name), env, sender) == 0

    assert _stored_alert_count(client) == forwarded


def test_forwarded_body_is_the_unmodified_wazuh_alert(
    client: TestClient, tmp_path: Path, env: dict[str, str]
) -> None:
    """The integrator is a transport: it must not rewrite the alert payload."""
    sender = IngestSender(client)
    name = "06_wazuh_windows_user_created.json"
    original = json.loads((SAMPLE_ALERTS / name).read_text(encoding="utf-8"))
    assert _run(_alert_file(tmp_path, name), env, sender) == 0
    assert json.loads(sender.requests[0]["body"]) == original
    assert sender.requests[0]["headers"]["X-API-Key"] == TEST_INGEST_KEY
