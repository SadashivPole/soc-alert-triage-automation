"""Phase 3.7 Task D10 — failure-isolation guards for the metrics surface.

Forces metric recording/rendering failures at representative D2-D9 paths
(middleware, ingest, rejection, enrichment, scoring/decision, notification,
feedback, incident transition, sweeper) and asserts that the original API
status/body, persistence, scoring/decision and lifecycle behavior are
unchanged. Business logic is never changed to accommodate the tests: the
recorder is non-load-bearing by design (ADR-9) and the guard verifies that
contract end to end.

Reads the app-scoped registry directly (never the process-global REGISTRY).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from soc_triage.core.config import Settings
from soc_triage.core.metrics import MetricsRegistry
from soc_triage.enrichment import EnrichmentChain
from soc_triage.enrichment.providers import EnrichmentContext, EnrichmentStatus, ProviderEnrichment
from soc_triage.main import create_app
from soc_triage.models.ioc import IOC
from soc_triage.notifications.client import N8NWebhookClient
from soc_triage.sweeper import sweep_once

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load_sample(name: str) -> dict[str, Any]:
    """Load one synthetic Wazuh sample payload."""
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


def _auth() -> dict[str, str]:
    """Ingest auth header (test API key)."""
    from tests.conftest import TEST_INGEST_KEY

    return {"X-API-Key": TEST_INGEST_KEY}


def _token() -> dict[str, str]:
    """Shared N8N token header for feedback/incident endpoints."""
    from tests.conftest import TEST_CALLBACK_TOKEN

    return {"X-N8N-Token": TEST_CALLBACK_TOKEN}


def _ingest(client: TestClient, payload: dict[str, Any]):
    """Post one ingest payload and return the raw response."""
    return client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())


def _rows(app, sql: str) -> list[tuple[Any, ...]]:
    """Run one read-only query against the app's engine."""
    from sqlalchemy import text

    engine = app.state.db_engine
    with engine.connect() as connection:
        return list(connection.execute(text(sql)))


def _fingerprint(body: dict[str, Any]) -> dict[str, Any]:
    """Deterministic response projection (ids/timestamps excluded)."""
    return {
        "status": body.get("status"),
        "duplicate": body.get("duplicate"),
        "dedupe_status": body.get("dedupe_status"),
        "enrichment_status": body.get("enrichment_status"),
        "risk_score": body.get("risk", {}).get("score") if body.get("risk") else None,
        "risk_tier": body.get("risk", {}).get("tier") if body.get("risk") else None,
        "risk_degraded": body.get("risk", {}).get("degraded") if body.get("risk") else None,
        "decision_action": body.get("decision", {}).get("action") if body.get("decision") else None,
        "dedupe_occurrences": body.get("dedupe", {}).get("occurrences"),
    }


class _FakeProvider:
    """Offline enrichment provider (registered name, fail-open support)."""

    def __init__(self, name: str, status: EnrichmentStatus, *, fail: bool = False) -> None:
        self._name = name
        self._status = status
        self._fail = fail

    @property
    def name(self) -> str:
        return self._name

    @property
    def enabled(self) -> bool:
        return True

    def enrich(
        self,
        iocs: list[IOC],
        *,
        context: EnrichmentContext,  # noqa: ARG002 - part of the provider contract
    ) -> ProviderEnrichment:
        if self._fail:
            raise RuntimeError("injected provider failure")
        return ProviderEnrichment(
            provider=self._name,
            status=self._status,
            results={ioc.key: {"mock": {"lookup_status": "found"}} for ioc in iocs},
            notes=["synthetic enrichment"],
        )


def _install_chain(client: TestClient, providers: list[Any]) -> None:
    """Swap the app's enrichment chain (allowed names stay registered)."""
    client.app.state.enrichment_chain = EnrichmentChain(providers)


def _mock_n8n_client(handler, *, max_retries: int = 1) -> tuple[N8NWebhookClient, httpx.Client]:
    """Build an N8NWebhookClient over a mock transport (no network I/O)."""
    transport = httpx.MockTransport(handler)
    httpx_client = httpx.Client(transport=transport)
    return (
        N8NWebhookClient(
            webhook_url="http://n8n:5678/webhook/soc-alert-scored",
            token="test-callback-token-not-a-real-secret",
            client=httpx_client,
            max_retries=max_retries,
            retry_backoff_seconds=0.01,
        ),
        httpx_client,
    )


def _age_incident(app, incident_id: str) -> None:
    """Age an incident's updated_at past the app's configured TTL."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import update as sa_update

    from soc_triage.models.orm import Incident as IncidentORM

    ttl = app.state.settings.incident_auto_close_ttl_seconds
    with app.state.db_engine.begin() as conn:
        conn.execute(
            sa_update(IncidentORM)
            .where(IncidentORM.incident_id == incident_id)
            .values(updated_at=datetime.now(UTC) - timedelta(seconds=ttl + 100))
        )


def _boom(*_args: object, **_kwargs: object) -> None:
    """Representative recorder failure (type only, never logged by value)."""
    raise RuntimeError("injected metrics recorder failure")


# ---------------------------------------------------------------------------
# D2 — exposition rendering failure
# ---------------------------------------------------------------------------


def test_metrics_render_failure_returns_empty_exposition_and_no_error(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing render degrades to an empty 200 exposition, never a 500."""
    from soc_triage.core import metrics as metrics_module

    app = create_app(
        settings=Settings(
            soc_env="test",
            soc_log_level="INFO",
            soc_instance_name="soc-fail-guard",
            triage_cors_origins="http://localhost:8080",
            triage_db_url=f"sqlite:///{tmp_path / 'render.db'}",
            triage_ingest_api_key="test-ingest-key-not-a-real-secret",
            n8n_callback_token="test-callback-token-not-a-real-secret",
            metrics_scrape_token="d10-scrape-2b8e-5a17-n0treal",
        )
    )

    def boom_render(*_args: object, **_kwargs: object) -> bytes:
        raise RuntimeError("injected render failure")

    monkeypatch.setattr(metrics_module, "generate_latest", boom_render)
    with TestClient(app) as client:
        response = client.get(
            "/metrics",
            headers={"Authorization": "Bearer d10-scrape-2b8e-5a17-n0treal"},
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(
            "text/plain; version=0.0.4; charset=utf-8"
        )
        assert response.text == ""


# ---------------------------------------------------------------------------
# D5 — HTTP middleware recording failure
# ---------------------------------------------------------------------------


def test_middleware_recorder_failure_never_changes_http_behavior(client, app, monkeypatch) -> None:
    """Records fail silently; status, body and DB state stay identical."""
    baseline = client.get("/health")
    assert baseline.status_code == 200
    assert _rows(app, "SELECT COUNT(*) FROM alerts") == [(0,)]

    monkeypatch.setattr(MetricsRegistry, "_increment", _boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", _boom)

    after = client.get("/health")
    assert after.status_code == baseline.status_code
    assert after.headers["content-type"] == baseline.headers["content-type"]
    assert {k: v for k, v in after.json().items() if k != "timestamp"} == {
        k: v for k, v in baseline.json().items() if k != "timestamp"
    }
    assert _rows(app, "SELECT COUNT(*) FROM alerts") == [(0,)]


# ---------------------------------------------------------------------------
# D6 — ingest/rejection recording failure
# ---------------------------------------------------------------------------


def test_ingest_and_rejection_unchanged_under_recorder_failure(client, app, monkeypatch) -> None:
    """A raising recorder cannot alter accept/reject semantics or persistence."""
    baseline = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))
    assert baseline.status_code == 202
    expected = _fingerprint(baseline.json())
    processed_before = app.state.metrics.registry.get_sample_value(
        "soc_triage_alerts_processed_total", {"outcome": "new_generation"}
    )

    monkeypatch.setattr(MetricsRegistry, "_increment", _boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", _boom)

    second = _load_sample("04_wazuh_malware_hash_virustotal.json")
    second["agent"] = dict(second["agent"], id="009")
    accepted = _ingest(client, second)
    assert accepted.status_code == 202
    assert accepted.json()["dedupe_status"] == "new_generation"
    assert _fingerprint(accepted.json()) == expected

    rejected = client.post("/api/v1/alerts/ingest", headers=_auth(), content=b"{{{invalid")
    assert rejected.status_code == 422
    assert rejected.json()["error"]["code"] == "validation_error"

    assert _rows(app, "SELECT COUNT(*) FROM alerts") == [(2,)]
    assert _rows(app, "SELECT COUNT(*) FROM alert_events") == [(2,)]
    # The failing recorder added nothing: the counter keeps only the
    # baseline increment.
    assert (
        app.state.metrics.registry.get_sample_value(
            "soc_triage_alerts_processed_total", {"outcome": "new_generation"}
        )
        == processed_before
    )


# ---------------------------------------------------------------------------
# D7 + D8 — scoring/decision and enrichment recording failure
# ---------------------------------------------------------------------------


def test_scoring_decision_enrichment_unchanged_under_recorder_failure(
    client, app, monkeypatch
) -> None:
    """Fail-open enrichment and deterministic scoring never depend on metrics."""
    _install_chain(
        client,
        [_FakeProvider("virustotal", EnrichmentStatus.COMPLETE)],
    )
    baseline = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))
    assert baseline.status_code == 202
    expected = _fingerprint(baseline.json())
    assert expected["enrichment_status"] == "complete"
    assert expected["decision_action"] == "open_incident"
    scored_before = app.state.metrics.registry.get_sample_value(
        "soc_triage_alerts_scored_total",
        {
            "tier": expected["risk_tier"],
            "decision": expected["decision_action"],
            "degraded": "1" if expected["risk_degraded"] else "0",
        },
    )
    assert scored_before == 1.0

    monkeypatch.setattr(MetricsRegistry, "_increment", _boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", _boom)

    after_payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    after_payload["agent"] = dict(after_payload["agent"], id="011")
    after = _ingest(client, after_payload)
    assert after.status_code == 202
    assert after.json()["dedupe_status"] == "new_generation"
    assert _fingerprint(after.json()) == expected
    # Persisted normalized payload matches the same risk/decision.
    row = json.loads(
        _rows(app, "SELECT normalized_payload FROM alerts ORDER BY rowid DESC LIMIT 1")[0][0]
    )
    assert row["risk"]["score"] == expected["risk_score"]
    assert row["decision"]["action"] == expected["decision_action"]
    # The recorder failure added no scoring series beyond the baseline.
    assert (
        app.state.metrics.registry.get_sample_value(
            "soc_triage_alerts_scored_total",
            {
                "tier": expected["risk_tier"],
                "decision": expected["decision_action"],
                "degraded": "1" if expected["risk_degraded"] else "0",
            },
        )
        == scored_before
    )


# ---------------------------------------------------------------------------
# D9 — notification/feedback/incident/sweeper recording failure
# ---------------------------------------------------------------------------


def test_notification_feedback_incident_sweeper_unchanged_under_recorder_failure(
    client, app, monkeypatch
) -> None:
    """The whole lifecycle is identical when every recorder call raises."""

    def ok_handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(ok_handler)
    client.app.state.n8n_client = n8n_client

    monkeypatch.setattr(MetricsRegistry, "_increment", _boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", _boom)
    monkeypatch.setattr(MetricsRegistry, "_apply_gauge", _boom)

    response = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))
    assert response.status_code == 202
    body = response.json()
    assert body["notification"]["delivered"] is True
    assert body["decision"]["action"] == "open_incident"
    assert body["enrichment_status"] == "skipped"  # default chain: no provider
    alert_id = body["alert_id"]
    incident_id = body["incident_id"]
    assert incident_id is not None

    patch = client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "acknowledged"},
        headers=_token(),
    )
    assert patch.status_code == 200
    assert patch.json() == {
        "incident_id": incident_id,
        "previous_status": "open",
        "status": "acknowledged",
        "acknowledged_at": patch.json()["acknowledged_at"],
        "resolved_at": None,
        "updated_at": patch.json()["updated_at"],
    }

    feedback = client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": "escalate"},
        headers=_token(),
    )
    assert feedback.status_code == 200
    assert feedback.json()["verdict"] == "escalate"

    _age_incident(app, incident_id)
    stats = sweep_once(
        client.app.state.session_factory,
        ttl_seconds=client.app.state.settings.incident_auto_close_ttl_seconds,
        metrics=app.state.metrics,
    )
    assert stats == {"candidates": 1, "closed": 1, "skipped": 0, "errors": 0}

    # Persistence is untouched: one alert, one feedback row, one incident
    # now resolved, audit trail complete.
    assert _rows(app, "SELECT COUNT(*) FROM alerts") == [(1,)]
    assert _rows(app, "SELECT COUNT(*) FROM analyst_feedback") == [(1,)]
    assert _rows(app, "SELECT COUNT(*) FROM incidents") == [(1,)]
    assert _rows(app, "SELECT status FROM incidents") == [("resolved",)]
    actions = {row[0] for row in _rows(app, "SELECT action FROM audit_log")}
    assert "notification.delivered" in actions
    assert "incident.auto_closed" in actions
