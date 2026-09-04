"""Phase 3.7 Task D6 — ingest metrics instrumentation tests.

Covers the approved ingest-only metric surface (no scoring/decision metrics
yet — D7 is separate):

* ``soc_triage_ingest_rejections`` with the exact bounded reasons, recorded
  exactly once per rejected request at the existing rejection boundary (no
  double counting through exception layers);
* ``soc_triage_alerts_processed`` incremented exactly once per successfully
  classified dedupe outcome (new_generation / repeated / exact_duplicate);
* ``soc_triage_alert_processing_duration_seconds`` observed exactly once per
  accepted attempt, starting after the body/JSON/schema guards and stopping
  before the fail-open n8n notification (rejected requests never observe);
* regression invariants: responses, DB state, audit rows, scores, decisions
  identical with metrics disabled — only metric counters differ;
* injected metrics failures can never break ingest.

Reads the app-scoped registry directly (never the process-global REGISTRY).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event, text
from sqlalchemy.exc import OperationalError

from soc_triage.api import alerts as alerts_module
from soc_triage.core.config import Settings
from soc_triage.core.metrics import MetricsRegistry
from soc_triage.main import create_app

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
from tests.conftest import TEST_INGEST_KEY  # noqa: E402


def _load_sample(name: str = "01_wazuh_ssh_brute_force.json") -> dict:
    """Load one synthetic Wazuh sample payload."""
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


def _auth(extra: str | None = None) -> dict[str, str]:
    """Ingest auth header; None value = use the test key."""
    return {"X-API-Key": extra if extra else TEST_INGEST_KEY}


def _sample_value(app, name: str, labels: dict[str, str]) -> float | None:
    """Read one exposition sample from the app-scoped registry."""
    return app.state.metrics.registry.get_sample_value(name, labels)


def _histogram(
    app, name: str, labels: dict[str, str] | None = None
) -> tuple[float | None, float | None]:
    """Return (count, sum) samples for a histogram family."""
    labels = labels or {}
    return (
        app.state.metrics.registry.get_sample_value(f"{name}_count", labels),
        app.state.metrics.registry.get_sample_value(f"{name}_sum", labels),
    )


def _rows(app, sql: str) -> list[tuple[Any, ...]]:
    """Run one read-only query against the app's engine."""
    engine: Engine = app.state.db_engine
    with engine.connect() as connection:
        return list(connection.execute(text(sql)))


# ---------------------------------------------------------------------------
# A. Rejection metrics — each reason exactly once, no double counting
# ---------------------------------------------------------------------------


def test_malformed_json_rejection_increments_exactly_once(client, app) -> None:
    response = client.post("/api/v1/alerts/ingest", headers=_auth(), content=b"{{{invalid")
    assert response.status_code == 422
    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "malformed_json"})
        == 1.0
    )
    # No other rejection reason was recorded for the same request.
    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "schema_invalid"})
        is None
    )


def test_schema_invalid_rejection_increments_exactly_once(client, app) -> None:
    response = client.post("/api/v1/alerts/ingest", headers=_auth(), json={})
    assert response.status_code == 422
    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "schema_invalid"})
        == 1.0
    )
    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "malformed_json"})
        is None
    )


def test_identity_invalid_rejection_increments_exactly_once(client, app) -> None:
    payload = dict(_load_sample(), agent={"id": "", "name": "x"})
    response = client.post("/api/v1/alerts/ingest", headers=_auth(), json=payload)
    assert response.status_code == 422
    assert "identity" in response.json()["error"]["message"]
    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "identity_invalid"})
        == 1.0
    )
    # Rejection at one boundary only — never also schema/malformed.
    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "schema_invalid"})
        is None
    )


def test_oversized_payload_rejection_increments_exactly_once(client, app) -> None:
    oversized = b"{" + b"a" * (300 * 1024) + b"}"
    response = client.post("/api/v1/alerts/ingest", headers=_auth(), content=oversized)
    assert response.status_code == 413
    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "payload_too_large"})
        == 1.0
    )


def test_auth_failure_rejection_increments_once_per_rejected_request(client, app) -> None:
    # Missing key → 401 (one increment).
    assert client.post("/api/v1/alerts/ingest", json=_load_sample()).status_code == 401
    # Wrong key → 401 (second increment).
    assert (
        client.post(
            "/api/v1/alerts/ingest",
            json=_load_sample(),
            headers=_auth("definitely-wrong-key"),
        ).status_code
        == 401
    )
    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "auth_failed"}) == 2.0
    )


def test_storage_unavailable_rejection_increments_exactly_once(client, app) -> None:
    """Simulated DB loss at the driver layer: 503 + one storage_unavailable."""
    engine: Engine = app.state.db_engine

    @event.listens_for(engine, "connect", insert=True)
    def _reject_connections(_dbapi_connection: Any, _connection_record: Any) -> None:
        raise OperationalError(
            "SELECT 1",
            {},
            sqlite3.OperationalError("unable to open database file"),
        )

    engine.dispose()
    try:
        response = client.post("/api/v1/alerts/ingest", json=_load_sample(), headers=_auth())
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "service_unavailable"
    finally:
        event.remove(engine, "connect", _reject_connections)
        engine.dispose()  # restore normal connections for the next test request

    assert (
        _sample_value(app, "soc_triage_ingest_rejections_total", {"reason": "storage_unavailable"})
        == 1.0
    )


# ---------------------------------------------------------------------------
# B. Processing outcome — exactly one per classified dedupe outcome
# ---------------------------------------------------------------------------


def test_new_generation_outcome_increments_exactly_once(client, app) -> None:
    response = client.post("/api/v1/alerts/ingest", json=_load_sample(), headers=_auth())
    assert response.status_code == 202
    assert response.json()["dedupe_status"] == "new_generation"
    assert (
        _sample_value(
            app,
            "soc_triage_alerts_processed_total",
            {"outcome": "new_generation"},
        )
        == 1.0
    )
    assert _sample_value(app, "soc_triage_alerts_processed_total", {"outcome": "repeated"}) is None
    assert (
        _sample_value(app, "soc_triage_alerts_processed_total", {"outcome": "exact_duplicate"})
        is None
    )


def test_repeated_outcome_increments_exactly_once(client, app) -> None:
    first = dict(_load_sample())
    repeated = dict(first, id="1770000000.100002")
    assert client.post("/api/v1/alerts/ingest", json=first, headers=_auth()).status_code == 202
    response = client.post("/api/v1/alerts/ingest", json=repeated, headers=_auth())
    assert response.status_code == 202
    assert response.json()["dedupe_status"] == "repeated"
    assert (
        _sample_value(
            app,
            "soc_triage_alerts_processed_total",
            {"outcome": "new_generation"},
        )
        == 1.0
    )
    assert (
        _sample_value(
            app,
            "soc_triage_alerts_processed_total",
            {"outcome": "repeated"},
        )
        == 1.0
    )
    assert (
        _sample_value(app, "soc_triage_alerts_processed_total", {"outcome": "exact_duplicate"})
        is None
    )


def test_exact_duplicate_outcome_increments_exactly_once(client, app) -> None:
    payload = _load_sample()
    first = client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())
    assert first.status_code == 202
    duplicate = client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())
    assert duplicate.status_code == 200
    assert duplicate.json()["dedupe_status"] == "exact_duplicate"
    assert (
        _sample_value(
            app,
            "soc_triage_alerts_processed_total",
            {"outcome": "new_generation"},
        )
        == 1.0
    )
    assert (
        _sample_value(
            app,
            "soc_triage_alerts_processed_total",
            {"outcome": "exact_duplicate"},
        )
        == 1.0
    )
    assert _sample_value(app, "soc_triage_alerts_processed_total", {"outcome": "repeated"}) is None


# ---------------------------------------------------------------------------
# C. Duration — one observation per accepted attempt; rejected never observe
# ---------------------------------------------------------------------------


def test_processing_histogram_one_observation_per_accepted_attempt(client, app) -> None:
    first = _load_sample()
    second = dict(first, id="1770000000.100002")
    assert client.post("/api/v1/alerts/ingest", json=first, headers=_auth()).status_code == 202
    count, _ = _histogram(app, "soc_triage_alert_processing_duration_seconds")
    assert count == 1.0
    assert client.post("/api/v1/alerts/ingest", json=second, headers=_auth()).status_code == 202
    count, total = _histogram(app, "soc_triage_alert_processing_duration_seconds")
    assert count == 2.0
    assert total >= 0.0


def test_rejected_requests_never_observe_processing_duration(client, app) -> None:
    assert client.post("/api/v1/alerts/ingest", json=_load_sample()).status_code == 401
    assert (
        client.post("/api/v1/alerts/ingest", headers=_auth(), content=b"{{{invalid").status_code
        == 422
    )
    assert client.post("/api/v1/alerts/ingest", headers=_auth(), json={}).status_code == 422
    count, total = _histogram(app, "soc_triage_alert_processing_duration_seconds")
    # The unlabeled family exists (defined at registry construction) but no
    # observation was ever recorded for any rejected request.
    assert count == 0.0
    assert total == 0.0


def test_duration_uses_deterministic_monotonic_clock(client, app, monkeypatch) -> None:
    """Patching the isolated clock proves the span is monotonic + exact."""
    ticks = iter([100.0, 100.5, 100.0, 100.25])
    monkeypatch.setattr(alerts_module, "_monotonic", lambda: next(ticks))

    assert (
        client.post("/api/v1/alerts/ingest", json=_load_sample(), headers=_auth()).status_code
        == 202
    )
    count, total = _histogram(app, "soc_triage_alert_processing_duration_seconds")
    assert count == 1.0
    assert total == pytest.approx(0.5)

    # Second accepted attempt gets its own deterministic span.
    assert (
        client.post(
            "/api/v1/alerts/ingest",
            json=dict(_load_sample(), id="1770000000.100002"),
            headers=_auth(),
        ).status_code
        == 202
    )
    count, total = _histogram(app, "soc_triage_alert_processing_duration_seconds")
    assert count == 2.0
    assert total == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# D. Regression invariants — metrics disabled twin must behave identically
# ---------------------------------------------------------------------------


def _twin_app(tmp_path: Path, *, metrics_enabled: bool):
    """A second, isolated app with the same config; metrics toggle differs."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=f"sqlite:///{tmp_path / 'twin.db'}",
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token="test-callback-token-not-a-real-secret",
        metrics_enabled=metrics_enabled,
    )
    return create_app(settings=settings)


def _response_fingerprint(response) -> dict:
    """Stable, volatile-free projection of an ingest response."""
    body = response.json()
    return {
        "status_code": response.status_code,
        "duplicate": body.get("duplicate"),
        "dedupe_status": body.get("dedupe_status"),
        "enrichment_status": body.get("enrichment_status"),
        "risk_score": body.get("risk", {}).get("score"),
        "risk_tier": body.get("risk", {}).get("tier"),
        "decision_action": body.get("decision", {}).get("action"),
        "occurrences": body.get("dedupe", {}).get("occurrences"),
    }


def test_successful_ingest_identical_with_and_without_metrics(
    tmp_path: Path, client: TestClient, app
) -> None:
    """Enabled vs disabled twin: same response/status/DB/score/decision."""
    with TestClient(_twin_app(tmp_path, metrics_enabled=False)) as twin:
        payload = _load_sample()
        ours = client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())
        theirs = twin.post(
            "/api/v1/alerts/ingest", json=payload, headers={"X-API-Key": TEST_INGEST_KEY}
        )
        assert _response_fingerprint(ours) == _response_fingerprint(theirs)
        assert ours.status_code == theirs.status_code == 202

        # Alerts / audit / dedupe state is identical (same deterministic writes).
        assert _rows(app, "SELECT COUNT(*) FROM alerts") == _rows(
            twin.app, "SELECT COUNT(*) FROM alerts"
        )
        assert _rows(app, "SELECT COUNT(*) FROM audit_log") == _rows(
            twin.app, "SELECT COUNT(*) FROM audit_log"
        )
        assert _rows(app, "SELECT COUNT(*) FROM alert_dedupe_groups") == _rows(
            twin.app, "SELECT COUNT(*) FROM alert_dedupe_groups"
        )

        # Persisted risk/decision payloads are identical too (JSON text column);
        # only the wall-clock decided_at timestamp may differ (received_at).
        ours_row = json.loads(_rows(app, "SELECT normalized_payload FROM alerts")[0][0])
        theirs_row = json.loads(_rows(twin.app, "SELECT normalized_payload FROM alerts")[0][0])
        assert ours_row["risk"] == theirs_row["risk"]
        ours_decision = dict(ours_row["decision"])
        theirs_decision = dict(theirs_row["decision"])
        ours_decision.pop("decided_at", None)
        theirs_decision.pop("decided_at", None)
        assert ours_decision == theirs_decision

        # Only metrics differ: enabled twin has counters, disabled twin does not.
        assert (
            _sample_value(
                app,
                "soc_triage_alerts_processed_total",
                {"outcome": "new_generation"},
            )
            == 1.0
        )
        assert not hasattr(twin.app.state, "metrics")


def test_rejected_ingest_identical_with_and_without_metrics(
    tmp_path: Path, client: TestClient, app
) -> None:
    """Rejection responses/statuses are byte-comparable across the toggle."""
    with TestClient(_twin_app(tmp_path, metrics_enabled=False)) as twin:
        twin_headers = {"X-API-Key": TEST_INGEST_KEY}
        cases = [
            (dict(headers=twin_headers, json={}), dict(headers=_auth(), json={})),
            (
                dict(headers=twin_headers, content=b"{{{invalid"),
                dict(headers=_auth(), content=b"{{{invalid"),
            ),
            (
                dict(headers=twin_headers, json=dict(_load_sample(), agent={"id": ""})),
                dict(headers=_auth(), json=dict(_load_sample(), agent={"id": ""})),
            ),
            (dict(json=_load_sample()), dict(json=_load_sample())),
        ]
        for theirs, ours in cases:
            their_response = twin.post("/api/v1/alerts/ingest", **theirs)
            our_response = client.post("/api/v1/alerts/ingest", **ours)
            assert our_response.status_code == their_response.status_code
            assert our_response.json()["error"]["code"] == their_response.json()["error"]["code"]
            assert (
                our_response.json()["error"]["message"] == their_response.json()["error"]["message"]
            )

        # Neither app created any alert/audit rows for a rejected ingest.
        assert _rows(app, "SELECT COUNT(*) FROM alerts") == [(0,)]
        assert _rows(twin.app, "SELECT COUNT(*) FROM alerts") == [(0,)]
        assert _rows(app, "SELECT COUNT(*) FROM audit_log") == [(0,)]
        assert _rows(twin.app, "SELECT COUNT(*) FROM audit_log") == [(0,)]


def test_forced_metrics_failure_cannot_break_ingest(client, monkeypatch) -> None:
    """A raising metrics apply-step can never change an ingest outcome."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected ingest metrics failure")

    monkeypatch.setattr(MetricsRegistry, "_increment", boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", boom)

    ok = client.post("/api/v1/alerts/ingest", json=_load_sample(), headers=_auth())
    assert ok.status_code == 202
    assert ok.json()["status"] == "accepted"
    assert ok.json()["risk"]["score"] == 43  # deterministic golden value
    assert ok.json()["decision"]["action"] == "monitor"

    bad = client.post("/api/v1/alerts/ingest", headers=_auth(), content=b"{{{invalid")
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "validation_error"


def test_metric_counters_do_not_affect_dedupe_idempotency(client, app) -> None:
    """The exact-duplicate idempotency contract is untouched by counters."""
    payload = _load_sample()
    first = client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())
    second = client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())
    assert first.json()["alert_id"] == second.json()["alert_id"]
    assert second.json()["duplicate"] is True
    # One alert row; occurrences never bumped by the duplicate delivery.
    assert _rows(app, "SELECT COUNT(*) FROM alerts") == [(1,)]
    assert _rows(app, "SELECT COUNT(*) FROM alert_events") == [(1,)]
    assert (
        _sample_value(
            app,
            "soc_triage_alerts_processed_total",
            {"outcome": "exact_duplicate"},
        )
        == 1.0
    )
