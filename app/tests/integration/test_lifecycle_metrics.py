"""Phase 3.7 Task D9 — notification/feedback/incident/sweeper metrics.

Covers the six approved metric families wired at their existing semantic
outcome boundaries using the D2 :class:`~soc_triage.core.metrics.MetricsRegistry`:

* ``soc_triage_n8n_notifications{outcome}`` (+ duration histogram) — exactly
  one outcome per actual send attempt / explicit skip / suppression decision;
  client retries are folded into one result, so they never double-count;
* ``soc_triage_feedback{verdict}`` — exactly one per accepted submission;
* ``soc_triage_incident_transitions{from_status,to_status}`` — only actual
  lifecycle changes, never unchanged/illegal states;
* ``soc_triage_incident_auto_close{outcome}`` and
  ``soc_triage_sweeper_passes{result}`` mirroring the existing sweeper
  result semantics exactly;

plus regression twins, forced-recorder-failure isolation and exposition
cardinality/secret guards.

Reads the app-scoped registry directly (never the process-global REGISTRY).
"""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import text

from soc_triage import sweeper as sweeper_mod
from soc_triage.core.config import Settings
from soc_triage.core.metrics import (
    AUTO_CLOSE_OUTCOMES,
    FEEDBACK_VERDICTS,
    INCIDENT_STATUSES,
    N8N_OUTCOMES,
    SWEEPER_RESULTS,
    MetricsRegistry,
)
from soc_triage.db.session import session_scope
from soc_triage.main import create_app
from soc_triage.models.canonical import CanonicalAlert
from soc_triage.models.incident import IncidentStatus
from soc_triage.models.repositories import IncidentRepository
from soc_triage.notifications.client import N8NWebhookClient
from soc_triage.sweeper import run_sweeper_loop

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY  # noqa: E402


def _load_sample(name: str) -> dict[str, Any]:
    """Load one synthetic Wazuh sample payload."""
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


def _auth() -> dict[str, str]:
    """Ingest auth header (test API key)."""
    return {"X-API-Key": TEST_INGEST_KEY}


def _token() -> dict[str, str]:
    """Shared N8N token header for feedback/incident endpoints."""
    return {"X-N8N-Token": TEST_CALLBACK_TOKEN}


def _ingest(client: TestClient, payload: dict[str, Any]):
    """Post one ingest payload and return the raw response."""
    return client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())


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


def _counter_series(registry, family: str, label_names: tuple[str, ...]):
    """Return ``{labels_tuple: value}`` for one counter family (no ``_created``)."""
    for collector in registry.collect():
        if collector.name == family:
            return {
                tuple(sample.labels[name] for name in label_names): sample.value
                for sample in collector.samples
                if sample.name == f"{family}_total"
            }
    return {}


def _histogram(app, name: str) -> tuple[float | None, float | None]:
    """Return (count, sum) samples for an unlabeled histogram family."""
    return (
        app.state.metrics.registry.get_sample_value(f"{name}_count", {}),
        app.state.metrics.registry.get_sample_value(f"{name}_sum", {}),
    )


def _rows(app, sql: str) -> list[tuple[Any, ...]]:
    """Run one read-only query against the app's engine."""
    engine = app.state.db_engine
    with engine.connect() as connection:
        return list(connection.execute(text(sql)))


def _twin_app(tmp_path: Path, *, metrics_enabled: bool):
    """A second, isolated app with the same config; the metrics toggle differs."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=f"sqlite:///{tmp_path / 'twin.db'}",
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        n8n_webhook_token="",
        metrics_enabled=metrics_enabled,
    )
    return create_app(settings=settings)


def _age_incident(app, incident_id: str) -> None:
    """Age an incident's updated_at past the app's configured TTL."""
    from sqlalchemy import update as sa_update

    from soc_triage.models.orm import Incident as IncidentORM

    ttl = app.state.settings.incident_auto_close_ttl_seconds
    ts = datetime.now(UTC) - timedelta(seconds=ttl + 100)
    with app.state.db_engine.begin() as conn:
        conn.execute(
            sa_update(IncidentORM)
            .where(IncidentORM.incident_id == incident_id)
            .values(updated_at=ts)
        )


def _ingest_incident(
    client: TestClient,
    *,
    event_id: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Ingest a high-tier alert (creates an incident) and return the body."""
    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    if event_id is not None:
        payload = dict(payload, id=event_id)
    if agent_id is not None:
        payload = dict(payload)
        payload["agent"] = dict(payload.get("agent", {}), id=agent_id)
    response = _ingest(client, payload)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["incident_id"] is not None
    return body


def _patch_status(client: TestClient, incident_id: str, target: str) -> Any:
    return client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": target},
        headers=_token(),
    )


def _submit_feedback(client: TestClient, alert_id: str, verdict: str) -> Any:
    return client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": verdict},
        headers=_token(),
    )


# ---------------------------------------------------------------------------
# A. Notifications — exactly one outcome per semantic boundary
# ---------------------------------------------------------------------------


def test_notification_delivered_exactly_once(client, app) -> None:
    """2xx send → delivered exactly once; one duration observation."""

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(handler)
    client.app.state.n8n_client = n8n_client
    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    assert response.json()["notification"]["delivered"] is True

    registry = app.state.metrics.registry
    assert _counter_series(registry, "soc_triage_n8n_notifications", ("outcome",)) == {
        ("delivered",): 1.0
    }
    count, total = _histogram(app, "soc_triage_n8n_notification_duration_seconds")
    assert count == 1.0
    assert total >= 0.0


def test_notification_failed_exactly_once_per_semantic_attempt(client, app) -> None:
    """Retries are folded: 2 HTTP calls, one failed outcome, one duration."""
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        calls["count"] += 1
        raise httpx.ConnectError("connection refused")

    n8n_client, _ = _mock_n8n_client(handler, max_retries=2)
    client.app.state.n8n_client = n8n_client
    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    assert calls["count"] == 2
    assert response.json()["notification"]["attempted"] is True
    assert response.json()["notification"]["delivered"] is False

    registry = app.state.metrics.registry
    assert _counter_series(registry, "soc_triage_n8n_notifications", ("outcome",)) == {
        ("failed",): 1.0
    }
    count, total = _histogram(app, "soc_triage_n8n_notification_duration_seconds")
    assert count == 1.0  # one semantic attempt, not one per retry
    assert total >= 0.0


def test_notification_skipped_exactly_once(client, app) -> None:
    """Disabled client → explicit skip exactly once; no duration observation."""
    # Default app n8n client is disabled (no webhook URL).
    assert client.app.state.n8n_client.enabled is False
    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    assert response.json()["notification"] is not None
    assert response.json()["notification"]["skipped"] is True

    registry = app.state.metrics.registry
    assert _counter_series(registry, "soc_triage_n8n_notifications", ("outcome",)) == {
        ("skipped",): 1.0
    }
    count, total = _histogram(app, "soc_triage_n8n_notification_duration_seconds")
    assert count == 0.0  # no actual send attempt
    assert total == 0.0


def test_notification_duplicate_suppressed_exactly_once(client, app) -> None:
    """A second notification for an already-delivered alert id is suppressed.

    Each distinct delivery carries its own alert id, so the repo-duplicate
    suppression boundary is exercised by notifying the *same* canonical
    alert twice through the real ``_notify_n8n`` path (the same boundary the
    ingest handler uses for a repeated event).
    """

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(handler)
    client.app.state.n8n_client = n8n_client
    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    assert response.json()["notification"]["delivered"] is True
    alert = CanonicalAlert.model_validate(response.json()["normalized"])
    received_at = datetime.fromisoformat(response.json()["received_at"].replace("Z", "+00:00"))

    from soc_triage.api import alerts as alerts_module

    # First explicit notification path → delivered; second same-alert path
    # → the existing duplicate-prevention boundary suppresses it.
    second = alerts_module._notify_n8n(
        session_factory=client.app.state.session_factory,
        n8n_client=n8n_client,
        alert=alert,
        dedupe_status="new_generation",
        received_at=received_at,
        metrics=app.state.metrics,
    )
    assert second is not None
    assert second.attempted is False
    assert second.skipped is True
    assert second.payload_hash == "duplicate"

    registry = app.state.metrics.registry
    assert _counter_series(registry, "soc_triage_n8n_notifications", ("outcome",)) == {
        ("delivered",): 1.0,
        ("duplicate_suppressed",): 1.0,
    }
    count, _ = _histogram(app, "soc_triage_n8n_notification_duration_seconds")
    assert count == 1.0  # only the real send attempt observes duration


def test_notification_recorder_failure_does_not_break_ingest(client, app, monkeypatch) -> None:
    """A raising metrics recorder cannot alter the notification outcome."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected notification metrics failure")

    monkeypatch.setattr(MetricsRegistry, "_increment", boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", boom)

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(handler)
    client.app.state.n8n_client = n8n_client
    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    assert response.json()["notification"]["delivered"] is True
    assert _rows(app, "SELECT COUNT(*) FROM alerts") == [(1,)]
    actions = {row[0] for row in _rows(app, "SELECT action FROM audit_log")}
    assert "notification.delivered" in actions


# ---------------------------------------------------------------------------
# B. Feedback — exactly one per submission, bounded verdicts
# ---------------------------------------------------------------------------


def test_every_feedback_verdict_maps_and_increments_once(client, app) -> None:
    """Each of the 7 enum verdicts records its own series exactly once."""
    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    alert_id = body.json()["alert_id"]
    expected: dict[tuple[str, ...], float] = {}
    for verdict in sorted(FEEDBACK_VERDICTS):
        response = _submit_feedback(client, alert_id, verdict)
        assert response.status_code == 200, (verdict, response.text)
        assert response.json()["verdict"] == verdict
        expected[(verdict,)] = 1.0

    series = _counter_series(app.state.metrics.registry, "soc_triage_feedback", ("verdict",))
    assert series == expected
    assert sum(series.values()) == 7.0
    # No incident is linked here, so no transition metrics may appear.
    assert (
        _counter_series(
            app.state.metrics.registry,
            "soc_triage_incident_transitions",
            ("from_status", "to_status"),
        )
        == {}
    )


def test_invalid_verdict_follows_existing_api_behavior(client, app) -> None:
    """Unknown verdict → 422; nothing recorded, nothing persisted."""
    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    alert_id = body.json()["alert_id"]
    response = _submit_feedback(client, alert_id, "not-a-verdict")
    assert response.status_code == 422
    assert _counter_series(app.state.metrics.registry, "soc_triage_feedback", ("verdict",)) == {}


def test_feedback_recorder_failure_does_not_affect_response_or_persistence(
    client, app, monkeypatch
) -> None:
    """A raising feedback recorder never changes the 200 or stored rows."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected feedback metrics failure")

    monkeypatch.setattr(MetricsRegistry, "_increment", boom)

    body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    alert_id = body.json()["alert_id"]
    response = _submit_feedback(client, alert_id, "true_positive")
    assert response.status_code == 200
    assert response.json()["verdict"] == "true_positive"
    assert _rows(app, "SELECT COUNT(*) FROM analyst_feedback") == [(1,)]
    assert _rows(app, "SELECT COUNT(*) FROM audit_log WHERE action = 'feedback.received'") == [(1,)]


# ---------------------------------------------------------------------------
# C. Incident transitions — actual changes only, bounded labels
# ---------------------------------------------------------------------------


def test_patch_transition_records_exactly_once(client, app) -> None:
    """open → investigating records exactly one transition series."""

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(handler)
    client.app.state.n8n_client = n8n_client
    body = _ingest_incident(client)
    response = _patch_status(client, body["incident_id"], "investigating")
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"

    series = _counter_series(
        app.state.metrics.registry, "soc_triage_incident_transitions", ("from_status", "to_status")
    )
    assert series == {("open", "investigating"): 1.0}


def test_unchanged_state_creates_no_transition(client, app) -> None:
    """PATCH to the current state is rejected (409) and records nothing."""

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(handler)
    client.app.state.n8n_client = n8n_client
    body = _ingest_incident(client)
    response = _patch_status(client, body["incident_id"], "open")
    assert response.status_code == 409
    assert (
        _counter_series(
            app.state.metrics.registry,
            "soc_triage_incident_transitions",
            ("from_status", "to_status"),
        )
        == {}
    )


def test_feedback_sync_records_actual_transitions_only(client, app) -> None:
    """Verdict-driven transitions count; no-transition verdicts never do."""

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(handler)
    client.app.state.n8n_client = n8n_client
    body = _ingest_incident(client)
    alert_id = body["alert_id"]
    incident_id = body["incident_id"]

    # open → acknowledged (legal), then acknowledged → resolved (legal),
    # then resolved again (terminal → no transition), then contain_requested
    # (approval-required → never a transition).
    assert _submit_feedback(client, alert_id, "acknowledged").status_code == 200
    assert _submit_feedback(client, alert_id, "resolved").status_code == 200
    assert _submit_feedback(client, alert_id, "resolved").status_code == 200
    assert _submit_feedback(client, alert_id, "contain_requested").status_code == 200

    transitions = _counter_series(
        app.state.metrics.registry, "soc_triage_incident_transitions", ("from_status", "to_status")
    )
    assert transitions == {
        ("open", "acknowledged"): 1.0,
        ("acknowledged", "resolved"): 1.0,
    }
    feedback = _counter_series(app.state.metrics.registry, "soc_triage_feedback", ("verdict",))
    assert feedback == {
        ("acknowledged",): 1.0,
        ("resolved",): 2.0,
        ("contain_requested",): 1.0,
    }
    # The incident is terminal after the two real transitions.
    with session_scope(client.app.state.session_factory) as session:
        incident = IncidentRepository(session).get(incident_id)
    assert incident is not None
    assert incident.status == IncidentStatus.RESOLVED


def test_transition_labels_bounded_and_no_ids_in_exposition(client, app) -> None:
    """After a transition, labels stay in the enum and IDs never leak."""

    def handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(handler)
    client.app.state.n8n_client = n8n_client
    body = _ingest_incident(client)
    incident_id = body["incident_id"]
    alert_id = body["alert_id"]
    assert _patch_status(client, incident_id, "escalated").status_code == 200

    series = _counter_series(
        app.state.metrics.registry, "soc_triage_incident_transitions", ("from_status", "to_status")
    )
    for from_status, to_status in series:
        assert from_status in {s.value for s in IncidentStatus}
        assert to_status in {s.value for s in IncidentStatus}

    exposition = app.state.metrics.render_text()
    for value in (incident_id, alert_id, "analyst@example.com", "http://n8n:5678"):
        assert f'"{value}"' not in exposition, value


# ---------------------------------------------------------------------------
# D. Sweeper auto-close + pass metrics
# ---------------------------------------------------------------------------


def test_auto_close_outcomes_map_closed_skipped_error(client, app, monkeypatch) -> None:
    """One sweep with error/skip/close candidates mirrors the stats exactly."""
    # Three incidents on distinct dedupe groups; age all past the TTL.
    body_a = _ingest_incident(client, event_id="d9-err", agent_id="801")
    body_b = _ingest_incident(client, event_id="d9-skip", agent_id="802")
    body_c = _ingest_incident(client, event_id="d9-close", agent_id="803")
    for its in (body_a, body_b, body_c):
        _age_incident(app, its["incident_id"])

    factory = client.app.state.session_factory
    ttl = client.app.state.settings.incident_auto_close_ttl_seconds
    original = IncidentRepository.auto_close_if_stale
    call_count = {"n": 0}

    def flaky(self, incident_id, **kwargs):  # type: ignore[no-untyped-def]
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("simulated per-incident failure")
        if call_count["n"] == 2:
            return None  # simulated concurrent update → skip
        return original(self, incident_id, **kwargs)

    monkeypatch.setattr(IncidentRepository, "auto_close_if_stale", flaky)
    try:
        stats = sweeper_mod.sweep_once(
            factory,
            ttl_seconds=ttl,
            metrics=app.state.metrics,
        )
    finally:
        IncidentRepository.auto_close_if_stale = original  # type: ignore[method-assign]

    assert stats == {"candidates": 3, "closed": 1, "skipped": 1, "errors": 1}
    series = _counter_series(
        app.state.metrics.registry, "soc_triage_incident_auto_close", ("outcome",)
    )
    assert series == {("closed",): 1.0, ("skipped",): 1.0, ("error",): 1.0}
    assert all(outcome in AUTO_CLOSE_OUTCOMES for (outcome,) in series)


def test_sweeper_pass_completed_recorded_exactly_once_per_pass(client) -> None:
    """The loop records one completed pass per actual successful pass."""

    async def _drive(settings: Settings, registry: MetricsRegistry) -> None:
        task = asyncio.create_task(
            run_sweeper_loop(
                client.app.state.session_factory,
                settings,
                metrics=registry,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    registry = MetricsRegistry()
    settings = Settings(
        soc_env="test",
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        n8n_webhook_token="",
        incident_sweeper_interval_seconds=1,
        incident_auto_close_ttl_seconds=60,
    )
    asyncio.run(_drive(settings, registry))

    series = _counter_series(registry.registry, "soc_triage_sweeper_passes", ("result",))
    assert series == {("completed",): 1.0}


def test_sweeper_pass_failed_recorded_exactly_once_per_pass() -> None:
    """A pass-level failure records exactly one failed pass, loop survives."""

    async def _drive(registry: MetricsRegistry) -> None:
        settings = Settings(
            soc_env="test",
            triage_ingest_api_key=TEST_INGEST_KEY,
            n8n_callback_token=TEST_CALLBACK_TOKEN,
            n8n_webhook_token="",
            incident_sweeper_interval_seconds=1,
            incident_auto_close_ttl_seconds=60,
        )

        def broken_factory(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("simulated DB failure")

        task = asyncio.create_task(
            run_sweeper_loop(
                broken_factory,  # type: ignore[arg-type]
                settings,
                metrics=registry,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    registry = MetricsRegistry()
    asyncio.run(_drive(registry))
    series = _counter_series(registry.registry, "soc_triage_sweeper_passes", ("result",))
    assert series == {("failed",): 1.0}


def test_sweeper_recorder_failure_does_not_break_loop(client, app, monkeypatch) -> None:
    """A raising recorder cannot change a sweep or crash a pass."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected sweeper metrics failure")

    monkeypatch.setattr(MetricsRegistry, "_increment", boom)

    body = _ingest_incident(client)
    _age_incident(app, body["incident_id"])
    stats = sweeper_mod.sweep_once(
        client.app.state.session_factory,
        ttl_seconds=client.app.state.settings.incident_auto_close_ttl_seconds,
        metrics=app.state.metrics,
    )
    assert stats == {"candidates": 1, "closed": 1, "skipped": 0, "errors": 0}
    with session_scope(client.app.state.session_factory) as session:
        incident = IncidentRepository(session).get(body["incident_id"])
    assert incident is not None
    assert incident.status == IncidentStatus.RESOLVED

    # The passes counter is irrelevant here (recorder was forced to fail);
    # the key assertion is that business behavior and the loop contract hold.
    assert ("incident.auto_closed",) in _rows(app, "SELECT action FROM audit_log")


# ---------------------------------------------------------------------------
# E. Security / cardinality — the full D9 exposition
# ---------------------------------------------------------------------------


def test_exposition_contains_only_approved_d9_labels(client, app) -> None:
    """Mixed D9 activity leaves only bounded enum labels in the exposition."""

    def ok_handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(ok_handler)
    client.app.state.n8n_client = n8n_client

    body = _ingest_incident(client)
    alert_id = body["alert_id"]
    incident_id = body["incident_id"]
    assert _patch_status(client, incident_id, "acknowledged").status_code == 200
    assert _submit_feedback(client, alert_id, "escalate").status_code == 200
    _age_incident(app, incident_id)
    assert (
        sweeper_mod.sweep_once(
            client.app.state.session_factory,
            ttl_seconds=client.app.state.settings.incident_auto_close_ttl_seconds,
            metrics=app.state.metrics,
        )["closed"]
        == 1
    )

    registry = app.state.metrics.registry
    notifications = _counter_series(registry, "soc_triage_n8n_notifications", ("outcome",))
    feedback = _counter_series(registry, "soc_triage_feedback", ("verdict",))
    transitions = _counter_series(
        registry, "soc_triage_incident_transitions", ("from_status", "to_status")
    )
    auto_close = _counter_series(registry, "soc_triage_incident_auto_close", ("outcome",))
    passes = _counter_series(registry, "soc_triage_sweeper_passes", ("result",))

    assert set(notifications) == {("delivered",)}
    assert set(feedback) == {("escalate",)}
    # PATCH open→acknowledged, then feedback escalate → acknowledged→escalated.
    assert set(transitions) == {
        ("open", "acknowledged"),
        ("acknowledged", "escalated"),
    }
    assert set(auto_close) == {("closed",)}
    assert set(passes) == {("completed",)}

    exposition = app.state.metrics.render_text()
    dynamic_values = [
        alert_id,
        incident_id,
        "87105",  # rule id (sample 04)
        "003",  # agent id (sample 04)
        "bc478d7a48bfab117da4b9bdcb5aee36",  # IOC md5 (sample 04)
        "https://www.virustotal.com/gui/file/",  # URL fragment (sample 04 payload)
        "analyst@example.com",
        "http://n8n:5678",  # webhook host (never a label)
        "wazuh:87105:003",  # dedupe group key
        "C:\\Users\\jdoe-lab\\Downloads\\invoice_tracker.exe",  # IOC path
    ]
    for value in dynamic_values:
        assert f'"{value}"' not in exposition, value

    for outcome in notifications:
        assert outcome[0] in N8N_OUTCOMES
    for verdict in feedback:
        assert verdict[0] in FEEDBACK_VERDICTS
    for from_status, to_status in transitions:
        assert from_status in INCIDENT_STATUSES
        assert to_status in INCIDENT_STATUSES
    for outcome in auto_close:
        assert outcome[0] in AUTO_CLOSE_OUTCOMES
    for result in passes:
        assert result[0] in SWEEPER_RESULTS


# ---------------------------------------------------------------------------
# F. Regression — metrics enabled vs disabled twins
# ---------------------------------------------------------------------------


def test_lifecycle_identical_with_and_without_metrics(tmp_path, client, app) -> None:
    """Notification + feedback + incident semantics are identical in twins."""
    with TestClient(_twin_app(tmp_path, metrics_enabled=False)) as twin:

        def ok_handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
            return httpx.Response(200, json={"ok": True})

        for target in (client, twin):
            n8n, _ = _mock_n8n_client(ok_handler)
            target.app.state.n8n_client = n8n

        # Same deterministic sequence on both apps.
        for target in (client, twin):
            payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
            response = target.post("/api/v1/alerts/ingest", json=payload, headers=_auth())
            assert response.status_code == 202
            assert response.json()["notification"]["delivered"] is True

        ours = client.app
        theirs = twin.app

        # Identical DB row counts for alerts/events/groups/audit/notifications.
        for table in (
            "alerts",
            "alert_events",
            "alert_dedupe_groups",
            "audit_log",
            "notification_attempts",
            "incidents",
        ):
            assert _rows(ours, f"SELECT COUNT(*) FROM {table}") == _rows(
                theirs, f"SELECT COUNT(*) FROM {table}"
            ), table

        # Identical incident lifecycle state and audit action sequence.
        ours_incident = _rows(ours, "SELECT status FROM incidents")
        theirs_incident = _rows(theirs, "SELECT status FROM incidents")
        assert ours_incident == theirs_incident == [("open",)]
        assert _rows(ours, "SELECT action FROM audit_log ORDER BY id") == _rows(
            theirs, "SELECT action FROM audit_log ORDER BY id"
        )

        # Identical risk/decision payloads (minus wall-clock decided_at).
        ours_row = json.loads(_rows(ours, "SELECT normalized_payload FROM alerts")[0][0])
        theirs_row = json.loads(_rows(theirs, "SELECT normalized_payload FROM alerts")[0][0])
        assert ours_row["risk"] == theirs_row["risk"]
        ours_decision = dict(ours_row["decision"])
        theirs_decision = dict(theirs_row["decision"])
        ours_decision.pop("decided_at", None)
        theirs_decision.pop("decided_at", None)
        assert ours_decision == theirs_decision

        # Feedback + a PATCH transition on both apps: identical responses.
        alert_id = _rows(ours, "SELECT alert_id FROM alerts")[0][0]
        twin_alert_id = _rows(theirs, "SELECT alert_id FROM alerts")[0][0]
        ours_fb = client.post(
            f"/api/v1/alerts/{alert_id}/feedback",
            json={"verdict": "acknowledged"},
            headers=_token(),
        )
        theirs_fb = twin.post(
            f"/api/v1/alerts/{twin_alert_id}/feedback",
            json={"verdict": "acknowledged"},
            headers=_token(),
        )
        assert ours_fb.status_code == theirs_fb.status_code == 200
        assert ours_fb.json()["verdict"] == theirs_fb.json()["verdict"]

        incident_id = _rows(ours, "SELECT incident_id FROM incidents")[0][0]
        twin_incident_id = _rows(theirs, "SELECT incident_id FROM incidents")[0][0]
        ours_patch = client.patch(
            f"/api/v1/incidents/{incident_id}/status",
            json={"status": "investigating"},
            headers=_token(),
        )
        theirs_patch = twin.patch(
            f"/api/v1/incidents/{twin_incident_id}/status",
            json={"status": "investigating"},
            headers=_token(),
        )
        assert ours_patch.status_code == theirs_patch.status_code == 200
        assert ours_patch.json()["status"] == theirs_patch.json()["status"] == "investigating"

        # Identical post-lifecycle audit action sequences and row counts.
        assert _rows(ours, "SELECT action FROM audit_log ORDER BY id") == _rows(
            theirs, "SELECT action FROM audit_log ORDER BY id"
        )
        assert _rows(ours, "SELECT COUNT(*) FROM incidents") == _rows(
            theirs, "SELECT COUNT(*) FROM incidents"
        )
        assert _rows(ours, "SELECT status FROM incidents") == _rows(
            theirs, "SELECT status FROM incidents"
        )

        # Only metrics differ.
        assert app.state.metrics is not None
        assert not hasattr(twin.app.state, "metrics")


# ---------------------------------------------------------------------------
# G. Failure isolation — all recorder paths
# ---------------------------------------------------------------------------


def test_every_d9_recorder_path_failure_keeps_business_behavior(client, app, monkeypatch) -> None:
    """Force every D9 recorder path to raise; behavior stays unchanged."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected D9 metrics failure")

    monkeypatch.setattr(MetricsRegistry, "_increment", boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", boom)

    def ok_handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(ok_handler)
    client.app.state.n8n_client = n8n_client

    # Notification + feedback + PATCH transition under a raising recorder.
    body = _ingest_incident(client)
    assert body["notification"]["delivered"] is True
    assert _submit_feedback(client, body["alert_id"], "acknowledged").status_code == 200
    assert _patch_status(client, body["incident_id"], "escalated").status_code == 200

    # Sweep with a raising recorder (auto-close + pass paths).
    _age_incident(app, body["incident_id"])
    stats = sweeper_mod.sweep_once(
        client.app.state.session_factory,
        ttl_seconds=client.app.state.settings.incident_auto_close_ttl_seconds,
        metrics=app.state.metrics,
    )
    assert stats["closed"] == 1

    # Business state unchanged: incident escalated then auto-closed (terminal).
    with session_scope(client.app.state.session_factory) as session:
        incident = IncidentRepository(session).get(body["incident_id"])
    assert incident is not None
    assert incident.status == IncidentStatus.RESOLVED
    actions = [row[0] for row in _rows(app, "SELECT action FROM audit_log ORDER BY id")]
    assert "notification.delivered" in actions
    assert "feedback.received" in actions
    assert "incident.status_updated" in actions
    assert "incident.auto_closed" in actions
