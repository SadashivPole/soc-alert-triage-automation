"""Phase 3.4 integration tests: incident auto-close TTL sweeper.

Covers the sweeper contract against a real (temp) SQLite database through
the same startup path the service uses:

* config defaults + overrides + validation;
* eligibility rules (open/investigating/acknowledged/escalated vs
  terminal/recently-updated);
* auto-close transition correctness (status, timestamps, actor, audit);
* idempotency (repeat sweeps, no double audit, no double-close);
* race-safety (manual update after candidate selection defeats stale close);
* restart persistence;
* background loop start/stop via the FastAPI lifespan.

Tests drive the sweeper synchronously via ``sweeper.sweep_once`` for
determinism; the async periodic loop is exercised through the lifespan
start/stop tests.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage import sweeper as sweeper_mod
from soc_triage.audit import ACTION_INCIDENT_AUTO_CLOSED, ACTOR_SWEEPER
from soc_triage.core.config import Settings
from soc_triage.db.session import session_scope
from soc_triage.main import create_app
from soc_triage.models.incident import IncidentStatus
from soc_triage.models.repositories import AuditRepository, IncidentRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
TOKEN_HEADERS = {"X-N8N-Token": TEST_CALLBACK_TOKEN}

# Use very short TTL / interval in tests so sweeper behavior is observable
# without waiting days; but we still age incidents via direct DB writes
# (lab-only test manipulation) rather than relying on wall-clock waits.
TEST_TTL_SECONDS = 60
TEST_INTERVAL_SECONDS = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _ingest_incident(
    client: TestClient,
    *,
    event_id: str | None = None,
    sample: str = "04_wazuh_malware_hash_virustotal.json",
    agent_id: str | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    """Ingest a high-tier alert and return the response body.

    When tests need two separate incidents (instead of both attaching to
    the same dedupe group), pass distinct ``agent_id`` / ``rule_id``.
    """
    payload = _load_sample(sample)
    if event_id is not None:
        payload = dict(payload, id=event_id)
    if agent_id is not None:
        payload = dict(payload)
        payload["agent"] = dict(payload.get("agent", {}), id=agent_id)
    if rule_id is not None:
        payload = dict(payload)
        payload["rule"] = dict(payload.get("rule", {}), id=rule_id)
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 202, response.text
    return response.json()


def _patch_status(client: TestClient, incident_id: str, target: str, **kwargs: Any) -> Any:
    body: dict[str, Any] = {"status": target, **kwargs}
    return client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json=body,
        headers=TOKEN_HEADERS,
    )


def _incident(client: TestClient, incident_id: str) -> Any:
    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        return IncidentRepository(session).get(incident_id)


def _audit(client: TestClient) -> list[Any]:
    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        return AuditRepository(session).all()


def _auto_close_events(client: TestClient) -> list[Any]:
    return [e for e in _audit(client) if e.action == ACTION_INCIDENT_AUTO_CLOSED]


def _set_incident_updated_at(
    client: TestClient, incident_id: str, new_updated_at: datetime
) -> None:
    """Test-only helper to age an incident's activity timestamp.

    Used instead of ``time.sleep`` so the TTL boundary is deterministic and
    tests run in milliseconds. We update through the ORM (not raw text SQL)
    so SQLAlchemy's datetime binding is consistent between writes and the
    sweeper's conditional UPDATE — a raw text() UPDATE would serialize
    datetimes differently than the ORM and cause false-negative predicate
    mismatches in SQLite. This mirrors the lab-only procedure documented
    for Phase 3.4 demo step B (manipulate the activity timestamp safely in
    a test-only/lab manner).
    """
    from sqlalchemy import update as sa_update

    from soc_triage.models.orm import Incident as IncidentORM
    from soc_triage.models.repositories import as_utc

    ts = as_utc(new_updated_at)
    with client.app.state.db_engine.begin() as conn:
        conn.execute(
            sa_update(IncidentORM)
            .where(IncidentORM.incident_id == incident_id)
            .values(updated_at=ts)
        )


def _sweeper_settings(
    db_url: str,
    *,
    ttl: int = TEST_TTL_SECONDS,
    interval: int = TEST_INTERVAL_SECONDS,
) -> Settings:
    return Settings(
        soc_env="test",
        soc_log_level="WARNING",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=db_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        n8n_webhook_token="",
        n8n_webhook_url="",
        incident_auto_close_ttl_seconds=ttl,
        incident_sweeper_interval_seconds=interval,
    )


def _app_client(
    db_url: str,
    *,
    ttl: int = TEST_TTL_SECONDS,
    interval: int = TEST_INTERVAL_SECONDS,
) -> TestClient:
    return TestClient(create_app(settings=_sweeper_settings(db_url, ttl=ttl, interval=interval)))


@pytest.fixture
def client(db_url: str) -> TestClient:  # type: ignore[override]
    """Override the shared `client` fixture to use the short test TTL/interval."""
    with _app_client(db_url) as c:
        yield c


def _run_sweep(
    client: TestClient,
    *,
    as_of: datetime | None = None,
) -> dict[str, int]:
    """Run one deterministic sweep using the client app's session factory."""
    return sweeper_mod.sweep_once(
        client.app.state.session_factory,
        ttl_seconds=client.app.state.settings.incident_auto_close_ttl_seconds,
        as_of=as_of,
    )


# ---------------------------------------------------------------------------
# CONFIG — tests 1-3
# ---------------------------------------------------------------------------


def test_default_ttl_and_interval_load() -> None:
    """Factory defaults match the documented conservative lab values."""
    s = Settings(
        soc_env="test",
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        n8n_webhook_token="",
    )
    # 7 days default TTL; 5 minute default interval.
    assert s.incident_auto_close_ttl_seconds == 7 * 24 * 3600
    assert s.incident_sweeper_interval_seconds == 300


def test_environment_override_works(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INCIDENT_AUTO_CLOSE_TTL_SECONDS", "3600")
    monkeypatch.setenv("INCIDENT_SWEEPER_INTERVAL_SECONDS", "60")
    s = Settings(
        soc_env="test",
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        n8n_webhook_token="",
    )
    assert s.incident_auto_close_ttl_seconds == 3600
    assert s.incident_sweeper_interval_seconds == 60


def test_non_positive_ttl_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import ValidationError

    monkeypatch.setenv("INCIDENT_AUTO_CLOSE_TTL_SECONDS", "0")
    with pytest.raises(ValidationError):
        Settings(
            soc_env="test",
            triage_ingest_api_key=TEST_INGEST_KEY,
            n8n_callback_token=TEST_CALLBACK_TOKEN,
            n8n_webhook_token="",
        )

    monkeypatch.setenv("INCIDENT_AUTO_CLOSE_TTL_SECONDS", "-5")
    with pytest.raises(ValidationError):
        Settings(
            soc_env="test",
            triage_ingest_api_key=TEST_INGEST_KEY,
            n8n_callback_token=TEST_CALLBACK_TOKEN,
            n8n_webhook_token="",
        )


# ---------------------------------------------------------------------------
# ELIGIBILITY — tests 4-10
# ---------------------------------------------------------------------------


def test_open_incident_older_than_ttl_is_eligible_and_closes(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    # Age it past the TTL.
    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 1),
    )

    stats = _run_sweep(client)

    assert stats["candidates"] == 1
    assert stats["closed"] == 1
    assert _incident(client, iid).status == IncidentStatus.RESOLVED


def test_investigating_incident_older_than_ttl_is_eligible(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    assert _patch_status(client, iid, "investigating").status_code == 200

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 1),
    )

    stats = _run_sweep(client)

    assert stats["closed"] == 1
    assert _incident(client, iid).status == IncidentStatus.RESOLVED


def test_acknowledged_incident_older_than_ttl_is_eligible(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    assert _patch_status(client, iid, "investigating").status_code == 200
    assert _patch_status(client, iid, "acknowledged").status_code == 200

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 1),
    )

    stats = _run_sweep(client)

    assert stats["closed"] == 1

    incident = _incident(client, iid)
    assert incident.status == IncidentStatus.RESOLVED

    # acknowledged_at must be preserved.
    assert incident.acknowledged_at is not None


def test_escalated_incident_older_than_ttl_is_eligible(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    assert _patch_status(client, iid, "escalated").status_code == 200

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 1),
    )

    stats = _run_sweep(client)

    assert stats["closed"] == 1
    assert _incident(client, iid).status == IncidentStatus.RESOLVED


def test_recently_updated_incident_is_not_eligible(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    # updated_at is "now" — well within the TTL.
    stats = _run_sweep(client)

    assert stats["candidates"] == 0
    assert stats["closed"] == 0
    assert _incident(client, iid).status == IncidentStatus.OPEN


def test_resolved_incident_is_not_eligible(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    assert _patch_status(client, iid, "investigating").status_code == 200
    assert _patch_status(client, iid, "resolved").status_code == 200

    # Even if updated_at is aged, terminal states are excluded.
    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(days=365),
    )

    stats = _run_sweep(client)

    assert stats["candidates"] == 0
    assert stats["closed"] == 0

    # resolved_at unchanged by sweeper.
    resolved_at_before = _incident(client, iid).resolved_at

    _run_sweep(client)

    assert _incident(client, iid).resolved_at == resolved_at_before


def test_false_positive_is_not_eligible(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    assert _patch_status(client, iid, "false_positive").status_code == 200

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(days=365),
    )

    stats = _run_sweep(client)

    assert stats["candidates"] == 0
    assert stats["closed"] == 0
    assert _incident(client, iid).status == IncidentStatus.FALSE_POSITIVE


def test_exact_ttl_boundary_is_deterministic(client: TestClient) -> None:
    """An incident whose updated_at is exactly 'now - TTL' IS eligible
    (the cutoff is <= as_of - ttl_seconds)."""
    body = _ingest_incident(client)
    iid = body["incident_id"]

    now = datetime.now(UTC)

    # Exactly at the boundary: updated_at == now - TTL -> should be selected.
    _set_incident_updated_at(
        client,
        iid,
        now - timedelta(seconds=TEST_TTL_SECONDS),
    )

    stats = _run_sweep(client, as_of=now)

    assert stats["candidates"] == 1
    assert stats["closed"] == 1


def test_just_inside_ttl_is_not_eligible(client: TestClient) -> None:
    """One second inside the window -> not eligible."""
    body = _ingest_incident(client)
    iid = body["incident_id"]

    now = datetime.now(UTC)

    _set_incident_updated_at(
        client,
        iid,
        now - timedelta(seconds=TEST_TTL_SECONDS - 1),
    )

    stats = _run_sweep(client, as_of=now)

    assert stats["candidates"] == 0
    assert stats["closed"] == 0


# ---------------------------------------------------------------------------
# AUTO-CLOSE correctness — tests 11-18
# ---------------------------------------------------------------------------


def test_eligible_incident_becomes_resolved(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    _run_sweep(client)

    incident = _incident(client, iid)

    assert incident.status == IncidentStatus.RESOLVED


def test_resolved_at_populated_once(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    _run_sweep(client)

    incident = _incident(client, iid)

    assert incident.resolved_at is not None

    resolved_at_first = incident.resolved_at

    # A second sweep must not change resolved_at.
    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(days=365),
    )

    _run_sweep(client)

    assert _incident(client, iid).resolved_at == resolved_at_first


def test_acknowledged_at_preserved(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    assert _patch_status(client, iid, "acknowledged").status_code == 200

    ack_at = _incident(client, iid).acknowledged_at
    assert ack_at is not None

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    _run_sweep(client)

    closed = _incident(client, iid)

    assert closed.acknowledged_at == ack_at
    assert closed.status == IncidentStatus.RESOLVED


def test_updated_at_changes_on_auto_close(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    old_time = datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 100)

    _set_incident_updated_at(client, iid, old_time)

    before = _incident(client, iid)

    assert (
        before.updated_at.replace(tzinfo=UTC)
        if before.updated_at.tzinfo is None
        else before.updated_at
    )

    sweep_time = datetime.now(UTC)

    _run_sweep(client, as_of=sweep_time)

    after = _incident(client, iid)

    # updated_at must have been refreshed to sweep_time (exact, within ms).
    assert after.updated_at >= sweep_time - timedelta(seconds=1)
    assert after.updated_at > old_time


def test_actor_is_system_sweeper(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    _run_sweep(client)

    events = _auto_close_events(client)

    assert len(events) == 1
    assert events[0].actor == ACTOR_SWEEPER
    assert events[0].after["actor"] == ACTOR_SWEEPER


def test_auto_close_creates_one_audit_row(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    _run_sweep(client)

    events = _auto_close_events(client)

    assert len(events) == 1

    entry = events[0]

    assert entry.action == ACTION_INCIDENT_AUTO_CLOSED
    assert entry.entity_type == "incident"
    assert entry.entity_id == iid
    assert entry.before == {"status": "open"}
    assert entry.after["incident_id"] == iid
    assert entry.after["previous_status"] == "open"
    assert entry.after["status"] == "resolved"
    assert entry.after["reason"] == "ttl_expired"
    assert entry.after["ttl_seconds"] == TEST_TTL_SECONDS
    assert entry.after["idle_seconds"] >= TEST_TTL_SECONDS
    assert entry.after["actor"] == ACTOR_SWEEPER

    # resolved_at populated in after snapshot.
    assert entry.after["resolved_at"] is not None


def test_repeat_sweep_is_idempotent(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    assert _run_sweep(client)["closed"] == 1

    # Subsequent sweeps must find no candidates (terminal) and add no new
    # audit rows.
    for _ in range(3):
        stats = _run_sweep(client)
        assert stats["candidates"] == 0
        assert stats["closed"] == 0

    assert len(_auto_close_events(client)) == 1


def test_unrelated_incidents_remain_unchanged(client: TestClient) -> None:
    # Use distinct agents so both creates get their own incident (distinct
    # dedupe groups) instead of attaching to the same open incident.
    body_a = _ingest_incident(client, event_id="ev-1", agent_id="901")
    body_b = _ingest_incident(client, event_id="ev-2", agent_id="902")

    iid_old = body_a["incident_id"]
    iid_new = body_b["incident_id"]

    assert iid_old != iid_new

    # Only age incident A.
    _set_incident_updated_at(
        client,
        iid_old,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    stats = _run_sweep(client)

    assert stats["candidates"] == 1
    assert stats["closed"] == 1
    assert _incident(client, iid_old).status == IncidentStatus.RESOLVED
    assert _incident(client, iid_new).status == IncidentStatus.OPEN


# ---------------------------------------------------------------------------
# RACE / SAFETY — tests 19-20
# ---------------------------------------------------------------------------


def test_manual_update_after_candidate_selection_prevents_stale_close(
    client: TestClient,
) -> None:
    """If the analyst patches an incident after the sweeper's SELECT but
    before the conditional UPDATE, the UPDATE must match zero rows and
    the manual change must win (no overwrite)."""
    body = _ingest_incident(client)
    iid = body["incident_id"]

    old_time = datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 100)

    _set_incident_updated_at(client, iid, old_time)

    # Simulate the scenario: run candidate SELECT inside a transaction,
    # then (before the conditional UPDATE) a manual PATCH bumps
    # updated_at. We do this by calling the repository directly in two
    # separate scoped sessions:
    factory = client.app.state.session_factory
    ttl = client.app.state.settings.incident_auto_close_ttl_seconds

    # 1) Select the candidate.
    with session_scope(factory) as session:
        candidates = IncidentRepository(session).list_incidents_eligible_for_auto_close(
            ttl_seconds=ttl,
            as_of=datetime.now(UTC),
            limit=100,
        )

    assert len(candidates) == 1
    candidate = candidates[0]

    # 2) Manual PATCH lands between SELECT and UPDATE: simulates an analyst
    # acknowledging the incident (this bumps updated_at and changes status).
    assert (
        _patch_status(
            client,
            iid,
            "investigating",
            actor="analyst@example.com",
        ).status_code
        == 200
    )

    # 3) Now run the per-incident conditional update with the *stale*
    #    candidate snapshot. It MUST return None (no close, no audit).
    with session_scope(factory) as session:
        closed = IncidentRepository(session).auto_close_if_stale(
            candidate.incident_id,
            ttl_seconds=ttl,
            as_of=datetime.now(UTC),
            expected_previous_updated_at=candidate.updated_at,
            expected_previous_status=candidate.status.value,
        )

        assert closed is None

        # No audit entry appended (we deliberately don't append here).

    # The manual "investigating" state survived, no auto-close happened.
    assert _incident(client, iid).status == IncidentStatus.INVESTIGATING
    assert _auto_close_events(client) == []


def test_two_sweep_passes_do_not_double_close_or_double_audit(client: TestClient) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    _run_sweep(client)
    _run_sweep(client)

    assert _incident(client, iid).status == IncidentStatus.RESOLVED
    assert len(_auto_close_events(client)) == 1


# ---------------------------------------------------------------------------
# RESTART — tests 21-22
# ---------------------------------------------------------------------------


def test_auto_closed_state_persists_across_app_restart(db_url: str) -> None:
    with _app_client(db_url) as client_a:
        body = _ingest_incident(client_a)
        iid = body["incident_id"]

        _set_incident_updated_at(
            client_a,
            iid,
            datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
        )

        assert _run_sweep(client_a)["closed"] == 1
        assert _incident(client_a, iid).status == IncidentStatus.RESOLVED

    with _app_client(db_url) as client_b:
        incident = _incident(client_b, iid)

        assert incident is not None
        assert incident.status == IncidentStatus.RESOLVED
        assert incident.resolved_at is not None

        # Exactly one auto_closed audit row survived the restart.
        assert len(_auto_close_events(client_b)) == 1

        # Sweep-after-restart is a no-op.
        assert _run_sweep(client_b)["closed"] == 0
        assert len(_auto_close_events(client_b)) == 1


def test_sweeper_starts_and_stops_cleanly_with_lifespan(db_url: str) -> None:
    """The background task is created at startup and cancelled at shutdown."""
    with _app_client(db_url, interval=1) as client:
        task = client.app.state.sweeper_task

        assert task is not None
        assert not task.done()

    # After the TestClient context exits, lifespan has run its finally
    # block; the task should be done (cancelled).
    assert task.done()
    assert task.cancelled() or task.exception() is None


# ---------------------------------------------------------------------------
# REGRESSION — tests 23-24
#
# 23 is enforced by running the full existing suite alongside this file
# (see the quality gate at the end of this branch).  24 is a direct
# assertion that terminal states remain protected through the manual API.
# ---------------------------------------------------------------------------


def test_terminal_states_remain_protected_from_manual_transitions(
    client: TestClient,
) -> None:
    body = _ingest_incident(client)
    iid = body["incident_id"]

    assert _patch_status(client, iid, "false_positive").status_code == 200

    # Attempting to transition out of false_positive must still be 409.
    response = _patch_status(client, iid, "investigating")

    assert response.status_code == 409
    assert _incident(client, iid).status == IncidentStatus.FALSE_POSITIVE


def test_sweeper_uses_system_sweeper_actor_not_analyst(client: TestClient) -> None:
    """Guard: the auto_closed audit must use ACTOR_SWEEPER, never 'analyst'."""
    body = _ingest_incident(client)
    iid = body["incident_id"]

    _set_incident_updated_at(
        client,
        iid,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    _run_sweep(client)

    events = _auto_close_events(client)

    assert len(events) == 1
    assert events[0].actor == sweeper_mod.SWEEPER_ACTOR
    assert events[0].actor.startswith("system:")


def test_sweeper_per_incident_error_does_not_stop_later_candidates(
    client: TestClient,
) -> None:
    """A failure on one incident must not abort the whole sweep pass.

    We simulate a per-incident failure by monkey-patching
    auto_close_if_stale to raise on the first candidate id; the second
    (aged) incident must still close successfully.
    """
    body_a = _ingest_incident(
        client,
        event_id="err-1",
        agent_id="701",
    )
    body_b = _ingest_incident(
        client,
        event_id="err-2",
        agent_id="702",
    )

    iid_a = body_a["incident_id"]
    iid_b = body_b["incident_id"]

    assert iid_a != iid_b

    _set_incident_updated_at(
        client,
        iid_a,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    _set_incident_updated_at(
        client,
        iid_b,
        datetime.now(UTC) - timedelta(seconds=TEST_TTL_SECONDS + 10),
    )

    factory = client.app.state.session_factory
    ttl = client.app.state.settings.incident_auto_close_ttl_seconds
    original = IncidentRepository.auto_close_if_stale

    call_count = {"n": 0}

    def flaky(self, incident_id, **kwargs):  # type: ignore[no-untyped-def]
        call_count["n"] += 1

        if call_count["n"] == 1:
            raise RuntimeError("simulated per-incident failure")

        return original(self, incident_id, **kwargs)

    IncidentRepository.auto_close_if_stale = flaky  # type: ignore[method-assign]

    try:
        stats = sweeper_mod.sweep_once(
            factory,
            ttl_seconds=ttl,
        )
    finally:
        IncidentRepository.auto_close_if_stale = original  # type: ignore[method-assign]

    # We should see one error and one close — the failure on the first
    # candidate must not prevent the loop from reaching the second.
    assert stats["errors"] == 1
    assert stats["closed"] == 1
    assert stats["candidates"] == 2

    # Exactly one of the two is now resolved (the non-failing one), the
    # failing candidate was rolled back and stayed OPEN.
    statuses = {
        _incident(client, iid_a).status,
        _incident(client, iid_b).status,
    }

    assert statuses == {
        IncidentStatus.OPEN,
        IncidentStatus.RESOLVED,
    }
