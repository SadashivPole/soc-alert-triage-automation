"""Phase 1D integration tests: persistent storage, restart recovery, and audit.

Covers the required persistence contract on a real (temp) SQLite database
through the same startup path the service uses (engine + Alembic migrations):

* new alert persistence (alerts + dedupe group + event + audit rows)
* exact duplicate persistence (idempotent, original alert_id, counters only)
* duplicate flooding must not extend the deduplication window
* repeated alert persistence and occurrence counts
* generation changes and window pruning
* restart/reload persistence (state restored from the database)
* audit records (sequence, before/after, no raw payloads, no secrets)
* rollback/error handling (atomic units of work; safe 503 envelope)
* health/readiness with a live database
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.engine import create_app_engine, create_session_factory, run_migrations
from soc_triage.db.session import session_scope
from soc_triage.ingest.deduplication import DedupeStatus, compute_event_identity
from soc_triage.ingest.normalizer import normalize_wazuh_alert
from soc_triage.ingest.persistent_deduplication import PersistentDeduplicator
from soc_triage.ingest.schemas import WazuhAlert
from soc_triage.main import create_app
from soc_triage.models.repositories import AlertRepository, AuditRepository

T0 = datetime(2026, 8, 29, 10, 15, 0, tzinfo=UTC)
GROUP_KEY = "wazuh:5710:001"

SAMPLE_FULL_LOG = "Failed password for admin from 203.0.113.50"


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------


def _settings(db_url: str) -> Settings:
    """Non-placeholder settings for a specific database file."""
    return Settings(
        soc_env="test",
        soc_log_level="WARNING",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=db_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
    )


def _engine_for(db_url: str) -> Engine:
    """Engine with migrations applied (same bootstrap as the app lifespan)."""
    engine = create_app_engine(db_url)
    run_migrations(engine)
    return engine


@pytest.fixture
def engine(db_url: str) -> Engine:
    eng = _engine_for(db_url)
    yield eng
    eng.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(engine)


@pytest.fixture
def deduplicator(session_factory: sessionmaker[Session]) -> PersistentDeduplicator:
    return PersistentDeduplicator(session_factory, window_seconds=900)


def build_alert(
    event_id: str = "1770000000.100001",
    *,
    full_log: str = SAMPLE_FULL_LOG,
    agent_id: str = "001",
    rule_id: str = "5710",
) -> WazuhAlert:
    """A valid synthetic Wazuh alert (documentation-range data only)."""
    return WazuhAlert.model_validate(
        {
            "id": event_id,
            "timestamp": "2026-08-29T10:15:29.000+0000",
            "rule": {"level": 5, "description": "sshd: failed login", "id": rule_id},
            "agent": {"id": agent_id, "name": f"host-{agent_id}"},
            "data": {"srcip": "203.0.113.50", "dstuser": "admin"},
            "location": "/var/log/auth.log",
            "full_log": full_log,
        }
    )


def _deliver(dedup: PersistentDeduplicator, alert: WazuhAlert, at: datetime) -> Any:
    canonical = normalize_wazuh_alert(alert, received_at=at)
    return dedup.process(alert, canonical, at)


def _rows(engine: Engine, query: str, params: tuple[Any, ...] = ()) -> list[Any]:
    with engine.connect() as conn:
        return list(conn.execute(text(query), params).fetchall())


def _audit_rows(engine: Engine) -> list[Any]:
    factory = create_session_factory(engine)
    with session_scope(factory) as session:
        return AuditRepository(session).all()


def _db_path(db_url: str) -> Path:
    return Path(db_url.removeprefix("sqlite:///"))


# ---------------------------------------------------------------------------
# New alert persistence
# ---------------------------------------------------------------------------


def test_new_alert_is_persisted(engine: Engine, deduplicator: PersistentDeduplicator) -> None:
    alert = build_alert()
    outcome = _deliver(deduplicator, alert, T0)

    assert outcome.status is DedupeStatus.NEW_GENERATION

    # alerts: one row with the denormalized query fields
    alerts = _rows(
        engine,
        "SELECT alert_id, source, received_at, dedupe_group_key, rule_id, rule_level, "
        "agent_id, agent_name FROM alerts",
    )
    assert len(alerts) == 1
    row = alerts[0]
    assert UUID(row[0]) == outcome.alert_id
    assert row[1] == "wazuh"
    assert row[2] == "2026-08-29 10:15:00.000000"  # stored as UTC
    assert row[3] == GROUP_KEY
    assert (row[4], row[5]) == ("5710", 5)
    assert (row[6], row[7]) == ("001", "host-001")

    # normalized payload round-trips to the canonical alert of record
    factory = create_session_factory(engine)
    with session_scope(factory) as session:
        stored = AlertRepository(session).get(outcome.alert_id)
    assert stored == outcome.canonical_alert

    # dedupe group: recurrence state
    groups = _rows(
        engine,
        "SELECT group_key, occurrences, generation, first_seen, last_seen, "
        "duplicate_deliveries FROM alert_dedupe_groups",
    )
    assert len(groups) == 1
    g = groups[0]
    assert g[0] == GROUP_KEY
    assert (g[1], g[2]) == (1, 1)
    assert g[3] == g[4] == "2026-08-29 10:15:00.000000"
    assert g[5] == 0

    # event record: idempotency bookkeeping
    events = _rows(
        engine,
        "SELECT event_identity, delivery_count, content_variants FROM alert_events",
    )
    assert len(events) == 1
    assert events[0][0] == compute_event_identity(alert)
    assert (events[0][1], events[0][2]) == (1, 1)

    # audit: generation start + alert creation
    audit = _audit_rows(engine)
    assert [a.action for a in audit] == ["dedupe.generation_started", "alert.created"]


# ---------------------------------------------------------------------------
# Exact duplicate persistence (idempotency contract)
# ---------------------------------------------------------------------------


def test_exact_duplicate_is_idempotent_and_persisted(
    engine: Engine, deduplicator: PersistentDeduplicator
) -> None:
    alert = build_alert()
    first = _deliver(deduplicator, alert, T0)
    duplicate = _deliver(deduplicator, alert, T0 + timedelta(seconds=10))

    # Contract: original alert_id and preserved original canonical alert.
    assert duplicate.status is DedupeStatus.EXACT_DUPLICATE
    assert duplicate.alert_id == first.alert_id
    assert duplicate.canonical_alert == first.canonical_alert
    # Recurrence state untouched — the window is not extended.
    assert duplicate.dedupe.occurrences == 1
    assert duplicate.dedupe.last_seen == T0
    assert duplicate.dedupe.duplicate_deliveries == 1

    # One alert row only; the event record counts the delivery.
    assert len(_rows(engine, "SELECT alert_id FROM alerts")) == 1
    events = _rows(engine, "SELECT delivery_count, last_delivered_at FROM alert_events")
    assert len(events) == 1
    assert events[0][0] == 2
    groups = _rows(
        engine,
        "SELECT occurrences, last_seen, duplicate_deliveries FROM alert_dedupe_groups",
    )
    assert groups[0][0] == 1
    assert groups[0][1] == "2026-08-29 10:15:00.000000"  # unchanged
    assert groups[0][2] == 1

    # Audit: the absorption is recorded with before/after counters.
    absorbed = [a for a in _audit_rows(engine) if a.action == "alert.duplicate_absorbed"]
    assert len(absorbed) == 1
    assert absorbed[0].before == {"delivery_count": 1, "duplicate_deliveries": 0}
    assert absorbed[0].after == {
        "alert_id": str(first.alert_id),
        "delivery_count": 2,
        "duplicate_deliveries": 1,
    }


def test_duplicate_flood_does_not_extend_deduplication_window(
    engine: Engine, deduplicator: PersistentDeduplicator
) -> None:
    """A flood of duplicate deliveries must not keep the group alive.

    Window is 900 s: A at T0, duplicate flood up to T0+800, then a distinct
    event B at T0+901 must start a *new generation* — the flood never
    extended the window (recurrence state is untouched by duplicates).
    """
    a = build_alert("1770000000.100001")
    b = build_alert("1770000000.100002")

    _deliver(deduplicator, a, T0)
    for i in range(1, 81):
        outcome = _deliver(deduplicator, a, T0 + timedelta(seconds=10 * i))
        assert outcome.status is DedupeStatus.EXACT_DUPLICATE

    outcome = _deliver(deduplicator, b, T0 + timedelta(seconds=901))
    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert outcome.dedupe.generation == 2
    assert outcome.dedupe.occurrences == 1

    groups = _rows(engine, "SELECT duplicate_deliveries, generation FROM alert_dedupe_groups")
    # The new generation reset the counter (by contract) — but the per-event
    # record still proves all 80 duplicate deliveries were counted, and the
    # generation advanced.
    assert groups[0][0] == 0
    assert groups[0][1] == 2
    event_counts = _rows(engine, "SELECT delivery_count FROM alert_events")
    assert max(count for (count,) in event_counts) == 81  # 1 + 80 absorbed


# ---------------------------------------------------------------------------
# Repeated alerts, occurrence counts, generations
# ---------------------------------------------------------------------------


def test_repeated_alerts_persist_occurrence_counts(
    engine: Engine, deduplicator: PersistentDeduplicator
) -> None:
    alerts = [build_alert(f"1770000000.10000{i}") for i in range(5)]
    outcomes = [
        _deliver(deduplicator, alert, T0 + timedelta(seconds=10 * i))
        for i, alert in enumerate(alerts)
    ]

    assert outcomes[0].status is DedupeStatus.NEW_GENERATION
    assert all(o.status is DedupeStatus.REPEATED for o in outcomes[1:])
    assert len({o.alert_id for o in outcomes}) == 5  # distinct events, distinct alerts

    assert len(_rows(engine, "SELECT alert_id FROM alerts")) == 5
    assert len(_rows(engine, "SELECT event_identity FROM alert_events")) == 5
    groups = _rows(
        engine,
        "SELECT occurrences, generation, first_seen, last_seen FROM alert_dedupe_groups",
    )
    assert groups[0][0] == 5
    assert groups[0][1] == 1
    assert groups[0][2] == "2026-08-29 10:15:00.000000"
    assert groups[0][3] == "2026-08-29 10:15:40.000000"  # T0 + 4*10 s

    # A duplicate re-delivery still does not bump the persisted counter.
    _deliver(deduplicator, alerts[0], T0 + timedelta(seconds=90))
    groups = _rows(engine, "SELECT occurrences, duplicate_deliveries FROM alert_dedupe_groups")
    assert groups[0] == (5, 1)

    created = [a for a in _audit_rows(engine) if a.action == "alert.created"]
    assert len(created) == 5


def test_generation_change_is_persisted(
    engine: Engine, deduplicator: PersistentDeduplicator
) -> None:
    a = build_alert("1770000000.100001")
    b = build_alert("1770000000.100002")

    _deliver(deduplicator, a, T0)
    outcome = _deliver(deduplicator, b, T0 + timedelta(seconds=901))

    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert outcome.dedupe.generation == 2
    assert outcome.dedupe.occurrences == 1
    assert outcome.dedupe.first_seen == T0 + timedelta(seconds=901)
    assert outcome.dedupe.duplicate_deliveries == 0

    groups = _rows(
        engine,
        "SELECT generation, occurrences, first_seen, last_seen FROM alert_dedupe_groups",
    )
    assert groups[0][0] == 2
    assert groups[0][1] == 1
    assert groups[0][2] == groups[0][3] == "2026-08-29 10:30:01.000000"

    started = [a for a in _audit_rows(engine) if a.action == "dedupe.generation_started"]
    assert len(started) == 2  # generation 1 (group birth) and generation 2
    assert started[1].before == {
        "generation": 1,
        "occurrences": 1,
        "duplicate_deliveries": 0,
        "first_seen": "2026-08-29T10:15:00+00:00",
        "last_seen": "2026-08-29T10:15:00+00:00",
    }
    assert started[1].after["generation"] == 2
    assert started[1].entity_id == GROUP_KEY


def test_redelivery_beyond_window_is_fresh_evidence_and_prunes(
    engine: Engine, deduplicator: PersistentDeduplicator
) -> None:
    """Past the horizon the event is new evidence; its old record is pruned."""
    a = build_alert("1770000000.100001")

    first = _deliver(deduplicator, a, T0)
    later = _deliver(deduplicator, a, T0 + timedelta(seconds=901))

    assert first.status is DedupeStatus.NEW_GENERATION
    assert later.status is DedupeStatus.NEW_GENERATION
    assert later.alert_id != first.alert_id

    # Two distinct alerts of record; only the recent event record survives.
    assert len(_rows(engine, "SELECT alert_id FROM alerts")) == 2
    assert len(_rows(engine, "SELECT event_identity FROM alert_events")) == 1
    remaining = _rows(engine, "SELECT alert_id FROM alert_events")[0][0]
    assert UUID(remaining) == later.alert_id


def test_content_divergence_is_counted_and_audited(
    engine: Engine, deduplicator: PersistentDeduplicator
) -> None:
    a = build_alert("1770000000.100001", full_log="Failed password for admin")
    mutated = build_alert("1770000000.100001", full_log="Failed password for ROOT")

    first = _deliver(deduplicator, a, T0)
    outcome = _deliver(deduplicator, mutated, T0 + timedelta(seconds=10))

    assert outcome.status is DedupeStatus.EXACT_DUPLICATE
    assert outcome.alert_id == first.alert_id
    events = _rows(engine, "SELECT delivery_count, content_variants FROM alert_events")
    assert events[0] == (2, 2)

    divergence = [a for a in _audit_rows(engine) if a.action == "alert.content_divergence"]
    assert len(divergence) == 1
    assert divergence[0].after["content_variants"] == 2


# ---------------------------------------------------------------------------
# Restart / reload persistence
# ---------------------------------------------------------------------------


def test_restart_restores_deduplication_state(db_url: str) -> None:
    """State must survive a full application restart (new engine/process)."""
    # --- First "process" lifetime ---
    engine1 = _engine_for(db_url)
    dedup1 = PersistentDeduplicator(create_session_factory(engine1), window_seconds=900)

    a = build_alert("1770000000.100001")
    b = build_alert("1770000000.100002")
    first_a = _deliver(dedup1, a, T0)
    first_b = _deliver(dedup1, b, T0 + timedelta(seconds=60))
    assert first_a.status is DedupeStatus.NEW_GENERATION
    assert first_b.status is DedupeStatus.REPEATED
    engine1.dispose()  # process death

    # --- Second "process" lifetime: fresh engine over the same file ---
    engine2 = _engine_for(db_url)
    dedup2 = PersistentDeduplicator(create_session_factory(engine2), window_seconds=900)

    # Exact re-delivery of the pre-restart event: idempotent, same alert_id.
    duplicate_a = _deliver(dedup2, a, T0 + timedelta(seconds=120))
    assert duplicate_a.status is DedupeStatus.EXACT_DUPLICATE
    assert duplicate_a.alert_id == first_a.alert_id
    assert duplicate_a.canonical_alert == first_a.canonical_alert

    # A distinct event within the restored window continues the generation.
    c = build_alert("1770000000.100003")
    repeat_c = _deliver(dedup2, c, T0 + timedelta(seconds=180))
    assert repeat_c.status is DedupeStatus.REPEATED
    assert repeat_c.dedupe.occurrences == 3  # a + b + c
    assert repeat_c.dedupe.generation == 1  # no accidental reset

    assert dedup2.group_count() == 1
    group = dedup2.group_state(GROUP_KEY)
    assert group is not None
    assert group.occurrences == 3
    assert group.duplicate_deliveries == 1
    assert group.generation == 1
    engine2.dispose()


# ---------------------------------------------------------------------------
# Audit records
# ---------------------------------------------------------------------------


def test_audit_records_sequence_and_content(
    engine: Engine, deduplicator: PersistentDeduplicator
) -> None:
    a = build_alert("1770000000.100001")
    b = build_alert("1770000000.100002")

    first_a = _deliver(deduplicator, a, T0)
    _deliver(deduplicator, a, T0 + timedelta(seconds=10))
    _deliver(deduplicator, b, T0 + timedelta(seconds=30))

    audit = _audit_rows(engine)
    assert [e.action for e in audit] == [
        "dedupe.generation_started",
        "alert.created",
        "alert.duplicate_absorbed",
        "alert.created",
    ]
    for entry in audit:
        assert entry.actor == "ingest"
        assert entry.occurred_at is not None

    gen, created_a, absorbed, created_b = audit
    assert gen.entity_type == "dedupe_group"
    assert gen.entity_id == GROUP_KEY
    assert gen.after == {
        "generation": 1,
        "occurrences": 1,
        "duplicate_deliveries": 0,
        "first_seen": "2026-08-29T10:15:00+00:00",
        "last_seen": "2026-08-29T10:15:00+00:00",
    }

    assert created_a.entity_type == "alert"
    assert created_a.entity_id == str(first_a.alert_id)
    assert created_a.after["dedupe_status"] == "new_generation"
    assert created_a.after["occurrences"] == 1

    assert absorbed.entity_id == str(first_a.alert_id)
    assert absorbed.before == {"delivery_count": 1, "duplicate_deliveries": 0}
    assert absorbed.after["delivery_count"] == 2
    assert absorbed.after["duplicate_deliveries"] == 1

    assert created_b.after["dedupe_status"] == "repeated"
    assert created_b.after["occurrences"] == 2
    assert created_b.after["generation"] == 1


def test_audit_rows_carry_no_raw_payload_or_secrets(
    engine: Engine, deduplicator: PersistentDeduplicator
) -> None:
    """Audit entries must stay small: no raw logs, no secret values."""
    a = build_alert("1770000000.100001")
    _deliver(deduplicator, a, T0)
    _deliver(deduplicator, a, T0 + timedelta(seconds=10))
    _deliver(deduplicator, build_alert("1770000000.100002"), T0 + timedelta(seconds=30))

    blob = json.dumps(
        [
            {
                "actor": e.actor,
                "action": e.action,
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "before": e.before,
                "after": e.after,
            }
            for e in _audit_rows(engine)
        ]
    )
    # The event identity (wazuh:{event_id}:{rule}:{agent}) is part of the
    # idempotency contract and legitimately appears; what must NOT appear is
    # the raw payload content or any secret.
    assert SAMPLE_FULL_LOG not in blob  # no raw alert data
    assert "full_log" not in blob
    assert TEST_INGEST_KEY not in blob  # no secrets (canary)
    assert TEST_CALLBACK_TOKEN not in blob  # no secrets (canary)


def test_api_persists_audit_records_for_ingest(db_url: str) -> None:
    """End-to-end: ingest requests produce durable audit rows."""
    payload = _sample_payload()
    payload_repeat = {**payload, "id": "1770000000.100002"}

    with TestClient(create_app(settings=_settings(db_url))) as client:
        assert (
            client.post("/api/v1/alerts/ingest", json=payload, headers=_auth()).status_code == 202
        )
        assert (
            client.post("/api/v1/alerts/ingest", json=payload, headers=_auth()).status_code == 200
        )
        assert (
            client.post("/api/v1/alerts/ingest", json=payload_repeat, headers=_auth()).status_code
            == 202
        )

    # New engine over the same file: the rows are durable. Phase 1F appends
    # `alert.scored` + `alert.decided` after each new alert's `alert.created`
    # (exact duplicates are echoed, never re-scored).
    audit = _audit_rows(create_app_engine(db_url))
    assert [e.action for e in audit] == [
        "dedupe.generation_started",
        "alert.created",
        "alert.scored",
        "alert.decided",
        "alert.duplicate_absorbed",
        "alert.created",
        "alert.scored",
        "alert.decided",
    ]


# ---------------------------------------------------------------------------
# Rollback / error handling
# ---------------------------------------------------------------------------


def test_rollback_on_failure_leaves_no_partial_state(engine: Engine) -> None:
    """A failure mid-transaction must roll back *all* writes of the unit of work.

    The failure is real: a trigger aborts the audit INSERT (a driver-level
    error raised inside the statement) *after* the alert, event, and group
    writes of the same unit of work have already executed. The unit of work
    must roll back completely.
    """
    from soc_triage.db.errors import StorageError

    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TRIGGER audit_fail BEFORE INSERT ON audit_log "
                "BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END"
            )
        )

    dedup = PersistentDeduplicator(create_session_factory(engine), window_seconds=900)
    with pytest.raises(StorageError):
        _deliver(dedup, build_alert(), T0)

    # Nothing partial survived: every table of the unit of work is empty.
    assert _rows(engine, "SELECT COUNT(*) FROM alerts") == [(0,)]
    assert _rows(engine, "SELECT COUNT(*) FROM alert_events") == [(0,)]
    assert _rows(engine, "SELECT COUNT(*) FROM alert_dedupe_groups") == [(0,)]
    assert _rows(engine, "SELECT COUNT(*) FROM audit_log") == [(0,)]

    # And the next delivery succeeds cleanly (no poisoned state).
    with engine.begin() as conn:
        conn.execute(text("DROP TRIGGER audit_fail"))
    outcome = _deliver(dedup, build_alert(), T0)
    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert _rows(engine, "SELECT COUNT(*) FROM alerts") == [(1,)]
    assert _rows(engine, "SELECT COUNT(*) FROM audit_log") == [(2,)]


def test_db_unavailable_returns_safe_503(db_url: str) -> None:
    """When the database is gone, ingest answers a retryable 503 — and the
    error envelope leaks no database internals (no paths, no driver text)."""
    path = _db_path(db_url)
    app = create_app(settings=_settings(db_url))

    with TestClient(app) as client:
        # Baseline: the database works.
        assert (
            client.post(
                "/api/v1/alerts/ingest", json=_sample_payload(), headers=_auth()
            ).status_code
            == 202
        )
        assert client.get("/health").status_code == 200

        # Simulate total database loss: drop the pool and lock the file away.
        client.app.state.db_engine.dispose()
        os.chmod(path, 0o000)
        try:
            response = client.post("/api/v1/alerts/ingest", json=_sample_payload(), headers=_auth())
            assert response.status_code == 503
            body = response.json()
            assert body["error"]["code"] == "service_unavailable"
            leaked = json.dumps(body)
            assert ".db" not in leaked
            assert "sqlite" not in leaked.lower()
            assert "unable to open" not in leaked.lower()
            assert str(path) not in leaked

            health = client.get("/health")
            assert health.status_code == 503
            ready = client.get("/ready")
            assert ready.status_code == 503
        finally:
            os.chmod(path, 0o644)


# ---------------------------------------------------------------------------
# Health / readiness with a live database
# ---------------------------------------------------------------------------


def test_health_and_ready_report_database(db_url: str) -> None:
    with TestClient(create_app(settings=_settings(db_url))) as client:
        health = client.get("/health").json()
        assert health["status"] == "ok"
        assert health["db"] == "ok"

        ready = client.get("/ready").json()
        assert ready["status"] == "ready"
        assert ready["checks"]["db"] == "ok"
        assert ready["checks"]["migrations"] == "ok"


# ---------------------------------------------------------------------------
# Concurrency (thread safety of the persistent path)
# ---------------------------------------------------------------------------


def test_concurrent_deliveries_serialize_deterministically(db_url: str) -> None:
    """Many threads hammering the persistent deduplicator: exactly one
    delivery creates an alert per identity; the rest are idempotent."""
    # NullPool: every session gets a fresh connection (harshest case).
    engine = create_app_engine(db_url, poolclass=NullPool)
    run_migrations(engine)
    factory = create_session_factory(engine)
    dedup = PersistentDeduplicator(factory, window_seconds=900)

    distinct = [build_alert(f"1770000000.2000{i:02d}") for i in range(8)]
    shared = build_alert("1770000000.200099")

    def run(index: int):
        at = T0 + timedelta(milliseconds=index)
        alert = shared if index % 3 == 0 else distinct[index % len(distinct)]
        return _deliver(dedup, alert, at)

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(run, range(64)))

    shared_identity = compute_event_identity(shared)
    shared_new = [
        o
        for o in outcomes
        if o.status is DedupeStatus.NEW_GENERATION and o.event_identity == shared_identity
    ]
    shared_dups = [
        o
        for o in outcomes
        if o.status is DedupeStatus.EXACT_DUPLICATE and o.event_identity == shared_identity
    ]
    assert len(shared_new) == 1
    assert all(o.alert_id == shared_new[0].alert_id for o in shared_dups)

    # Distinct identities: each is created exactly once (as NEW or REPEATED);
    # re-deliveries of the same identity are idempotent duplicates.
    new_outcomes = [o for o in outcomes if o.status is DedupeStatus.NEW_GENERATION]
    assert len({o.alert_id for o in new_outcomes}) == len({o.event_identity for o in new_outcomes})
    all_dups = [o for o in outcomes if o.status is DedupeStatus.EXACT_DUPLICATE]
    created_or_repeated = [o for o in outcomes if o.status is not DedupeStatus.EXACT_DUPLICATE]
    assert len(created_or_repeated) == len({o.event_identity for o in outcomes})

    group = dedup.group_state(GROUP_KEY)
    assert group is not None
    assert group.occurrences == len({o.event_identity for o in outcomes})
    assert group.duplicate_deliveries == len(all_dups)
    assert len(_rows(engine, "SELECT alert_id FROM alerts")) == len(
        {o.event_identity for o in outcomes}
    )
    engine.dispose()


# ---------------------------------------------------------------------------
# API-level idempotency over the persistent backend
# ---------------------------------------------------------------------------


def _sample_payload() -> dict[str, Any]:
    return {
        "id": "1770000000.100001",
        "timestamp": "2026-08-29T10:15:29.000+0000",
        "rule": {
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "id": "5710",
        },
        "agent": {"id": "001", "name": "web-prod-01"},
        "data": {"srcip": "203.0.113.50", "dstuser": "admin"},
        "location": "/var/log/auth.log",
        "full_log": SAMPLE_FULL_LOG,
    }


def _auth() -> dict[str, str]:
    return {"X-API-Key": TEST_INGEST_KEY}


def test_api_idempotency_and_counts_persist_across_instances(db_url: str) -> None:
    """Two separate app instances on one database behave as one service:
    the exact-duplicate contract and occurrence counts hold across the
    process boundary."""
    payload = _sample_payload()
    repeat = {**payload, "id": "1770000000.100002"}

    with TestClient(create_app(settings=_settings(db_url))) as client_a:
        first = client_a.post("/api/v1/alerts/ingest", json=payload, headers=_auth())
        assert first.status_code == 202
        first_id: UUID = UUID(first.json()["alert_id"])
        second = client_a.post("/api/v1/alerts/ingest", json=repeat, headers=_auth())
        assert second.status_code == 202
        assert second.json()["dedupe_status"] == "repeated"
        assert second.json()["dedupe"]["occurrences"] == 2

    with TestClient(create_app(settings=_settings(db_url))) as client_b:
        duplicate = client_b.post("/api/v1/alerts/ingest", json=payload, headers=_auth())
        assert duplicate.status_code == 200
        assert duplicate.json()["duplicate"] is True
        assert UUID(duplicate.json()["alert_id"]) == first_id
        assert duplicate.json()["normalized"] == first.json()["normalized"]
        assert duplicate.json()["dedupe"]["occurrences"] == 2
        assert duplicate.json()["dedupe"]["duplicate_deliveries"] == 1

    engine = create_app_engine(db_url)
    assert _rows(engine, "SELECT COUNT(*) FROM alerts") == [(2,)]
    engine.dispose()
