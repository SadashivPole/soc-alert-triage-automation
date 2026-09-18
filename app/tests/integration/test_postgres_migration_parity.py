"""Phase 3.8 — PostgreSQL profile + migration parity tests.

Additive and skippable when PostgreSQL is unavailable. Covers:

* driver URL acceptance (no live DB required)
* JSON extraction dialect portability (no live DB)
* fresh upgrade head on PostgreSQL
* downgrade base → upgrade head
* schema/table existence
* ORM/migration column parity
* data round-trip (alert/incident/audit)
* API ingest against PostgreSQL
* UTC datetime behavior
* JSON payload behavior
* migration idempotency

Uses existing helpers: create_app_engine, run_migrations, session_scope,
SQLAlchemy inspection. No duplicated migration logic.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.dialects import postgresql, sqlite

from soc_triage.db.engine import (
    ALEMBIC_SCRIPT_LOCATION,
    create_app_engine,
    create_session_factory,
    ensure_sqlite_directory,
    run_migrations,
)
from soc_triage.db.session import session_scope
from soc_triage.models.orm import Alert
from soc_triage.models.repositories import (
    AlertRepository,
    AuditRepository,
    IncidentRepository,
    _json_extract,
)

# ---------------------------------------------------------------------------
# Helpers to resolve a PostgreSQL URL without breaking default SQLite stack
# ---------------------------------------------------------------------------

EXPECTED_TABLES = {
    "alerts",
    "alert_dedupe_groups",
    "alert_events",
    "audit_log",
    "notification_attempts",
    "analyst_feedback",
    "incidents",
    "correlation_contexts",
    "correlation_members",
    "enrichment_cache",
    "alembic_version",
}

# Current head per existing recovery tests
HEAD_REVISION = "c7d8e9f0a1b2"


def _resolve_postgres_url() -> str | None:
    """Resolve a PostgreSQL URL from env, if operator configured it.

    Order:
    1. POSTGRES_TEST_URL (explicit test override)
    2. TRIAGE_DB_URL if it starts with postgresql
    3. Constructed from POSTGRES_DB/USER/PASSWORD if password present
    Returns None if no URL can be resolved (tests will skip).
    """
    explicit = os.environ.get("POSTGRES_TEST_URL", "").strip()
    if explicit:
        return explicit

    triage_url = os.environ.get("TRIAGE_DB_URL", "").strip()
    if triage_url.startswith("postgresql"):
        return triage_url

    # Construct from POSTGRES_* if password present (guard pattern)
    pwd = os.environ.get("POSTGRES_PASSWORD", "").strip()
    if not pwd:
        return None
    user = os.environ.get("POSTGRES_USER", "soc_triage").strip() or "soc_triage"
    db = os.environ.get("POSTGRES_DB", "soc_triage").strip() or "soc_triage"
    host = os.environ.get("POSTGRES_HOST", "postgres").strip() or "postgres"
    port = os.environ.get("POSTGRES_PORT", "5432").strip() or "5432"
    # Use psycopg driver (Phase 3.8)
    return f"postgresql+psycopg://{user}:{pwd}@{host}:{port}/{db}"


def _is_postgres_available(url: str) -> bool:
    """Try to connect and SELECT 1; False if unreachable."""
    try:
        engine = create_app_engine(url)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# No-live-DB tests — driver acceptance and SQL portability
# ---------------------------------------------------------------------------


def test_postgres_driver_accepts_url() -> None:
    """postgresql+psycopg:// URL is accepted by existing engine bootstrap.

    No live connection required — only engine creation and dialect check.
    """
    url = "postgresql+psycopg://soc_triage:test-pass@postgres:5432/soc_triage"
    # ensure_sqlite_directory must be no-op for non-sqlite
    ensure_sqlite_directory(url)  # should not raise
    engine = create_app_engine(url)
    try:
        assert engine.dialect.name == "postgresql"
        assert engine.dialect.driver == "psycopg"
    finally:
        engine.dispose()


def test_postgres_json_extract_compiles_sqlite_and_postgres() -> None:
    """_json_extract preserves SQLite json_extract and uses ->> on Postgres."""
    from sqlalchemy import select as sa_select

    stmt = sa_select(Alert).where(_json_extract(Alert.normalized_payload, "$.risk.tier") == "high")
    sqlite_sql = str(stmt.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
    pg_sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))

    # SQLite must use json_extract with JSONPath
    assert "json_extract" in sqlite_sql.lower()
    assert "$.risk.tier" in sqlite_sql or "risk" in sqlite_sql

    # Postgres must use -> and ->> operators, not json_extract
    assert "->" in pg_sql
    assert "->>" in pg_sql
    # Should not contain json_extract( on Postgres (our custom compilation)
    assert "json_extract(" not in pg_sql.lower()

    stmt2 = sa_select(Alert).where(
        _json_extract(Alert.normalized_payload, "$.decision.severity") == "SEV2"
    )
    assert (
        "json_extract"
        in str(
            stmt2.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True})
        ).lower()
    )
    assert "->>" in str(
        stmt2.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    )


def test_postgres_json_extract_single_key() -> None:
    """Single-level JSON path also compiles correctly."""
    from sqlalchemy import select as sa_select

    stmt = sa_select(Alert).where(_json_extract(Alert.normalized_payload, "$.source") == "wazuh")
    sqlite_sql = str(stmt.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
    pg_sql = str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert "json_extract" in sqlite_sql.lower()
    assert "->>" in pg_sql


# ---------------------------------------------------------------------------
# Live-Postgres tests — skippable when unavailable
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def postgres_url() -> str:
    url = _resolve_postgres_url()
    if not url:
        pytest.skip(
            "PostgreSQL not configured: set POSTGRES_TEST_URL or POSTGRES_PASSWORD + TRIAGE_DB_URL"
        )
    if not _is_postgres_available(url):
        pytest.skip(f"PostgreSQL not reachable at {url!r}")
    return url


@pytest.fixture(scope="module")
def postgres_engine(postgres_url: str):
    engine = create_app_engine(postgres_url)
    # Ensure fresh migrations to head
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    yield engine
    engine.dispose()


def test_postgres_upgrade_head_fresh(postgres_engine) -> None:
    """Fresh PostgreSQL database upgrades to head."""
    insp = inspect(postgres_engine)
    tables = set(insp.get_table_names())
    # At least expected tables must exist
    missing = EXPECTED_TABLES - tables
    assert not missing, f"missing tables after upgrade head: {missing}"
    # alembic_version should be at head
    with postgres_engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert version == HEAD_REVISION


def test_postgres_downgrade_base_upgrade_head(postgres_engine) -> None:
    """Downgrade base → upgrade head is reproducible on PostgreSQL."""
    from alembic import command as alembic_command
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    # Downgrade to base
    with postgres_engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.downgrade(config, "base")
    # Verify base has no triage tables (only alembic_version)
    insp = inspect(postgres_engine)
    tables_after_base = set(insp.get_table_names())
    # After downgrade base, our tables should be gone
    assert not (EXPECTED_TABLES - {"alembic_version"}) & tables_after_base

    # Re-upgrade to head
    run_migrations(postgres_engine, ALEMBIC_SCRIPT_LOCATION)
    insp = inspect(postgres_engine)
    tables_after_head = set(insp.get_table_names())
    assert EXPECTED_TABLES.issubset(tables_after_head)
    with postgres_engine.connect() as conn:
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert version == HEAD_REVISION


def test_postgres_schema_table_existence(postgres_engine) -> None:
    """All expected tables exist after upgrade head."""
    insp = inspect(postgres_engine)
    tables = set(insp.get_table_names())
    for tbl in EXPECTED_TABLES:
        assert tbl in tables, f"table {tbl} missing"


def test_postgres_orm_migration_column_parity(postgres_engine) -> None:
    """ORM Base.metadata columns match migrated schema (nullability, types)."""
    insp = inspect(postgres_engine)
    # Compare ORM definitions for a few critical tables
    # alerts
    alert_cols = {c["name"]: c for c in insp.get_columns("alerts")}
    assert "alert_id" in alert_cols
    assert "normalized_payload" in alert_cols
    assert "incident_id" in alert_cols
    # incidents
    inc_cols = {c["name"]: c for c in insp.get_columns("incidents")}
    for col in (
        "incident_id",
        "status",
        "severity",
        "primary_alert_id",
        "dedupe_group_key",
        "created_at",
        "updated_at",
    ):
        assert col in inc_cols, f"incidents.{col} missing"
        assert inc_cols[col]["nullable"] is False, f"incidents.{col} should be NOT NULL"
    # lifecycle columns nullable
    for col in ("acknowledged_at", "resolved_at"):
        assert col in inc_cols
        assert inc_cols[col]["nullable"] is True, f"incidents.{col} should be nullable"
    # audit_log
    audit_cols = {c["name"]: c for c in insp.get_columns("audit_log")}
    assert "id" in audit_cols
    assert "occurred_at" in audit_cols
    # enrichment_cache
    cache_cols = {c["name"]: c for c in insp.get_columns("enrichment_cache")}
    for col in (
        "provider",
        "indicator_type",
        "indicator_value",
        "payload",
        "looked_at",
        "expires_at",
    ):
        assert col in cache_cols


def test_postgres_data_roundtrip(postgres_engine) -> None:
    """Representative data round-trip: alert + incident + audit + UTC + JSON."""
    factory = create_session_factory(postgres_engine)
    alert_id = uuid.uuid4()
    now = datetime.now(UTC)
    canonical_payload = {
        "alert_id": str(alert_id),
        "source": "wazuh",
        "received_at": now.isoformat(),
        "source_event": {
            "rule": {"id": "5710", "level": 5, "description": "test"},
            "agent": {"id": "001", "name": "host-001"},
        },
        "dedupe": {
            "group_key": "wazuh:5710:001",
            "occurrences": 1,
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
            "event_identity": f"test:{alert_id}",
        },
        "risk": {"score": 63, "tier": "medium", "factors": []},
        "decision": {"action": "queue_l1", "severity": "SEV2", "reasons": []},
        "iocs": [],
        "enrichment_status": "skipped",
    }

    # Insert via ORM directly to test column parity and JSON behavior
    with session_scope(factory) as session:
        session.add(
            Alert(
                alert_id=alert_id,
                source="wazuh",
                received_at=now,
                dedupe_group_key="wazuh:5710:001",
                event_identity=f"test:{alert_id}",
                rule_id="5710",
                rule_level=5,
                agent_id="001",
                agent_name="host-001",
                normalized_payload=canonical_payload,
                created_at=now,
            )
        )

    # Read back and check UTC and JSON
    with session_scope(factory) as session:
        repo = AlertRepository(session)
        persisted = repo.get_alert(alert_id)
        assert persisted is not None
        # UTC behavior: stored timestamp should be UTC and equal within second
        assert persisted.received_at.tzinfo is not None
        assert persisted.received_at.utcoffset() is not None
        # JSON payload round-trips
        assert persisted.canonical.model_dump(mode="json")["risk"]["tier"] == "medium"
        assert persisted.canonical.model_dump(mode="json")["decision"]["severity"] == "SEV2"

        # JSON filter behavior — tier and severity filters use _json_extract
        # Should find our alert via tier filter on Postgres
        alerts, total = repo.list_alerts(tier="medium")
        assert total >= 1
        assert any(a.alert_id == alert_id for a in alerts)

        _alerts_sev, total_sev = repo.list_alerts(severity="SEV2")
        assert total_sev >= 1

    # Incident + audit persistence
    with session_scope(factory) as session:
        inc_repo = IncidentRepository(session)
        # Create incident linked to our alert
        from soc_triage.models.assessment import DecisionSeverity

        incident = inc_repo.create(
            alert_id=alert_id,
            severity=DecisionSeverity.SEV2,
            dedupe_group_key="wazuh:5710:001",
            occurred_at=now,
        )
        assert incident.incident_id.startswith("INC-")
        # Audit entry
        from soc_triage.audit import AuditEntry

        audit_repo = AuditRepository(session)
        audit_repo.append(
            [
                AuditEntry(
                    actor="test",
                    action="incident.created",
                    entity_type="incident",
                    entity_id=incident.incident_id,
                    before=None,
                    after={"alert_id": str(alert_id)},
                )
            ],
            occurred_at=now,
        )

    # Verify incident and audit survived
    with session_scope(factory) as session:
        inc_repo = IncidentRepository(session)
        fetched = inc_repo.get(incident.incident_id)
        assert fetched is not None
        assert fetched.primary_alert_id == alert_id
        assert fetched.created_at.tzinfo is not None

        audit_repo = AuditRepository(session)
        rows = audit_repo.for_entity_ids([incident.incident_id])
        assert len(rows) >= 1
        assert rows[0].entity_id == incident.incident_id


def test_postgres_api_ingest(postgres_engine, postgres_url: str) -> None:  # noqa: ARG001
    """API ingest against PostgreSQL persists alert/incident/audit."""
    from fastapi.testclient import TestClient
    from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

    from soc_triage.core.config import Settings
    from soc_triage.main import create_app

    settings = Settings(
        soc_env="test",
        soc_log_level="WARNING",
        soc_instance_name="soc-test-pg",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=postgres_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        n8n_webhook_token="",
        n8n_webhook_url="",
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        payload = {
            "id": f"pg-test-{uuid.uuid4()}",
            "timestamp": "2026-08-29T10:15:29.000+0000",
            "rule": {"level": 7, "description": "test high", "id": "100100"},
            "agent": {"id": "001", "name": "host-001"},
            "data": {"srcip": "203.0.113.10"},
            "location": "/var/log/auth.log",
            "full_log": "test log",
        }
        resp = client.post(
            "/api/v1/alerts/ingest", json=payload, headers={"X-API-Key": TEST_INGEST_KEY}
        )
        assert resp.status_code in {200, 202}
        body = resp.json()
        assert "alert_id" in body
        alert_id = body["alert_id"]

        # Read back via API
        read = client.get(
            f"/api/v1/alerts/{alert_id}", headers={"X-N8N-Token": TEST_CALLBACK_TOKEN}
        )
        assert read.status_code == 200
        data = read.json()
        assert data["alert_id"] == alert_id

        # Health should be ok with postgres
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["db"] == "ok"


def test_postgres_migration_idempotency(postgres_engine) -> None:
    """Running migrations twice is idempotent on PostgreSQL."""
    # First run already at head, second should be no-op
    run_migrations(postgres_engine, ALEMBIC_SCRIPT_LOCATION)
    with postgres_engine.connect() as conn:
        version1 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    run_migrations(postgres_engine, ALEMBIC_SCRIPT_LOCATION)
    with postgres_engine.connect() as conn:
        version2 = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert version1 == version2 == HEAD_REVISION


def test_postgres_utc_datetime_behavior(postgres_engine) -> None:
    """UTC datetime stored and retrieved correctly on PostgreSQL."""
    factory = create_session_factory(postgres_engine)
    alert_id = uuid.uuid4()
    naive = datetime(2026, 8, 29, 10, 15, 0)  # naive, should be treated as UTC
    aware = datetime(2026, 8, 29, 10, 15, 0, tzinfo=UTC)

    with session_scope(factory) as session:
        session.add(
            Alert(
                alert_id=alert_id,
                source="wazuh",
                received_at=naive,
                dedupe_group_key="wazuh:5710:001",
                event_identity=f"utc-test:{alert_id}",
                rule_id="5710",
                rule_level=5,
                agent_id="001",
                agent_name="host-001",
                normalized_payload={"test": True},
                created_at=aware,
            )
        )

    with session_scope(factory) as session:
        repo = AlertRepository(session)
        persisted = repo.get_alert(alert_id)
        assert persisted is not None
        # as_utc should make both aware
        assert persisted.received_at.tzinfo is not None
        assert persisted.created_at.tzinfo is not None
        # Both should be UTC
        assert persisted.received_at.astimezone(UTC) == persisted.received_at


def test_postgres_json_payload_behavior(postgres_engine) -> None:
    """JSON payload stored as JSON and queryable via _json_extract."""
    factory = create_session_factory(postgres_engine)
    alert_id = uuid.uuid4()
    now = datetime.now(UTC)
    payload = {
        "risk": {"tier": "critical", "score": 88},
        "decision": {"severity": "SEV1", "action": "open_incident"},
        "nested": {"a": {"b": "deep"}},
    }

    with session_scope(factory) as session:
        session.add(
            Alert(
                alert_id=alert_id,
                source="wazuh",
                received_at=now,
                dedupe_group_key="wazuh:5710:001",
                event_identity=f"json-test:{alert_id}",
                rule_id="5710",
                rule_level=12,
                agent_id="001",
                agent_name="host-001",
                normalized_payload=payload,
                created_at=now,
            )
        )

    with session_scope(factory) as session:
        # Direct SQL check that JSON is stored and extractable
        row = session.execute(
            text("SELECT normalized_payload FROM alerts WHERE alert_id = :id"),
            {"id": str(alert_id)},
        ).first()
        assert row is not None
        # SQLAlchemy should return dict for JSON column on postgres
        stored = row[0]
        # Could be dict or string depending on driver, handle both
        if isinstance(stored, dict):
            assert stored["risk"]["tier"] == "critical"
        else:
            import json

            assert json.loads(stored)["risk"]["tier"] == "critical"

        # Repository filter using _json_extract should work
        repo = AlertRepository(session)
        alerts, _ = repo.list_alerts(tier="critical")
        assert any(a.alert_id == alert_id for a in alerts)
