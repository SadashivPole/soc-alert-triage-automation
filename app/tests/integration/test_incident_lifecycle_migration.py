"""Phase 3.2 regression tests: the incident lifecycle timestamps migration.

The ``e7f8a9b0c1d2`` revision adds two nullable columns (``acknowledged_at``
/ ``resolved_at``) to ``incidents``. These tests pin its data-safety and
restart-safety contract:

* an existing Phase 3.1 database (with incident/alert/audit rows) upgrades
  cleanly, with every pre-existing row preserved;
* a run interrupted after the first ``ADD COLUMN`` (SQLite DDL autocommits
  — the column is durably committed while ``alembic_version`` still names
  d4e5f6a7b8c9) is finished on restart instead of failing on "duplicate
  column name";
* the downgrade drops the columns again — on SQLite via a batch recreate of
  ``incidents`` that must survive live ``alerts`` rows (FK pair) and must
  restore ``PRAGMA foreign_keys`` afterwards;
* the application reads the migrated rows (lifecycle timestamps NULL until
  the state is reached) and a full lifecycle works on the upgraded database.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from alembic import command as alembic_command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.engine import ALEMBIC_SCRIPT_LOCATION, create_app_engine, run_migrations
from soc_triage.db.session import session_scope
from soc_triage.main import create_app
from soc_triage.models.repositories import IncidentRepository

PREVIOUS_REVISION = "d4e5f6a7b8c9"  # Phase 3.1 head
HEAD_REVISION = "f9a0b1c2d3e4"  # current migration head (Phase 6.4)

ALERT_ID = "00000000-0000-0000-0000-000000000001"
INCIDENT_ID = "INC-2026-08-29-0001"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_phase_3_1_database(db_url: str) -> Any:
    """A database at the Phase 3.1 head (d4e5f6a7b8c9), pre-3.2."""
    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.downgrade(config, PREVIOUS_REVISION)
    return engine


def _seed_incident_data(conn: Any) -> None:
    """One alert + one open incident + audit rows, all at Phase 3.1 shape.

    The seeded incident lives in its own dedupe group (agent 999) so the
    later sample-alert ingest (group wazuh:87105:003) creates its own
    incident instead of attaching to the seeded open one.
    """
    conn.execute(
        text(
            "INSERT INTO alerts (alert_id, source, received_at, dedupe_group_key, "
            "event_identity, rule_id, rule_level, agent_id, agent_name, "
            "normalized_payload, created_at) VALUES "
            "(:alert_id, 'wazuh', '2026-08-29 10:00:00.000000', 'wazuh:87105:999', "
            "'wazuh:legacy:87105:999', '87105', 7, '999', 'hr-wks-99', "
            '\'{"rule": {"id": "87105", "level": 7}}\', \'2026-08-29 10:00:00.000000\')'
        ),
        {"alert_id": ALERT_ID},
    )
    conn.execute(
        text(
            "INSERT INTO alert_dedupe_groups (group_key, occurrences, generation, "
            "first_seen, last_seen, duplicate_deliveries, updated_at) VALUES "
            "('wazuh:87105:999', 1, 1, '2026-08-29 10:00:00.000000', "
            "'2026-08-29 10:00:00.000000', 0, '2026-08-29 10:00:00.000000')"
        )
    )
    conn.execute(
        text(
            "INSERT INTO incidents (incident_id, status, severity, primary_alert_id, "
            "dedupe_group_key, created_at, updated_at) VALUES "
            "(:incident_id, 'open', 'SEV2', :alert_id, 'wazuh:87105:999', "
            "'2026-08-29 10:00:00.000000', '2026-08-29 10:00:00.000000')"
        ),
        {"incident_id": INCIDENT_ID, "alert_id": ALERT_ID},
    )
    conn.execute(
        text("UPDATE alerts SET incident_id = :incident_id WHERE alert_id = :alert_id"),
        {"incident_id": INCIDENT_ID, "alert_id": ALERT_ID},
    )
    conn.execute(
        text(
            "INSERT INTO audit_log (occurred_at, actor, action, entity_type, entity_id, "
            "before, after) VALUES ('2026-08-29 10:00:00.000000', 'decisions', "
            "'incident.created', 'incident', :incident_id, NULL, '{}')"
        ),
        {"incident_id": INCIDENT_ID},
    )


#: Explicit column lists (no ``SELECT *``): the migration adds columns to
#: ``incidents``, so a ``*`` snapshot would differ in arity before/after by
#: design, and autoincrement ids are not data.
_SNAPSHOT_COLUMNS = {
    "alerts": (
        "alert_id, source, received_at, dedupe_group_key, event_identity, rule_id, "
        "rule_level, agent_id, agent_name, normalized_payload, incident_id, created_at"
    ),
    "incidents": (
        "incident_id, status, severity, primary_alert_id, dedupe_group_key, created_at, updated_at"
    ),
    "audit_log": "occurred_at, actor, action, entity_type, entity_id, before, after",
    "alert_dedupe_groups": (
        "group_key, occurrences, generation, first_seen, last_seen, "
        "duplicate_deliveries, updated_at"
    ),
}


def _data_snapshot(conn: Any) -> dict[str, list[tuple[Any, ...]]]:
    """Row snapshot of every table the migration must not disturb.

    The caller owns the connection/transaction — this helper must never
    commit or close it (a nested ``with conn:`` would close the connection
    and roll back the caller's open transaction).
    """
    snapshot: dict[str, list[tuple[Any, ...]]] = {}
    for table, columns in _SNAPSHOT_COLUMNS.items():
        rows = conn.execute(text(f"SELECT {columns} FROM {table} ORDER BY 1")).fetchall()
        snapshot[table] = [tuple(row) for row in rows]
    return snapshot


def _alembic_version(engine: Any) -> str | None:
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _incidents_columns(engine: Any) -> dict[str, bool]:
    """incidents column name -> nullable."""
    inspector = inspect(engine)
    return {col["name"]: col["nullable"] for col in inspector.get_columns("incidents")}


def _settings(db_url: str) -> Settings:
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
        incident_auto_close_ttl_seconds=3650 * 24 * 3600,
    )


def _ingest_high_alert(client: TestClient, *, event_id: str) -> dict[str, Any]:
    sample_path = (
        Path(__file__).parent.parent / "fixtures" / "04_wazuh_malware_hash_virustotal.json"
    )
    payload = json.loads(sample_path.read_text())
    payload["id"] = event_id
    response = client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers={"X-API-Key": TEST_INGEST_KEY},
    )
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _assert_lifecycle_columns(engine: Any) -> None:
    columns = _incidents_columns(engine)
    assert columns["acknowledged_at"] is True
    assert columns["resolved_at"] is True
    # The Phase 3.1 columns are untouched.
    for name in (
        "incident_id",
        "status",
        "severity",
        "primary_alert_id",
        "dedupe_group_key",
        "created_at",
        "updated_at",
    ):
        assert columns[name] is False, f"incidents.{name} must stay NOT NULL"


# ---------------------------------------------------------------------------
# 1. Existing database upgrades cleanly, data preserved
# ---------------------------------------------------------------------------


def test_lifecycle_migration_upgrades_existing_database_preserving_data(db_url: str) -> None:
    engine = _build_phase_3_1_database(db_url)
    with engine.begin() as conn:
        _seed_incident_data(conn)
        before = _data_snapshot(conn)
    assert _alembic_version(engine) == PREVIOUS_REVISION

    # Application startup path: bring the database to head.
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == HEAD_REVISION
    _assert_lifecycle_columns(engine)
    with engine.connect() as conn:
        assert _data_snapshot(conn) == before  # every row byte-for-byte preserved
        # Pre-3.2 incidents read as NULL lifecycle timestamps.
        assert conn.execute(
            text("SELECT acknowledged_at, resolved_at FROM incidents WHERE incident_id = :iid"),
            {"iid": INCIDENT_ID},
        ).fetchone() == (None, None)
    engine.dispose()

    # The upgraded database is operational end to end: a fresh alert creates
    # an incident, and a full lifecycle (status + timestamps) works.
    with TestClient(create_app(settings=_settings(db_url))) as client:
        body = _ingest_high_alert(client, event_id="1770000000.500001")
        assert body["incident_id"] is not None
        new_incident = body["incident_id"]
        response = client.patch(
            f"/api/v1/incidents/{new_incident}/status",
            json={"status": "acknowledged"},
            headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
        )
        assert response.status_code == 200, response.text
        assert response.json()["acknowledged_at"] is not None
        factory = client.app.state.session_factory
        with session_scope(factory) as session:
            incident = IncidentRepository(session).get(new_incident)
        assert incident is not None
        assert incident.acknowledged_at is not None
        assert incident.resolved_at is None
        # The seeded pre-3.1 incident is still readable, timestamps NULL.
        with session_scope(factory) as session:
            seeded = IncidentRepository(session).get(INCIDENT_ID)
        assert seeded is not None
        assert seeded.status.value == "open"
        assert seeded.acknowledged_at is None
        assert seeded.resolved_at is None


# ---------------------------------------------------------------------------
# 2. Restart safety: interruption after the first ADD COLUMN
# ---------------------------------------------------------------------------


def test_lifecycle_migration_is_restart_safe_after_interruption(db_url: str) -> None:
    engine = _build_phase_3_1_database(db_url)
    with engine.begin() as conn:
        _seed_incident_data(conn)
        before = _data_snapshot(conn)

    # Simulate a crash after the first column was committed (SQLite DDL is
    # non-transactional): acknowledged_at exists, resolved_at does not, and
    # the revision was never recorded.
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE incidents ADD COLUMN acknowledged_at DATETIME"))
    assert _alembic_version(engine) == PREVIOUS_REVISION
    assert "acknowledged_at" in _incidents_columns(engine)
    assert "resolved_at" not in _incidents_columns(engine)

    # Restart: the idempotent upgrade finishes what the interrupted run left.
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == HEAD_REVISION
    _assert_lifecycle_columns(engine)
    with engine.connect() as conn:
        assert _data_snapshot(conn) == before
    engine.dispose()


# ---------------------------------------------------------------------------
# 3. Downgrade: columns drop, data and FK integrity survive (SQLite)
# ---------------------------------------------------------------------------


def test_lifecycle_migration_downgrade_drops_columns_with_data(db_url: str) -> None:
    engine = _build_phase_3_1_database(db_url)
    with engine.begin() as conn:
        _seed_incident_data(conn)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    assert _alembic_version(engine) == HEAD_REVISION

    # Give the lifecycle columns real values so the downgrade must drop them
    # without losing the rest of the rows.
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE incidents SET status = 'acknowledged', "
                "acknowledged_at = '2026-08-29 11:00:00.000000', "
                "updated_at = '2026-08-29 11:00:00.000000' "
                "WHERE incident_id = :iid"
            ),
            {"iid": INCIDENT_ID},
        )
    with engine.connect() as conn:
        rows_before = conn.execute(
            text("SELECT incident_id, status, severity, created_at FROM incidents")
        ).fetchall()

    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.downgrade(config, PREVIOUS_REVISION)

    assert _alembic_version(engine) == PREVIOUS_REVISION
    columns = _incidents_columns(engine)
    assert "acknowledged_at" not in columns
    assert "resolved_at" not in columns

    with engine.connect() as conn:
        rows_after = conn.execute(
            text("SELECT incident_id, status, severity, created_at FROM incidents")
        ).fetchall()
        assert rows_after == rows_before  # row data survived the column drop
        # FK integrity intact, and the application pragma state is restored.
        assert conn.execute(text("PRAGMA foreign_key_check")).fetchall() == []
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
    engine.dispose()

    # Re-upgrade back to head (upgrade is repeatable after a downgrade).
    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    assert _alembic_version(engine) == HEAD_REVISION
    _assert_lifecycle_columns(engine)
    engine.dispose()
