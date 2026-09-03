"""Regression tests: recovery from a partially-applied Phase 3.1 migration.

PR #16 hit a real migration/restart bug in the Windows Docker E2E:

    Alembic:   b2c3d4e5f6a7 -> d4e5f6a7b8c9
    SQLite:    sqlalchemy.exc.OperationalError: table incidents already exists

Root cause (two interacting problems, see the migration module docstring):

1. The batch ALTER of ``alerts`` failed with ``FOREIGN KEY constraint
   failed`` on databases whose alerts have child rows (alert_events,
   notification_attempts, analyst_feedback): the application engine enables
   ``PRAGMA foreign_keys=ON`` and SQLite's DROP TABLE runs an implicit
   DELETE FROM that violates those child references.
2. SQLite DDL is applied non-transactionally (the pysqlite driver
   autocommits DDL), so the already-created ``incidents`` table, its indexes
   and the Alembic batch scratch table ``_alembic_tmp_alerts`` stayed
   committed while ``alembic_version`` remained at ``b2c3d4e5f6a7``.
   Every restart replayed the migration and crashed on
   ``CREATE TABLE incidents``.

These tests pin the recovery contract:

* the exact crash state (partially-created ``incidents`` + orphaned scratch
  table, version left at ``b2c3d4e5f6a7``) upgrades to head without data
  loss — never by blind-stamping, but by verifying the partial schema first;
* the normal fresh-database path still works;
* a real Phase 2B database (alert/feedback/audit rows) upgrades cleanly;
* a partially-created schema missing later pieces is completed;
* an *incompatible* partial schema fails clearly instead of corrupting data;
* a catastrophic partial state (alert data stuck inside the scratch table)
  is refused, not deleted;
* the application restarts after the migration and incidents persist.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.conftest import TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.engine import ALEMBIC_SCRIPT_LOCATION, create_app_engine, run_migrations
from soc_triage.main import create_app

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
INCIDENT_ID_RE = re.compile(r"^INC-\d{4}-\d{2}-\d{2}-\d{4}$")

PREVIOUS_REVISION = "b2c3d4e5f6a7"
INCIDENT_REVISION = "d4e5f6a7b8c9"
#: Phase 3.2 head revision (incident lifecycle timestamps).
HEAD_REVISION = "e7f8a9b0c1d2"

#: The exact DDL the interrupted migration left committed in the Windows
#: Docker database (verbatim from the crash): the incidents table with all of
#: its indexes, plus Alembic's empty batch scratch table for the alerts ALTER
#: that never completed.
CRASHED_INCIDENTS_DDL = """
CREATE TABLE incidents (
    incident_id VARCHAR(32) NOT NULL,
    status VARCHAR(16) NOT NULL,
    severity VARCHAR(8) NOT NULL,
    primary_alert_id CHAR(32) NOT NULL,
    dedupe_group_key VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (incident_id),
    FOREIGN KEY(primary_alert_id) REFERENCES alerts (alert_id)
)
"""

CRASHED_INCIDENT_INDEX_DDL = (
    "CREATE INDEX ix_incidents_created_at ON incidents (created_at)",
    "CREATE INDEX ix_incidents_dedupe_group_key ON incidents (dedupe_group_key)",
    "CREATE INDEX ix_incidents_group_status ON incidents (dedupe_group_key, status)",
    "CREATE UNIQUE INDEX ix_incidents_primary_alert_id ON incidents (primary_alert_id)",
    "CREATE INDEX ix_incidents_severity ON incidents (severity)",
    "CREATE INDEX ix_incidents_status ON incidents (status)",
)

#: Alembic's batch scratch table: the *new* alerts shape (with the incident
#: link) that the interrupted batch created and copied into — committed empty,
#: because the INSERT is DML and rolled back with the failed transaction.
CRASHED_SCRATCH_DDL = """
CREATE TABLE _alembic_tmp_alerts (
    alert_id CHAR(32) NOT NULL,
    source VARCHAR(32) NOT NULL,
    received_at DATETIME NOT NULL,
    dedupe_group_key VARCHAR(255) NOT NULL,
    event_identity VARCHAR(512) NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    rule_level INTEGER NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    normalized_payload JSON NOT NULL,
    created_at DATETIME NOT NULL,
    incident_id VARCHAR(32),
    PRIMARY KEY (alert_id),
    CONSTRAINT fk_alerts_incident_id FOREIGN KEY(incident_id) REFERENCES incidents (incident_id)
)
"""

ALERT_IDS = (
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_phase_2b_database(db_url: str, *, with_data: bool = True) -> Any:
    """Create a Phase 2B database (revision b2c3d4e5f6a7) on ``db_url``.

    Migrates a fresh database all the way to head and downgrades to the
    previous revision — the exact shape of the pre-incident production
    database — then optionally seeds realistic rows in every table.
    """
    from alembic import command as alembic_command
    from alembic.config import Config

    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.downgrade(config, PREVIOUS_REVISION)

    if with_data:
        with engine.begin() as conn:
            for alert_id in ALERT_IDS:
                conn.execute(
                    text(
                        "INSERT INTO alerts (alert_id, source, received_at, "
                        "dedupe_group_key, event_identity, rule_id, rule_level, agent_id, "
                        "agent_name, normalized_payload, created_at) VALUES "
                        "(:alert_id, 'wazuh', '2026-08-29 10:00:00.000000', "
                        "'wazuh:5710:001', :event_identity, '5710', 5, '001', "
                        "'web-prod-01', :payload, '2026-08-29 10:00:00.000000')"
                    ),
                    {
                        "alert_id": alert_id,
                        "event_identity": f"wazuh:legacy:5710:{alert_id[-12:]}",
                        "payload": json.dumps({"rule": {"id": "5710", "level": 5}}),
                    },
                )
            conn.execute(
                text(
                    "INSERT INTO alert_dedupe_groups (group_key, occurrences, generation, "
                    "first_seen, last_seen, duplicate_deliveries, updated_at) VALUES "
                    "('wazuh:5710:001', 2, 1, '2026-08-29 10:00:00.000000', "
                    "'2026-08-29 10:01:00.000000', 0, '2026-08-29 10:01:00.000000')"
                )
            )
            for alert_id in ALERT_IDS:
                conn.execute(
                    text(
                        "INSERT INTO alert_events (event_identity, group_key, alert_id, "
                        "payload_fingerprint, delivery_count, content_variants, "
                        "first_delivered_at, last_delivered_at) VALUES "
                        "(:event_identity, 'wazuh:5710:001', :alert_id, "
                        "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "
                        "1, 1, '2026-08-29 10:00:00.000000', '2026-08-29 10:00:00.000000')"
                    ),
                    {
                        "event_identity": f"wazuh:legacy:5710:{alert_id[-12:]}",
                        "alert_id": alert_id,
                    },
                )
            conn.execute(
                text(
                    "INSERT INTO notification_attempts (alert_id, attempted_at, status, "
                    "http_status, error_type, retry_count, payload_hash, webhook_host, "
                    "duration_ms) VALUES (:alert_id, '2026-08-29 10:00:01.000000', "
                    "'delivered', 200, NULL, 0, "
                    "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', "
                    "'n8n.local', 42)"
                ),
                {"alert_id": ALERT_IDS[0]},
            )
            for verdict in ("acknowledged", "false_positive"):
                conn.execute(
                    text(
                        "INSERT INTO analyst_feedback (alert_id, received_at, actor, "
                        "verdict, notes) VALUES (:alert_id, '2026-08-29 10:05:00.000000', "
                        "'analyst@lab.local', :verdict, 'checked by L2')"
                    ),
                    {"alert_id": ALERT_IDS[0], "verdict": verdict},
                )
            for alert_id in ALERT_IDS:
                conn.execute(
                    text(
                        "INSERT INTO audit_log (occurred_at, actor, action, entity_type, "
                        "entity_id, before, after) VALUES "
                        "('2026-08-29 10:00:00.000000', 'system', 'alert.stored', 'alert', "
                        ":alert_id, NULL, '{}')"
                    ),
                    {"alert_id": alert_id},
                )
    return engine


def _simulate_crashed_migration(engine: Any, *, include_scratch_table: bool = True) -> None:
    """Recreate the exact state the failed migration left in the database.

    The interrupted run had already committed the incidents table with all
    indexes, plus Alembic's empty batch scratch table, while alembic_version
    still pointed at the previous revision.
    """
    with engine.begin() as conn:
        conn.execute(text(CRASHED_INCIDENTS_DDL))
        for ddl in CRASHED_INCIDENT_INDEX_DDL:
            conn.execute(text(ddl))
        if include_scratch_table:
            conn.execute(text(CRASHED_SCRATCH_DDL))


def _alembic_version(engine: Any) -> str | None:
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _table_names(engine: Any) -> set[str]:
    with engine.connect() as conn:
        return {
            row[0]
            for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        }


#: Explicit column lists per table: the Phase 2B schema as it existed before
#: the incident migration (alerts gains the nullable incident_id column, so a
#: ``SELECT *`` snapshot would differ in arity by design).
_SNAPSHOT_COLUMNS = {
    "alerts": (
        "alert_id, source, received_at, dedupe_group_key, event_identity, rule_id, "
        "rule_level, agent_id, agent_name, normalized_payload, created_at"
    ),
    "alert_dedupe_groups": (
        "group_key, occurrences, generation, first_seen, last_seen, "
        "duplicate_deliveries, updated_at"
    ),
    "alert_events": (
        "event_identity, group_key, alert_id, payload_fingerprint, delivery_count, "
        "content_variants, first_delivered_at, last_delivered_at"
    ),
    "notification_attempts": (
        "id, alert_id, attempted_at, status, http_status, error_type, retry_count, "
        "payload_hash, webhook_host, duration_ms"
    ),
    "analyst_feedback": "id, alert_id, received_at, actor, verdict, notes",
    "audit_log": ("id, occurred_at, actor, action, entity_type, entity_id, before, after"),
}


def _data_snapshot(engine: Any) -> dict[str, Any]:
    """Full row snapshot of every Phase 2B table (for no-data-loss asserts)."""
    snapshot: dict[str, Any] = {}
    with engine.connect() as conn:
        for table, columns in _SNAPSHOT_COLUMNS.items():
            rows = conn.execute(text(f"SELECT {columns} FROM {table} ORDER BY 1, 2")).fetchall()
            snapshot[table] = [tuple(row) for row in rows]
    return snapshot


def _column_names(engine: Any, table: str) -> list[str]:
    with engine.connect() as conn:
        return [row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))]


def _index_names(engine: Any, table: str) -> set[str]:
    with engine.connect() as conn:
        return {
            row[0]
            for row in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=:t"),
                {"t": table},
            )
        }


def _assert_complete_incident_schema(engine: Any) -> None:
    """Assert the full intended schema of migration d4e5f6a7b8c9."""
    from sqlalchemy import inspect

    inspector = inspect(engine)

    incidents_columns = {col["name"]: col for col in inspector.get_columns("incidents")}
    assert set(incidents_columns) == {
        "incident_id",
        "status",
        "severity",
        "primary_alert_id",
        "dedupe_group_key",
        "created_at",
        "updated_at",
        # Phase 3.2 lifecycle timestamps (nullable until the state is reached)
        "acknowledged_at",
        "resolved_at",
    }
    for name, column in incidents_columns.items():
        if name in ("acknowledged_at", "resolved_at"):
            assert column["nullable"], f"incidents.{name} must be nullable"
        else:
            assert not column["nullable"], f"incidents.{name} must be NOT NULL"

    pk = inspector.get_pk_constraint("incidents")
    assert pk["constrained_columns"] == ["incident_id"]

    incidents_fks = inspector.get_foreign_keys("incidents")
    assert any(
        fk["constrained_columns"] == ["primary_alert_id"]
        and fk["referred_table"] == "alerts"
        and fk["referred_columns"] == ["alert_id"]
        for fk in incidents_fks
    )

    expected_indexes = {
        "ix_incidents_created_at",
        "ix_incidents_dedupe_group_key",
        "ix_incidents_group_status",
        "ix_incidents_primary_alert_id",
        "ix_incidents_severity",
        "ix_incidents_status",
    }
    assert expected_indexes <= _index_names(engine, "incidents")
    indexes = {idx["name"]: idx for idx in inspector.get_indexes("incidents")}
    assert indexes["ix_incidents_primary_alert_id"]["unique"]
    assert indexes["ix_incidents_group_status"]["column_names"] == ["dedupe_group_key", "status"]

    assert "incident_id" in _column_names(engine, "alerts")
    alerts_columns = {col["name"]: col for col in inspector.get_columns("alerts")}
    assert alerts_columns["incident_id"]["nullable"] is True
    assert "ix_alerts_incident_id" in _index_names(engine, "alerts")

    alerts_fks = inspector.get_foreign_keys("alerts")
    assert any(
        fk.get("name") == "fk_alerts_incident_id"
        or (
            fk["constrained_columns"] == ["incident_id"]
            and fk["referred_table"] == "incidents"
            and fk["referred_columns"] == ["incident_id"]
        )
        for fk in alerts_fks
    )

    # The FK link is enforced in both directions (circular FK contract).
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1


def _app_settings(db_url: str) -> Settings:
    return Settings(
        soc_env="test",
        soc_log_level="WARNING",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=db_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token="test-callback-token-not-a-real-secret",
    )


def _ingest_high_alert(client: TestClient, *, event_id: str) -> dict[str, Any]:
    payload = json.loads((FIXTURES_DIR / "04_wazuh_malware_hash_virustotal.json").read_text())
    payload["id"] = event_id
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    # 202 for a fresh alert, 200 for an idempotent duplicate re-delivery.
    assert response.status_code in {200, 202}, response.text
    return response.json()


# ---------------------------------------------------------------------------
# 1. The exact reported failure: partially-applied migration + restart
# ---------------------------------------------------------------------------


def test_upgrade_recovers_from_partially_applied_incidents_table(db_url: str) -> None:
    """The Windows Docker crash state upgrades cleanly, with zero data loss.

    Simulates the exact failure: incidents (+ indexes) committed by the
    interrupted run, the orphaned Alembic batch scratch table present, real
    Phase 2B rows in the database, and alembic_version still at
    b2c3d4e5f6a7. Restarting the application (which reruns migrations to
    head) must recover instead of crashing with 'table incidents already
    exists'.
    """
    engine = _build_phase_2b_database(db_url, with_data=True)
    before = _data_snapshot(engine)
    _simulate_crashed_migration(engine)

    # The crash state: partial schema present, revision not applied.
    assert _alembic_version(engine) == PREVIOUS_REVISION
    assert "incidents" in _table_names(engine)
    assert "_alembic_tmp_alerts" in _table_names(engine)
    assert "incident_id" not in _column_names(engine, "alerts")

    # Application startup path: bring the database to head.
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    # Migration completed and the revision is recorded.
    assert _alembic_version(engine) == HEAD_REVISION
    # The orphaned batch scratch table was cleaned up.
    assert "_alembic_tmp_alerts" not in _table_names(engine)
    # Full intended schema is in place (verified, not blind-stamped).
    _assert_complete_incident_schema(engine)

    # No data loss: every pre-existing row is byte-for-byte identical.
    after = _data_snapshot(engine)
    assert after == before

    # Legacy alerts stay unattached.
    with engine.connect() as conn:
        links = conn.execute(text("SELECT alert_id, incident_id FROM alerts")).fetchall()
    assert [row[1] for row in links] == [None, None]
    assert {str(UUID(row[0])) for row in links} == set(ALERT_IDS)

    # Referential integrity holds after the batch recreate of alerts.
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_key_check")).fetchall() == []
    engine.dispose()


# ---------------------------------------------------------------------------
# 2. Normal fresh-database path
# ---------------------------------------------------------------------------


def test_fresh_database_migrates_cleanly_to_head(db_url: str) -> None:
    """A brand-new database migrates to head (e7f8a9b0c1d2) with the full schema."""
    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == HEAD_REVISION
    assert "_alembic_tmp_alerts" not in _table_names(engine)
    _assert_complete_incident_schema(engine)

    # Migrations are idempotent: a second startup run is a no-op.
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    assert _alembic_version(engine) == HEAD_REVISION
    _assert_complete_incident_schema(engine)

    # Downgrade still works from a fresh head (batch recreate with no data).
    from alembic import command as alembic_command
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.downgrade(config, PREVIOUS_REVISION)
    assert _alembic_version(engine) == PREVIOUS_REVISION
    assert "incidents" not in _table_names(engine)
    assert "incident_id" not in _column_names(engine, "alerts")
    engine.dispose()


# ---------------------------------------------------------------------------
# 3. Real Phase 2B database (the original trigger of the crash)
# ---------------------------------------------------------------------------


def test_upgrade_phase_2b_database_with_real_data(db_url: str) -> None:
    """A pre-incident database with alert/feedback/audit rows upgrades cleanly.

    This is the state that produced the original crash: the batch ALTER of
    alerts must not fail on 'FOREIGN KEY constraint failed' while child rows
    (alert_events, notification_attempts, analyst_feedback) reference it.
    """
    engine = _build_phase_2b_database(db_url, with_data=True)
    before = _data_snapshot(engine)

    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == HEAD_REVISION
    _assert_complete_incident_schema(engine)
    assert _data_snapshot(engine) == before
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_key_check")).fetchall() == []
    engine.dispose()


# ---------------------------------------------------------------------------
# 4. Partially-created pieces are completed (not replayed blindly)
# ---------------------------------------------------------------------------


def test_recovery_completes_partially_created_pieces(db_url: str) -> None:
    """A kill in the middle of the migration is finished piece by piece.

    Simulates an interruption after the incidents table was created but
    before all indexes existed, and after alerts.incident_id existed but
    before its FK/index were in place.
    """
    engine = _build_phase_2b_database(db_url, with_data=True)
    before = _data_snapshot(engine)

    with engine.begin() as conn:
        conn.execute(text(CRASHED_INCIDENTS_DDL))
        # Only the first two indexes made it before the interruption.
        conn.execute(text(CRASHED_INCIDENT_INDEX_DDL[0]))
        conn.execute(text(CRASHED_INCIDENT_INDEX_DDL[1]))
        # The link column exists (e.g. manually added), but no FK, no index.
        conn.execute(text("ALTER TABLE alerts ADD COLUMN incident_id VARCHAR(32)"))
    assert _alembic_version(engine) == PREVIOUS_REVISION

    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == HEAD_REVISION
    _assert_complete_incident_schema(engine)
    assert _data_snapshot(engine) == before
    engine.dispose()


# ---------------------------------------------------------------------------
# 5. Incompatible partial schema fails clearly (never silent corruption)
# ---------------------------------------------------------------------------


def test_incompatible_partial_incidents_table_fails_clearly(db_url: str) -> None:
    """An incidents table that does not match the intended schema aborts.

    The migration must not stamp the revision over an incompatible table;
    it must fail with a precise diff and leave the database untouched.
    """
    engine = _build_phase_2b_database(db_url, with_data=True)
    before = _data_snapshot(engine)

    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE incidents ("
                "incident_id VARCHAR(32) NOT NULL, "
                "status VARCHAR(16) NOT NULL, "
                "severity INTEGER NOT NULL, "  # wrong type
                "extra_column VARCHAR(8), "  # unexpected column
                "primary_alert_id CHAR(32) NOT NULL, "
                "dedupe_group_key VARCHAR(255) NOT NULL, "
                "created_at DATETIME NOT NULL, "
                "updated_at DATETIME NOT NULL, "
                "PRIMARY KEY (incident_id), "
                "FOREIGN KEY(primary_alert_id) REFERENCES alerts (alert_id))"
            )
        )

    with pytest.raises(RuntimeError, match=r"incidents\.severity type is INTEGER"):
        run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    # Nothing was stamped and nothing was modified.
    assert _alembic_version(engine) == PREVIOUS_REVISION
    assert "incident_id" not in _column_names(engine, "alerts")
    assert _data_snapshot(engine) == before
    # The incompatible table itself was left exactly as found.
    with engine.connect() as conn:
        severity_type = [
            row[2]
            for row in conn.execute(text("PRAGMA table_info(incidents)"))
            if row[1] == "severity"
        ]
    assert severity_type == ["INTEGER"]
    engine.dispose()


def test_incompatible_alert_link_state_fails_clearly(db_url: str) -> None:
    """A wrongly-defined existing alerts link (e.g. unique index) aborts
    clearly instead of failing inside the batch or stamping over it."""
    engine = _build_phase_2b_database(db_url, with_data=True)
    before = _data_snapshot(engine)

    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE alerts ADD COLUMN incident_id VARCHAR(32)"))
        # A UNIQUE index where the migration needs a non-unique one.
        conn.execute(text("CREATE UNIQUE INDEX ix_alerts_incident_id ON alerts (incident_id)"))

    with pytest.raises(RuntimeError, match=r"ix_alerts_incident_id.*expected"):
        run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == PREVIOUS_REVISION
    assert _data_snapshot(engine) == before
    engine.dispose()


# ---------------------------------------------------------------------------
# 6. Catastrophic partial state is refused, never deleted
# ---------------------------------------------------------------------------


def test_scratch_table_without_alerts_table_is_refused(db_url: str) -> None:
    """If the alert data ended up inside the batch scratch table, refuse.

    When the interrupted batch dropped 'alerts' before dying, the scratch
    table holds the only copy of the data: the recovery must fail loudly
    with rename guidance instead of dropping it to satisfy the schema.
    """
    engine = _build_phase_2b_database(db_url, with_data=True)
    row_count = len(_data_snapshot(engine)["alerts"])
    with engine.begin() as conn:
        # Simulate the kill-after-DROP state: data lives in the scratch table.
        conn.execute(text("ALTER TABLE alerts RENAME TO _alembic_tmp_alerts"))

    with pytest.raises(RuntimeError, match=r"rename.*_alembic_tmp_alerts.*back"):
        run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    # The scratch table (and the data inside it) is still there.
    tables = _table_names(engine)
    assert "_alembic_tmp_alerts" in tables
    assert "alerts" not in tables
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM _alembic_tmp_alerts")).scalar() == (
            row_count
        )
    assert _alembic_version(engine) == PREVIOUS_REVISION
    engine.dispose()


# ---------------------------------------------------------------------------
# 7. Application restart after migration (the Docker restart scenario)
# ---------------------------------------------------------------------------


def test_restart_after_recovered_migration_serves_and_persists_incident(db_url: str) -> None:
    """After recovery, triage-api starts, creates incidents, and survives a
    restart with the same incident persisted (no crash loop)."""
    engine = _build_phase_2b_database(db_url, with_data=True)
    _simulate_crashed_migration(engine)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)  # first startup: recovers
    assert _alembic_version(engine) == HEAD_REVISION
    engine.dispose()

    # triage-api boots against the recovered database and serves traffic.
    settings = _app_settings(db_url)
    with TestClient(create_app(settings=settings)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200
        body = _ingest_high_alert(client, event_id="1770000000.400001")
        assert body["decision"]["action"] == "open_incident"
        incident_id = body["incident_id"]
        assert incident_id is not None
        assert INCIDENT_ID_RE.match(incident_id)

    # "Restart triage-api": a brand-new process on the same database file.
    with TestClient(create_app(settings=settings)) as restarted:
        assert restarted.get("/health").status_code == 200
        assert restarted.get("/ready").status_code == 200
        with restarted.app.state.db_engine.connect() as conn:
            rows = conn.execute(
                text("SELECT incident_id, status, severity FROM incidents")
            ).fetchall()
        assert [row[0] for row in rows] == [incident_id]
        assert rows[0][1:] == ("open", "SEV2")
        # The alert that opened the incident is linked to it.
        linked = (
            restarted.app.state.db_engine.connect()
            .execute(text("SELECT alert_id, incident_id FROM alerts WHERE incident_id IS NOT NULL"))
            .fetchall()
        )
        assert [row[1] for row in linked] == [incident_id]
        # A duplicate delivery is idempotent and echoes the same incident.
        duplicate = _ingest_high_alert(restarted, event_id="1770000000.400001")
        assert duplicate["incident_id"] == incident_id
        with restarted.app.state.db_engine.connect() as conn:
            assert conn.execute(text("SELECT COUNT(*) FROM incidents")).scalar_one() == 1
