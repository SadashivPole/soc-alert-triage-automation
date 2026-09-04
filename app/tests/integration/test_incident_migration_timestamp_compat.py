"""Regression tests: PostgreSQL timestamp reflection in migration d4e5f6a7b8c9.

Phase 3.8 D3 — migration parity testing on PostgreSQL 16 + psycopg 3 found the
self-verifying gate of ``d4e5f6a7b8c9`` rejecting a schema the migration itself
had just created::

    incidents.created_at type is TIMESTAMP,
    expected one of ['DATETIME', 'TIMESTAMP WITH TIME ZONE']

Cause (reproduced here against a live PostgreSQL server): reflection never runs
a dialect compiler, so a ``TIMESTAMP WITH TIME ZONE`` column is reflected as
``postgresql.TIMESTAMP(timezone=True)`` whose ``__visit_name__`` is
``TIMESTAMP`` — ``str()`` therefore renders plain ``TIMESTAMP`` and the
``WITH TIME ZONE`` suffix (which only exists in emitted DDL) never appears.
PostgreSQL reflects a naive ``TIMESTAMP`` as the *same* string, so the fix
accepts the rendering while a separate check keeps the timezone-awareness
requirement in force.

These tests pin the contract:

* SQLite still passes (its DATETIME rendering is accepted and the
  timezone-awareness check is skipped, because SQLite has no
  timezone-qualified timestamp type to report);
* PostgreSQL's reflected ``TIMESTAMP`` is accepted when the reflected type
  object says it is timezone-aware;
* an actually incompatible timestamp representation is still rejected — a
  naive ``TIMESTAMP`` on PostgreSQL, a non-timestamp type, and a type that
  reports no timezone information at all (fails closed);
* the full migration chain reaches ``e7f8a9b0c1d2``.

Live PostgreSQL coverage
------------------------
Set ``TRIAGE_TEST_POSTGRES_URL`` to run the same contract against a real
server (e.g. ``postgresql+psycopg://user:pw@host:5432/triage``). Those tests
are skipped — never xfailed, never substituted with SQLite — when the
variable is unset, so a missing server can never mask a failure.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import event, text
from sqlalchemy.dialects import postgresql

from soc_triage.db.engine import ALEMBIC_SCRIPT_LOCATION, create_app_engine, run_migrations

MIGRATION_FILE = ALEMBIC_SCRIPT_LOCATION / "versions" / "d4e5f6a7b8c9_incident_persistence.py"

#: Revision whose compatibility gate is under test.
INCIDENT_REVISION = "d4e5f6a7b8c9"
#: Revision immediately before it: the pre-incident production shape.
PREVIOUS_REVISION = "b2c3d4e5f6a7"
#: Migration chain head (Phase 3.2 lifecycle timestamps).
HEAD_REVISION = "e7f8a9b0c1d2"

POSTGRES_URL = os.environ.get("TRIAGE_TEST_POSTGRES_URL", "").strip()
requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="TRIAGE_TEST_POSTGRES_URL not set — live PostgreSQL parity tests skipped",
)

#: An ``incidents`` table whose timestamps are *not* timezone-aware: the exact
#: shape that must keep being rejected after the compatibility widening.
NAIVE_TIMESTAMP_INCIDENTS_DDL = """
CREATE TABLE incidents (
    incident_id VARCHAR(32) NOT NULL,
    status VARCHAR(16) NOT NULL,
    severity VARCHAR(8) NOT NULL,
    primary_alert_id UUID NOT NULL,
    dedupe_group_key VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (incident_id),
    FOREIGN KEY(primary_alert_id) REFERENCES alerts (alert_id)
)
"""


class _OpaqueTimestampType(sa.types.TypeEngine):
    """A timestamp-looking type that reports no timezone information at all.

    Renders as ``TIMESTAMP`` (so the widened accepted set matches it) but has
    no ``timezone`` attribute — the "unknown" case the check must fail closed
    on rather than accept.
    """

    __visit_name__ = "TIMESTAMP"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_migration_module() -> Any:
    """Load revision d4e5f6a7b8c9 the way Alembic does (it is not a package)."""
    assert MIGRATION_FILE.is_file(), f"migration file not found: {MIGRATION_FILE}"
    spec = importlib.util.spec_from_file_location("migration_d4e5f6a7b8c9", MIGRATION_FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = _load_migration_module()


class _ReflectedIncidentsStub:
    """Reflection stand-in reporting a real PostgreSQL dialect dialect name.

    Implements only the calls ``_incidents_compatibility_problems`` makes. The
    column types are genuine SQLAlchemy type objects — ``created_at`` /
    ``updated_at`` are whatever ``timestamp_type`` is passed, so the stub can
    hand back the exact ``postgresql.TIMESTAMP`` instances live PostgreSQL
    reflection produces.
    """

    def __init__(self, timestamp_type: Any) -> None:
        self._timestamp_type = timestamp_type
        self.bind = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def get_columns(self, table: str) -> list[dict[str, Any]]:
        assert table == "incidents"
        columns: list[tuple[str, Any]] = [
            ("incident_id", sa.String(32)),
            ("status", sa.String(16)),
            ("severity", sa.String(8)),
            ("primary_alert_id", postgresql.UUID()),
            ("dedupe_group_key", sa.String(255)),
            ("created_at", self._timestamp_type),
            ("updated_at", self._timestamp_type),
        ]
        return [{"name": name, "type": type_, "nullable": False} for name, type_ in columns]

    def get_pk_constraint(self, table: str) -> dict[str, Any]:
        assert table == "incidents"
        return {"constrained_columns": ["incident_id"]}

    def get_foreign_keys(self, table: str) -> list[dict[str, Any]]:
        assert table == "incidents"
        return [
            {
                "constrained_columns": ["primary_alert_id"],
                "referred_table": "alerts",
                "referred_columns": ["alert_id"],
                "name": "incidents_primary_alert_id_fkey",
            }
        ]

    def get_indexes(self, table: str) -> list[dict[str, Any]]:
        assert table == "incidents"
        return []


def _compatibility_problems(timestamp_type: Any) -> list[str]:
    return migration._incidents_compatibility_problems(_ReflectedIncidentsStub(timestamp_type))


def _drop_everything(engine: Any) -> None:
    """Drop every table in the public schema (a parity database is reusable)."""
    with engine.begin() as conn:
        tables = [
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            ).fetchall()
        ]
        for table in tables:
            conn.execute(text(f'DROP TABLE IF EXISTS "{table}" CASCADE'))


def _alembic_version(engine: Any) -> str | None:
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _upgrade_to(engine: Any, revision: str) -> None:
    """Migrate ``engine`` to a specific revision (not necessarily head)."""
    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.upgrade(config, revision)


def _downgrade_to(engine: Any, revision: str) -> None:
    """Migrate ``engine`` back to a specific revision."""
    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.downgrade(config, revision)


def _incident_revision_inspector(engine: Any) -> Any:
    """A cache-cleared inspector for the schema d4e5f6a7b8c9 is responsible for."""
    inspector = sa.inspect(engine)
    inspector.clear_cache()
    return inspector


@pytest.fixture(scope="module")
def postgres_engine() -> Any:
    """The application engine on the live PostgreSQL parity database.

    Module-scoped and pooled exactly as the application configures it: the
    parity target is the app's own engine setup, and a single reused
    connection is also what single-backend PostgreSQL-compatible test servers
    cope with.
    """
    engine = create_app_engine(POSTGRES_URL)

    @event.listens_for(engine, "connect")
    def _disable_prepared_statements(dbapi_connection: Any, _record: Any) -> None:
        """Keep psycopg 3 from caching server-side prepared statements.

        psycopg 3 names its cached statements per connection (``_pg3_0``, …).
        A multiplexed PostgreSQL test server serves every client connection
        from a single backend where those names are shared, so a second
        connection dies with ``DuplicatePreparedStatement``. Real PostgreSQL
        gives each connection its own statement namespace; disabling the cache
        only costs the parity run a little server-side parsing.
        """
        dbapi_connection.prepare_threshold = None

    yield engine
    engine.dispose()


@pytest.fixture
def clean_postgres(postgres_engine: Any) -> Any:
    """An empty parity database, emptied again after the test."""
    _drop_everything(postgres_engine)
    yield postgres_engine
    _drop_everything(postgres_engine)


# ---------------------------------------------------------------------------
# 1. The premise: how PostgreSQL reflection actually renders these columns
# ---------------------------------------------------------------------------


def test_postgresql_timestamp_rendering_is_what_the_gate_compares() -> None:
    """``postgresql.TIMESTAMP`` renders as plain ``TIMESTAMP``, with or
    without the timezone qualifier — the root cause of the D2 failure.

    Pinned here so a future SQLAlchemy release that changes the rendering
    fails this test instead of silently re-breaking (or over-widening) the
    migration's accepted set.
    """
    tz_aware = postgresql.TIMESTAMP(timezone=True)
    naive = postgresql.TIMESTAMP(timezone=False)

    assert str(tz_aware).strip().upper() == "TIMESTAMP"
    assert str(naive).strip().upper() == "TIMESTAMP"
    # The string alone cannot tell them apart; only the type object can.
    assert tz_aware.timezone is True
    assert naive.timezone is False

    accepted = migration._INCIDENT_COLUMNS["created_at"][0]
    assert "TIMESTAMP" in accepted
    assert "DATETIME" in accepted
    assert "TIMESTAMP WITH TIME ZONE" in accepted
    assert migration._INCIDENT_COLUMNS["updated_at"][0] == accepted


# ---------------------------------------------------------------------------
# 2. Compatibility gate against PostgreSQL reflection (dialect-level)
# ---------------------------------------------------------------------------


def test_postgresql_reflected_timezone_aware_timestamp_is_accepted() -> None:
    """The reflected shape of ``TIMESTAMP WITH TIME ZONE`` passes the gate."""
    assert _compatibility_problems(postgresql.TIMESTAMP(timezone=True)) == []


def test_postgresql_reflected_naive_timestamp_is_rejected() -> None:
    """Accepting the ``TIMESTAMP`` rendering must not accept a naive column.

    This is the assertion that keeps the widening from being a weakening: a
    column created as ``TIMESTAMP`` **without** time zone renders identically
    and must still abort the migration.
    """
    problems = _compatibility_problems(postgresql.TIMESTAMP(timezone=False))
    assert len(problems) == 2
    assert problems == [
        "incidents.created_at is not a timezone-aware timestamp (reflected "
        "without a time-zone qualifier), expected TIMESTAMP WITH TIME ZONE",
        "incidents.updated_at is not a timezone-aware timestamp (reflected "
        "without a time-zone qualifier), expected TIMESTAMP WITH TIME ZONE",
    ]


def test_non_timestamp_representation_is_still_rejected() -> None:
    """An unrelated type for a timestamp column is still an incompatible schema."""
    problems = _compatibility_problems(sa.String(32))
    assert len(problems) == 2
    for problem, column in zip(problems, ("created_at", "updated_at"), strict=True):
        assert problem.startswith(f"incidents.{column} type is VARCHAR(32), expected one of [")


def test_timestamp_type_without_timezone_information_fails_closed() -> None:
    """A timestamp that reports no timezone attribute is rejected, not trusted."""
    problems = _compatibility_problems(_OpaqueTimestampType())
    assert len(problems) == 2
    assert all("not a timezone-aware timestamp" in problem for problem in problems)


# ---------------------------------------------------------------------------
# 3. SQLite still passes end to end
# ---------------------------------------------------------------------------


def test_sqlite_migration_chain_reaches_head_and_passes_its_own_gate(tmp_path: Path) -> None:
    """The widened accepted set does not disturb the SQLite path.

    SQLite reflects ``DateTime(timezone=True)`` as the generic DATETIME with
    ``timezone=False`` — it has no timezone-qualified timestamp type — so the
    rendering must stay accepted *and* the timezone-awareness check must be
    skipped there rather than rejecting a schema SQLite cannot express.
    """
    db_url = f"sqlite:///{tmp_path / 'soc_triage_pg_compat.db'}"
    engine = create_app_engine(db_url)

    # Stop at the revision under test so its gate judges exactly its own schema
    # (e7f8a9b0c1d2 later adds two lifecycle columns of its own).
    _upgrade_to(engine, INCIDENT_REVISION)
    assert _alembic_version(engine) == INCIDENT_REVISION

    inspector = _incident_revision_inspector(engine)
    reflected = {col["name"]: col for col in inspector.get_columns("incidents")}
    for name in ("created_at", "updated_at"):
        assert str(reflected[name]["type"]).strip().upper() == "DATETIME"
        # SQLite genuinely cannot report the qualifier — hence the skip.
        assert reflected[name]["type"].timezone is False

    # The migration's own verification gate finds nothing to complain about.
    assert migration._incidents_compatibility_problems(inspector) == []

    # ...and the chain still goes on to head.
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    assert _alembic_version(engine) == HEAD_REVISION
    engine.dispose()


# ---------------------------------------------------------------------------
# 4. Live PostgreSQL parity (TRIAGE_TEST_POSTGRES_URL)
# ---------------------------------------------------------------------------


@requires_postgres
def test_postgresql_migration_chain_reaches_head(clean_postgres: Any) -> None:
    """The full chain applies on PostgreSQL and is idempotent on re-run.

    This is the exact path that failed in Phase 3.8 D2 at d4e5f6a7b8c9.
    """
    run_migrations(clean_postgres, ALEMBIC_SCRIPT_LOCATION)
    assert _alembic_version(clean_postgres) == HEAD_REVISION

    # Self-verifying design: a second run is a no-op, not a re-application.
    run_migrations(clean_postgres, ALEMBIC_SCRIPT_LOCATION)
    assert _alembic_version(clean_postgres) == HEAD_REVISION


@requires_postgres
def test_postgresql_timestamp_columns_are_timezone_aware_and_accepted(
    clean_postgres: Any,
) -> None:
    """The migrated columns really are timezone-aware, and the gate agrees.

    Three independent observations of the same column: the dialect type
    PostgreSQL reflection returns, the ``data_type`` PostgreSQL itself reports,
    and the verdict of the migration's own compatibility check. Stopped at
    d4e5f6a7b8c9 so the gate judges exactly the schema it created.
    """
    _upgrade_to(clean_postgres, INCIDENT_REVISION)
    assert _alembic_version(clean_postgres) == INCIDENT_REVISION

    inspector = _incident_revision_inspector(clean_postgres)
    reflected = {col["name"]: col for col in inspector.get_columns("incidents")}
    for name in ("created_at", "updated_at"):
        column_type = reflected[name]["type"]
        assert str(column_type).strip().upper() == "TIMESTAMP"
        assert column_type.timezone is True, f"incidents.{name} lost its time-zone qualifier"

    with clean_postgres.connect() as conn:
        data_types = dict(
            conn.execute(
                text(
                    "SELECT column_name, data_type FROM information_schema.columns "
                    "WHERE table_name = 'incidents' AND column_name IN "
                    "('created_at', 'updated_at')"
                )
            ).fetchall()
        )
    assert data_types == {
        "created_at": "timestamp with time zone",
        "updated_at": "timestamp with time zone",
    }

    # The gate that failed in D2 now passes on the schema it just verified.
    assert migration._incidents_compatibility_problems(inspector) == []


@requires_postgres
def test_postgresql_naive_timestamp_incidents_table_is_refused(clean_postgres: Any) -> None:
    """A pre-existing ``incidents`` table with naive timestamps still aborts.

    End-to-end proof on a real server that the fix did not weaken the
    semantic requirement: the migration must refuse to stamp its revision
    over timestamps that were not created timezone-aware.
    """
    run_migrations(clean_postgres, ALEMBIC_SCRIPT_LOCATION)
    _downgrade_to(clean_postgres, PREVIOUS_REVISION)
    assert _alembic_version(clean_postgres) == PREVIOUS_REVISION

    with clean_postgres.begin() as conn:
        conn.execute(text(NAIVE_TIMESTAMP_INCIDENTS_DDL))

    with pytest.raises(RuntimeError, match=r"incidents\.created_at is not a timezone-aware"):
        run_migrations(clean_postgres, ALEMBIC_SCRIPT_LOCATION)

    # Nothing stamped over the incompatible table.
    assert _alembic_version(clean_postgres) == PREVIOUS_REVISION
    with clean_postgres.connect() as conn:
        data_type = conn.execute(
            text(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_name = 'incidents' AND column_name = 'created_at'"
            )
        ).scalar()
    assert data_type == "timestamp without time zone"


@requires_postgres
def test_postgresql_incident_revision_gate_is_the_only_failure_point(
    clean_postgres: Any,
) -> None:
    """The chain reaches d4e5f6a7b8c9 and beyond — no other revision blocks."""
    run_migrations(clean_postgres, ALEMBIC_SCRIPT_LOCATION)
    assert _alembic_version(clean_postgres) == HEAD_REVISION

    # Step back one revision and forward again: d4e5f6a7b8c9 -> e7f8a9b0c1d2
    # must re-apply cleanly on PostgreSQL, proving the timestamp acceptance is
    # not the only thing standing between the two revisions.
    _downgrade_to(clean_postgres, INCIDENT_REVISION)
    assert _alembic_version(clean_postgres) == INCIDENT_REVISION
    run_migrations(clean_postgres, ALEMBIC_SCRIPT_LOCATION)
    assert _alembic_version(clean_postgres) == HEAD_REVISION
