"""incident persistence (Phase 3.1) — recovery-safe against partial application

Revision ID: d4e5f6a7b8c9
Revises: b2c3d4e5f6a7
Create Date: 2026-09-02

Phase 3.1 — first-class incident persistence and automatic incident creation:

* ``incidents`` — one row per open incident: human-readable
  ``INC-YYYY-MM-DD-NNNN`` id (PK, sequential per UTC date), severity
  (SEV1/SEV2), status (``open``), FK to the primary alert that opened it, the
  dedupe group it belongs to, and UTC timestamps. Indexes support the
  "existing open incident for a group" lookup used for recurrence linking.
* ``alerts.incident_id`` — nullable FK from alerts to incidents so each alert
  references the incident it belongs to (recurring/deduplicated alerts attach
  to the existing open incident instead of creating duplicates).

Timestamps are timezone-aware (UTC). Batch mode keeps the same DDL runnable on
SQLite and PostgreSQL later (ARCHITECTURE.md §19). Existing databases upgrade
cleanly: pre-existing alerts simply keep ``incident_id = NULL``.

Recovery-safe application (Windows Docker E2E, PR #16)
------------------------------------------------------
SQLite DDL is applied non-transactionally: the SQLAlchemy pysqlite driver
autocommits DDL statements (the SQLite dialect reports
``supports_transactional_ddl = False``), so a migration that is interrupted
after its first ``CREATE TABLE`` leaves that table durably committed while
``alembic_version`` still names the previous revision. A naive rerun then dies
with ``table incidents already exists`` — a permanent startup crash loop.

An earlier revision of this migration had exactly that failure mode. When it
ran against a database whose ``alerts`` table had child rows
(``alert_events`` / ``notification_attempts`` / ``analyst_feedback``), the
batch ALTER of ``alerts`` failed at ``DROP TABLE alerts`` with
``FOREIGN KEY constraint failed`` (the application engine enables
``PRAGMA foreign_keys=ON`` on every connection, and SQLite's implicit
``DELETE FROM`` inside DROP TABLE violates the child references), leaving
behind a committed ``incidents`` table, a committed — empty — alembic batch
scratch table ``_alembic_tmp_alerts``, and no recorded revision.

This revision is therefore *idempotent and self-verifying*; it never assumes a
clean slate and never deletes or resets data:

1. An orphaned ``_alembic_tmp_alerts`` scratch table from an interrupted batch
   run is dropped — but only while the authoritative ``alerts`` table still
   exists (otherwise the data itself is inside the scratch table and the
   migration fails loudly instead of destroying it).
2. If ``incidents`` already exists, its schema (columns, types, nullability,
   primary key, FK to ``alerts``) is verified against the intended definition
   before it is treated as applied; an incompatible table aborts the migration
   with a precise diff instead of silently stamping over unknown schema.
   Missing pieces (indexes that were never created) are completed.
3. The ``alerts`` link is only built from what is missing (column, FK,
   index) — each piece is checked first so a partially applied batch is
   finished rather than replayed.
4. The batch ALTER of ``alerts`` runs with SQLite foreign-key enforcement
   temporarily disabled (inside Alembic's ``autocommit_block``, so the PRAGMA
   cannot be a silent no-op inside a transaction, and with a read-back
   check), because recreating ``alerts`` with live child rows is exactly what
   the enabled pragma makes fail. The previous setting is always restored —
   the pooled application connection must keep FK enforcement on.
5. After the batch, ``PRAGMA foreign_key_check`` proves no referential damage
   was done, and a final full-schema verification gate must pass before the
   migration returns: only then does Alembic record the revision as applied.

PostgreSQL reflection compatibility (Phase 3.8 D3)
--------------------------------------------------
The same verification gate ran on PostgreSQL and rejected a schema the
migration itself had just created::

    incidents.created_at type is TIMESTAMP,
    expected one of ['DATETIME', 'TIMESTAMP WITH TIME ZONE']

Reflection never runs a dialect compiler, so a PostgreSQL
``TIMESTAMP WITH TIME ZONE`` column comes back as
``postgresql.TIMESTAMP(timezone=True)`` whose ``str()`` rendering is plain
``TIMESTAMP`` — the ``WITH TIME ZONE`` suffix exists only in emitted DDL. That
rendering is now accepted (``_TIMESTAMP_TYPES``) without giving up the
requirement that these columns are timezone-aware: PostgreSQL reflects
``TIMESTAMP`` *without* time zone as the identical string, so
``_timezone_aware_timestamp_problems`` checks the reflected type object's
``timezone`` attribute and still rejects a naive timestamp. Dialects that
cannot express a timezone-qualified timestamp (SQLite) are skipped rather than
failed, because their DDL carries no qualifier for reflection to report.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import Any

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d4e5f6a7b8c9"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

_INCIDENTS = "incidents"
_ALERTS = "alerts"
#: Alembic's batch-mode scratch table name on SQLite (``_alembic_tmp_`` prefix).
_BATCH_TMP_ALERTS = "_alembic_tmp_alerts"

#: Renderings of a timezone-aware ``DateTime(timezone=True)`` column across the
#: supported dialects (all three are the same logical schema):
#:
#: * ``DATETIME`` — SQLite reflects ``DateTime(timezone=True)`` as the generic
#:   ``DATETIME`` type;
#: * ``TIMESTAMP`` — PostgreSQL reflects the ``TIMESTAMP WITH TIME ZONE`` DDL
#:   as ``postgresql.TIMESTAMP(timezone=True)``, whose ``__visit_name__`` is
#:   ``TIMESTAMP``. The ``str()`` rendering compared here therefore has **no**
#:   ``WITH TIME ZONE`` suffix: that suffix only appears when a *dialect
#:   compiler* renders DDL, which reflection never does. Without this
#:   rendering the migration failed its own final verification gate on
#:   PostgreSQL (Phase 3.8 D3).
#: * ``TIMESTAMP WITH TIME ZONE`` — the dialect-compiler spelling, kept for
#:   dialects/drivers that reflect it verbatim.
#:
#: Accepting the plain ``TIMESTAMP`` rendering does not weaken the "created as
#: timezone-aware" requirement: PostgreSQL reflects ``TIMESTAMP`` *without*
#: time zone as the very same ``TIMESTAMP`` string, so
#: ``_timezone_aware_timestamp_problems`` below checks the reflected type
#: object's ``timezone`` attribute to keep naive timestamps rejected.
_TIMESTAMP_TYPES = frozenset({"DATETIME", "TIMESTAMP", "TIMESTAMP WITH TIME ZONE"})

#: Columns that must have been created as timezone-aware timestamps.
_TIMEZONE_AWARE_COLUMNS = frozenset({"created_at", "updated_at"})

#: Dialects whose *reflection* preserves the timezone qualifier, i.e. where the
#: requirement above is checkable. SQLite has no timezone-qualified timestamp
#: type at all (its DDL renders ``DateTime(timezone=True)`` as plain DATETIME
#: and reflection hands back ``timezone=False``), so there is nothing to check
#: there — the check is skipped rather than weakened.
_TIMEZONE_AWARE_REFLECTION_DIALECTS = frozenset({"postgresql"})

#: Expected ``incidents`` columns: name -> (accepted type renderings, nullable).
#: SQLite renders ``Uuid`` as CHAR(32) and ``DateTime(timezone=True)`` as
#: DATETIME; PostgreSQL renders UUID / TIMESTAMP (see ``_TIMESTAMP_TYPES``).
#: Every spelling of the same logical schema is accepted.
_INCIDENT_COLUMNS: dict[str, tuple[frozenset[str], bool]] = {
    "incident_id": (frozenset({"VARCHAR(32)"}), False),
    "status": (frozenset({"VARCHAR(16)"}), False),
    "severity": (frozenset({"VARCHAR(8)"}), False),
    "primary_alert_id": (frozenset({"CHAR(32)", "UUID"}), False),
    "dedupe_group_key": (frozenset({"VARCHAR(255)"}), False),
    "created_at": (_TIMESTAMP_TYPES, False),
    "updated_at": (_TIMESTAMP_TYPES, False),
}

#: Expected ``incidents`` indexes: name -> (columns, unique).
_INCIDENT_INDEXES: dict[str, tuple[tuple[str, ...], bool]] = {
    "ix_incidents_created_at": (("created_at",), False),
    "ix_incidents_dedupe_group_key": (("dedupe_group_key",), False),
    "ix_incidents_group_status": (("dedupe_group_key", "status"), False),
    "ix_incidents_primary_alert_id": (("primary_alert_id",), True),
    "ix_incidents_severity": (("severity",), False),
    "ix_incidents_status": (("status",), False),
}

_ALERT_LINK_COLUMN = "incident_id"
_ALERT_LINK_TYPES = frozenset({"VARCHAR(32)"})
_ALERT_LINK_INDEX = "ix_alerts_incident_id"
_ALERT_LINK_FK_NAME = "fk_alerts_incident_id"


# ---------------------------------------------------------------------------
# Introspection helpers
# ---------------------------------------------------------------------------


def _fresh_inspector(bind: Any) -> Any:
    """Return an inspector whose reflection cache does not predate our DDL."""
    inspector = sa.inspect(bind)
    inspector.clear_cache()
    return inspector


def _table_exists(inspector: Any, name: str) -> bool:
    return name.lower() in {t.lower() for t in inspector.get_table_names()}


def _column_defs(inspector: Any, table: str) -> dict[str, tuple[str, bool]]:
    """Column name -> (upper-cased type rendering, nullable)."""
    return {
        col["name"].lower(): (str(col["type"]).strip().upper(), bool(col["nullable"]))
        for col in inspector.get_columns(table)
    }


def _index_defs(inspector: Any, table: str) -> dict[str, tuple[tuple[str, ...], bool]]:
    """Index name -> (lower-cased column tuple, unique)."""
    return {
        (idx["name"] or "").lower(): (
            tuple((c or "").lower() for c in idx["column_names"] or ()),
            bool(idx["unique"]),
        )
        for idx in inspector.get_indexes(table)
        if idx["name"]
    }


def _fk_defs(inspector: Any, table: str) -> list[tuple[list[str], str, list[str], str]]:
    """All FKs as (constrained columns, referred table, referred columns, name)."""
    defs: list[tuple[list[str], str, list[str], str]] = []
    for fk in inspector.get_foreign_keys(table):
        defs.append(
            (
                [c.lower() for c in fk.get("constrained_columns") or []],
                (fk.get("referred_table") or "").lower(),
                [c.lower() for c in fk.get("referred_columns") or []],
                (fk.get("name") or "").lower(),
            )
        )
    return defs


def _reflected_timezone_flags(inspector: Any, table: str) -> dict[str, bool]:
    """Column name -> whether the reflected type carries a time-zone qualifier.

    ``False`` both for a genuinely naive timestamp and for a type that reports
    no ``timezone`` attribute at all: the check fails closed.
    """
    return {
        col["name"].lower(): bool(getattr(col["type"], "timezone", False))
        for col in inspector.get_columns(table)
    }


# ---------------------------------------------------------------------------
# Compatibility checks — an existing object is only *accepted* when it matches
# the intended schema; anything else fails the migration with a precise diff.
# Missing pieces are not errors here: they are completed later.
# ---------------------------------------------------------------------------


def _timezone_aware_timestamp_problems(inspector: Any, accepted_names: set[str]) -> list[str]:
    """Accepted-as-timestamp columns that are not timezone-aware, where visible.

    This is what keeps ``_TIMESTAMP_TYPES`` accepting PostgreSQL's plain
    ``TIMESTAMP`` rendering from also accepting a column created as
    ``TIMESTAMP`` **without** time zone: PostgreSQL reflects both as
    ``postgresql.TIMESTAMP`` and ``str()`` renders both as ``TIMESTAMP``, so
    only the type object's ``timezone`` attribute tells them apart. Dialects
    that cannot express a timezone-qualified timestamp at all are skipped (see
    ``_TIMEZONE_AWARE_REFLECTION_DIALECTS``) — for those the DDL itself carries
    no qualifier that reflection could ever report.

    Only columns whose *rendering* was already accepted are examined, so a
    column of an unrelated type is reported once (as a type mismatch) instead
    of twice.
    """
    if inspector.bind.dialect.name not in _TIMEZONE_AWARE_REFLECTION_DIALECTS:
        return []
    flags = _reflected_timezone_flags(inspector, _INCIDENTS)
    return [
        f"incidents.{name} is not a timezone-aware timestamp (reflected without "
        "a time-zone qualifier), expected TIMESTAMP WITH TIME ZONE"
        for name in sorted(_TIMEZONE_AWARE_COLUMNS & accepted_names)
        if not flags.get(name)
    ]


def _incidents_compatibility_problems(inspector: Any) -> list[str]:
    """Problems with an existing ``incidents`` table (missing indexes excluded)."""
    problems: list[str] = []

    actual_columns = _column_defs(inspector, _INCIDENTS)
    expected_names = set(_INCIDENT_COLUMNS)
    actual_names = set(actual_columns)
    for name in sorted(expected_names - actual_names):
        problems.append(f"incidents.{name} column is missing")
    for name in sorted(actual_names - expected_names):
        problems.append(f"incidents.{name} column is unexpected")
    accepted_timestamps: set[str] = set()
    for name in sorted(expected_names & actual_names):
        types, nullable = _INCIDENT_COLUMNS[name]
        actual_type, actual_nullable = actual_columns[name]
        if actual_type not in types:
            problems.append(
                f"incidents.{name} type is {actual_type}, expected one of {sorted(types)}"
            )
        elif name in _TIMEZONE_AWARE_COLUMNS:
            accepted_timestamps.add(name)
        if actual_nullable != nullable:
            problems.append(f"incidents.{name} nullable is {actual_nullable}, expected {nullable}")
    # A rendering that is accepted is not yet a timezone-aware timestamp (see
    # _TIMESTAMP_TYPES): PostgreSQL renders both spellings as 'TIMESTAMP'.
    problems.extend(_timezone_aware_timestamp_problems(inspector, accepted_timestamps))

    pk_columns = [
        c.lower()
        for c in (inspector.get_pk_constraint(_INCIDENTS).get("constrained_columns") or [])
    ]
    if pk_columns != ["incident_id"]:
        problems.append(
            f"incidents primary key is {pk_columns or 'missing'}, expected ['incident_id']"
        )

    expected_fk = (["primary_alert_id"], _ALERTS, ["alert_id"])
    if not any(
        (constrained, table, referred) == expected_fk
        for constrained, table, referred, _ in _fk_defs(inspector, _INCIDENTS)
    ):
        problems.append("incidents.primary_alert_id -> alerts.alert_id foreign key is missing")

    actual_indexes = _index_defs(inspector, _INCIDENTS)
    for name, definition in _INCIDENT_INDEXES.items():
        if name in actual_indexes and actual_indexes[name] != definition:
            problems.append(
                f"index {name} on incidents is {actual_indexes[name]}, expected {definition}"
            )
    return problems


def _verify_incidents_table(inspector: Any) -> None:
    """Fail clearly when an existing ``incidents`` table is incompatible."""
    problems = _incidents_compatibility_problems(inspector)
    if problems:
        raise RuntimeError(
            "Migration d4e5f6a7b8c9 found an existing 'incidents' table that does not "
            "match the schema it needs to create (an interrupted earlier attempt, or a "
            "table created by something else). The database was NOT modified and the "
            "revision was NOT recorded as applied. Resolve manually — do not delete "
            "alert data: " + "; ".join(problems)
        )


def _verify_alert_link_state(inspector: Any) -> None:
    """Fail clearly when existing ``alerts`` link pieces are incompatible."""
    column = _column_defs(inspector, _ALERTS).get(_ALERT_LINK_COLUMN)
    if column is not None:
        actual_type, actual_nullable = column
        if actual_type not in _ALERT_LINK_TYPES or actual_nullable is not True:
            raise RuntimeError(
                f"Migration d4e5f6a7b8c9 found alerts.{_ALERT_LINK_COLUMN} with type "
                f"{actual_type} (nullable={actual_nullable}), expected one of "
                f"{sorted(_ALERT_LINK_TYPES)} (nullable=True). The database was NOT "
                "modified and the revision was NOT recorded as applied."
            )

    index = _index_defs(inspector, _ALERTS).get(_ALERT_LINK_INDEX)
    if index is not None and index != ((_ALERT_LINK_COLUMN,), False):
        raise RuntimeError(
            f"Migration d4e5f6a7b8c9 found the index {_ALERT_LINK_INDEX} on "
            f"{_ALERTS} defined as {index}, expected "
            f"(({_ALERT_LINK_COLUMN!r},), False). The database was NOT modified and "
            "the revision was NOT recorded as applied."
        )

    expected_fk = ([_ALERT_LINK_COLUMN], _INCIDENTS, [_ALERT_LINK_COLUMN])
    for constrained, table, referred, name in _fk_defs(inspector, _ALERTS):
        if name == _ALERT_LINK_FK_NAME and (constrained, table, referred) != expected_fk:
            raise RuntimeError(
                f"Migration d4e5f6a7b8c9 found a foreign key named "
                f"{_ALERT_LINK_FK_NAME} on {_ALERTS} pointing at {table}{referred} "
                f"via {constrained}, but the incident link needs {expected_fk}. The "
                "database was NOT modified and the revision was NOT recorded as "
                "applied."
            )


def _alert_link_fk_present(inspector: Any) -> bool:
    """True only when the structurally-correct alerts -> incidents FK exists."""
    expected = ([_ALERT_LINK_COLUMN], _INCIDENTS, [_ALERT_LINK_COLUMN])
    return any(
        (constrained, table, referred) == expected
        for constrained, table, referred, _ in _fk_defs(inspector, _ALERTS)
    )


def _alert_link_index_present(inspector: Any) -> bool:
    return _index_defs(inspector, _ALERTS).get(_ALERT_LINK_INDEX) == (
        (_ALERT_LINK_COLUMN,),
        False,
    )


# ---------------------------------------------------------------------------
# SQLite foreign-key enforcement control
# ---------------------------------------------------------------------------


def _sqlite(bind: Any) -> bool:
    return bind.dialect.name == "sqlite"


def _sqlite_foreign_keys_enabled(bind: Any) -> int:
    return int(bind.exec_driver_sql("PRAGMA foreign_keys").scalar() or 0)


def _set_sqlite_foreign_keys(bind: Any, enabled: int) -> None:
    """Toggle ``PRAGMA foreign_keys`` outside any transaction and verify it.

    ``PRAGMA foreign_keys`` is a silent no-op inside a transaction, so the
    change runs inside Alembic's ``autocommit_block`` (which commits any open
    transaction first). The new value is read back — if the driver could not
    apply it, the migration refuses to run the batch ALTER half-blind.
    """
    with op.get_context().autocommit_block():
        bind.exec_driver_sql(f"PRAGMA foreign_keys={enabled:d}")
    if _sqlite_foreign_keys_enabled(bind) != enabled:
        raise RuntimeError(
            f"could not set SQLite PRAGMA foreign_keys={enabled:d}; refusing to run "
            "the batch ALTER of 'alerts' without control over foreign-key enforcement"
        )


def _assert_foreign_keys_clean(bind: Any, *tables: str) -> None:
    """Fail clearly if the tables have any foreign-key violations."""
    for table in tables:
        violations = bind.exec_driver_sql(f"PRAGMA foreign_key_check({table})").fetchall()
        if violations:
            raise RuntimeError(
                f"foreign key violations detected in '{table}' after migration "
                f"d4e5f6a7b8c9 ({violations!r}); the revision was NOT recorded as "
                "applied — resolve the data conflict instead of stamping over it"
            )


# ---------------------------------------------------------------------------
# Recovery of an interrupted batch ALTER
# ---------------------------------------------------------------------------


def _drop_orphaned_batch_scratch_table(inspector: Any) -> None:
    """Drop ``_alembic_tmp_alerts`` left behind by an interrupted batch run.

    The scratch table is Alembic's copy buffer (``_alembic_tmp_`` + table
    name); it is only ever transient. When an interrupted batch ALTER left it
    behind while the authoritative ``alerts`` table still exists, it holds no
    unique data and is safe — and required — to remove before another batch
    run tries to create it again.

    If ``alerts`` itself is gone, the surviving scratch table is the *only*
    copy of the alert data: the migration must fail loudly rather than drop
    it.
    """
    if not _table_exists(inspector, _BATCH_TMP_ALERTS):
        return
    if not _table_exists(inspector, _ALERTS):
        raise RuntimeError(
            f"Migration d4e5f6a7b8c9 found the Alembic batch scratch table "
            f"'{_BATCH_TMP_ALERTS}' but no '{_ALERTS}' table: an interrupted batch "
            "ALTER appears to have left the alert data inside the scratch table. "
            "The migration will not drop it. Recover manually (rename "
            f"'{_BATCH_TMP_ALERTS}' back to '{_ALERTS}', verifying row counts) "
            "before re-running."
        )
    logger.warning(
        "migration d4e5f6a7b8c9: dropping orphaned batch scratch table %s left by an "
        "interrupted batch ALTER of %s",
        _BATCH_TMP_ALERTS,
        _ALERTS,
    )
    op.drop_table(_BATCH_TMP_ALERTS)


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


def _create_incidents_table() -> None:
    op.create_table(
        _INCIDENTS,
        sa.Column("incident_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=8), nullable=False),
        sa.Column("primary_alert_id", sa.Uuid(), nullable=False),
        sa.Column("dedupe_group_key", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["primary_alert_id"], ["alerts.alert_id"]),
        sa.PrimaryKeyConstraint("incident_id"),
    )


def _ensure_incident_indexes(inspector: Any) -> None:
    """Create the expected incidents indexes that do not exist yet."""
    existing = _index_defs(inspector, _INCIDENTS)
    for name, (columns, unique) in _INCIDENT_INDEXES.items():
        if name not in existing:
            op.create_index(name, _INCIDENTS, list(columns), unique=unique)


def _create_all_incident_indexes() -> None:
    """Emit the incidents indexes unconditionally (offline / fresh-table path)."""
    for name, (columns, unique) in _INCIDENT_INDEXES.items():
        op.create_index(name, _INCIDENTS, list(columns), unique=unique)


def _verify_complete_schema(bind: Any) -> None:
    """Final gate: the full intended schema must be in place before stamping."""
    inspector = _fresh_inspector(bind)
    problems: list[str] = []

    if not _table_exists(inspector, _INCIDENTS):
        problems.append(f"'{_INCIDENTS}' table is missing")
    else:
        problems.extend(_incidents_compatibility_problems(inspector))
        existing = _index_defs(inspector, _INCIDENTS)
        for name in _INCIDENT_INDEXES:
            if name not in existing:
                problems.append(f"index {name} on incidents is missing")

    link_column = _column_defs(inspector, _ALERTS).get(_ALERT_LINK_COLUMN)
    if link_column is None:
        problems.append(f"alerts.{_ALERT_LINK_COLUMN} column is missing")
    else:
        actual_type, actual_nullable = link_column
        if actual_type not in _ALERT_LINK_TYPES or actual_nullable is not True:
            problems.append(
                f"alerts.{_ALERT_LINK_COLUMN} is {actual_type} (nullable={actual_nullable})"
            )
    if not _alert_link_fk_present(inspector):
        problems.append(f"alerts.{_ALERT_LINK_COLUMN} -> incidents foreign key is missing")
    if not _alert_link_index_present(inspector):
        problems.append(f"index {_ALERT_LINK_INDEX} on alerts is missing")

    if problems:
        raise RuntimeError(
            "Migration d4e5f6a7b8c9 finished but the final schema verification "
            "failed, so the revision was NOT recorded as applied: " + "; ".join(problems)
        )


def upgrade() -> None:
    if op.get_context().as_sql:
        # Offline (--sql) mode emits DDL without a database to introspect.
        _create_incidents_table()
        _create_all_incident_indexes()
        with op.batch_alter_table(_ALERTS, schema=None) as batch_op:
            batch_op.add_column(sa.Column(_ALERT_LINK_COLUMN, sa.String(length=32), nullable=True))
            batch_op.create_foreign_key(
                _ALERT_LINK_FK_NAME, _INCIDENTS, [_ALERT_LINK_COLUMN], [_ALERT_LINK_COLUMN]
            )
            batch_op.create_index(_ALERT_LINK_INDEX, [_ALERT_LINK_COLUMN], unique=False)
        return

    bind = op.get_bind()

    # 1. Clean up the batch scratch table an interrupted earlier run may have
    #    committed (SQLite DDL autocommits; see module docstring).
    _drop_orphaned_batch_scratch_table(_fresh_inspector(bind))

    # 2. incidents: create, or verify the partially-applied table and finish it.
    inspector = _fresh_inspector(bind)
    if _table_exists(inspector, _INCIDENTS):
        logger.warning(
            "migration d4e5f6a7b8c9: found existing 'incidents' table; verifying "
            "schema compatibility before treating it as applied"
        )
        _verify_incidents_table(inspector)
    else:
        _create_incidents_table()
        inspector = _fresh_inspector(bind)
    _ensure_incident_indexes(inspector)

    # 3. alerts link: verify what exists, then build only the missing pieces.
    inspector = _fresh_inspector(bind)
    _verify_alert_link_state(inspector)
    has_column = _ALERT_LINK_COLUMN in _column_defs(inspector, _ALERTS)
    needs_fk = not _alert_link_fk_present(inspector)
    needs_index = not _alert_link_index_present(inspector)

    if not has_column or needs_fk or needs_index:
        # The batch ALTER recreates 'alerts' (SQLite cannot ADD CONSTRAINT).
        # DROP TABLE alerts would otherwise fail with 'FOREIGN KEY constraint
        # failed' while child rows (alert_events, notification_attempts,
        # analyst_feedback) reference it — this is the failure that left the
        # partially-applied schema in the first place. Recreating 'alerts'
        # also cascades over the circular incidents -> alerts FK, so FK
        # enforcement must be suspended for the duration and restored after.
        previous_fk_state = _sqlite_foreign_keys_enabled(bind) if _sqlite(bind) else None
        try:
            if previous_fk_state is not None:
                _set_sqlite_foreign_keys(bind, 0)
            with op.batch_alter_table(_ALERTS, schema=None) as batch_op:
                if not has_column:
                    batch_op.add_column(
                        sa.Column(_ALERT_LINK_COLUMN, sa.String(length=32), nullable=True)
                    )
                if needs_fk:
                    batch_op.create_foreign_key(
                        _ALERT_LINK_FK_NAME,
                        _INCIDENTS,
                        [_ALERT_LINK_COLUMN],
                        [_ALERT_LINK_COLUMN],
                    )
                if needs_index:
                    batch_op.create_index(_ALERT_LINK_INDEX, [_ALERT_LINK_COLUMN], unique=False)
        except BaseException:
            # Roll the half-applied batch back *before* the restore below:
            # entering an autocommit block would otherwise commit it.
            with suppress(Exception):
                bind.rollback()
            raise
        finally:
            if previous_fk_state is not None:
                # Always restore: this pooled connection serves the application
                # afterwards and must keep foreign-key enforcement enabled.
                _set_sqlite_foreign_keys(bind, previous_fk_state)
        if _sqlite(bind):
            _assert_foreign_keys_clean(bind, _ALERTS, _INCIDENTS)

    # 4. Final verification gate: only a complete, correct schema may be
    #    stamped as applied.
    _verify_complete_schema(bind)


def downgrade() -> None:
    if op.get_context().as_sql:
        with op.batch_alter_table(_ALERTS, schema=None) as batch_op:
            batch_op.drop_index(_ALERT_LINK_INDEX)
            batch_op.drop_constraint(_ALERT_LINK_FK_NAME, type_="foreignkey")
            batch_op.drop_column(_ALERT_LINK_COLUMN)
        for name in _INCIDENT_INDEXES:
            op.drop_index(name, table_name=_INCIDENTS)
        op.drop_table(_INCIDENTS)
        return

    bind = op.get_bind()
    _drop_orphaned_batch_scratch_table(_fresh_inspector(bind))

    inspector = _fresh_inspector(bind)
    has_column = _ALERT_LINK_COLUMN in _column_defs(inspector, _ALERTS)
    needs_fk_drop = _alert_link_fk_present(inspector)
    needs_index_drop = _alert_link_index_present(inspector)
    if has_column or needs_fk_drop or needs_index_drop:
        # Same batch-recreate constraint as upgrade(): FK enforcement must be
        # suspended while 'alerts' is dropped and renamed.
        previous_fk_state = _sqlite_foreign_keys_enabled(bind) if _sqlite(bind) else None
        try:
            if previous_fk_state is not None:
                _set_sqlite_foreign_keys(bind, 0)
            with op.batch_alter_table(_ALERTS, schema=None) as batch_op:
                if needs_index_drop:
                    batch_op.drop_index(_ALERT_LINK_INDEX)
                if needs_fk_drop:
                    batch_op.drop_constraint(_ALERT_LINK_FK_NAME, type_="foreignkey")
                if has_column:
                    batch_op.drop_column(_ALERT_LINK_COLUMN)
        except BaseException:
            with suppress(Exception):
                bind.rollback()
            raise
        finally:
            if previous_fk_state is not None:
                _set_sqlite_foreign_keys(bind, previous_fk_state)

    inspector = _fresh_inspector(bind)
    if _table_exists(inspector, _INCIDENTS):
        existing = _index_defs(inspector, _INCIDENTS)
        for name in _INCIDENT_INDEXES:
            if name in existing:
                op.drop_index(name, table_name=_INCIDENTS)
        op.drop_table(_INCIDENTS)
