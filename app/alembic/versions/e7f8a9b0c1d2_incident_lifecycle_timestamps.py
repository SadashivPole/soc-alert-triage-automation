"""incident lifecycle timestamps (Phase 3.2) — restart-safe nullable column adds

Revision ID: e7f8a9b0c1d2
Revises: d4e5f6a7b8c9
Create Date: 2026-09-02

Phase 3.2 — incident lifecycle + feedback synchronization:

* ``incidents.acknowledged_at`` — nullable UTC timestamp, populated exactly
  when the incident transitions to ``acknowledged``;
* ``incidents.resolved_at`` — nullable UTC timestamp, populated exactly when
  the incident reaches a terminal state (``resolved`` or ``false_positive``).

Both columns are **nullable**: pre-existing incident rows keep their data and
simply carry NULL until the corresponding lifecycle state is actually
reached. No row data is read, rewritten, or deleted by this migration.

Restart-safety (same environment as d4e5f6a7b8c9)
-------------------------------------------------
SQLite DDL is applied non-transactionally: the SQLAlchemy pysqlite driver
autocommits DDL statements (the SQLite dialect reports
``supports_transactional_ddl = False``), so a migration interrupted after
its first ``ADD COLUMN`` leaves that column durably committed while
``alembic_version`` still names the previous revision. The upgrade is
therefore idempotent and self-verifying: it introspects the table first and
adds only the columns that are missing, then verifies both are present
before the revision is recorded as applied. Adding nullable columns is a
plain ``ALTER TABLE ... ADD COLUMN`` — no table recreation, no data copy,
and no interaction with foreign-key enforcement, so it cannot corrupt
``alerts``/``incidents`` data.

The downgrade drops the two columns. On SQLite that requires Alembic's batch
recreate of ``incidents``, which — like d4e5f6a7b8c9's ``alerts`` batch —
must temporarily suspend ``PRAGMA foreign_keys`` because ``alerts`` rows
reference ``incidents`` (circular FK pair). The previous pragma state is
always restored.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import Any

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "e7f8a9b0c1d2"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

_INCIDENTS = "incidents"
#: Lifecycle columns in upgrade order: name -> column definition.
_LIFECYCLE_COLUMNS: tuple[tuple[str, Any], ...] = (
    ("acknowledged_at", sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True)),
    ("resolved_at", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True)),
)


def _table_names(bind: Any) -> set[str]:
    inspector = sa.inspect(bind)
    inspector.clear_cache()
    return {t.lower() for t in inspector.get_table_names()}


def _existing_columns(bind: Any) -> set[str]:
    inspector = sa.inspect(bind)
    inspector.clear_cache()
    return {col["name"].lower() for col in inspector.get_columns(_INCIDENTS)}


# ---------------------------------------------------------------------------
# SQLite foreign-key enforcement control (downgrade batch recreate)
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
    apply it, the migration refuses to run the batch recreate half-blind.
    """
    with op.get_context().autocommit_block():
        bind.exec_driver_sql(f"PRAGMA foreign_keys={enabled:d}")
    if _sqlite_foreign_keys_enabled(bind) != enabled:
        raise RuntimeError(
            f"could not set SQLite PRAGMA foreign_keys={enabled:d}; refusing to run "
            "the batch recreate of 'incidents' without control over foreign-key "
            "enforcement"
        )


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


def upgrade() -> None:
    if op.get_context().as_sql:
        # Offline (--sql) mode emits DDL without a database to introspect.
        for _name, column in _LIFECYCLE_COLUMNS:
            op.add_column(_INCIDENTS, column)
        return

    bind = op.get_bind()

    # The previous revision created 'incidents'; if it is missing the
    # database was not brought to d4e5f6a7b8c9 first — fail loudly instead
    # of creating a half-schema.
    if _INCIDENTS not in _table_names(bind):
        raise RuntimeError(
            "Migration e7f8a9b0c1d2 cannot add lifecycle timestamps: the "
            f"'{_INCIDENTS}' table is missing. Apply revision d4e5f6a7b8c9 "
            "first (the database appears not to be at the expected revision)."
        )

    # Idempotent: add only what is missing (an interrupted earlier run may
    # have committed one of the columns without recording this revision).
    for name, column in _LIFECYCLE_COLUMNS:
        if name in _existing_columns(bind):
            logger.warning(
                "migration e7f8a9b0c1d2: incidents.%s already exists; treating "
                "this column as applied from an interrupted earlier run",
                name,
            )
            continue
        op.add_column(_INCIDENTS, column)

    # Final verification gate: both lifecycle columns must be present (and
    # nullable — a non-nullable leftover from something else would abort the
    # revision rather than be stamped over).
    inspector = sa.inspect(bind)
    inspector.clear_cache()
    for name, _column in _LIFECYCLE_COLUMNS:
        col = next(
            (c for c in inspector.get_columns(_INCIDENTS) if c["name"].lower() == name), None
        )
        if col is None:
            raise RuntimeError(
                f"Migration e7f8a9b0c1d2 finished but incidents.{name} is still "
                "missing; the revision was NOT recorded as applied."
            )
        if not col["nullable"]:
            raise RuntimeError(
                f"Migration e7f8a9b0c1d2 found incidents.{name} as NOT NULL, "
                "expected NULLABLE. The database was NOT modified beyond the "
                "missing-column additions and the revision was NOT recorded."
            )


def downgrade() -> None:
    if op.get_context().as_sql:
        with op.batch_alter_table(_INCIDENTS, schema=None) as batch_op:
            for name, _column in reversed(_LIFECYCLE_COLUMNS):
                batch_op.drop_column(name)
        return

    bind = op.get_bind()
    if _INCIDENTS not in _table_names(bind):
        # Nothing to drop (e.g. the previous revision's downgrade ran first
        # on a database that never applied this one's upgrade).
        return
    existing = _existing_columns(bind)
    if not any(name in existing for name, _column in _LIFECYCLE_COLUMNS):
        return

    if _sqlite(bind):
        # The batch recreate drops and renames 'incidents'; with live 'alerts'
        # rows referencing it, PRAGMA foreign_keys=ON would make the implicit
        # DELETE inside DROP TABLE fail (same constraint as d4e5f6a7b8c9).
        previous_fk_state = _sqlite_foreign_keys_enabled(bind)
        try:
            _set_sqlite_foreign_keys(bind, 0)
            with op.batch_alter_table(_INCIDENTS, schema=None) as batch_op:
                for name, _column in reversed(_LIFECYCLE_COLUMNS):
                    if name in existing:
                        batch_op.drop_column(name)
        except BaseException:
            # Roll the half-applied batch back *before* the restore below:
            # entering an autocommit block would otherwise commit it.
            with suppress(Exception):
                bind.rollback()
            raise
        finally:
            # Always restore: this pooled connection serves the application
            # afterwards and must keep foreign-key enforcement enabled.
            _set_sqlite_foreign_keys(bind, previous_fk_state)
    else:
        for name, _column in reversed(_LIFECYCLE_COLUMNS):
            if name in existing:
                op.drop_column(_INCIDENTS, name)
