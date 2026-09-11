"""cross-alert correlation contexts (Phase 6.4)

Revision ID: f9a0b1c2d3e4
Revises: e7f8a9b0c1d2
Create Date: 2026-09-11

Phase 6.4 — deterministic, explainable cross-alert correlation as a
*read-side investigation context*. Two new tables, no changes to any existing
table (``alerts.dedupe_group_key`` and ``alerts.incident_id`` are untouched —
correlation never overwrites recurrence or incident linkage):

* ``correlation_contexts`` — one row per investigation context:
  human-readable ``CORR-YYYY-MM-DD-NNNN`` id (PK, sequential per UTC date,
  same convention as incidents), UTC ``created_at`` / ``updated_at``, and
  ``first_seen`` / ``last_seen`` bounding the ``received_at`` span of the
  member alerts. No status column: a context has no lifecycle of its own and
  is never coupled to incident state.
* ``correlation_members`` — one row per member alert: FK to the context, FK
  to ``alerts.alert_id`` (**unique** — an alert belongs to at most one
  context, so exact duplicates can never create memberships), ``joined_at``,
  and a small JSON ``evidence`` list (``{evidence_type, value,
  peer_alert_id}``) explaining *why* the alert is in the context.

Existing databases upgrade cleanly: both tables are new, so pre-existing
rows are simply unaffected and no data is rewritten.

Recovery-safe application (same concern as revision d4e5f6a7b8c9): SQLite DDL
autocommits per statement, so an interrupted run can leave ``correlation_
contexts`` created but unstamped. The upgrade therefore checks for existing
tables and verifies their schema before treating them as applied; a partial
application is *completed* (missing tables/indexes are created) rather than
replayed blindly, and an incompatible table aborts the migration loudly.
There is no batch ALTER and no existing-table rewrite, so the foreign-key
pragma dance of d4e5f6a7b8c9 is not needed here.
"""

from __future__ import annotations

import logging
from typing import Any

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f9a0b1c2d3e4"
down_revision = "e7f8a9b0c1d2"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

_CONTEXTS = "correlation_contexts"
_MEMBERS = "correlation_members"

#: Expected ``correlation_contexts`` columns: name -> (type renderings, nullable).
_CONTEXT_COLUMNS: dict[str, tuple[frozenset[str], bool]] = {
    "context_id": (frozenset({"VARCHAR(32)"}), False),
    "created_at": (frozenset({"DATETIME", "TIMESTAMP WITH TIME ZONE"}), False),
    "updated_at": (frozenset({"DATETIME", "TIMESTAMP WITH TIME ZONE"}), False),
    "first_seen": (frozenset({"DATETIME", "TIMESTAMP WITH TIME ZONE"}), False),
    "last_seen": (frozenset({"DATETIME", "TIMESTAMP WITH TIME ZONE"}), False),
}

#: Expected ``correlation_members`` columns.
_MEMBER_COLUMNS: dict[str, tuple[frozenset[str], bool]] = {
    "id": (frozenset({"INTEGER", "BIGINT"}), False),
    "context_id": (frozenset({"VARCHAR(32)"}), False),
    "alert_id": (frozenset({"CHAR(32)", "UUID"}), False),
    "joined_at": (frozenset({"DATETIME", "TIMESTAMP WITH TIME ZONE"}), False),
    "evidence": (frozenset({"JSON", "TEXT"}), False),
}

_CONTEXT_INDEXES: dict[str, tuple[tuple[str, ...], bool]] = {
    "ix_correlation_contexts_created_at": (("created_at",), False),
}

_MEMBER_INDEXES: dict[str, tuple[tuple[str, ...], bool]] = {
    "ix_correlation_members_context": (("context_id", "joined_at"), False),
    "ix_correlation_members_alert_id": (("alert_id",), True),
}


def _table_exists(inspector: Any, table: str) -> bool:
    return table in inspector.get_table_names()


def _column_defs(inspector: Any, table: str) -> dict[str, tuple[str, bool]]:
    return {
        column["name"]: (str(column["type"]), bool(column["nullable"]))
        for column in inspector.get_columns(table)
    }


def _index_defs(inspector: Any, table: str) -> dict[str, tuple[tuple[str, ...], bool]]:
    return {
        index["name"]: (tuple(index["column_names"]), bool(index["unique"]))
        for index in inspector.get_indexes(table)
    }


def _verify_table(inspector: Any, table: str, expected: dict[str, Any], label: str) -> None:
    """Abort loudly if an existing table does not match the intended schema."""
    problems: list[str] = []
    actual = _column_defs(inspector, table)
    for name, (types, nullable) in expected.items():
        if name not in actual:
            problems.append(f"{table}.{name} column is missing")
            continue
        actual_type, actual_nullable = actual[name]
        if actual_type not in types:
            problems.append(f"{table}.{name} is {actual_type}, expected one of {sorted(types)}")
        if actual_nullable is not nullable:
            problems.append(f"{table}.{name} nullable={actual_nullable}, expected {nullable}")
    if problems:
        raise RuntimeError(
            f"Migration {revision} found an incompatible existing '{table}' table "
            f"({label}); the revision was NOT recorded as applied: " + "; ".join(problems)
        )


def _create_contexts_table() -> None:
    op.create_table(
        _CONTEXTS,
        sa.Column("context_id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("context_id"),
    )


def _create_members_table() -> None:
    op.create_table(
        _MEMBERS,
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("context_id", sa.String(length=32), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.alert_id"]),
        sa.ForeignKeyConstraint(["context_id"], ["correlation_contexts.context_id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id", name="uq_correlation_members_alert_id"),
    )


def _ensure_indexes(inspector: Any) -> None:
    """Create any expected index that does not exist yet (partial recovery)."""
    for table, expected in ((_CONTEXTS, _CONTEXT_INDEXES), (_MEMBERS, _MEMBER_INDEXES)):
        if not _table_exists(inspector, table):
            continue
        existing = _index_defs(inspector, table)
        for name, (columns, unique) in expected.items():
            if name not in existing:
                op.create_index(name, table, list(columns), unique=unique)


def _verify_complete_schema(bind: Any) -> None:
    """Final gate: the full intended schema must be in place before stamping."""
    inspector = sa.inspect(bind)
    problems: list[str] = []
    for table, columns in ((_CONTEXTS, _CONTEXT_COLUMNS), (_MEMBERS, _MEMBER_COLUMNS)):
        if not _table_exists(inspector, table):
            problems.append(f"'{table}' table is missing")
            continue
        _verify_table(inspector, table, columns, "final verification")
        existing = _index_defs(inspector, table)
        expected = _CONTEXT_INDEXES if table == _CONTEXTS else _MEMBER_INDEXES
        for name in expected:
            if name not in existing:
                problems.append(f"index {name} on {table} is missing")
    if problems:
        raise RuntimeError(
            f"Migration {revision} finished but the final schema verification "
            "failed, so the revision was NOT recorded as applied: " + "; ".join(problems)
        )


def upgrade() -> None:
    if op.get_context().as_sql:
        # Offline (--sql) mode emits DDL without a database to introspect.
        _create_contexts_table()
        _create_members_table()
        for name, (columns, unique) in _CONTEXT_INDEXES.items():
            op.create_index(name, _CONTEXTS, list(columns), unique=unique)
        for name, (columns, unique) in _MEMBER_INDEXES.items():
            op.create_index(name, _MEMBERS, list(columns), unique=unique)
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _table_exists(inspector, _CONTEXTS):
        logger.warning(
            "migration %s: found existing '%s' table; verifying schema "
            "compatibility before treating it as applied",
            revision,
            _CONTEXTS,
        )
        _verify_table(inspector, _CONTEXTS, _CONTEXT_COLUMNS, "pre-existing table")
    else:
        _create_contexts_table()
        inspector = sa.inspect(bind)

    if _table_exists(inspector, _MEMBERS):
        logger.warning(
            "migration %s: found existing '%s' table; verifying schema "
            "compatibility before treating it as applied",
            revision,
            _MEMBERS,
        )
        _verify_table(inspector, _MEMBERS, _MEMBER_COLUMNS, "pre-existing table")
    else:
        _create_members_table()
        inspector = sa.inspect(bind)

    _ensure_indexes(inspector)
    _verify_complete_schema(bind)


def downgrade() -> None:
    if op.get_context().as_sql:
        for name in _MEMBER_INDEXES:
            op.drop_index(name, table_name=_MEMBERS)
        op.drop_table(_MEMBERS)
        for name in _CONTEXT_INDEXES:
            op.drop_index(name, table_name=_CONTEXTS)
        op.drop_table(_CONTEXTS)
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    # Members reference contexts (FK), so drop members first.
    if _table_exists(inspector, _MEMBERS):
        existing = _index_defs(inspector, _MEMBERS)
        for name in _MEMBER_INDEXES:
            if name in existing:
                op.drop_index(name, table_name=_MEMBERS)
        op.drop_table(_MEMBERS)
    if _table_exists(inspector, _CONTEXTS):
        existing = _index_defs(inspector, _CONTEXTS)
        for name in _CONTEXT_INDEXES:
            if name in existing:
                op.drop_index(name, table_name=_CONTEXTS)
        op.drop_table(_CONTEXTS)
