"""enrichment response TTL cache (Phase 2.3)

Revision ID: c7d8e9f0a1b2
Revises: f9a0b1c2d3e4
Create Date: 2026-09-13

Phase 2.3 — SQLite-backed response TTL cache for threat-intel lookups
(ARCHITECTURE.md §7.2 step 2). One new table, no changes to any existing
table:

* ``enrichment_cache`` — one row per
  ``(provider, indicator_type, indicator_value)`` **definitive** verdict
  (``found`` / ``not_found`` only; transient failures stay retryable and are
  never cached). ``payload`` stores the serialized, sanitized
  ``LookupRecord`` exactly as the live lookup produced it (byte-identical
  replay on a hit, including the original timestamp); ``looked_at`` is the
  original lookup instant and ``expires_at = looked_at + ttl_for(type)``
  (hashes 6 h, IPv4 1 h, other types 1 h — ARCHITECTURE.md §7.2), so a
  restored database never extends a verdict's lifetime. Entries are
  provider-scoped: a VirusTotal verdict is never served for a MISP lookup.

The table is a quota/latency optimization only — it never feeds scoring or
decisions on its own, and the feature stays **disabled by default**
(``TRIAGE_ENRICHMENT_CACHE_ENABLED``). Existing databases upgrade cleanly:
the table is new, so pre-existing rows are unaffected and no data is
rewritten.

Recovery-safe application (same concern as revisions d4e5f6a7b8c9 and
f9a0b1c2d3e4): SQLite DDL autocommits per statement, so an interrupted run
can leave ``enrichment_cache`` created but unstamped. The upgrade therefore
checks for an existing table and verifies its schema before treating it as
applied; a partial application is *completed* (missing indexes are created)
rather than replayed blindly, and an incompatible table aborts the migration
loudly. There is no batch ALTER and no existing-table rewrite.
"""

from __future__ import annotations

import logging
from typing import Any

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "c7d8e9f0a1b2"
down_revision = "f9a0b1c2d3e4"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

_CACHE = "enrichment_cache"

#: Expected ``enrichment_cache`` columns: name -> (type renderings, nullable).
_CACHE_COLUMNS: dict[str, tuple[frozenset[str], bool]] = {
    "id": (frozenset({"INTEGER", "BIGINT"}), False),
    "provider": (frozenset({"VARCHAR(32)"}), False),
    "indicator_type": (frozenset({"VARCHAR(16)"}), False),
    "indicator_value": (frozenset({"TEXT"}), False),
    "lookup_status": (frozenset({"VARCHAR(16)"}), False),
    "payload": (frozenset({"TEXT"}), False),
    "looked_at": (frozenset({"DATETIME", "TIMESTAMP WITH TIME ZONE"}), False),
    "expires_at": (frozenset({"DATETIME", "TIMESTAMP WITH TIME ZONE"}), False),
}

_CACHE_INDEXES: dict[str, tuple[tuple[str, ...], bool]] = {
    "ix_enrichment_cache_lookup": (
        ("provider", "indicator_type", "indicator_value"),
        True,
    ),
    "ix_enrichment_cache_expires_at": (("expires_at",), False),
}


def _table_exists(inspector: Any, table: str) -> bool:
    return table in inspector.get_table_names()


def _column_defs(inspector: Any, table: str) -> dict[str, tuple[str, bool]]:
    """Column name -> (upper-cased type rendering, nullable)."""
    definitions: dict[str, tuple[str, bool]] = {}
    for column in inspector.get_columns(table):
        column_type = column["type"]
        rendered_type = str(column_type).strip().upper()
        if rendered_type == "TIMESTAMP" and getattr(column_type, "timezone", False):
            rendered_type = "TIMESTAMP WITH TIME ZONE"
        definitions[column["name"]] = (rendered_type, bool(column["nullable"]))
    return definitions


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


def _create_cache_table() -> None:
    op.create_table(
        _CACHE,
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("indicator_value", sa.Text(), nullable=False),
        sa.Column("lookup_status", sa.String(length=16), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("looked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def _ensure_indexes(inspector: Any) -> None:
    """Create any expected index that does not exist yet (partial recovery)."""
    if not _table_exists(inspector, _CACHE):
        return
    existing = _index_defs(inspector, _CACHE)
    for name, (columns, unique) in _CACHE_INDEXES.items():
        if name not in existing:
            op.create_index(name, _CACHE, list(columns), unique=unique)


def _verify_complete_schema(bind: Any) -> None:
    """Final gate: the full intended schema must be in place before stamping."""
    inspector = sa.inspect(bind)
    problems: list[str] = []
    if not _table_exists(inspector, _CACHE):
        problems.append(f"'{_CACHE}' table is missing")
    else:
        _verify_table(inspector, _CACHE, _CACHE_COLUMNS, "final verification")
        existing = _index_defs(inspector, _CACHE)
        for name in _CACHE_INDEXES:
            if name not in existing:
                problems.append(f"index {name} on {_CACHE} is missing")
    if problems:
        raise RuntimeError(
            f"Migration {revision} finished but the final schema verification "
            "failed, so the revision was NOT recorded as applied: " + "; ".join(problems)
        )


def upgrade() -> None:
    if op.get_context().as_sql:
        # Offline (--sql) mode emits DDL without a database to introspect.
        _create_cache_table()
        for name, (columns, unique) in _CACHE_INDEXES.items():
            op.create_index(name, _CACHE, list(columns), unique=unique)
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _table_exists(inspector, _CACHE):
        logger.warning(
            "migration %s: found existing '%s' table; verifying schema "
            "compatibility before treating it as applied",
            revision,
            _CACHE,
        )
        _verify_table(inspector, _CACHE, _CACHE_COLUMNS, "pre-existing table")
    else:
        _create_cache_table()
        inspector = sa.inspect(bind)

    _ensure_indexes(inspector)
    _verify_complete_schema(bind)


def downgrade() -> None:
    if op.get_context().as_sql:
        for name in _CACHE_INDEXES:
            op.drop_index(name, table_name=_CACHE)
        op.drop_table(_CACHE)
        return

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _table_exists(inspector, _CACHE):
        existing = _index_defs(inspector, _CACHE)
        for name in _CACHE_INDEXES:
            if name in existing:
                op.drop_index(name, table_name=_CACHE)
        op.drop_table(_CACHE)
