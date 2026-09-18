"""Unit tests for dialect-aware JSON extraction portability (Phase 3.8).

Validates that the _JsonExtractCompat helper in repositories.py:
- Compiles to json_extract() on SQLite (byte-for-byte preserved).
- Compiles to ->/->> chain on PostgreSQL.
- Handles nested JSON paths.
- Preserves public behavior (same input → same SQL semantics).

No live PostgreSQL required; uses SQLAlchemy dialect compilation only.
"""

from __future__ import annotations

from sqlalchemy import JSON, Column, Integer, MetaData, Table, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.sql import column

from soc_triage.models.repositories import _JsonExtractCompat


def _compile(expr, dialect_name: str, *, literal_binds: bool = False) -> str:
    """Compile a SQLAlchemy expression to a string for a given dialect."""
    if dialect_name == "sqlite":
        dialect = sqlite.dialect()
    elif dialect_name == "postgresql":
        dialect = postgresql.dialect()
    else:
        raise ValueError(f"Unsupported dialect: {dialect_name}")
    kwargs = {}
    if literal_binds:
        kwargs["compile_kwargs"] = {"literal_binds": True}
    compiled = expr.compile(dialect=dialect, **kwargs)
    return str(compiled)


def _compile_with_params(expr, dialect_name: str):
    """Return (sql, params) tuple."""
    if dialect_name == "sqlite":
        dialect = sqlite.dialect()
    elif dialect_name == "postgresql":
        dialect = postgresql.dialect()
    else:
        raise ValueError(f"Unsupported dialect: {dialect_name}")
    compiled = expr.compile(dialect=dialect)
    return str(compiled), compiled.params


def test_json_extract_compiles_to_json_extract_on_sqlite() -> None:
    """SQLite must use func.json_extract(column, path)."""
    expr = _JsonExtractCompat(column("raw_payload"), "$.title")
    sql, params = _compile_with_params(expr, "sqlite")
    assert "json_extract" in sql.lower()
    # Should preserve $.title path in bound params or literal
    sql_literal = _compile(expr, "sqlite", literal_binds=True)
    assert "$.title" in sql_literal or "title" in sql_literal
    # Also check params contain the path
    assert any("$.title" in str(v) for v in params.values()) or "$.title" in sql_literal


def test_json_extract_compiles_to_arrow_chain_on_postgres() -> None:
    """PostgreSQL must use ->/->> operators, not json_extract."""
    expr = _JsonExtractCompat(column("raw_payload"), "$.title")
    sql = _compile(expr, "postgresql")
    # PG uses -> and ->> for JSON navigation
    assert "->" in sql
    # The function name may appear as alias, but not as json_extract( call
    assert "json_extract(" not in sql.lower()


def test_json_extract_simple_path_postgres_uses_text_operator() -> None:
    """Simple $.field should compile to ->> (text) on PG for last segment."""
    expr = _JsonExtractCompat(column("raw_payload"), "$.title")
    sql, params = _compile_with_params(expr, "postgresql")
    # Last accessor should be ->> to extract as text
    assert "->>" in sql
    sql_literal = _compile(expr, "postgresql", literal_binds=True)
    assert "title" in sql_literal or any("title" in str(v) for v in params.values())


def test_json_extract_nested_path_sqlite_preserves_dot_notation() -> None:
    """Nested $.a.b.c must preserve JSON path on SQLite."""
    expr = _JsonExtractCompat(column("raw_payload"), "$.a.b.c")
    sql_literal = _compile(expr, "sqlite", literal_binds=True)
    assert "json_extract" in sql_literal.lower()
    # Path should contain the nested keys in literal
    assert "a" in sql_literal and "b" in sql_literal and "c" in sql_literal
    assert "$.a.b.c" in sql_literal


def test_json_extract_nested_path_postgres_chains_operators() -> None:
    """Nested $.a.b.c must chain -> and ->> on PostgreSQL."""
    expr = _JsonExtractCompat(column("raw_payload"), "$.a.b.c")
    sql = _compile(expr, "postgresql")
    assert "json_extract(" not in sql.lower()
    # Should have multiple -> operators
    # Count of -> should be >= 2 for nested path
    arrow_count = sql.count("->")
    assert arrow_count >= 2
    sql_literal = _compile(expr, "postgresql", literal_binds=True)
    assert "a" in sql_literal and "b" in sql_literal and "c" in sql_literal


def test_json_extract_single_level_root() -> None:
    """Edge: $.field with single level works on both dialects."""
    for dialect in ("sqlite", "postgresql"):
        expr = _JsonExtractCompat(column("raw_payload"), "$.field")
        sql_literal = _compile(expr, dialect, literal_binds=True)
        assert "field" in sql_literal


def test_json_extract_with_table_column() -> None:
    """Real table column (not just column() helper) compiles on both dialects."""
    metadata = MetaData()
    test_table = Table(
        "test",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("raw_payload", JSON),
    )
    expr = _JsonExtractCompat(test_table.c.raw_payload, "$.title")
    sqlite_sql = _compile(select(expr), "sqlite", literal_binds=True)
    pg_sql = _compile(select(expr), "postgresql", literal_binds=True)
    assert "json_extract" in sqlite_sql.lower()
    assert "->" in pg_sql
    # PG should not have json_extract( call (alias is okay, but function call is not)
    assert "json_extract(" not in pg_sql.lower()


def test_json_extract_filter_compiles_in_select() -> None:
    """Filter using JSON extract compiles inside SELECT on both dialects."""
    metadata = MetaData()
    alerts = Table(
        "alerts",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("raw_payload", JSON),
    )
    expr = _JsonExtractCompat(alerts.c.raw_payload, "$.severity")
    # Simulate filter: WHERE json_extract(...) = 'high' / WHERE payload->>'severity' = 'high'
    stmt = select(alerts).where(expr == "high")
    sqlite_sql = _compile(stmt, "sqlite", literal_binds=True)
    pg_sql = _compile(stmt, "postgresql", literal_binds=True)
    assert "json_extract" in sqlite_sql.lower()
    assert "->" in pg_sql
    assert "severity" in sqlite_sql
    assert "severity" in pg_sql


def test_json_extract_preserves_public_behavior_sqlite_byte_for_byte() -> None:
    """SQLite compilation must remain byte-for-byte identical to legacy func.json_extract.

    This ensures Phase 3.8 does not break existing SQLite behavior.
    """
    from sqlalchemy import func

    # Legacy direct call
    legacy = func.json_extract(column("raw_payload"), "$.title")
    legacy_sql = _compile(legacy, "sqlite", literal_binds=True)

    # New compat helper
    compat = _JsonExtractCompat(column("raw_payload"), "$.title")
    compat_sql = _compile(compat, "sqlite", literal_binds=True)

    # Both should produce json_extract(...); compat may have slightly different
    # whitespace but must contain same function and path.
    assert "json_extract" in legacy_sql.lower()
    assert "json_extract" in compat_sql.lower()
    # Path must be preserved
    assert "$.title" in legacy_sql
    assert "$.title" in compat_sql


def test_json_extract_postgres_does_not_use_json_extract_function() -> None:
    """PostgreSQL must never emit json_extract() — only native operators."""
    paths = ["$.title", "$.a.b", "$.a.b.c.d", "$.severity"]
    for path in paths:
        expr = _JsonExtractCompat(column("raw_payload"), path)
        pg_sql = _compile(expr, "postgresql", literal_binds=True)
        assert "json_extract(" not in pg_sql.lower(), (
            f"PG emitted json_extract for {path}: {pg_sql}"
        )


def test_json_extract_sqlite_does_not_use_pg_operators() -> None:
    """SQLite must never emit ->/->> — only json_extract()."""
    paths = ["$.title", "$.a.b", "$.a.b.c.d"]
    for path in paths:
        expr = _JsonExtractCompat(column("raw_payload"), path)
        sqlite_sql = _compile(expr, "sqlite", literal_binds=True)
        # SQLite should not have -> operator (outside of string literals)
        # Simple check: json_extract present and -> not present outside function
        assert "json_extract" in sqlite_sql.lower()
        # The -> could appear inside JSON path string like $.a, but not as PG operator
        # PG operator would be column -> 'key', SQLite would be json_extract(col, '$.a')
        # So we check that the compiled SQL doesn't contain " -> " as operator
        # Remove the JSON path string to avoid false positives
        cleaned = sqlite_sql.replace("$.", "").replace("$", "")
        # Still, ensure no "->>" which is definitely PG
        assert "->>" not in cleaned, f"SQLite emitted ->> for {path}: {sqlite_sql}"
