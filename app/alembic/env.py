"""Alembic environment for the Triage API storage layer (Phase 1D).

The database is resolved, in order:

1. an explicit connection placed in ``config.attributes["connection"]`` by
   the application (the startup bootstrap shares the app's own engine, so
   app and migrations always target the exact same database);
2. an engine built from ``sqlalchemy.url`` in ``alembic.ini``;
3. the ``TRIAGE_DB_URL`` environment variable (the app's own variable).

Batch mode is enabled so SQLite's limited ALTER support stays in play — the
same migrations must run unmodified on PostgreSQL later (ARCHITECTURE.md
§19: "Alembic migrations identical").
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Engine, engine_from_config, pool
from sqlalchemy.engine import Connection

from soc_triage.models.orm import Base

# Alembic Config object (values from alembic.ini).
config = context.config

# Set the Python logging from the config file, if present.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# MetaData for 'autogenerate' support.
target_metadata = Base.metadata


def _resolve_url() -> str:
    """Resolve the database URL from the ini option or TRIAGE_DB_URL."""
    url = config.get_main_option("sqlalchemy.url") or os.environ.get("TRIAGE_DB_URL") or ""
    if not url:
        raise RuntimeError(
            "no database URL configured: set TRIAGE_DB_URL in the environment "
            "or sqlalchemy.url in alembic.ini"
        )
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout)."""
    context.configure(
        url=_resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (real database connection)."""
    connectable: Connection | None = config.attributes.get("connection")
    owned_engine: Engine | None = None
    if connectable is None:
        owned_engine = engine_from_config(
            config.get_section(config.config_ini_section, {}),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
            url=_resolve_url(),
        )
        connectable = owned_engine.connect()

    try:
        context.configure(
            connection=connectable,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    finally:
        if connectable is not None:
            connectable.close()
        if owned_engine is not None:
            owned_engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
