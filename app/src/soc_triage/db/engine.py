"""Database engine bootstrap (Phase 1D).

Owns everything about *how* the application talks to the database:

* engine creation from the configured ``TRIAGE_DB_URL`` (SQLite for the MVP,
  PostgreSQL via the same SQLAlchemy URL shape later — ARCHITECTURE.md §19);
* SQLite pragmas (foreign keys, WAL journaling, busy timeout) registered as
  connection events;
* the session factory used by the repositories;
* programmatic Alembic migrations so the application can start against a
  fresh database without a separate manual migration step.

Business logic never imports this module directly — it receives a session
factory or repositories (ARCHITECTURE.md §12: DB access only in ``models/``
repositories). The database URL is configuration, never a secret: it may
contain credentials for a PostgreSQL profile, so it is never logged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import unquote

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from sqlalchemy import Engine, create_engine, event, make_url
from sqlalchemy.orm import Session, sessionmaker

#: ``app/alembic`` — the Alembic script location relative to this package.
#: (src/soc_triage/db → src/soc_triage → src → app)
ALEMBIC_SCRIPT_LOCATION = Path(__file__).resolve().parents[3] / "alembic"

#: Seconds a SQLite connection waits for a locked database before failing.
_SQLITE_BUSY_TIMEOUT_SECONDS = 10.0


def ensure_sqlite_directory(db_url: str) -> None:
    """Create the parent directory of a SQLite database file if missing.

    No-op for non-SQLite URLs, in-memory databases, and relative paths whose
    parent already exists.
    """
    url = make_url(db_url)
    if url.drivername != "sqlite":
        return
    database = url.database
    if not database or database == ":memory:":
        return
    parent = Path(unquote(database)).expanduser().parent
    if parent and parent != Path("."):
        parent.mkdir(parents=True, exist_ok=True)


def _register_sqlite_pragmas(engine: Engine) -> None:
    """Apply defensive SQLite pragmas on every new DBAPI connection.

    * ``foreign_keys=ON`` — enforce FK integrity (OFF by default in SQLite).
    * ``journal_mode=WAL`` — readers do not block writers; required for the
      API to serve health checks while ingest is committing.
    * ``synchronous=NORMAL`` — safe with WAL, faster than FULL.
    * ``busy_timeout`` — wait (instead of failing) when another connection
      holds a write lock.
    """

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute(f"PRAGMA busy_timeout={int(_SQLITE_BUSY_TIMEOUT_SECONDS * 1000)}")
        finally:
            cursor.close()


def create_app_engine(db_url: str, *, poolclass: Any | None = None) -> Engine:
    """Create the application engine for ``db_url``.

    SQLite connections are created with ``check_same_thread=False`` because
    the engine's pool hands connections between the ASGI worker and the
    thread pool that serves synchronous endpoints (standard FastAPI +
    SQLite recipe). ``poolclass`` may override the default pool (tests use
    ``NullPool`` for the harshest connection-churn case).
    """
    url = make_url(db_url)
    connect_args: dict[str, Any] = {}
    if url.drivername == "sqlite":
        ensure_sqlite_directory(db_url)
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = _SQLITE_BUSY_TIMEOUT_SECONDS
    engine_kwargs: dict[str, Any] = {"connect_args": connect_args, "pool_pre_ping": True}
    if poolclass is not None:
        engine_kwargs["poolclass"] = poolclass
    engine = create_engine(db_url, **engine_kwargs)
    if url.drivername == "sqlite":
        _register_sqlite_pragmas(engine)
    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create the application's session factory.

    ``expire_on_commit=False`` keeps loaded objects readable after the
    transaction commits — the deduplicator builds its outcome from
    application (Pydantic) state after the unit of work closes.
    """
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def run_migrations(engine: Engine, script_location: str | Path = ALEMBIC_SCRIPT_LOCATION) -> None:
    """Bring the database schema to Alembic ``head`` on ``engine``.

    Uses the engine's own connection so the app and the migrations share the
    exact same database and pool configuration. Idempotent: a database
    already at head is a no-op.
    """
    config = AlembicConfig()
    config.set_main_option("script_location", str(script_location))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.upgrade(config, "head")


__all__ = [
    "ALEMBIC_SCRIPT_LOCATION",
    "create_app_engine",
    "create_session_factory",
    "ensure_sqlite_directory",
    "run_migrations",
]
