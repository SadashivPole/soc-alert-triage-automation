"""Database layer (Phase 1D): engine bootstrap, transactions, storage errors.

Layering (ARCHITECTURE.md §12): this package owns *how* database access works
(engine, pool, transactions). ORM objects live in :mod:`soc_triage.models`
and only :mod:`soc_triage.models.repositories` (plus Alembic migrations) ever
touch them.
"""

from .engine import (
    ALEMBIC_SCRIPT_LOCATION,
    create_app_engine,
    create_session_factory,
    ensure_sqlite_directory,
    run_migrations,
)
from .errors import StorageError
from .session import session_scope

__all__ = [
    "ALEMBIC_SCRIPT_LOCATION",
    "StorageError",
    "create_app_engine",
    "create_session_factory",
    "ensure_sqlite_directory",
    "run_migrations",
    "session_scope",
]
