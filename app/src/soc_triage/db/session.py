"""Transactional session handling (Phase 1D).

``session_scope`` is the single unit-of-work boundary used by the
persistence-backed components: everything inside one ``session_scope`` block
commits atomically or rolls back as a whole. No component opens its own
sessions ad hoc — that is what keeps multi-table writes (alert + dedupe
state + audit rows) transactionally consistent (ARCHITECTURE.md §16).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy.orm import Session, sessionmaker


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """Yield a session; commit on success, roll back on any error, always close.

    Raises:
        Exception: the original exception, after the transaction has been
            rolled back. Callers that must not leak internals should catch
            this and translate (see :mod:`soc_triage.db.errors`).
    """
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


__all__ = ["session_scope"]
