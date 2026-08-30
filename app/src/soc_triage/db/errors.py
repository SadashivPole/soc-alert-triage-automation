"""Storage-layer error types (Phase 1D).

These exceptions deliberately carry **no database internals** — no URLs, file
paths, driver messages, or stack context. Routing layers translate them into
the shared error envelope (a retryable ``503``), while the structured log line
emitted by the storage layer itself records only the exception *type*
(ARCHITECTURE.md §16: DB unavailable → retryable 503, fail loud for the
pipeline, never leak internals to clients).
"""

from __future__ import annotations


class StorageError(RuntimeError):
    """A persistent-storage operation failed (connection, transaction, or I/O).

    Raised by the persistence-backed components after the offending
    transaction has been rolled back. Safe to expose: the message is a
    constant, caller-independent string.
    """


__all__ = ["StorageError"]
