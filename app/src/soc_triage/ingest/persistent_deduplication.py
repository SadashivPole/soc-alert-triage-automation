"""Persistence-backed deduplication (Phase 1D).

``PersistentDeduplicator`` implements the same :class:`Deduplicator`
contract as :class:`InMemoryDeduplicator`, but with SQLite as the system of
record: normalized alerts, deduplication recurrence state (occurrences,
generation, duplicate deliveries), per-event idempotency records, and audit
entries all survive an application restart.

**Contract reproduction.** The classification itself is the pure
:func:`decide_delivery` state machine shared with the in-memory
implementation (ARCHITECTURE.md §6: "a persistence-backed implementation must
reproduce this contract"), so:

* an exact duplicate returns the *original* ``alert_id`` and the preserved
  original canonical alert — idempotent across restarts;
* duplicate flooding never extends the deduplication window (recurrence
  state is untouched; only delivery counters advance);
* occurrence counts and generation information are persisted per group.

**Transactions.** Each delivery is one unit of work (``db.session_scope``):
read group state (with window-bounded pruning) → decide → write alert +
event + group state + audit rows → commit, or roll back everything on any
failure (ARCHITECTURE.md §16: DB failures are retryable, nothing is written
half-way). A process-local lock serializes decisions exactly like the
in-memory implementation, so concurrent deliveries resolve deterministically
(exactly one delivery creates an alert per identity; the rest are
idempotent duplicates).

**Error safety.** Database failures are logged (exception *type* only —
never payload data) and surfaced as the generic :class:`StorageError`,
which routing layers translate into a retryable 503 without leaking
internals.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from ..audit import audit_entries_for_decision
from ..core.logging import get_logger
from ..db.errors import StorageError
from ..db.session import session_scope
from ..models.canonical import CanonicalAlert
from ..models.repositories import AuditRepository, DedupeStateRepository
from .deduplication import (
    DedupeOutcome,
    DedupeStatus,
    GroupState,
    InvalidDedupeInputError,
    compute_event_identity,
    compute_group_key,
    compute_payload_fingerprint,
    decide_delivery,
    dedupe_info,
)
from .schemas import WazuhAlert

logger = get_logger("soc_triage.deduplication.persistent")


def _require_aware(value: datetime, field: str) -> datetime:
    """Reject naive datetimes: window math must be unambiguous."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise InvalidDedupeInputError(f"{field} must be timezone-aware, got naive datetime")
    return value


class PersistentDeduplicator:
    """Deduplication with SQLite persistence (Phase 1D).

    Implements the :class:`soc_triage.ingest.deduplication.Deduplicator`
    contract over the repositories in :mod:`soc_triage.models.repositories`.
    """

    def __init__(self, session_factory: sessionmaker, *, window_seconds: int = 900) -> None:
        if window_seconds < 1:
            raise InvalidDedupeInputError("window_seconds must be >= 1")
        self._window = timedelta(seconds=window_seconds)
        self._window_seconds = window_seconds
        self._session_factory = session_factory
        self._lock = threading.RLock()

    @property
    def window(self) -> timedelta:
        """The configured deduplication window."""
        return self._window

    # ------------------------------------------------------------------
    # Public API (Deduplicator contract)
    # ------------------------------------------------------------------

    def process(
        self,
        alert: WazuhAlert,
        canonical: CanonicalAlert,
        received_at: datetime,
    ) -> DedupeOutcome:
        """Classify a delivery and persist the resulting state atomically.

        Raises:
            InvalidDedupeInputError: on blank rule/agent ids or a naive
                ``received_at`` — never guess an identity (422 at the API).
            StorageError: if the storage operation failed; the transaction
                has been rolled back (503 at the API).
        """
        identity = compute_event_identity(alert)
        group_key = compute_group_key(alert.rule.id, alert.agent.id)
        fingerprint = compute_payload_fingerprint(alert)
        received = _require_aware(received_at, "received_at")

        with self._lock:
            try:
                with session_scope(self._session_factory) as session:
                    state = DedupeStateRepository(session)
                    group = state.load_state(
                        group_key, received=received, window_seconds=self._window_seconds
                    )
                    decision = decide_delivery(
                        group,
                        group_key=group_key,
                        identity=identity,
                        fingerprint=fingerprint,
                        received=received,
                        window=self._window,
                        canonical=canonical,
                    )
                    if decision.status is DedupeStatus.EXACT_DUPLICATE:
                        state.absorb_event(group=decision.group, record=decision.record)
                    else:
                        state.record_event(group=decision.group, record=decision.record)
                    AuditRepository(session).append(
                        audit_entries_for_decision(decision), occurred_at=received
                    )
            except SQLAlchemyError as exc:
                # session_scope already rolled back the unit of work. Log the
                # exception type only — never payload data or DB internals.
                logger.error(
                    "storage_operation_failed",
                    component="dedupe",
                    dedupe_group=group_key,
                    error_type=type(exc).__name__,
                )
                raise StorageError("persistent storage operation failed") from exc

        if decision.status is DedupeStatus.EXACT_DUPLICATE:
            # Absorbed, not discarded: counted and logged so duplicate floods
            # are observable without alert noise.
            logger.info(
                "duplicate_delivery_absorbed",
                component="dedupe",
                dedupe_group=decision.group.group_key,
                alert_id=str(decision.record.alert_id),
                occurrences=decision.group.occurrences,
                duplicate_deliveries=decision.group.duplicate_deliveries,
            )
        if decision.content_diverged:
            logger.warning(
                "duplicate_identity_content_divergence",
                component="dedupe",
                dedupe_group=decision.group.group_key,
                alert_id=str(decision.record.alert_id),
                variants=decision.record.content_variants,
            )

        return DedupeOutcome(
            status=decision.status,
            alert_id=decision.record.alert_id,
            group_key=decision.group.group_key,
            event_identity=identity,
            dedupe=dedupe_info(decision.group, identity),
            canonical_alert=decision.record.canonical_alert,
        )

    def group_state(self, group_key: str) -> GroupState | None:
        """Return a copy of a group's stored state, or ``None`` if untracked."""
        with self._lock:
            try:
                with session_scope(self._session_factory) as session:
                    return DedupeStateRepository(session).group_state(group_key)
            except SQLAlchemyError as exc:
                logger.error(
                    "storage_operation_failed",
                    component="dedupe",
                    dedupe_group=group_key,
                    error_type=type(exc).__name__,
                )
                raise StorageError("persistent storage operation failed") from exc

    def group_count(self) -> int:
        """Return the number of tracked groups."""
        with self._lock:
            try:
                with session_scope(self._session_factory) as session:
                    return DedupeStateRepository(session).group_count()
            except SQLAlchemyError as exc:
                logger.error(
                    "storage_operation_failed",
                    component="dedupe",
                    error_type=type(exc).__name__,
                )
                raise StorageError("persistent storage operation failed") from exc


__all__ = ["PersistentDeduplicator"]
