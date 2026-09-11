"""Cross-alert correlation orchestration (Phase 6.4).

:class:`CorrelationService` runs after a newly recorded alert (a
``NEW_GENERATION`` / ``REPEATED`` delivery — never an exact duplicate) has
been persisted with its assessment. It loads the alert of record, finds
*candidate* alerts within the correlation window (distinct alerts: different
``alert_id`` **and** different dedupe group), derives the deterministic
evidence for each candidate (:func:`soc_triage.correlation.evidence.
pairwise_evidence`), and — when the evidence policy permits — links the
alerts into one investigation context.

Relationship to the existing concepts (DEVELOPMENT_PLAN.md 6.4):

* **dedupe group / recurrence** — untouched: candidates from the alert's own
  group are excluded, so recurrence can never surface as correlation and
  ``compute_group_key`` semantics are unchanged;
* **incident** — untouched: correlation never reads or writes
  ``alerts.incident_id`` and never creates, attaches, merges or escalates
  incidents. A context is an investigation aid;
* **alert of record** — untouched: each member stays a distinct persisted
  alert; correlation only adds membership rows.

Window semantics
----------------

The correlation window (``TRIAGE_CORRELATION_WINDOW_SECONDS``, default 900 s,
explicitly configurable and deliberately independent from the dedupe window)
bounds *pairwise* evidence: two alerts are comparable when
``0 <= newer.received_at - older.received_at <= window`` (inclusive
boundary — the same convention the deduplicator uses). The window exists
because evidence gets weaker with time: an indicator shared by two alerts
hours apart describes at most a campaign, not one investigation. A context
itself may span longer than one window when evidence chains transitively
(alert A ↔ B within the window, later B ↔ C within the window): the context
records each pairwise relationship with its own evidence, so the analyst
sees exactly which pair justified which link.

Merging
-------

An alert belongs to at most one context (unique membership). When a newly
ingested alert presents qualifying evidence against members of two different
contexts, the contexts are joined — deterministically into the
earlier-created one (smallest ``context_id``; the ``CORR-YYYY-MM-DD-NNNN``
ids sort chronologically) — and the merge is audited. Contexts are never
merged without such bridging evidence, and incidents are never merged at
all.

Failure semantics
-----------------

Each :meth:`correlate` call is one transaction (all-or-nothing). Storage
failures are logged with the exception *type* only and surfaced as
:class:`StorageError`; the ingest pipeline treats correlation as fail-open —
a correlation failure can never reject or corrupt an alert
(ARCHITECTURE.md §16).
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from uuid import UUID

from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from ..audit import (
    audit_entry_for_correlation_alert_linked,
    audit_entry_for_correlation_context_created,
    audit_entry_for_correlation_contexts_merged,
)
from ..core.logging import get_logger
from ..db.errors import StorageError
from ..db.session import session_scope
from ..models.records import CorrelationEvidenceItem, PersistedAlert
from ..models.repositories import AlertRepository, AuditRepository, CorrelationRepository
from .evidence import (
    CORRELATION_POLICY_VERSION,
    EvidenceItem,
    evidence_reasons,
    is_sufficient,
    pairwise_evidence,
    sort_evidence,
)

logger = get_logger("soc_triage.correlation")


class InvalidCorrelationInputError(ValueError):
    """Raised when correlation inputs cannot yield a valid decision."""


def _require_aware(value: datetime, field: str) -> datetime:
    """Reject naive datetimes: window math must be unambiguous."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise InvalidCorrelationInputError(f"{field} must be timezone-aware, got naive datetime")
    return value.astimezone(UTC)


class CorrelationResult(BaseModel):
    """Outcome of correlating one newly recorded alert (immutable).

    ``context_id`` is the investigation context the alert joined (existing
    or new); ``linked_alert_ids`` are the peers the evidence related it to;
    ``evidence`` is the merged, deterministically ordered evidence list;
    ``merged_context_ids`` lists contexts that were joined into the target
    through this alert (empty in the normal case).
    """

    model_config = {"frozen": True}

    context_id: str
    alert_id: UUID
    linked_alert_ids: list[UUID] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    merged_context_ids: list[str] = Field(default_factory=list)


class CorrelationService:
    """Deterministic cross-alert correlation over the persistent store.

    Mirrors :class:`soc_triage.ingest.persistent_deduplication.
    PersistentDeduplicator`: a process-local lock serializes decisions, one
    transaction per alert, SQLAlchemy errors surfaced as :class:`StorageError`.
    """

    def __init__(self, session_factory: sessionmaker, *, window_seconds: int = 900) -> None:
        if window_seconds < 1:
            raise InvalidCorrelationInputError("window_seconds must be >= 1")
        self._window = timedelta(seconds=window_seconds)
        self._window_seconds = window_seconds
        self._session_factory = session_factory
        self._lock = threading.RLock()

    @property
    def window(self) -> timedelta:
        """The configured correlation window."""
        return self._window

    @property
    def window_seconds(self) -> int:
        """The configured correlation window, in seconds."""
        return self._window_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, *, alert_id: UUID, received_at: datetime) -> CorrelationResult | None:
        """Correlate one newly recorded alert; ``None`` when nothing matched.

        Runs only for alerts of record (the caller invokes it exclusively on
        non-duplicate deliveries). Exact duplicates never reach this method
        and can therefore never create or extend a context; the unique
        membership constraint plus an explicit guard also make repeated
        calls for the same alert idempotent no-ops.

        Raises:
            InvalidCorrelationInputError: on a naive ``received_at``.
            StorageError: if the storage operation failed; the transaction
                has been rolled back (correlation is fail-open upstream).
        """
        received = _require_aware(received_at, "received_at")
        with self._lock:
            try:
                with session_scope(self._session_factory) as session:
                    result = self._decide_and_apply(session, alert_id=alert_id, received=received)
            except SQLAlchemyError as exc:
                # session_scope already rolled back the unit of work. Log the
                # exception type only — never payload data or DB internals.
                logger.error(
                    "correlation_storage_failed",
                    component="correlation",
                    alert_id=str(alert_id),
                    error_type=type(exc).__name__,
                )
                raise StorageError("correlation storage operation failed") from exc

        if result is not None:
            logger.info(
                "correlation_linked",
                component="correlation",
                context_id=result.context_id,
                alert_id=str(alert_id),
                linked_alerts=len(result.linked_alert_ids),
                evidence=[item.reason for item in result.evidence],
                merged_contexts=len(result.merged_context_ids),
                policy=CORRELATION_POLICY_VERSION,
            )
        return result

    # ------------------------------------------------------------------
    # Internals (inside one transaction, under the lock)
    # ------------------------------------------------------------------

    def _decide_and_apply(
        self, session: Session, *, alert_id: UUID, received: datetime
    ) -> CorrelationResult | None:
        alert_repo = AlertRepository(session)
        repo = CorrelationRepository(session)

        # The alert of record must exist (the caller persisted it first) and
        # must not already be a member (idempotency guard — an alert joins at
        # most one context, exactly once).
        alert = alert_repo.get_alert(alert_id)
        if alert is None:
            logger.warning(
                "correlation_alert_missing",
                component="correlation",
                alert_id=str(alert_id),
            )
            return None
        if repo.membership_for_alert(alert_id) is not None:
            return None

        candidates = repo.candidates(
            received_at=received,
            window_seconds=self._window_seconds,
            exclude_alert_id=alert_id,
            exclude_group_key=alert.dedupe_group_key,
        )

        # Pairwise evidence against every candidate; keep only qualifying
        # pairs. An alert never correlates with itself (candidates exclude
        # its own alert_id) and never with its dedupe-group siblings.
        qualifying: list[tuple[PersistedAlert, list[EvidenceItem]]] = []
        for candidate in candidates:
            items = pairwise_evidence(alert.canonical, candidate.canonical)
            if items and is_sufficient(items):
                qualifying.append((candidate, items))
        if not qualifying:
            return None

        peer_ids = [candidate.alert_id for candidate, _ in qualifying]
        context_of = repo.context_ids_for_alerts(peer_ids)
        involved = sorted({context_of[peer] for peer in peer_ids if peer in context_of})

        audit_entries = []
        if not involved:
            context = repo.create_context(occurred_at=received)
            target_id = context.context_id
            merged_from: list[str] = []
            founding_reasons = evidence_reasons(
                sort_evidence([item for _, items in qualifying for item in items])
            )
            audit_entries.append(
                audit_entry_for_correlation_context_created(
                    context_id=target_id,
                    member_alert_ids=[alert_id, *peer_ids],
                    evidence_reasons=founding_reasons,
                )
            )
        else:
            # Deterministic target: the earliest-created context wins (the
            # CORR-YYYY-MM-DD-NNNN ids sort chronologically).
            target_id = involved[0]
            merged_from = []
            for other in involved[1:]:
                repo.move_members(source_context_id=other, target_context_id=target_id)
                merged_from.append(other)
                audit_entries.append(
                    audit_entry_for_correlation_contexts_merged(
                        kept_context_id=target_id,
                        merged_context_id=other,
                        bridge_alert_id=alert_id,
                    )
                )

        # New memberships: the new alert plus any qualifying peer that is
        # not yet a member of any context. Evidence is stored pairwise —
        # each item names the peer alert it was derived against.
        new_alert_evidence = [
            CorrelationEvidenceItem(
                evidence_type=item.evidence_type.value,
                value=item.value,
                peer_alert_id=str(candidate.alert_id),
            )
            for candidate, items in qualifying
            for item in items
        ]
        added: list[tuple[UUID, list[CorrelationEvidenceItem]]] = []
        for candidate, items in qualifying:
            peer_id = candidate.alert_id
            if peer_id in context_of:
                continue
            stored_for_peer = [
                CorrelationEvidenceItem(
                    evidence_type=item.evidence_type.value,
                    value=item.value,
                    peer_alert_id=str(alert_id),
                )
                for item in items
            ]
            repo.add_member(
                context_id=target_id,
                alert_id=peer_id,
                evidence=stored_for_peer,
                joined_at=received,
            )
            added.append((peer_id, stored_for_peer))
        repo.add_member(
            context_id=target_id,
            alert_id=alert_id,
            evidence=new_alert_evidence,
            joined_at=received,
        )
        added.append((alert_id, new_alert_evidence))

        repo.refresh_bounds(context_id=target_id, updated_at=received)
        for member_alert_id, stored in sorted(added, key=lambda pair: str(pair[0])):
            audit_entries.append(
                audit_entry_for_correlation_alert_linked(
                    context_id=target_id,
                    alert_id=member_alert_id,
                    evidence=stored,
                )
            )
        AuditRepository(session).append(audit_entries, occurred_at=received)

        all_items = sort_evidence([item for _, items in qualifying for item in items])
        return CorrelationResult(
            context_id=target_id,
            alert_id=alert_id,
            linked_alert_ids=sorted(peer_ids),
            evidence=all_items,
            merged_context_ids=merged_from,
        )


__all__ = [
    "CorrelationResult",
    "CorrelationService",
    "InvalidCorrelationInputError",
]
