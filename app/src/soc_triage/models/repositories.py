"""SQLAlchemy repositories (Phase 1D).

The **only** modules that import ORM objects. They translate between the
domain models (``GroupState`` / ``EventRecord`` / ``CanonicalAlert`` /
``AuditEntry`` / ``Incident``) and table rows inside the caller's session —
i.e. inside the caller's transaction (``db.session_scope``). Business logic
(the deduplicator, the API) never sees ORM objects, which keeps
database/session mechanics out of the domain (ARCHITECTURE.md §12).

Timestamp convention: all datetimes are normalized to UTC on write and on
read (SQLite stores naive values; treating them as UTC keeps window math
unambiguous across drivers).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..audit import AuditEntry
from ..ingest.deduplication import EventRecord, GroupState
from ..notifications.client import NotificationResult
from .assessment import DecisionSeverity
from .canonical import CanonicalAlert
from .incident import Incident as IncidentDomain
from .incident import IncidentStatus
from .orm import (
    Alert,
    AlertDedupeGroup,
    AlertEvent,
    AnalystFeedback,
    AuditEvent,
    Incident,
    NotificationAttempt,
)


def as_utc(value: datetime) -> datetime:
    """Normalize a datetime to UTC (naive values are assumed to be UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _event_to_record(event: AlertEvent, alert: Alert) -> EventRecord:
    """Rebuild a domain event record from its rows."""
    return EventRecord(
        event_identity=event.event_identity,
        alert_id=event.alert_id,
        payload_fingerprint=event.payload_fingerprint,
        canonical_alert=CanonicalAlert.model_validate(alert.normalized_payload),
        delivery_count=event.delivery_count,
        content_variants=event.content_variants,
        first_delivered_at=as_utc(event.first_delivered_at),
        last_delivered_at=as_utc(event.last_delivered_at),
    )


def _events_for_group(session: Session, group_key: str) -> list[EventRecord]:
    """Load a group's event records joined with their alert rows."""
    rows = session.execute(
        select(AlertEvent, Alert)
        .join(Alert, Alert.alert_id == AlertEvent.alert_id)
        .where(AlertEvent.group_key == group_key)
    ).all()
    return [_event_to_record(event, alert) for event, alert in rows]


class AlertRepository:
    """Read access to persisted alerts (of record)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, alert_id: uuid.UUID) -> CanonicalAlert | None:
        """Return the canonical alert stored for ``alert_id``, if any."""
        row = self._session.get(Alert, alert_id)
        if row is None:
            return None
        return CanonicalAlert.model_validate(row.normalized_payload)

    def update_normalized_payload(self, alert_id: uuid.UUID, canonical: CanonicalAlert) -> None:
        """Overwrite the alert of record's canonical payload (Phase 1F).

        Used to persist the risk assessment and decision back onto the alert
        row after scoring, so the alert of record carries its score/decision
        (ARCHITECTURE.md §5.2). Raises :class:`LookupError` if the alert row
        is missing — callers should only update alerts they just created.
        """
        row = self._session.get(Alert, alert_id)
        if row is None:
            raise LookupError(f"alert {alert_id} not found")
        row.normalized_payload = canonical.model_dump(mode="json")


class DedupeStateRepository:
    """Persistent storage for the deduplication recurrence state.

    ``load_state`` + ``record_event`` / ``absorb_event`` are designed to be
    called as a unit inside one transaction: read state → decide (pure
    domain logic) → write the resulting state, all-or-nothing.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def load_state(
        self, group_key: str, *, received: datetime, window_seconds: float
    ) -> GroupState | None:
        """Load a group's current state, pruning expired event records first.

        Pruning mirrors the in-memory contract: an event record is dropped
        once no delivery for it arrived within the window, so a re-delivery
        older than the window is fresh evidence, never a silent duplicate.
        The prune and the read happen in the caller's transaction.
        """
        horizon = as_utc(received)
        self._session.execute(
            delete(AlertEvent).where(
                AlertEvent.group_key == group_key,
                AlertEvent.last_delivered_at < horizon - timedelta(seconds=window_seconds),
            )
        )
        group_row = self._session.get(AlertDedupeGroup, group_key)
        if group_row is None:
            return None
        return self._group_state(group_row, _events_for_group(self._session, group_key))

    def group_state(self, group_key: str) -> GroupState | None:
        """Observability copy of a group's stored state (no pruning)."""
        group_row = self._session.get(AlertDedupeGroup, group_key)
        if group_row is None:
            return None
        return self._group_state(group_row, _events_for_group(self._session, group_key))

    def group_count(self) -> int:
        """Number of tracked deduplication groups."""
        return self._session.execute(select(func.count(AlertDedupeGroup.group_key))).scalar_one()

    # ------------------------------------------------------------------
    # Writes (inside the caller's transaction)
    # ------------------------------------------------------------------

    def record_event(self, *, group: GroupState, record: EventRecord) -> None:
        """Persist a *new* distinct event: its alert row, its idempotency
        record, and the group's updated recurrence state. All-or-nothing."""
        canonical = record.canonical_alert
        self._session.add(
            Alert(
                alert_id=record.alert_id,
                source=canonical.source,
                received_at=as_utc(canonical.received_at),
                dedupe_group_key=group.group_key,
                event_identity=record.event_identity,
                rule_id=canonical.source_event.rule.id,
                rule_level=canonical.source_event.rule.level,
                agent_id=canonical.source_event.agent.id,
                agent_name=canonical.source_event.agent.name,
                normalized_payload=canonical.model_dump(mode="json"),
                created_at=as_utc(record.first_delivered_at),
            )
        )
        self._session.add(
            AlertEvent(
                event_identity=record.event_identity,
                group_key=group.group_key,
                alert_id=record.alert_id,
                payload_fingerprint=record.payload_fingerprint,
                delivery_count=record.delivery_count,
                content_variants=record.content_variants,
                first_delivered_at=as_utc(record.first_delivered_at),
                last_delivered_at=as_utc(record.last_delivered_at),
            )
        )
        self._upsert_group(group)

    def absorb_event(self, *, group: GroupState, record: EventRecord) -> None:
        """Persist an exact-duplicate absorption: bump the event record's
        delivery counters and the group's ``duplicate_deliveries``. No new
        alert row, no recurrence change (idempotency contract)."""
        event_row = self._session.get(AlertEvent, record.event_identity)
        if event_row is None:  # pragma: no cover - defensive: load_state always sees it
            raise LookupError(f"event record {record.event_identity!r} is missing")
        event_row.payload_fingerprint = record.payload_fingerprint
        event_row.delivery_count = record.delivery_count
        event_row.content_variants = record.content_variants
        event_row.last_delivered_at = as_utc(record.last_delivered_at)
        self._upsert_group(group)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _upsert_group(self, group: GroupState) -> None:
        row = self._session.get(AlertDedupeGroup, group.group_key)
        if row is None:
            row = AlertDedupeGroup(group_key=group.group_key)
            self._session.add(row)
        row.occurrences = group.occurrences
        row.generation = group.generation
        row.first_seen = as_utc(group.first_seen) if group.first_seen is not None else None
        row.last_seen = as_utc(group.last_seen) if group.last_seen is not None else None
        row.duplicate_deliveries = group.duplicate_deliveries
        row.updated_at = as_utc(group.last_seen or group.first_seen or datetime.now(UTC))

    @staticmethod
    def _group_state(group_row: AlertDedupeGroup, events: list[EventRecord]) -> GroupState:
        return GroupState(
            group_key=group_row.group_key,
            occurrences=group_row.occurrences,
            first_seen=as_utc(group_row.first_seen) if group_row.first_seen is not None else None,
            last_seen=as_utc(group_row.last_seen) if group_row.last_seen is not None else None,
            generation=group_row.generation,
            duplicate_deliveries=group_row.duplicate_deliveries,
            events={record.event_identity: record for record in events},
        )


class IncidentRepository:
    """Persistence for first-class incidents (Phase 3.1).

    Called inside the caller's transaction (the same unit of work that persists
    the alert assessment), so incident creation, alert linking and audit rows
    commit or roll back together.

    Incident ids are ``INC-YYYY-MM-DD-NNNN``: sequential per UTC date, derived
    from the existing rows for that date (never random), which is safe under
    the normal single-instance SQLite lab usage this project targets
    (ARCHITECTURE.md §10).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def open_for_group(self, group_key: str) -> IncidentDomain | None:
        """The oldest open incident of a dedupe group, if any.

        Recurring/deduplicated alerts of the same rule+agent group attach to
        this incident instead of creating a second open incident.
        """
        row = self._session.execute(
            select(Incident)
            .where(Incident.dedupe_group_key == group_key)
            .where(Incident.status == IncidentStatus.OPEN.value)
            .order_by(Incident.created_at, Incident.incident_id)
            .limit(1)
        ).scalar_one_or_none()
        return self._to_domain(row) if row is not None else None

    def for_alert(self, alert_id: uuid.UUID) -> IncidentDomain | None:
        """The incident an alert is attached to (via its ``incident_id``)."""
        row = self._session.execute(
            select(Incident)
            .join(Alert, Alert.incident_id == Incident.incident_id)
            .where(Alert.alert_id == alert_id)
        ).scalar_one_or_none()
        return self._to_domain(row) if row is not None else None

    def get(self, incident_id: str) -> IncidentDomain | None:
        """Return one incident by its human-readable id, if any."""
        row = self._session.get(Incident, incident_id)
        return self._to_domain(row) if row is not None else None

    def all(self, *, limit: int | None = None) -> list[IncidentDomain]:
        """All incidents (for tests/observability), oldest first."""
        statement = select(Incident).order_by(Incident.created_at, Incident.incident_id)
        if limit is not None:
            statement = statement.limit(limit)
        return [self._to_domain(row) for row in self._session.scalars(statement)]

    def count(self) -> int:
        """Number of persisted incidents."""
        return self._session.execute(select(func.count(Incident.incident_id))).scalar_one()

    # ------------------------------------------------------------------
    # Writes (inside the caller's transaction)
    # ------------------------------------------------------------------

    def create(
        self,
        *,
        alert_id: uuid.UUID,
        severity: DecisionSeverity,
        dedupe_group_key: str,
        occurred_at: datetime,
    ) -> IncidentDomain:
        """Create a new open incident and link it to its primary alert.

        Raises:
            LookupError: if the alert row is missing (callers only create for
                alerts they just persisted).
        """
        alert_row = self._session.get(Alert, alert_id)
        if alert_row is None:
            raise LookupError(f"alert {alert_id} not found")
        incident_id = self._next_id(occurred_at)
        row = Incident(
            incident_id=incident_id,
            status=IncidentStatus.OPEN.value,
            severity=severity.value,
            primary_alert_id=alert_id,
            dedupe_group_key=dedupe_group_key,
            created_at=as_utc(occurred_at),
            updated_at=as_utc(occurred_at),
        )
        self._session.add(row)
        # Flush the new incident before touching the alert: the alert link and
        # ``primary_alert_id`` form a circular FK pair (alerts.incident_id ↔
        # incidents.primary_alert_id), so the incident row must exist before
        # the alert UPDATE is emitted (all inside the caller's transaction).
        self._session.flush()
        alert_row.incident_id = incident_id
        return self._to_domain(row)

    def attach(self, *, alert_id: uuid.UUID, incident_id: str) -> None:
        """Attach an alert to an existing incident (no new row).

        Used for recurring/deduplicated alerts that belong to an open incident
        of the same dedupe group. Raises :class:`LookupError` when either the
        alert or the incident does not exist.
        """
        if self.get(incident_id) is None:
            raise LookupError(f"incident {incident_id!r} not found")
        self._link_alert(alert_id, incident_id)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _link_alert(self, alert_id: uuid.UUID, incident_id: str) -> None:
        alert_row = self._session.get(Alert, alert_id)
        if alert_row is None:
            raise LookupError(f"alert {alert_id} not found")
        alert_row.incident_id = incident_id

    def _next_id(self, occurred_at: datetime) -> str:
        """Next ``INC-YYYY-MM-DD-NNNN`` id for the UTC date of ``occurred_at``.

        Sequential per UTC date: the max existing id for the date prefix plus
        one, zero-padded to four digits. Deterministic and collision-safe for
        the single-instance SQLite lab (an INSERT serializes with the same
        transaction; the next maximal id is only computed after this row is
        committed).
        """
        day = as_utc(occurred_at).strftime("%Y-%m-%d")
        prefix = f"INC-{day}-"
        last = self._session.execute(
            select(func.max(Incident.incident_id)).where(Incident.incident_id.like(f"{prefix}%"))
        ).scalar_one_or_none()
        sequence = int(str(last).rsplit("-", 1)[-1]) + 1 if last else 1
        return f"{prefix}{sequence:04d}"

    @staticmethod
    def _to_domain(row: Incident) -> IncidentDomain:
        return IncidentDomain(
            incident_id=row.incident_id,
            status=IncidentStatus(row.status),
            severity=DecisionSeverity(row.severity),
            primary_alert_id=row.primary_alert_id,
            dedupe_group_key=row.dedupe_group_key,
            created_at=as_utc(row.created_at),
            updated_at=as_utc(row.updated_at),
        )


class AuditRepository:
    """Append-only writer for the ``audit_log`` table.

    Exposes **only** :meth:`append` — there is deliberately no update or
    delete path (ARCHITECTURE.md §15: audit_log is the system of record).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, entries: Sequence[AuditEntry], *, occurred_at: datetime) -> None:
        """Insert audit entries (no-op for an empty sequence)."""
        for entry in entries:
            self._session.add(
                AuditEvent(
                    occurred_at=as_utc(occurred_at),
                    actor=entry.actor,
                    action=entry.action,
                    entity_type=entry.entity_type,
                    entity_id=entry.entity_id,
                    before=entry.before,
                    after=entry.after,
                )
            )

    def all(self, *, limit: int | None = None) -> list[AuditEvent]:
        """Read access for tests/observability (append-only, never mutated)."""
        statement = select(AuditEvent).order_by(AuditEvent.id)
        if limit is not None:
            statement = statement.limit(limit)
        return list(self._session.scalars(statement))


class NotificationRepository:
    """Persistence for n8n notification attempts (Phase 2B).

    One row per logical attempt (retries aggregated). Used for duplicate
    prevention and audit. The full payload is never stored — only a hash.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, result: NotificationResult, *, occurred_at: datetime) -> None:
        """Persist a notification result."""
        status = "delivered" if result.delivered else ("skipped" if result.skipped else "failed")
        # For attempted but not delivered, keep "failed" unless skipped
        if result.attempted and not result.delivered and not result.skipped:
            status = "failed"
        elif not result.attempted and result.skipped:
            status = "skipped"

        self._session.add(
            NotificationAttempt(
                alert_id=uuid.UUID(result.alert_id),
                attempted_at=as_utc(occurred_at),
                status=status,
                http_status=result.status_code,
                error_type=result.error_type,
                retry_count=result.attempts,
                payload_hash=result.payload_hash,
                webhook_host=result.webhook_host,
                duration_ms=result.duration_ms,
            )
        )

    def has_delivered(self, alert_id: uuid.UUID) -> bool:
        """Whether a successful delivery already exists for alert_id."""
        stmt = (
            select(NotificationAttempt.id)
            .where(NotificationAttempt.alert_id == alert_id)
            .where(NotificationAttempt.status == "delivered")
            .limit(1)
        )
        return self._session.execute(stmt).first() is not None

    def attempts_for(self, alert_id: uuid.UUID) -> list[NotificationAttempt]:
        """All attempts for an alert (for tests/observability)."""
        stmt = (
            select(NotificationAttempt)
            .where(NotificationAttempt.alert_id == alert_id)
            .order_by(NotificationAttempt.attempted_at)
        )
        return list(self._session.scalars(stmt))

    def all(self, *, limit: int | None = None) -> list[NotificationAttempt]:
        stmt = select(NotificationAttempt).order_by(NotificationAttempt.attempted_at)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self._session.scalars(stmt))


class FeedbackRepository:
    """Persistence for analyst feedback (Phase 2B)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(
        self,
        *,
        alert_id: uuid.UUID,
        actor: str,
        verdict: str,
        notes: str | None,
        received_at: datetime,
    ) -> AnalystFeedback:
        row = AnalystFeedback(
            alert_id=alert_id,
            received_at=as_utc(received_at),
            actor=actor,
            verdict=verdict,
            notes=notes,
        )
        self._session.add(row)
        return row

    def for_alert(self, alert_id: uuid.UUID) -> list[AnalystFeedback]:
        stmt = (
            select(AnalystFeedback)
            .where(AnalystFeedback.alert_id == alert_id)
            .order_by(AnalystFeedback.received_at)
        )
        return list(self._session.scalars(stmt))

    def all(self, *, limit: int | None = None) -> list[AnalystFeedback]:
        stmt = select(AnalystFeedback).order_by(AnalystFeedback.received_at)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self._session.scalars(stmt))


__all__ = [
    "AlertRepository",
    "AuditRepository",
    "DedupeStateRepository",
    "FeedbackRepository",
    "IncidentRepository",
    "NotificationRepository",
    "as_utc",
]
