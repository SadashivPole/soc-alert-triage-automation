"""SQLAlchemy ORM models for persistent storage (Phase 1D + 2B).

Schema design (SQLite for the MVP; the same DDL runs on PostgreSQL later —
ARCHITECTURE.md §19):

* ``alerts`` — one row per *distinct source event* (i.e. per ``alert_id``).
  The full normalized (canonical) alert is stored in ``normalized_payload``
  so later phases (scoring, enrichment, console) see exactly what ingestion
  produced. Denormalized ``rule_*`` / ``agent_*`` columns support queries
  without decoding the JSON. ``incident_id`` (nullable FK) attaches an alert
  to the incident it belongs to (Phase 3.1).
* ``incidents`` — first-class incidents (Phase 3.1), created automatically
  when an alert decision is ``open_incident``: human-readable ``INC-YYYY-MM-DD-NNNN``
  id (sequential per UTC date, unique), severity (SEV1/SEV2), status
  (``open``), the primary alert it was opened from, and the dedupe group it
  belongs to (so recurring/deduplicated alerts attach to the existing open
  incident instead of creating duplicates).
* ``alert_dedupe_groups`` — the **recurrence / generation state** required by
  the Phase 1C deduplication contract (ARCHITECTURE.md §6): one row per
  deduplication group (``rule.id + agent.id``) carrying ``occurrences``,
  ``generation``, ``first_seen`` / ``last_seen`` and ``duplicate_deliveries``.
* ``alert_events`` — per-event-identity idempotency records (``delivery_count``,
  ``content_variants``, delivery timestamps). One row per event identity;
  identity embeds the rule+agent context, so it is globally unique. Pruned by
  the deduplication window (a stale re-delivery is fresh evidence, never a
  silent duplicate).
* ``audit_log`` — append-only audit trail (ARCHITECTURE.md §15): actor,
  action, entity, before/after JSON, timestamp. Repositories only ever INSERT
  here.
* ``notification_attempts`` — outbound n8n webhook attempts (Phase 2B):
  alert_id, status, http code, error type, retry count, payload hash,
  webhook host (never full URL/token). Used for duplicate notification
  prevention and audit.
* ``analyst_feedback`` — analyst acknowledgement/feedback via n8n callback
  (Phase 2B): alert_id, verdict, notes, actor, timestamp.

Timestamps are stored as UTC (normalized on write/read by the repositories).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all ORM models (Alembic target metadata)."""


class Alert(Base):
    """A normalized alert of record: one row per distinct source event."""

    __tablename__ = "alerts"

    alert_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    dedupe_group_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    event_identity: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_level: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Full canonical alert (``CanonicalAlert.model_dump(mode="json")``) as
    #: returned on the event's first delivery — the idempotency payload.
    normalized_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    #: Human-readable incident id this alert belongs to (nullable: alerts that
    #: never triggered ``open_incident`` stay unattached). Set by
    #: :class:`IncidentRepository` when an incident is created or attached.
    incident_id: Mapped[str | None] = mapped_column(
        String(32),
        ForeignKey("incidents.incident_id", name="fk_alerts_incident_id"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Incident(Base):
    """First-class incident, opened automatically for ``open_incident`` decisions.

    The human-readable ``incident_id`` (``INC-YYYY-MM-DD-NNNN``) is sequential
    per UTC date and unique; it is the stable key the alert link and audit
    entries reference. ``primary_alert_id`` is the alert that triggered the
    incident; ``dedupe_group_key`` is the rule+agent recurrence group the
    incident belongs to, so recurring/deduplicated alerts of the same group
    attach to the existing *open* incident instead of creating duplicates
    (Phase 3.1).
    """

    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_group_status", "dedupe_group_key", "status"),)

    incident_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    #: Incident lifecycle status (Phase 3.1 only creates ``open`` rows).
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    #: SEV1 (critical) / SEV2 (high) as decided by the decision engine.
    severity: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    primary_alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("alerts.alert_id"), nullable=False, unique=True, index=True
    )
    dedupe_group_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AlertDedupeGroup(Base):
    """Recurrence and generation state of one deduplication group.

    Mirrors :class:`soc_triage.ingest.deduplication.GroupState` so the
    persistence-backed deduplicator can restore the exact Phase 1C contract
    after a restart: window math, occurrence counters, and generation resets
    all survive process death.
    """

    __tablename__ = "alert_dedupe_groups"

    group_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duplicate_deliveries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AlertEvent(Base):
    """Idempotency record for one event identity inside a dedupe group.

    Bounded by the window: rows whose ``last_delivered_at`` falls outside the
    deduplication horizon are pruned on the next delivery for the group, so a
    re-delivery older than the window is treated as fresh evidence.
    """

    __tablename__ = "alert_events"
    __table_args__ = (
        Index("ix_alert_events_group_last_delivered", "group_key", "last_delivered_at"),
    )

    event_identity: Mapped[str] = mapped_column(String(512), primary_key=True)
    group_key: Mapped[str] = mapped_column(
        String(255),
        ForeignKey("alert_dedupe_groups.group_key", ondelete="CASCADE"),
        nullable=False,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("alerts.alert_id"), nullable=False, unique=True, index=True
    )
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    delivery_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    content_variants: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_delivered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_delivered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEvent(Base):
    """One append-only audit entry (``audit_log`` table).

    ``before``/``after`` carry small structured snapshots of the state change
    (counts, ids, timestamps) — never raw alert payloads or secrets
    (SECURITY.md §5, §7).
    """

    __tablename__ = "audit_log"

    #: BigInteger for PostgreSQL parity; SQLite autoincrement requires INTEGER.
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    before: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class NotificationAttempt(Base):
    """Outbound n8n notification attempt (Phase 2B).

    One row per attempt (including retries aggregated as one logical attempt
    with ``retry_count``). The full payload is **never** stored — only a hash
    and safe metadata (host, status). This prevents secret leakage and
    avoids storing large blobs (SECURITY.md §5).
    """

    __tablename__ = "notification_attempts"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("alerts.alert_id"), nullable=False, index=True
    )
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    webhook_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AnalystFeedback(Base):
    """Analyst acknowledgement / feedback via n8n callback (Phase 2B).

    Stores the analyst verdict for an alert. Verdicts are audited and can
    feed future tuning (ARCHITECTURE.md §10). No destructive actions are
    stored here — only human decisions.
    """

    __tablename__ = "analyst_feedback"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("alerts.alert_id"), nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    notes: Mapped[str | None] = mapped_column(String(2000), nullable=True)


__all__ = [
    "Alert",
    "AlertDedupeGroup",
    "AlertEvent",
    "AnalystFeedback",
    "AuditEvent",
    "Base",
    "Incident",
    "NotificationAttempt",
]
