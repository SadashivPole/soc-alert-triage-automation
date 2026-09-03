"""Incident timeline assembly (Phase 3.3).

A **pure** helper: given already-loaded audit records, produce a
chronological, deterministic list of :class:`TimelineEvent`s. No I/O, no
clock, no mutation — GET ``/incidents/{id}/timeline`` is read-only by
construction (ARCHITECTURE.md §10, §15).

Ordering contract
-----------------
Events are sorted **strictly** by ``occurred_at`` ascending, with a
deterministic tie-breaker of ``(id, action, entity_type, entity_id)``.
``id`` is the append-only ``audit_log`` primary key, so equal timestamps
(common: ingest writes ``alert.created`` / ``alert.scored`` /
``alert.decided`` / ``incident.created`` in one clock tick) replay in
insertion order, identically across requests.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from .models.records import AuditRecord, TimelineEvent


def _as_utc(value: datetime) -> datetime:
    """Normalize a datetime to UTC (naive values are assumed to be UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _status_metadata(record: AuditRecord) -> dict[str, Any]:
    """Extract before/after status (and verdict) when the snapshots carry them."""
    metadata: dict[str, Any] = {}
    before = record.before or {}
    after = record.after or {}
    if "status" in before:
        metadata["before_status"] = before.get("status")
    if "status" in after:
        metadata["after_status"] = after.get("status")
    if "verdict" in after:
        metadata["verdict"] = after.get("verdict")
    if "severity" in after:
        metadata["severity"] = after.get("severity")
    return metadata


def _sort_key(record: AuditRecord) -> tuple[object, ...]:
    """Timestamp first, then a unique deterministic tie-breaker."""
    return (
        _as_utc(record.occurred_at),
        record.id,
        record.action,
        record.entity_type,
        record.entity_id,
    )


def build_timeline(records: Sequence[AuditRecord]) -> list[TimelineEvent]:
    """Map audit records onto a chronological, deterministic timeline.

    Snapshots are passed through as-is (they are already small and
    secret-free by audit policy). Equal timestamps keep a stable order.
    """
    events: list[TimelineEvent] = []
    for record in sorted(records, key=_sort_key):
        events.append(
            TimelineEvent(
                timestamp=_as_utc(record.occurred_at),
                action=record.action,
                entity_type=record.entity_type,
                entity_id=record.entity_id,
                actor=record.actor,
                before=record.before,
                after=record.after,
                metadata=_status_metadata(record),
            )
        )
    return events


__all__ = ["build_timeline"]
