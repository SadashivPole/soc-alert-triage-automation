"""Unit tests for the Phase 3.3 incident timeline helper.

The helper is pure: same inputs always produce the same ordered events.
Equal timestamps are ordered by the audit id (then action / entity).
"""

from __future__ import annotations

from datetime import UTC, datetime

from soc_triage.models.records import AuditRecord
from soc_triage.timeline import build_timeline

STAMP = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)


def _record(
    audit_id: int,
    action: str,
    *,
    occurred_at: datetime = STAMP,
    entity_type: str = "incident",
    entity_id: str = "INC-2026-09-03-0001",
    actor: str = "decisions",
    before: dict | None = None,
    after: dict | None = None,
) -> AuditRecord:
    return AuditRecord(
        id=audit_id,
        occurred_at=occurred_at,
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        before=before,
        after=after,
    )


def test_timeline_sorts_equal_timestamps_by_id() -> None:
    """Equal timestamps keep insertion order via the audit id tie-breaker."""
    later = datetime(2026, 9, 3, 12, 0, 5, tzinfo=UTC)
    records = [
        _record(
            4,
            "incident.status_updated",
            occurred_at=later,
            before={"status": "open"},
            after={"status": "investigating"},
        ),
        _record(2, "alert.scored", entity_type="alert", entity_id="a"),
        _record(1, "alert.created", entity_type="alert", entity_id="a"),
        _record(3, "incident.created", after={"status": "open"}),
    ]
    events = build_timeline(records)
    assert [event.action for event in events] == [
        "alert.created",
        "alert.scored",
        "incident.created",
        "incident.status_updated",
    ]
    # Byte-stable across calls.
    assert [e.model_dump(mode="json") for e in build_timeline(records)] == [
        e.model_dump(mode="json") for e in events
    ]


def test_timeline_extracts_before_after_status_metadata() -> None:
    events = build_timeline(
        [
            _record(
                1,
                "incident.status_updated",
                actor="analyst@example.com",
                before={"status": "open"},
                after={"status": "acknowledged", "verdict": None},
            )
        ]
    )
    assert events[0].metadata["before_status"] == "open"
    assert events[0].metadata["after_status"] == "acknowledged"
    assert events[0].actor == "analyst@example.com"


def test_timeline_is_empty_for_no_records() -> None:
    assert build_timeline([]) == []


def test_timeline_normalizes_naive_timestamps_as_utc() -> None:
    naive = datetime(2026, 9, 3, 12, 0, 0)
    events = build_timeline([_record(1, "incident.created", occurred_at=naive)])
    assert events[0].timestamp.tzinfo is not None
    assert events[0].timestamp.utcoffset().total_seconds() == 0
