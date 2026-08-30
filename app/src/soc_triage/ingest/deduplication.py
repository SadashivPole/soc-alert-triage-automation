"""Alert deduplication and idempotency logic.

Handles idempotent processing of exact duplicates, and groups repeated
alerts into the same deduplication window.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from enum import Enum
from typing import NamedTuple

from pydantic import BaseModel

from ..models.canonical import CanonicalDedupe
from .schemas import WazuhAlert


class DedupeStatus(Enum):
    """Result of the deduplication process."""

    EXACT_DUPLICATE = "exact_duplicate"
    REPEATED = "repeated"
    NEW_GENERATION = "new_generation"


class DedupeResult(NamedTuple):
    status: DedupeStatus
    dedupe_info: CanonicalDedupe


class DedupeGroupState(BaseModel):
    """In-memory state for a deduplication group."""

    group_key: str
    occurrences: int
    first_seen: datetime
    last_seen: datetime
    seen_events: set[str]


def compute_event_identity(alert: WazuhAlert) -> str:
    """Compute a deterministic identity for an alert event."""
    if alert.id:
        return f"wazuh:{alert.id}"

    parts = [alert.timestamp or "", alert.rule.id, alert.agent.id, alert.full_log or ""]
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(part.encode("utf-8"))
        hasher.update(b"|")
    return f"wazuh:hash:{hasher.hexdigest()}"


def compute_group_key(rule_id: str, agent_id: str) -> str:
    """Compute the deduplication group key."""
    return f"{rule_id}:{agent_id}"


class MemoryDeduplicator:
    """In-memory deduplication service for Phase 1C."""

    def __init__(self, window_seconds: int = 900):
        self.window = timedelta(seconds=window_seconds)
        self._groups: dict[str, DedupeGroupState] = {}

    def process_alert(
        self,
        alert: WazuhAlert,
        received_at: datetime,
    ) -> DedupeResult:
        """Process an alert for deduplication.

        Args:
            alert: The incoming Wazuh alert.
            received_at: The timestamp when the alert was received.

        Returns:
            DedupeResult with the status and the canonical dedupe info.
        """
        event_id = compute_event_identity(alert)
        group_key = compute_group_key(alert.rule.id, alert.agent.id)

        state = self._groups.get(group_key)

        if state is not None:
            # Check for exact duplicate
            if event_id in state.seen_events:
                # Idempotent: do not modify state
                return DedupeResult(
                    status=DedupeStatus.EXACT_DUPLICATE,
                    dedupe_info=CanonicalDedupe(
                        group_key=state.group_key,
                        occurrences=state.occurrences,
                        first_seen=state.first_seen,
                        last_seen=state.last_seen,
                    ),
                )

            # Check if window expired
            if received_at - state.last_seen > self.window:
                # New generation
                state = DedupeGroupState(
                    group_key=group_key,
                    occurrences=1,
                    first_seen=received_at,
                    last_seen=received_at,
                    seen_events={event_id},
                )
                self._groups[group_key] = state
                return DedupeResult(
                    status=DedupeStatus.NEW_GENERATION,
                    dedupe_info=CanonicalDedupe(
                        group_key=state.group_key,
                        occurrences=state.occurrences,
                        first_seen=state.first_seen,
                        last_seen=state.last_seen,
                    ),
                )

            # Repeated within window
            state.occurrences += 1
            state.last_seen = received_at
            state.seen_events.add(event_id)
            return DedupeResult(
                status=DedupeStatus.REPEATED,
                dedupe_info=CanonicalDedupe(
                    group_key=state.group_key,
                    occurrences=state.occurrences,
                    first_seen=state.first_seen,
                    last_seen=state.last_seen,
                ),
            )

        # Brand new group
        state = DedupeGroupState(
            group_key=group_key,
            occurrences=1,
            first_seen=received_at,
            last_seen=received_at,
            seen_events={event_id},
        )
        self._groups[group_key] = state
        return DedupeResult(
            status=DedupeStatus.NEW_GENERATION,
            dedupe_info=CanonicalDedupe(
                group_key=state.group_key,
                occurrences=state.occurrences,
                first_seen=state.first_seen,
                last_seen=state.last_seen,
            ),
        )
