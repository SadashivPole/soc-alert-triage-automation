"""Alert deduplication and idempotency (Phase 1C; persistence in Phase 1D).

Deterministic, unit-testable deduplication of incoming alerts. This module is
pure domain logic: it never imports FastAPI (ARCHITECTURE.md §12) and performs
no I/O. Routing layers only orchestrate it.

Definitions (ARCHITECTURE.md §6, §16):

* **Event identity** — a deterministic string that uniquely identifies the
  *source event* a delivery carries:
    * When Wazuh supplies an event ``id`` (its ``epoch.microsec`` alert id) the
      identity is ``wazuh:{id}:{rule_id}:{agent_id}`` — the idempotency key is
      bound to the rule/agent context so a re-delivery under the same id can
      never silently collapse divergent content.
    * Without an event id, the identity is a versioned SHA-256 content hash
      (``wazuh-h1:{digest}``) over the full validated payload, excluding
      volatile fields (``rule.firedtimes`` — a per-delivery counter that
      changes between re-fires of the same underlying event).
* **Deduplication group** — ``rule.id + agent.id``. Repeats of *distinct*
  events from the same rule on the same agent are recurrences of one alert.
* **Deduplication window** — a configurable sliding window (default 15 min,
  ``TRIAGE_DEDUPE_WINDOW_SECONDS``). An arrival is *within the window* when
  ``received_at - group.last_seen <= window``.

The three distinguishable outcomes:

* ``EXACT_DUPLICATE`` — same event identity re-delivered within the window
  since that event's previous delivery. **Idempotent**: the original canonical
  alert (same ``alert_id``) is returned unchanged; recurrence state
  (``occurrences``/``last_seen``) is *not* touched, so duplicate re-delivery
  can never extend the recurrence window. The delivery is still counted
  (``duplicate_deliveries``, per-event ``delivery_count``) — evidence is
  never silently discarded. If the same identity arrives with divergent
  content, the divergence is counted and logged as a warning.
* ``REPEATED`` — a distinct event for a group whose previous distinct event
  arrived within the window. ``occurrences`` increments, ``last_seen``
  advances (this is the recurrence signal used later by scoring).
* ``NEW_GENERATION`` — a group's first event, or a distinct event arriving
  after the window expired. A new generation starts: ``occurrences`` resets
  to 1, ``first_seen``/``last_seen`` reset, ``generation`` increments.

State retention is bounded by the window: event records are pruned once no
delivery for them arrived within the window, so an exact re-delivery older
than the window is treated as fresh evidence (a new occurrence), never as a
silent duplicate.

**Shared state machine.** :func:`decide_delivery` is the single, pure
implementation of the transitions above. Both storage backends build on it —
the in-memory :class:`InMemoryDeduplicator` (Phase 1C) and the persistence-
backed :class:`soc_triage.ingest.persistent_deduplication.PersistentDeduplicator`
(Phase 1D) — so the idempotency contract is reproduced exactly by the
database and restored after a restart.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import quote
from uuid import UUID

import structlog
from pydantic import BaseModel, Field

from ..models.canonical import CanonicalAlert, CanonicalDedupe
from .schemas import WazuhAlert

logger = structlog.get_logger("soc_triage.dedupe")

#: Hash algorithm version tag for content-based identities. Bump when the
#: identity payload layout changes (old identities then simply age out).
_IDENTITY_HASH_VERSION = "h1"

#: Volatile payload fields excluded from content identities: they vary between
#: deliveries of the same underlying event and must not split identity.
_VOLATILE_IDENTITY_FIELDS: tuple[tuple[str, ...], ...] = (
    ("rule", "firedtimes"),
    ("id",),  # absent by definition on the content-hash path
)


class DedupeStatus(StrEnum):
    """Result of deduplicating one delivery.

    Values are part of the API contract (``dedupe_status`` field).
    """

    NEW_GENERATION = "new_generation"
    EXACT_DUPLICATE = "exact_duplicate"
    REPEATED = "repeated"


class InvalidDedupeInputError(ValueError):
    """Raised when an alert or timestamp cannot yield a valid dedupe key.

    This is a *caller input* problem (e.g. blank rule/agent id, naive
    timestamp) and must be surfaced as a validation error, never swallowed —
    silently guessing an identity would risk discarding evidence.
    """


def _require_non_empty(value: str, field: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise InvalidDedupeInputError(f"{field} must be a non-empty string")
    return cleaned


def _require_aware(value: datetime, field: str) -> datetime:
    """Reject naive datetimes: window math must be unambiguous."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise InvalidDedupeInputError(f"{field} must be timezone-aware, got naive datetime")
    return value.astimezone(UTC)


def _quote_component(value: str) -> str:
    """Make a key component collision-proof while staying human-readable."""
    return quote(_require_non_empty(value, "key component"), safe="")


def compute_group_key(rule_id: str, agent_id: str) -> str:
    """Deterministic deduplication group key: ``wazuh:{rule}:{agent}``.

    Components are percent-encoded so ids containing separators cannot make
    two distinct (rule, agent) pairs collide.
    """
    return f"wazuh:{_quote_component(rule_id)}:{_quote_component(agent_id)}"


def _identity_payload(alert: WazuhAlert) -> dict[str, Any]:
    """Full validated payload with volatile fields removed, JSON-safe."""
    payload = alert.model_dump(mode="json")
    for path in _VOLATILE_IDENTITY_FIELDS:
        node: Any = payload
        for key in path[:-1]:
            nested = node.get(key) if isinstance(node, dict) else None
            if not isinstance(nested, dict):
                node = None
                break
            node = nested
        if isinstance(node, dict):
            node.pop(path[-1], None)
    return payload


def _canonical_json(payload: dict[str, Any]) -> str:
    """Stable JSON serialization: sorted keys, no incidental whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_payload_fingerprint(alert: WazuhAlert) -> str:
    """SHA-256 over the full validated payload (volatile fields excluded).

    Used as divergence evidence: deliveries sharing an event id but not a
    fingerprint are counted and logged, never silently merged.
    """
    digest = hashlib.sha256(_canonical_json(_identity_payload(alert)).encode("utf-8"))
    return digest.hexdigest()


def compute_event_identity(alert: WazuhAlert) -> str:
    """Deterministic identity of the source event carried by ``alert``.

    Raises:
        InvalidDedupeInputError: if the rule or agent id is blank.
    """
    rule_id = _require_non_empty(alert.rule.id, "rule.id")
    agent_id = _require_non_empty(alert.agent.id, "agent.id")
    event_id = (alert.id or "").strip()

    if event_id:
        return (
            f"wazuh:{_quote_component(event_id)}"
            f":{_quote_component(rule_id)}"
            f":{_quote_component(agent_id)}"
        )

    digest = hashlib.sha256(_canonical_json(_identity_payload(alert)).encode("utf-8"))
    return f"wazuh-{_IDENTITY_HASH_VERSION}:{digest.hexdigest()}"


class EventRecord(BaseModel):
    """Per-event-identity bookkeeping inside a deduplication group."""

    event_identity: str
    alert_id: UUID
    payload_fingerprint: str
    canonical_alert: CanonicalAlert
    delivery_count: int = Field(default=1, ge=1)
    content_variants: int = Field(default=1, ge=1)
    first_delivered_at: datetime
    last_delivered_at: datetime


class GroupState(BaseModel):
    """Mutable state of one deduplication group (``rule.id + agent.id``).

    ``occurrences`` counts *distinct events* in the current generation.
    ``events`` intentionally survives generation resets (pruned only by the
    per-event window horizon) so a re-delivery of a recent event stays
    idempotent even after other events reset the group.
    """

    group_key: str
    occurrences: int = Field(default=0, ge=0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    generation: int = Field(default=0, ge=0)
    duplicate_deliveries: int = Field(default=0, ge=0)
    events: dict[str, EventRecord] = Field(default_factory=dict)


class DedupeOutcome(BaseModel):
    """Immutable result of running one delivery through the deduplicator.

    ``canonical_alert`` is the alert of record for this delivery: the newly
    normalized alert (with its dedupe info embedded) for ``NEW_GENERATION`` /
    ``REPEATED``, or the *preserved* original canonical alert for
    ``EXACT_DUPLICATE`` — callers must respond with it to stay idempotent.
    """

    model_config = {"frozen": True}

    status: DedupeStatus
    alert_id: UUID
    group_key: str
    event_identity: str
    dedupe: CanonicalDedupe
    canonical_alert: CanonicalAlert


class DeliveryDecision(BaseModel):
    """Pure result of classifying one delivery (see :func:`decide_delivery`).

    Carries the resulting group and event record plus enough *before*
    snapshots for audit entries and for callers that want to observe what
    changed. ``group_before``/``record_before`` are ``None`` for a brand-new
    group or a first-seen event respectively.
    """

    model_config = {"frozen": True}

    status: DedupeStatus
    group: GroupState
    record: EventRecord
    group_before: GroupState | None = None
    record_before: EventRecord | None = None
    content_diverged: bool = False
    generation_started: bool = False


class Deduplicator(Protocol):
    """Deduplication contract implemented by storage backends."""

    def process(
        self,
        alert: WazuhAlert,
        canonical: CanonicalAlert,
        received_at: datetime,
    ) -> DedupeOutcome:
        """Classify one delivery and update recurrence state."""
        ...

    def group_state(self, group_key: str) -> GroupState | None:
        """Return a defensive copy of a group's state (observability/tests)."""
        ...

    def group_count(self) -> int:
        """Return the number of tracked groups (observability/tests)."""
        ...


def dedupe_info(group: GroupState, identity: str) -> CanonicalDedupe:
    """Build the canonical dedupe snapshot for the current group state."""
    return CanonicalDedupe(
        group_key=group.group_key,
        occurrences=group.occurrences,
        first_seen=_required(group.first_seen, group.group_key),
        last_seen=_required(group.last_seen, group.group_key),
        event_identity=identity,
        generation=group.generation,
        duplicate_deliveries=group.duplicate_deliveries,
    )


def _prune_expired(group: GroupState, now: datetime, window: timedelta) -> None:
    """Drop event records whose idempotency horizon (the window) passed."""
    expired = [
        identity
        for identity, record in group.events.items()
        if now - record.last_delivered_at > window
    ]
    for identity in expired:
        del group.events[identity]


def _new_event_record(
    canonical: CanonicalAlert,
    identity: str,
    fingerprint: str,
    dedupe: CanonicalDedupe,
    received: datetime,
) -> EventRecord:
    preserved = canonical.model_copy(update={"dedupe": dedupe})
    return EventRecord(
        event_identity=identity,
        alert_id=canonical.alert_id,
        payload_fingerprint=fingerprint,
        canonical_alert=preserved,
        first_delivered_at=received,
        last_delivered_at=received,
    )


def decide_delivery(
    group: GroupState | None,
    *,
    group_key: str,
    identity: str,
    fingerprint: str,
    received: datetime,
    window: timedelta,
    canonical: CanonicalAlert,
) -> DeliveryDecision:
    """Pure deduplication state machine for one delivery.

    ``group`` is the group's current state (``None`` if untracked); on return
    the decision's ``group`` is the authoritative new state. No I/O, no
    logging, no clocks — fully deterministic. Both storage backends share this
    function so the Phase 1C contract (idempotency, non-extending duplicates,
    window-bounded retention) holds identically in memory and in the database.
    """
    if group is None:
        new_group = GroupState(group_key=group_key)
        new_group.generation = 1
        new_group.occurrences = 1
        new_group.first_seen = received
        new_group.last_seen = received
        dedupe = dedupe_info(new_group, identity)
        record = _new_event_record(canonical, identity, fingerprint, dedupe, received)
        new_group.events[identity] = record
        return DeliveryDecision(
            status=DedupeStatus.NEW_GENERATION,
            group=new_group,
            record=record,
            generation_started=True,
        )

    _prune_expired(group, received, window)

    existing = group.events.get(identity)
    if existing is not None:
        # Absorb a re-delivery of a known event. Recurrence state
        # (occurrences/last_seen) deliberately does not change: duplicate
        # delivery must never extend the window or inflate recurrence. The
        # delivery is still counted — evidence is preserved.
        group_before = group.model_copy(deep=True)
        record_before = existing.model_copy(deep=True)
        existing.delivery_count += 1
        content_diverged = existing.payload_fingerprint != fingerprint
        if content_diverged:
            existing.content_variants += 1
            existing.payload_fingerprint = fingerprint
        existing.last_delivered_at = received
        group.duplicate_deliveries += 1
        return DeliveryDecision(
            status=DedupeStatus.EXACT_DUPLICATE,
            group=group,
            record=existing,
            group_before=group_before,
            record_before=record_before,
            content_diverged=content_diverged,
        )

    group_before = group.model_copy(deep=True)
    if received - _required(group.last_seen, group.group_key) > window:
        # Distinct event after the window: start a new generation.
        group.generation += 1
        group.occurrences = 1
        group.first_seen = received
        group.last_seen = received
        group.duplicate_deliveries = 0
        status = DedupeStatus.NEW_GENERATION
        generation_started = True
    else:
        # Distinct event within the window: a recurrence.
        group.occurrences += 1
        group.last_seen = received
        status = DedupeStatus.REPEATED
        generation_started = False

    dedupe = dedupe_info(group, identity)
    record = _new_event_record(canonical, identity, fingerprint, dedupe, received)
    group.events[identity] = record
    return DeliveryDecision(
        status=status,
        group=group,
        record=record,
        group_before=group_before,
        generation_started=generation_started,
    )


class InMemoryDeduplicator:
    """Thread-safe in-memory deduplicator (Phase 1C).

    All state transitions happen under a lock, so concurrent or repeated
    deliveries of the same event serialize deterministically: exactly one
    delivery creates the alert, every other delivery is an idempotent
    exact-duplicate response carrying the original ``alert_id``.
    """

    def __init__(self, window_seconds: int = 900) -> None:
        if window_seconds < 1:
            raise InvalidDedupeInputError("window_seconds must be >= 1")
        self._window = timedelta(seconds=window_seconds)
        self._groups: dict[str, GroupState] = {}
        self._lock = threading.RLock()

    @property
    def window(self) -> timedelta:
        """The configured deduplication window."""
        return self._window

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(
        self,
        alert: WazuhAlert,
        canonical: CanonicalAlert,
        received_at: datetime,
    ) -> DedupeOutcome:
        """Classify a delivery and update recurrence state.

        Args:
            alert: The validated source alert (identity inputs).
            canonical: The normalized canonical alert for this delivery. On
                ``NEW_GENERATION``/``REPEATED`` it is preserved (with dedupe
                info embedded) as the alert of record; on exact duplicates it
                is discarded in favor of the preserved original.
            received_at: Timezone-aware reception timestamp.

        Raises:
            InvalidDedupeInputError: on blank rule/agent ids or a naive
                ``received_at`` — never guess an identity.
        """
        identity = compute_event_identity(alert)
        group_key = compute_group_key(alert.rule.id, alert.agent.id)
        fingerprint = compute_payload_fingerprint(alert)
        received = _require_aware(received_at, "received_at")

        with self._lock:
            decision = decide_delivery(
                self._groups.get(group_key),
                group_key=group_key,
                identity=identity,
                fingerprint=fingerprint,
                received=received,
                window=self._window,
                canonical=canonical,
            )
            self._groups[decision.group.group_key] = decision.group

        if decision.status is DedupeStatus.EXACT_DUPLICATE:
            # Absorbed, not discarded: the delivery is counted and logged so
            # duplicate floods are observable without alert noise.
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
        """Return a deep copy of a group's state, or ``None`` if untracked."""
        with self._lock:
            state = self._groups.get(group_key)
            return state.model_copy(deep=True) if state else None

    def group_count(self) -> int:
        """Return the number of tracked groups."""
        with self._lock:
            return len(self._groups)


def _required(value: datetime | None, group_key: str) -> datetime:
    """Unwrap a group timestamp that construction always sets."""
    if value is None:  # pragma: no cover - defensive, groups always initialize
        raise InvalidDedupeInputError(f"group {group_key!r} is missing timestamps")
    return value


__all__ = [
    "DedupeOutcome",
    "DedupeStatus",
    "Deduplicator",
    "DeliveryDecision",
    "EventRecord",
    "GroupState",
    "InMemoryDeduplicator",
    "InvalidDedupeInputError",
    "compute_event_identity",
    "compute_group_key",
    "compute_payload_fingerprint",
    "decide_delivery",
    "dedupe_info",
]
