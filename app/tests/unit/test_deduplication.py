"""Unit tests for alert deduplication and idempotency (Phase 1C).

Covers the required contract: first alert, exact duplicate, repeated within
window, occurrence increments, alert outside the window, different agent/rule
combinations, invalid identity inputs, and concurrent/repeated delivery —
plus identity determinism and evidence-preservation guarantees.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from soc_triage.ingest.deduplication import (
    DedupeStatus,
    InMemoryDeduplicator,
    InvalidDedupeInputError,
    compute_event_identity,
    compute_group_key,
    compute_payload_fingerprint,
)
from soc_triage.ingest.normalizer import normalize_wazuh_alert
from soc_triage.ingest.schemas import WazuhAlert
from soc_triage.models.canonical import CanonicalDedupe

T0 = datetime(2026, 8, 29, 10, 15, 0, tzinfo=UTC)
WINDOW = 900  # 15 minutes


def build_alert(overrides: dict[str, Any] | None = None) -> WazuhAlert:
    """Return a valid Wazuh alert with optional field overrides."""
    payload: dict[str, Any] = {
        "id": "1770000000.100001",
        "timestamp": "2026-08-29T10:15:29.000+0000",
        "rule": {
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "id": "5710",
            "firedtimes": 1,
        },
        "agent": {"id": "001", "name": "web-prod-01"},
        "data": {"srcip": "203.0.113.50", "dstuser": "admin"},
        "location": "/var/log/auth.log",
        "full_log": "Failed password for admin from 203.0.113.50",
    }
    if overrides:
        payload = deep_merge(payload, overrides)
    return WazuhAlert.model_validate(payload)


def identity_of(alert: WazuhAlert) -> str:
    """Shorthand for the deterministic event identity in tests."""
    return compute_event_identity(alert)


def deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge dicts so tests can override nested alert fields."""
    merged = json.loads(json.dumps(base))
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class Harness:
    """Small helper bundling a deduplicator with a process() shortcut."""

    def __init__(self, window_seconds: int = WINDOW) -> None:
        self.dedup = InMemoryDeduplicator(window_seconds=window_seconds)

    def deliver(
        self,
        alert: WazuhAlert,
        at: datetime,
        *,
        alert_id: Any = None,
    ):
        canonical = normalize_wazuh_alert(alert, received_at=at, alert_id=alert_id)
        return self.dedup.process(alert, canonical, at)


@pytest.fixture
def harness() -> Harness:
    return Harness()


@pytest.fixture
def sample_alert() -> WazuhAlert:
    return build_alert()


# ---------------------------------------------------------------------------
# Deterministic event identity
# ---------------------------------------------------------------------------


def test_identity_uses_wazuh_event_id_when_present(sample_alert: WazuhAlert) -> None:
    identity = compute_event_identity(sample_alert)
    assert identity == "wazuh:1770000000.100001:5710:001"


def test_identity_is_deterministic_across_instances() -> None:
    first = compute_event_identity(build_alert())
    second = compute_event_identity(build_alert())
    assert first == second


def test_identity_without_event_id_is_stable_content_hash() -> None:
    alert = build_alert({"id": None})
    identity = compute_event_identity(alert)
    assert identity.startswith("wazuh-h1:")
    assert compute_event_identity(build_alert({"id": None})) == identity


def test_identity_without_event_id_distinguishes_different_events() -> None:
    base = build_alert({"id": None})
    other_ip = build_alert({"id": None, "data": {"srcip": "198.51.100.9"}})
    assert compute_event_identity(base) != compute_event_identity(other_ip)


def test_identity_ignores_volatile_firedtimes_counter() -> None:
    """firedtimes changes between re-fires; it must not split identity."""
    without_id = build_alert({"id": None})
    refired = build_alert({"id": None, "rule": {"firedtimes": 8}})
    assert compute_event_identity(without_id) == compute_event_identity(refired)


def test_identity_is_key_order_independent() -> None:
    a = build_alert({"id": None})
    reordered = WazuhAlert.model_validate(
        {
            "full_log": "Failed password for admin from 203.0.113.50",
            "location": "/var/log/auth.log",
            "data": {"dstuser": "admin", "srcip": "203.0.113.50"},
            "agent": {"name": "web-prod-01", "id": "001"},
            "rule": {
                "firedtimes": 1,
                "id": "5710",
                "description": "sshd: Attempt to login using a non-existent user",
                "level": 5,
            },
            "timestamp": "2026-08-29T10:15:29.000+0000",
            "id": None,
        }
    )
    assert compute_event_identity(a) == compute_event_identity(reordered)


def test_payload_fingerprint_detects_divergent_content() -> None:
    base = build_alert()
    divergent = build_alert({"full_log": "Failed password for root from 203.0.113.50"})
    assert compute_payload_fingerprint(base) != compute_payload_fingerprint(divergent)
    assert compute_payload_fingerprint(base) == compute_payload_fingerprint(build_alert())


def test_group_key_combines_rule_and_agent() -> None:
    assert compute_group_key("5710", "001") == "wazuh:5710:001"


def test_group_key_components_cannot_collide() -> None:
    """Separator-containing ids must not produce colliding group keys."""
    assert compute_group_key("5:1", "0:01") != compute_group_key("5", "10:01")
    assert compute_group_key("a:b", "c") != compute_group_key("a", "b:c")


# ---------------------------------------------------------------------------
# First alert / exact duplicate / repeated / window semantics
# ---------------------------------------------------------------------------


def test_first_alert_starts_new_generation(harness: Harness, sample_alert: WazuhAlert) -> None:
    outcome = harness.deliver(sample_alert, T0)

    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert outcome.dedupe.occurrences == 1
    assert outcome.dedupe.group_key == "wazuh:5710:001"
    assert outcome.dedupe.first_seen == T0
    assert outcome.dedupe.last_seen == T0
    assert outcome.dedupe.generation == 1
    assert outcome.dedupe.duplicate_deliveries == 0
    assert outcome.canonical_alert.alert_id == outcome.alert_id
    # The canonical alert carries its dedupe snapshot.
    assert outcome.canonical_alert.dedupe is not None
    assert outcome.canonical_alert.dedupe.occurrences == 1


def test_exact_duplicate_is_idempotent(harness: Harness, sample_alert: WazuhAlert) -> None:
    first = harness.deliver(sample_alert, T0)
    duplicate = harness.deliver(sample_alert, T0 + timedelta(seconds=10))

    assert duplicate.status is DedupeStatus.EXACT_DUPLICATE
    # Same alert of record, same id: the delivery is idempotent.
    assert duplicate.alert_id == first.alert_id
    assert duplicate.canonical_alert == first.canonical_alert
    # Recurrence state untouched...
    assert duplicate.dedupe.occurrences == 1
    assert duplicate.dedupe.last_seen == T0
    # ...but the delivery is still counted (evidence preserved).
    assert duplicate.dedupe.duplicate_deliveries == 1
    group = harness.dedup.group_state("wazuh:5710:001")
    assert group is not None
    assert group.events[identity_of(sample_alert)].delivery_count == 2


def test_exact_duplicate_does_not_extend_window(harness: Harness) -> None:
    """Re-delivery of the same event must not keep the group alive forever."""
    alert_a = build_alert()
    alert_b = build_alert({"id": "1770000000.100002"})

    harness.deliver(alert_a, T0)
    # Duplicate flood of A well into what would otherwise be the window...
    harness.deliver(alert_a, T0 + timedelta(seconds=800))
    # ...so a genuinely new event just past the original window still resets:
    outcome = harness.deliver(alert_b, T0 + timedelta(seconds=901))

    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert outcome.dedupe.occurrences == 1
    assert outcome.dedupe.generation == 2


def test_repeated_alert_within_window_increments_occurrences(
    harness: Harness, sample_alert: WazuhAlert
) -> None:
    first = harness.deliver(sample_alert, T0)
    second_event = build_alert({"id": "1770000000.100002"})
    at = T0 + timedelta(seconds=60)

    outcome = harness.deliver(second_event, at)

    assert outcome.status is DedupeStatus.REPEATED
    assert outcome.dedupe.occurrences == 2
    assert outcome.dedupe.first_seen == T0
    assert outcome.dedupe.last_seen == at
    # Each distinct event keeps its own alert id.
    assert outcome.alert_id != first.alert_id


def test_occurrences_increment_across_sequence(harness: Harness) -> None:
    for index in range(1, 6):
        alert = build_alert({"id": f"1770000000.1000{index}"})
        outcome = harness.deliver(alert, T0 + timedelta(seconds=index * 10))
        assert outcome.dedupe.occurrences == index
        if index > 1:
            assert outcome.status is DedupeStatus.REPEATED
    # A duplicate re-delivery of the first event must not bump the counter.
    repeat = harness.deliver(build_alert({"id": "1770000000.10001"}), T0 + timedelta(seconds=90))
    assert repeat.status is DedupeStatus.EXACT_DUPLICATE
    group = harness.dedup.group_state("wazuh:5710:001")
    assert group is not None
    assert group.occurrences == 5
    assert group.duplicate_deliveries == 1


def test_repeated_alert_keeps_distinct_alert_ids(harness: Harness) -> None:
    first = harness.deliver(build_alert(), T0)
    second = harness.deliver(build_alert({"id": "1770000000.100002"}), T0 + timedelta(seconds=5))
    assert first.alert_id != second.alert_id


def test_alert_outside_window_starts_new_generation(harness: Harness) -> None:
    harness.deliver(build_alert(), T0)
    later_event = build_alert({"id": "1770000000.100002"})
    way_later = T0 + timedelta(seconds=WINDOW + 1)

    outcome = harness.deliver(later_event, way_later)

    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert outcome.dedupe.occurrences == 1
    assert outcome.dedupe.first_seen == way_later
    assert outcome.dedupe.last_seen == way_later
    assert outcome.dedupe.generation == 2


def test_alert_exactly_at_window_boundary_is_within(harness: Harness) -> None:
    """Window is inclusive: received_at - last_seen == window is a repeat."""
    harness.deliver(build_alert(), T0)
    outcome = harness.deliver(
        build_alert({"id": "1770000000.100002"}), T0 + timedelta(seconds=WINDOW)
    )
    assert outcome.status is DedupeStatus.REPEATED
    assert outcome.dedupe.occurrences == 2


def test_exact_duplicate_after_other_events_still_idempotent(harness: Harness) -> None:
    """A re-delivery is matched by identity even with intervening events."""
    alert_a = build_alert()
    alert_b = build_alert({"id": "1770000000.100002"})
    alert_c = build_alert({"id": "1770000000.100003"})

    first_a = harness.deliver(alert_a, T0)
    harness.deliver(alert_b, T0 + timedelta(seconds=30))
    harness.deliver(alert_c, T0 + timedelta(seconds=60))
    duplicate_a = harness.deliver(alert_a, T0 + timedelta(seconds=400))

    assert duplicate_a.status is DedupeStatus.EXACT_DUPLICATE
    assert duplicate_a.alert_id == first_a.alert_id
    assert duplicate_a.canonical_alert == first_a.canonical_alert
    group = harness.dedup.group_state("wazuh:5710:001")
    assert group is not None
    assert group.occurrences == 3
    assert group.duplicate_deliveries == 1


def test_exact_duplicate_within_window_after_burst(harness: Harness) -> None:
    alert_a = build_alert()
    harness.deliver(alert_a, T0)
    late_duplicate = harness.deliver(alert_a, T0 + timedelta(seconds=WINDOW))
    assert late_duplicate.status is DedupeStatus.EXACT_DUPLICATE


def test_redelivery_beyond_window_is_fresh_evidence(harness: Harness) -> None:
    """Past the identity horizon the event is treated as new, never swallowed."""
    alert = build_alert()
    first = harness.deliver(alert, T0)

    outcome = harness.deliver(alert, T0 + timedelta(seconds=WINDOW + 1))

    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert outcome.alert_id != first.alert_id
    assert outcome.dedupe.occurrences == 1


def test_duplicate_content_divergence_is_counted(harness: Harness) -> None:
    """Same identity, different content: counted, never silently merged."""
    alert = build_alert()
    harness.deliver(alert, T0)
    mutated = build_alert({"full_log": "Failed password for ROOT from 203.0.113.50"})

    outcome = harness.deliver(mutated, T0 + timedelta(seconds=10))

    assert outcome.status is DedupeStatus.EXACT_DUPLICATE
    group = harness.dedup.group_state("wazuh:5710:001")
    assert group is not None
    record = group.events[compute_event_identity(alert)]
    assert record.content_variants == 2
    assert record.delivery_count == 2


def test_generation_resets_duplicate_counter(harness: Harness) -> None:
    harness.deliver(build_alert(), T0)
    harness.deliver(build_alert(), T0 + timedelta(seconds=5))
    after_window = harness.deliver(
        build_alert({"id": "1770000000.100002"}), T0 + timedelta(seconds=WINDOW + 1)
    )
    assert after_window.dedupe.generation == 2
    assert after_window.dedupe.duplicate_deliveries == 0


# ---------------------------------------------------------------------------
# Different agent / rule combinations
# ---------------------------------------------------------------------------


def test_different_agents_form_separate_groups(harness: Harness, sample_alert: WazuhAlert) -> None:
    harness.deliver(sample_alert, T0)
    other_agent = build_alert({"id": "1770000000.100002", "agent": {"id": "002"}})

    outcome = harness.deliver(other_agent, T0)

    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert outcome.dedupe.group_key == "wazuh:5710:002"
    assert outcome.dedupe.occurrences == 1
    assert harness.dedup.group_count() == 2


def test_different_rules_form_separate_groups(harness: Harness, sample_alert: WazuhAlert) -> None:
    harness.deliver(sample_alert, T0)
    other_rule = build_alert({"id": "1770000000.100002", "rule": {"id": "5402", "level": 7}})

    outcome = harness.deliver(other_rule, T0)

    assert outcome.status is DedupeStatus.NEW_GENERATION
    assert outcome.dedupe.group_key == "wazuh:5402:001"
    assert harness.dedup.group_count() == 2


def test_same_payload_different_agent_is_not_exact_duplicate(
    harness: Harness, sample_alert: WazuhAlert
) -> None:
    """Identity binds the event id to rule+agent context (evidence safety)."""
    harness.deliver(sample_alert, T0)
    spoofed = build_alert({"agent": {"id": "002"}})

    outcome = harness.deliver(spoofed, T0 + timedelta(seconds=5))

    assert outcome.status is not DedupeStatus.EXACT_DUPLICATE
    assert outcome.dedupe.group_key == "wazuh:5710:002"


def test_recurrence_isolated_per_group(harness: Harness) -> None:
    for agent in ("001", "002", "003"):
        harness.deliver(build_alert({"agent": {"id": agent}}), T0)
        harness.deliver(
            build_alert({"id": "1770000000.100002", "agent": {"id": agent}}),
            T0 + timedelta(seconds=30),
        )
    for agent in ("001", "002", "003"):
        group = harness.dedup.group_state(f"wazuh:5710:{agent}")
        assert group is not None
        assert group.occurrences == 2


# ---------------------------------------------------------------------------
# Invalid identity inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule": {"id": ""}},
        {"rule": {"id": "   "}},
        {"agent": {"id": ""}},
        {"agent": {"id": "  \t "}},
    ],
)
def test_blank_rule_or_agent_id_rejected(overrides: dict[str, Any]) -> None:
    alert = build_alert(overrides)
    with pytest.raises(InvalidDedupeInputError):
        compute_event_identity(alert)
    with pytest.raises(InvalidDedupeInputError):
        compute_group_key(alert.rule.id, alert.agent.id)


def test_blank_event_id_falls_back_to_content_hash() -> None:
    alert = build_alert({"id": ""})
    assert compute_event_identity(alert).startswith("wazuh-h1:")


def test_naive_received_at_rejected(harness: Harness, sample_alert: WazuhAlert) -> None:
    canonical = normalize_wazuh_alert(sample_alert, received_at=T0)
    naive = datetime(2026, 8, 29, 10, 16, 0)  # no tzinfo
    with pytest.raises(InvalidDedupeInputError):
        harness.dedup.process(sample_alert, canonical, naive)


def test_zero_or_negative_window_rejected() -> None:
    with pytest.raises(InvalidDedupeInputError):
        InMemoryDeduplicator(window_seconds=0)
    with pytest.raises(InvalidDedupeInputError):
        InMemoryDeduplicator(window_seconds=-5)


def test_non_utc_offsets_normalized(harness: Harness) -> None:
    """Same instant expressed in another timezone must behave identically."""
    ist = timezone(timedelta(hours=5, minutes=30))
    first = harness.deliver(build_alert(), T0)
    same_instant_ist = harness.deliver(build_alert(), T0.astimezone(ist))
    assert same_instant_ist.status is DedupeStatus.EXACT_DUPLICATE
    assert same_instant_ist.alert_id == first.alert_id
    group = harness.dedup.group_state("wazuh:5710:001")
    assert group is not None
    # Stored timestamps normalize to UTC regardless of input offset.
    assert group.first_seen is not None and group.first_seen.utcoffset() == timedelta(0)


# ---------------------------------------------------------------------------
# Canonical alert preservation & dedupe model
# ---------------------------------------------------------------------------


def test_preserved_canonical_alert_keeps_source_evidence(
    harness: Harness, sample_alert: WazuhAlert
) -> None:
    outcome = harness.deliver(sample_alert, T0)
    duplicate = harness.deliver(sample_alert, T0 + timedelta(seconds=15))

    preserved = duplicate.canonical_alert
    assert preserved == outcome.canonical_alert
    assert preserved.source_event.full_log == sample_alert.full_log
    assert preserved.source_event.location == sample_alert.location
    assert preserved.source_event.agent.id == sample_alert.agent.id
    assert preserved.source_event.rule.id == sample_alert.rule.id
    assert preserved.dedupe is not None
    assert preserved.dedupe.event_identity == compute_event_identity(sample_alert)


def test_canonical_dedupe_defaults_stay_backward_compatible() -> None:
    at = T0
    info = CanonicalDedupe(group_key="wazuh:5710:001", first_seen=at, last_seen=at)
    assert info.occurrences == 1
    assert info.generation == 1
    assert info.duplicate_deliveries == 0
    assert info.event_identity is None


def test_canonical_alert_is_frozen_after_dedupe(harness: Harness) -> None:
    from pydantic import ValidationError as PydanticValidationError

    outcome = harness.deliver(build_alert(), T0)
    with pytest.raises((PydanticValidationError, TypeError, AttributeError)):
        outcome.canonical_alert.dedupe.occurrences = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Concurrent / repeated delivery
# ---------------------------------------------------------------------------


def test_repeated_rapid_delivery_is_idempotent(harness: Harness) -> None:
    """20 deliveries of the same event: one alert, 19 counted duplicates."""
    alert = build_alert()
    outcomes = [harness.deliver(alert, T0 + timedelta(milliseconds=i)) for i in range(20)]

    assert outcomes[0].status is DedupeStatus.NEW_GENERATION
    assert all(o.status is DedupeStatus.EXACT_DUPLICATE for o in outcomes[1:])
    assert len({o.alert_id for o in outcomes}) == 1
    group = harness.dedup.group_state("wazuh:5710:001")
    assert group is not None
    assert group.occurrences == 1
    assert group.duplicate_deliveries == 19
    assert group.events[compute_event_identity(alert)].delivery_count == 20


def test_concurrent_deliveries_serialize_deterministically(
    harness: Harness,
) -> None:
    """Concurrent deliveries serialize without losing idempotency.

    Exactly one delivery may create the group's first alert. The shared event
    may be that first delivery or may arrive after a distinct event has already
    created the group. In either case, all deliveries of the same event must
    resolve to the same canonical alert.
    """
    distinct_events = [build_alert({"id": f"1770000000.2000{i:02d}"}) for i in range(8)]
    same_event = build_alert()

    def deliver(index: int):
        at = T0 + timedelta(milliseconds=index)
        if index % 3 == 0:
            return harness.deliver(same_event, at)
        return harness.deliver(
            distinct_events[index % len(distinct_events)],
            at,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(deliver, range(64)))

    new_outcomes = [o for o in outcomes if o.status is DedupeStatus.NEW_GENERATION]
    duplicate_outcomes = [o for o in outcomes if o.status is DedupeStatus.EXACT_DUPLICATE]
    repeated_outcomes = [o for o in outcomes if o.status is DedupeStatus.REPEATED]

    # Exactly one concurrent delivery may create the group's first alert.
    assert len(new_outcomes) == 1

    # Every delivery of the shared event must resolve to the same canonical
    # alert, whether that event won the race or arrived after another event.
    shared_identity = compute_event_identity(same_event)
    shared_outcomes = [o for o in outcomes if o.event_identity == shared_identity]

    assert shared_outcomes
    assert len({o.alert_id for o in shared_outcomes}) == 1
    assert all(o.canonical_alert is not None for o in shared_outcomes)

    shared_new = [o for o in shared_outcomes if o.status is DedupeStatus.NEW_GENERATION]
    shared_dups = [o for o in shared_outcomes if o.status is DedupeStatus.EXACT_DUPLICATE]
    shared_repeated = [o for o in shared_outcomes if o.status is DedupeStatus.REPEATED]

    # If the shared event wins the race it is NEW; otherwise it is REPEATED.
    assert len(shared_new) <= 1
    assert all(o.alert_id == shared_outcomes[0].alert_id for o in shared_dups + shared_repeated)

    # Eight distinct events plus the shared event.
    distinct_delivered = len({o.event_identity for o in outcomes})
    assert distinct_delivered == 9
    assert len(new_outcomes) == 1
    assert len(repeated_outcomes) == distinct_delivered - 1

    group = harness.dedup.group_state("wazuh:5710:001")
    assert group is not None
    assert group.occurrences == distinct_delivered
    assert group.duplicate_deliveries == len(duplicate_outcomes)

    # Every delivery resolved to a canonical alert of record.
    assert all(o.canonical_alert is not None for o in outcomes)


def test_concurrent_mixed_groups_stay_isolated(harness: Harness) -> None:
    """Concurrent traffic across different groups never cross-contaminates."""
    alerts = [
        build_alert({"id": f"1770000000.3000{i:02d}", "agent": {"id": f"{i % 4:03d}"}})
        for i in range(40)
    ]

    def deliver(alert: WazuhAlert):
        return harness.deliver(alert, T0)

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(deliver, alerts))

    by_group: dict[str, set[str]] = {}
    for outcome in outcomes:
        by_group.setdefault(outcome.dedupe.group_key, set()).add(outcome.event_identity)
    assert len(by_group) == 4
    assert sum(len(identities) for identities in by_group.values()) == 40
    for key, identities in by_group.items():
        group = harness.dedup.group_state(key)
        assert group is not None
        assert group.occurrences == len(identities)


def test_status_values_are_stable_api_contract() -> None:
    assert DedupeStatus.NEW_GENERATION.value == "new_generation"
    assert DedupeStatus.EXACT_DUPLICATE.value == "exact_duplicate"
    assert DedupeStatus.REPEATED.value == "repeated"


def test_window_property_reflects_configuration() -> None:
    dedup = InMemoryDeduplicator(window_seconds=60)
    assert dedup.window == timedelta(seconds=60)
