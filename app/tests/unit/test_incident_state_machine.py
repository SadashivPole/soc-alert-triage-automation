"""Unit tests: incident lifecycle state machine + feedback mapping (Phase 3.2).

Pure domain coverage — no database:

* the exact valid-transition table from the Phase 3.2 spec (nothing implied,
  nothing invented, terminal states allow nothing);
* ``can_transition`` / ``InvalidIncidentTransitionError`` semantics;
* the ``Incident`` domain model's lifecycle timestamp fields;
* the documented verdict → incident-status mapping used by the feedback
  synchronizer (``plan_incident_sync``): conservative, never auto-resolves on
  a verdict, ``contain_requested`` never moves the incident.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from soc_triage.api.feedback import (
    FEEDBACK_INCIDENT_STATUS_TARGETS,
    FeedbackVerdict,
    plan_incident_sync,
)
from soc_triage.models.assessment import DecisionSeverity
from soc_triage.models.incident import (
    TERMINAL_STATUSES,
    VALID_TRANSITIONS,
    Incident,
    IncidentStatus,
    InvalidIncidentTransitionError,
    can_transition,
)

OPEN = IncidentStatus.OPEN
INVESTIGATING = IncidentStatus.INVESTIGATING
ACKNOWLEDGED = IncidentStatus.ACKNOWLEDGED
RESOLVED = IncidentStatus.RESOLVED
FALSE_POSITIVE = IncidentStatus.FALSE_POSITIVE
ESCALATED = IncidentStatus.ESCALATED

_NOW = datetime(2026, 9, 2, 10, 0, 0, tzinfo=UTC)


def _incident(status: IncidentStatus) -> Incident:
    return Incident(
        incident_id="INC-2026-08-29-0001",
        status=status,
        severity=DecisionSeverity.SEV2,
        primary_alert_id=UUID("00000000-0000-0000-0000-000000000001"),
        dedupe_group_key="wazuh:87105:003",
        created_at=_NOW,
        updated_at=_NOW,
    )


# ---------------------------------------------------------------------------
# The exact transition table
# ---------------------------------------------------------------------------


def test_transition_table_matches_the_phase_3_2_spec() -> None:
    """Every transition is exactly as specified — no more, no less."""
    expected = {
        OPEN: {INVESTIGATING, ACKNOWLEDGED, FALSE_POSITIVE, ESCALATED},
        INVESTIGATING: {ACKNOWLEDGED, RESOLVED, ESCALATED, FALSE_POSITIVE},
        ACKNOWLEDGED: {INVESTIGATING, RESOLVED, ESCALATED},
        ESCALATED: {INVESTIGATING, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE},
        RESOLVED: set(),
        FALSE_POSITIVE: set(),
    }
    assert set(VALID_TRANSITIONS) == set(IncidentStatus)
    for current, targets in expected.items():
        assert VALID_TRANSITIONS[current] == frozenset(targets), f"from {current.value}"


def test_terminal_states_allow_no_transitions() -> None:
    assert {RESOLVED, FALSE_POSITIVE} == TERMINAL_STATUSES
    for terminal in TERMINAL_STATUSES:
        assert VALID_TRANSITIONS[terminal] == frozenset()
        for target in IncidentStatus:
            assert not can_transition(terminal, target)


def test_can_transition_covers_every_pair() -> None:
    for current in IncidentStatus:
        for target in IncidentStatus:
            expected = target in VALID_TRANSITIONS[current]
            assert can_transition(current, target) is expected, f"{current} -> {target}"


def test_no_self_transitions() -> None:
    for current in IncidentStatus:
        assert not can_transition(current, current)


def test_invalid_transition_error_carries_both_states() -> None:
    try:
        # Guarded by the repository; construct directly to pin the contract.
        raise InvalidIncidentTransitionError(RESOLVED, INVESTIGATING)
    except InvalidIncidentTransitionError as exc:
        assert exc.current is RESOLVED
        assert exc.target is INVESTIGATING
        assert "resolved -> investigating" in str(exc)
        assert "terminal" in str(exc)
    assert isinstance(InvalidIncidentTransitionError(RESOLVED, INVESTIGATING), ValueError)


def test_invalid_transition_error_lists_allowed_targets() -> None:
    try:
        raise InvalidIncidentTransitionError(OPEN, RESOLVED)
    except InvalidIncidentTransitionError as exc:
        assert "open -> resolved" in str(exc)
        # open may not resolve directly — the allowed set is enumerated.
        assert "investigating" in str(exc)
        assert "acknowledged" in str(exc)
        assert "escalated" in str(exc)
        assert "false_positive" in str(exc)


# ---------------------------------------------------------------------------
# Domain model timestamp fields
# ---------------------------------------------------------------------------


def test_incident_domain_defaults_lifecycle_timestamps_to_none() -> None:
    incident = _incident(OPEN)
    assert incident.acknowledged_at is None
    assert incident.resolved_at is None


def test_incident_domain_carries_lifecycle_timestamps() -> None:
    incident = _incident(ACKNOWLEDGED).model_copy(
        update={"acknowledged_at": _NOW, "updated_at": _NOW}
    )
    assert incident.acknowledged_at == _NOW
    assert incident.resolved_at is None


# ---------------------------------------------------------------------------
# Documented feedback → incident mapping
# ---------------------------------------------------------------------------


def test_feedback_mapping_table_is_documented_and_conservative() -> None:
    assert FEEDBACK_INCIDENT_STATUS_TARGETS == {
        FeedbackVerdict.TRUE_POSITIVE: ACKNOWLEDGED,  # confirmation, not resolution
        FeedbackVerdict.ACKNOWLEDGED: ACKNOWLEDGED,
        FeedbackVerdict.RESOLVED: RESOLVED,
        FeedbackVerdict.FALSE_POSITIVE: FALSE_POSITIVE,
        FeedbackVerdict.ESCALATE: ESCALATED,
        FeedbackVerdict.BENIGN: FALSE_POSITIVE,  # safest terminal meaning, never "resolved"
    }
    # contain_requested is deliberately absent (approval-required, no transition).
    assert FeedbackVerdict.CONTAIN_REQUESTED not in FEEDBACK_INCIDENT_STATUS_TARGETS
    # No verdict maps to RESOLVED except an explicit "resolved" verdict.
    assert [
        verdict
        for verdict, target in FEEDBACK_INCIDENT_STATUS_TARGETS.items()
        if target is RESOLVED
    ] == [FeedbackVerdict.RESOLVED]


def test_plan_true_positive_acknowledges_but_never_resolves() -> None:
    assert plan_incident_sync(_incident(OPEN), FeedbackVerdict.TRUE_POSITIVE) is ACKNOWLEDGED
    assert (
        plan_incident_sync(_incident(INVESTIGATING), FeedbackVerdict.TRUE_POSITIVE) is ACKNOWLEDGED
    )
    assert plan_incident_sync(_incident(ESCALATED), FeedbackVerdict.TRUE_POSITIVE) is ACKNOWLEDGED
    # Not legal from these states — the incident stays exactly as-is.
    assert plan_incident_sync(_incident(ACKNOWLEDGED), FeedbackVerdict.TRUE_POSITIVE) is None
    assert plan_incident_sync(_incident(RESOLVED), FeedbackVerdict.TRUE_POSITIVE) is None
    assert plan_incident_sync(_incident(FALSE_POSITIVE), FeedbackVerdict.TRUE_POSITIVE) is None


def test_plan_acknowledged_verdict() -> None:
    assert plan_incident_sync(_incident(OPEN), FeedbackVerdict.ACKNOWLEDGED) is ACKNOWLEDGED
    assert (
        plan_incident_sync(_incident(INVESTIGATING), FeedbackVerdict.ACKNOWLEDGED) is ACKNOWLEDGED
    )
    assert plan_incident_sync(_incident(ESCALATED), FeedbackVerdict.ACKNOWLEDGED) is ACKNOWLEDGED
    assert plan_incident_sync(_incident(ACKNOWLEDGED), FeedbackVerdict.ACKNOWLEDGED) is None
    assert plan_incident_sync(_incident(RESOLVED), FeedbackVerdict.ACKNOWLEDGED) is None
    assert plan_incident_sync(_incident(FALSE_POSITIVE), FeedbackVerdict.ACKNOWLEDGED) is None


def test_plan_resolved_verdict_respects_the_state_machine() -> None:
    # open → resolved is NOT a legal transition: the incident must be
    # investigated/acknowledged first.
    assert plan_incident_sync(_incident(OPEN), FeedbackVerdict.RESOLVED) is None
    assert plan_incident_sync(_incident(INVESTIGATING), FeedbackVerdict.RESOLVED) is RESOLVED
    assert plan_incident_sync(_incident(ACKNOWLEDGED), FeedbackVerdict.RESOLVED) is RESOLVED
    assert plan_incident_sync(_incident(ESCALATED), FeedbackVerdict.RESOLVED) is RESOLVED
    assert plan_incident_sync(_incident(RESOLVED), FeedbackVerdict.RESOLVED) is None
    assert plan_incident_sync(_incident(FALSE_POSITIVE), FeedbackVerdict.RESOLVED) is None


def test_plan_false_positive_and_benign_verdicts() -> None:
    for verdict in (FeedbackVerdict.FALSE_POSITIVE, FeedbackVerdict.BENIGN):
        assert plan_incident_sync(_incident(OPEN), verdict) is FALSE_POSITIVE
        assert plan_incident_sync(_incident(INVESTIGATING), verdict) is FALSE_POSITIVE
        assert plan_incident_sync(_incident(ESCALATED), verdict) is FALSE_POSITIVE
        # acknowledged → false_positive is not in the state machine.
        assert plan_incident_sync(_incident(ACKNOWLEDGED), verdict) is None
        assert plan_incident_sync(_incident(RESOLVED), verdict) is None
        assert plan_incident_sync(_incident(FALSE_POSITIVE), verdict) is None
    # benign never means "resolved" — never.
    assert plan_incident_sync(_incident(OPEN), FeedbackVerdict.BENIGN) is not RESOLVED


def test_plan_escalate_verdict() -> None:
    assert plan_incident_sync(_incident(OPEN), FeedbackVerdict.ESCALATE) is ESCALATED
    assert plan_incident_sync(_incident(INVESTIGATING), FeedbackVerdict.ESCALATE) is ESCALATED
    assert plan_incident_sync(_incident(ACKNOWLEDGED), FeedbackVerdict.ESCALATE) is ESCALATED
    assert plan_incident_sync(_incident(ESCALATED), FeedbackVerdict.ESCALATE) is None
    assert plan_incident_sync(_incident(RESOLVED), FeedbackVerdict.ESCALATE) is None
    assert plan_incident_sync(_incident(FALSE_POSITIVE), FeedbackVerdict.ESCALATE) is None


def test_plan_contain_requested_never_moves_the_incident() -> None:
    for status in IncidentStatus:
        assert plan_incident_sync(_incident(status), FeedbackVerdict.CONTAIN_REQUESTED) is None
