"""Unit tests for the Phase 6.5 deterministic explanation builder.

The builder is pure: it projects already-persisted facts (the canonical
alert of record with its authoritative scoring.v1 / decisions.v1 outputs,
dedupe group state, correlation.v1 membership, incident linkage, and audit
rows) into the explanation.v1 contract. These tests pin determinism, score
arithmetic reconciliation, factor ordering, explicit-null behavior for
missing facts, and the strict no-fabrication rule.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from tests.conftest import make_canonical_alert, make_ioc

from soc_triage.audit import ACTION_ALERT_CREATED, ACTION_ALERT_SCORED
from soc_triage.explanation.builder import (
    EXPLANATION_VERSION,
    MAX_AUDIT_EVENTS,
    ExplanationRead,
    build_explanation,
)
from soc_triage.ingest.deduplication import EventRecord, GroupState
from soc_triage.models.assessment import (
    Decision,
    DecisionAction,
    DecisionSeverity,
    RiskAssessment,
    RiskTier,
    ScoreFactor,
)
from soc_triage.models.canonical import CanonicalDedupe
from soc_triage.models.incident import Incident, IncidentStatus
from soc_triage.models.ioc import IOC, IOCProvenance, IOCType
from soc_triage.models.records import (
    AuditRecord,
    CorrelationContextRecord,
    CorrelationEvidenceItem,
    CorrelationMemberSummary,
    PersistedAlert,
)

NOW = datetime(2026, 9, 11, 4, 0, 0, tzinfo=UTC)
GROUP_KEY = "wazuh:5710:001"
EVENT_IDENTITY = "wazuh:1770000000.100:5710:001"


def _factor(name: str, points: int, *, max_points: int = 30) -> ScoreFactor:
    return ScoreFactor(name=name, points=points, max=max_points, detail=f"{name} detail")


def _risk(factors: tuple[ScoreFactor, ...], *, score: int | None = None) -> RiskAssessment:
    raw = sum(f.points for f in factors)
    return RiskAssessment(
        score=max(0, min(100, raw)) if score is None else score,
        tier=RiskTier.MEDIUM,
        engine_version="scoring.v1",
        factors=factors,
        summary="summary",
    )


def _decision(*, action: DecisionAction = DecisionAction.QUEUE_L1) -> Decision:
    return Decision(
        action=action,
        severity=DecisionSeverity.SEV2 if action is DecisionAction.OPEN_INCIDENT else None,
        reasons=("score=45 tier=medium",),
        decided_at=NOW,
    )


def _record(
    *,
    risk: RiskAssessment | None = None,
    decision: Decision | None = None,
    with_dedupe: bool = True,
    iocs: list[IOC] | None = None,
    mitre: dict | None = None,
    enrichment_status: str | None = "skipped",
    duplicate_deliveries: int = 0,
) -> PersistedAlert:
    canonical = make_canonical_alert(
        received_at=NOW,
        iocs=iocs or [],
        with_dedupe=with_dedupe,
        enrichment_status=enrichment_status,
    )
    if mitre is not None:
        canonical = canonical.model_copy(
            update={
                "source_event": canonical.source_event.model_copy(
                    update={"rule": canonical.source_event.rule.model_copy(update={"mitre": mitre})}
                )
            }
        )
    if with_dedupe and canonical.dedupe is not None:
        canonical = canonical.model_copy(
            update={
                "dedupe": CanonicalDedupe(
                    group_key=GROUP_KEY,
                    occurrences=canonical.dedupe.occurrences,
                    first_seen=canonical.dedupe.first_seen,
                    last_seen=canonical.dedupe.last_seen,
                    event_identity=EVENT_IDENTITY,
                    generation=canonical.dedupe.generation,
                    duplicate_deliveries=duplicate_deliveries,
                )
            }
        )
    canonical = canonical.model_copy(update={"risk": risk, "decision": decision})
    return PersistedAlert(
        alert_id=canonical.alert_id,
        source=canonical.source,
        received_at=canonical.received_at,
        created_at=canonical.received_at,
        incident_id=None,
        rule_id=canonical.source_event.rule.id,
        rule_level=canonical.source_event.rule.level,
        agent_id=canonical.source_event.agent.id,
        agent_name=canonical.source_event.agent.name,
        dedupe_group_key=GROUP_KEY,
        event_identity=EVENT_IDENTITY,
        canonical=canonical,
    )


def _group_state(*, delivery_count: int = 1) -> GroupState:
    record = _record()
    event = EventRecord(
        event_identity=EVENT_IDENTITY,
        alert_id=record.alert_id,
        payload_fingerprint="f" * 64,
        canonical_alert=record.canonical,
        delivery_count=delivery_count,
        content_variants=1,
        first_delivered_at=NOW,
        last_delivered_at=NOW,
    )
    return GroupState(
        group_key=GROUP_KEY,
        occurrences=1,
        first_seen=NOW,
        last_seen=NOW,
        generation=1,
        duplicate_deliveries=delivery_count - 1,
        events={EVENT_IDENTITY: event},
    )


def _audit(alert_id: object, *, status: str = "new_generation") -> list[AuditRecord]:
    return [
        AuditRecord(
            id=1,
            occurred_at=NOW,
            actor="system:ingest",
            action=ACTION_ALERT_CREATED,
            entity_type="alert",
            entity_id=str(alert_id),
            after={"dedupe_status": status},
        )
    ]


def test_builder_output_is_versioned_and_deterministic() -> None:
    record = _record(risk=_risk((_factor("rule_severity", 20),)), decision=_decision())
    first = build_explanation(
        record=record,
        group_state=_group_state(),
        incident=None,
        context=None,
        members=[],
        audit_records=_audit(record.alert_id),
    )
    second = build_explanation(
        record=record,
        group_state=_group_state(),
        incident=None,
        context=None,
        members=[],
        audit_records=_audit(record.alert_id),
    )
    assert isinstance(first, ExplanationRead)
    assert first.explanation_version == EXPLANATION_VERSION == "explanation.v1"
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_factor_order_is_preserved_and_kinds_are_explicit() -> None:
    factors = (
        _factor("rule_severity", 20),
        _factor("rule_groups_mitre", 0),
        _factor("allowlist_modifier", -5),
    )
    record = _record(risk=_risk(factors), decision=_decision())
    explanation = build_explanation(
        record=record,
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.score is not None
    assert [f.name for f in explanation.score.factors] == [
        "rule_severity",
        "rule_groups_mitre",
        "allowlist_modifier",
    ]
    assert [f.kind for f in explanation.score.factors] == ["positive", "zero", "negative"]


def test_score_arithmetic_reconciles_with_stored_score() -> None:
    factors = (_factor("rule_severity", 20), _factor("ioc_evidence", 10))
    record = _record(risk=_risk(factors), decision=_decision())
    explanation = build_explanation(
        record=record,
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.score is not None
    assert explanation.score.policy_version == "scoring.v1"
    assert explanation.score.factor_points_total == 30
    assert explanation.score.reconciles is True
    assert explanation.score.notes == []
    assert explanation.score.score == 30


def test_score_clipping_is_reported_not_corrected() -> None:
    factors = (_factor("rule_severity", 90), _factor("ioc_evidence", 40))
    risk = RiskAssessment(
        score=100,
        tier=RiskTier.CRITICAL,
        engine_version="scoring.v1",
        factors=factors,
        summary="s",
    )
    record = _record(risk=risk, decision=_decision(action=DecisionAction.OPEN_INCIDENT))
    explanation = build_explanation(
        record=record,
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.score is not None
    assert explanation.score.factor_points_total == 130
    assert explanation.score.reconciles is True
    assert explanation.score.notes == ["raw factor sum 130 clipped to the 0-100 score contract"]
    # Severity comes from the stored decision path, nothing else.
    assert explanation.score.severity == "SEV2"
    assert explanation.decision is not None
    assert explanation.decision.severity == "SEV2"


def test_irreconcilable_stored_score_is_flagged_authoritative() -> None:
    factors = (_factor("rule_severity", 20),)
    risk = RiskAssessment(
        score=21,  # does not equal clip(sum(factors)) — defensive path
        tier=RiskTier.MEDIUM,
        engine_version="scoring.v1",
        factors=factors,
        summary="s",
    )
    record = _record(risk=risk)
    explanation = build_explanation(
        record=record,
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.score is not None
    assert explanation.score.reconciles is False
    assert explanation.score.notes == [
        "stored score does not equal the clipped factor sum; the stored score is authoritative"
    ]


def test_degraded_assessment_is_labeled() -> None:
    risk = RiskAssessment(
        score=20,
        tier=RiskTier.MEDIUM,
        engine_version="scoring.v1",
        factors=(_factor("rule_severity", 20),),
        summary="degraded",
        degraded=True,
    )
    explanation = build_explanation(
        record=_record(risk=risk),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.score is not None
    assert explanation.score.degraded is True
    assert any("degraded" in note for note in explanation.score.notes)


def test_missing_assessment_and_decision_are_explicit_nulls() -> None:
    explanation = build_explanation(
        record=_record(),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.score is None
    assert explanation.decision is None
    assert explanation.correlation is None


def test_decision_policy_version_is_null_by_contract() -> None:
    """explanation.v1 limitation: the decision policy version is not persisted
    with the alert, so it must be null — never the currently configured one."""
    explanation = build_explanation(
        record=_record(risk=_risk((_factor("rule_severity", 20),)), decision=_decision()),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.decision is not None
    assert explanation.decision.policy_version is None
    assert explanation.decision.action == "queue_l1"
    assert explanation.decision.reasons == ["score=45 tier=medium"]


def test_dedupe_facts_come_from_stored_state_only() -> None:
    record = _record(duplicate_deliveries=2)
    explanation = build_explanation(
        record=record,
        group_state=_group_state(delivery_count=3),
        incident=None,
        context=None,
        members=[],
        audit_records=_audit(record.alert_id, status="repeated"),
    )
    dedupe = explanation.dedupe
    assert dedupe is not None
    assert dedupe.group_key == GROUP_KEY
    assert dedupe.event_identity == EVENT_IDENTITY
    assert dedupe.dedupe_status == "repeated"
    assert dedupe.is_exact_duplicate is False
    assert dedupe.delivery_count == 3
    assert dedupe.occurrences == 1
    assert dedupe.generation == 1
    assert dedupe.duplicate_deliveries == 2


def test_dedupe_without_audit_or_group_state_has_explicit_nulls() -> None:
    explanation = build_explanation(
        record=_record(),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    dedupe = explanation.dedupe
    assert dedupe is not None
    assert dedupe.dedupe_status is None
    assert dedupe.is_exact_duplicate is None
    assert dedupe.delivery_count is None
    assert dedupe.content_variants is None
    # Stored canonical dedupe facts remain present.
    assert dedupe.occurrences == 1


def test_dedupe_section_survives_missing_canonical_dedupe_without_fabrication() -> None:
    explanation = build_explanation(
        record=_record(with_dedupe=False),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    dedupe = explanation.dedupe
    assert dedupe is not None
    assert dedupe.group_key == GROUP_KEY  # column-backed fact
    assert dedupe.event_identity == EVENT_IDENTITY  # column-backed fact
    assert dedupe.occurrences is None  # never invented
    assert dedupe.generation is None
    assert dedupe.duplicate_deliveries is None


def test_detection_mitre_is_verbatim_or_null() -> None:
    explanation = build_explanation(
        record=_record(mitre={"id": ["T1110"], "tactic": ["Credential Access"]}),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.detection.mitre == {"id": ["T1110"], "tactic": ["Credential Access"]}

    explanation_none = build_explanation(
        record=_record(),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation_none.detection.mitre is None


def test_detection_mitre_secret_keys_are_redacted_not_fabricated() -> None:
    explanation = build_explanation(
        record=_record(mitre={"id": ["T1078"], "api_key": "should-not-appear"}),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.detection.mitre == {"id": ["T1078"]}


def test_correlation_section_maps_stored_evidence_and_peers() -> None:
    record = _record()
    peer_id = uuid4()
    context = CorrelationContextRecord(
        context_id="CORR-2026-09-11-0001",
        created_at=NOW,
        updated_at=NOW,
        first_seen=NOW,
        last_seen=NOW,
        member_count=2,
    )
    members = [
        CorrelationMemberSummary(
            alert_id=record.alert_id,
            received_at=NOW,
            joined_at=NOW,
            rule_id="5710",
            rule_level=5,
            agent_id="001",
            agent_name="host-001",
            dedupe_group_key=GROUP_KEY,
            evidence=[
                CorrelationEvidenceItem(
                    evidence_type="shared_source_ip",
                    value="203.0.113.50",
                    peer_alert_id=str(peer_id),
                )
            ],
        ),
        CorrelationMemberSummary(
            alert_id=peer_id,
            received_at=NOW,
            joined_at=NOW,
            rule_id="5712",
            rule_level=7,
            agent_id="002",
            agent_name="host-002",
            dedupe_group_key="wazuh:5712:002",
            evidence=[
                CorrelationEvidenceItem(
                    evidence_type="shared_source_ip",
                    value="203.0.113.50",
                    peer_alert_id=str(record.alert_id),
                )
            ],
        ),
    ]
    explanation = build_explanation(
        record=record,
        group_state=None,
        incident=None,
        context=context,
        members=members,
        audit_records=[],
    )
    assert explanation.correlation is not None
    assert explanation.correlation.context_id == "CORR-2026-09-11-0001"
    assert explanation.correlation.linked_alert_ids == [str(peer_id)]
    assert [item.model_dump() for item in explanation.correlation.evidence] == [
        {
            "evidence_type": "shared_source_ip",
            "value": "203.0.113.50",
            "reason": "shared source IP 203.0.113.50",
            "peer_alert_id": str(peer_id),
        }
    ]


def test_incident_and_audit_projection() -> None:
    record = _record()
    incident = Incident(
        incident_id="INC-2026-09-11-0001",
        status=IncidentStatus.OPEN,
        severity=DecisionSeverity.SEV2,
        primary_alert_id=record.alert_id,
        dedupe_group_key=GROUP_KEY,
        created_at=NOW,
        updated_at=NOW,
    )
    audit = [
        *_audit(record.alert_id),
        AuditRecord(
            id=2,
            occurred_at=NOW,
            actor="system:scoring",
            action=ACTION_ALERT_SCORED,
            entity_type="alert",
            entity_id=str(record.alert_id),
            after={"score": 30},
        ),
    ]
    explanation = build_explanation(
        record=record,
        group_state=None,
        incident=incident,
        context=None,
        members=[],
        audit_records=audit,
    )
    assert explanation.investigation.incident is not None
    assert explanation.investigation.incident.incident_id == "INC-2026-09-11-0001"
    assert explanation.investigation.incident.status == "open"
    actions = [event.action for event in explanation.investigation.audit_events]
    assert actions == ["alert.created", "alert.scored"]
    assert explanation.investigation.audit_events_truncated is False


def test_audit_events_are_capped_deterministically() -> None:
    record = _record()
    audit = [
        AuditRecord(
            id=index,
            occurred_at=NOW,
            actor="system:test",
            action="alert.created",
            entity_type="alert",
            entity_id=str(record.alert_id),
        )
        for index in range(MAX_AUDIT_EVENTS + 7)
    ]
    explanation = build_explanation(
        record=record,
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=audit,
    )
    events = explanation.investigation.audit_events
    assert len(events) == MAX_AUDIT_EVENTS
    assert explanation.investigation.audit_events_truncated is True
    # Deterministic tie-break: append-only audit ids order equal timestamps.
    assert [event.before for event in events] == [None] * MAX_AUDIT_EVENTS


def test_iocs_are_projected_and_redacted() -> None:
    ioc = make_ioc("203.0.113.50")
    ioc = ioc.model_copy(
        update={
            "enrichment": {"virustotal": {"positives": 3}, "api_key": "secret-value"},
            "provenance": (
                IOCProvenance(
                    field="data.srcip",
                    extractor="typed_field",
                    raw_value="203.0.113.50",
                    location=None,
                ),
            ),
        }
    )
    explanation = build_explanation(
        record=_record(iocs=[ioc]),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert [item.model_dump() for item in explanation.investigation.iocs] == [
        {
            "type": IOCType.IPV4.value,
            "value": "203.0.113.50",
            "enrichment": {"virustotal": {"positives": 3}},
            "provenance": [{"field": "data.srcip", "extractor": "typed_field", "location": None}],
        }
    ]


def test_investigation_absent_facts_are_explicit() -> None:
    explanation = build_explanation(
        record=_record(enrichment_status=None),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    assert explanation.investigation.enrichment_status is None
    assert explanation.investigation.incident is None
    assert explanation.investigation.iocs == []
    assert explanation.investigation.audit_events == []
    assert explanation.investigation.audit_events_truncated is False

    stored_default = build_explanation(
        record=_record(),
        group_state=None,
        incident=None,
        context=None,
        members=[],
        audit_records=[],
    )
    # The persisted canonical status is surfaced verbatim, never invented.
    assert stored_default.investigation.enrichment_status == "skipped"
