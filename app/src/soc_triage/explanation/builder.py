"""Deterministic analyst explainability (Phase 6.5).

The explanation layer is a **read-only projection** over facts the pipeline
already computed and persisted: the canonical alert of record (carrying the
authoritative scoring.v1 ``RiskAssessment`` and decisions.v1 ``Decision``),
the dedupe group state, the incident linkage, the correlation.v1 membership
evidence, and the append-only audit log. It never re-scores, never
re-decides, never reinterprets recurrence as correlation, and it adds no new
risk points or routing rules — the stored outputs remain authoritative
(DEVELOPMENT_PLAN.md 6.5, ARCHITECTURE.md §8, §9).

Determinism contract: for identical persisted alert state the builder
returns identical content and ordering. It performs no I/O, no network or
LLM calls, no clock reads (every timestamp in the output is a persisted
timestamp), and no randomness. Missing facts are represented as explicit
``null`` — the builder never infers or fabricates evidence.

Security (SECURITY.md §5, §7): IOC enrichment blobs and stored MITRE
metadata pass through the shared :func:`soc_triage.core.redaction.redact_mapping`;
``full_log``, credentials, tokens, and raw payloads never enter the output.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..audit import ACTION_ALERT_CREATED
from ..core.redaction import redact_mapping
from ..correlation.evidence import evidence_reason
from ..ingest.deduplication import GroupState
from ..models.incident import Incident
from ..models.records import (
    AuditRecord,
    CorrelationContextRecord,
    CorrelationMemberSummary,
    PersistedAlert,
    TimelineEvent,
)
from ..timeline import build_timeline

#: Contract version for the explanation payload (bumped on shape changes).
EXPLANATION_VERSION = "explanation.v1"

#: Maximum audit events embedded in one explanation (deterministic cap).
MAX_AUDIT_EVENTS = 50


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _clamp(score: int) -> int:
    """The scoring engine's 0-100 clip, mirrored for reconciliation only."""
    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Read models (frozen; field order is the deterministic JSON field order)
# ---------------------------------------------------------------------------


class ExplanationRuleRead(BaseModel):
    """Stored rule metadata for the alert (never raw payloads)."""

    model_config = {"frozen": True}

    id: str
    level: int
    description: str
    groups: list[str] = Field(default_factory=list)


class ExplanationAgentRead(BaseModel):
    """Stored agent identity for the alert."""

    model_config = {"frozen": True}

    id: str
    name: str
    ip: str | None = None


class ExplanationAlertRead(BaseModel):
    """A. Alert summary — identity and context exactly as persisted."""

    model_config = {"frozen": True}

    alert_id: str
    source: str
    received_at: str
    created_at: str
    rule: ExplanationRuleRead
    agent: ExplanationAgentRead
    asset: dict[str, Any] | None = None
    location: str | None = None


class ExplanationDetectionRead(BaseModel):
    """B. Detection explanation — the matched rule and stored ATT&CK metadata.

    ``mitre`` is the rule's stored MITRE mapping verbatim (redacted
    defensively); ``null`` when the rule carries no mapping. The explanation
    never derives techniques that are not already stored.
    """

    model_config = {"frozen": True}

    rule_id: str
    rule_description: str
    groups: list[str] = Field(default_factory=list)
    mitre: dict[str, Any] | None = None


class ExplanationScoreFactorRead(BaseModel):
    """One stored scoring factor: name, points, weight, evidence detail.

    ``kind`` distinguishes positive, zero, and negative contributions
    (``allowlist_modifier`` is the subtractive factor in scoring.v1).
    """

    model_config = {"frozen": True}

    name: str
    points: int
    max: int
    detail: str
    kind: Literal["positive", "zero", "negative"]


class ExplanationScoreRead(BaseModel):
    """C. Score explanation — the authoritative stored scoring.v1 result.

    ``factors`` preserves the stored factor order. ``factor_points_total``
    and ``reconciles`` make the arithmetic auditable: the stored score must
    equal the 0-100 clip of the factor sum (the engine clips raw sums); any
    deviation is flagged, never silently corrected. ``severity`` is the
    decision path's stored severity, when one was produced.
    """

    model_config = {"frozen": True}

    policy_version: str | None = None
    score: int
    tier: str
    severity: str | None = None
    degraded: bool = False
    summary: str
    factors: list[ExplanationScoreFactorRead] = Field(default_factory=list)
    factor_points_total: int = 0
    reconciles: bool = True
    notes: list[str] = Field(default_factory=list)


class ExplanationDecisionRead(BaseModel):
    """D. Decision explanation — the authoritative stored decisions.v1 result.

    ``policy_version`` is **always null** in explanation.v1: the decision
    policy version is not persisted with the alert, and the explanation
    layer does not fabricate history (documented limitation; no migration).
    """

    model_config = {"frozen": True}

    policy_version: str | None = None
    action: str
    severity: str | None = None
    reasons: list[str] = Field(default_factory=list)
    runbook: str | None = None
    decided_at: str | None = None


class ExplanationDedupeRead(BaseModel):
    """E. Deduplication / recurrence explanation — stored facts only.

    ``dedupe_status`` is the authoritative per-alert status recorded in the
    ``alert.created`` audit entry (``new_generation`` / ``repeated``); an
    addressable alert row is never an exact duplicate (exact re-deliveries
    are absorbed onto the original row and counted in ``delivery_count`` /
    ``duplicate_deliveries``). Recurrence here is **never** reinterpreted as
    correlation — correlation lives in its own section.

    Source distinction (all persisted facts, none recomputed):
    ``occurrences`` / ``generation`` / ``first_seen`` / ``last_seen`` are
    the alert's own record as persisted at scoring time (exact-duplicate
    absorptions never rewrite it); ``delivery_count`` / ``content_variants``
    / ``duplicate_deliveries`` are the dedupe group's currently stored
    counters, so absorbed duplicates delivered *after* this alert are still
    visible.
    """

    model_config = {"frozen": True}

    group_key: str
    event_identity: str | None = None
    dedupe_status: str | None = None
    is_exact_duplicate: bool | None = None
    delivery_count: int | None = None
    content_variants: int | None = None
    duplicate_deliveries: int | None = None
    occurrences: int | None = None
    generation: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None


class ExplanationCorrelationEvidenceRead(BaseModel):
    """One stored correlation.v1 pairwise evidence item (verbatim semantics)."""

    model_config = {"frozen": True}

    evidence_type: str
    value: str
    reason: str
    peer_alert_id: str


class ExplanationCorrelationRead(BaseModel):
    """F. Correlation explanation — the stored investigation context.

    ``linked_alert_ids`` are the *other* members of the context (oldest
    received first, the repository's deterministic order). ``evidence`` is
    this alert's stored pairwise evidence; the section is ``null`` when the
    alert is uncorrelated. Distinct from duplicates/recurrence by design.
    """

    model_config = {"frozen": True}

    context_id: str
    linked_alert_ids: list[str] = Field(default_factory=list)
    evidence: list[ExplanationCorrelationEvidenceRead] = Field(default_factory=list)


class ExplanationIncidentRead(BaseModel):
    """Stored incident linkage (ids and status only — no payloads)."""

    model_config = {"frozen": True}

    incident_id: str
    status: str
    severity: str


class ExplanationIocRead(BaseModel):
    """Analyst-safe IOC view: type/value/redacted enrichment/provenance."""

    model_config = {"frozen": True}

    type: str
    value: str
    enrichment: dict[str, Any] = Field(default_factory=dict)
    provenance: list[dict[str, Any]] = Field(default_factory=list)


class ExplanationInvestigationRead(BaseModel):
    """G. Investigation context — IOCs, enrichment, incident, audit history.

    ``audit_events`` are the already-persisted audit rows for the alert, its
    dedupe group, and its incident (when linked), in the deterministic
    timeline order, capped at :data:`MAX_AUDIT_EVENTS`; the truncated flag
    says so explicitly instead of hiding it.
    """

    model_config = {"frozen": True}

    iocs: list[ExplanationIocRead] = Field(default_factory=list)
    enrichment_status: str | None = None
    incident: ExplanationIncidentRead | None = None
    audit_events: list[TimelineEvent] = Field(default_factory=list)
    audit_events_truncated: bool = False


class ExplanationRead(BaseModel):
    """The complete deterministic explanation for one persisted alert.

    Sections are ``null`` when the underlying stored fact does not exist —
    absence is always explicit, never inferred.
    """

    model_config = {"frozen": True}

    explanation_version: str = EXPLANATION_VERSION
    alert_id: str
    alert: ExplanationAlertRead
    detection: ExplanationDetectionRead
    score: ExplanationScoreRead | None = None
    decision: ExplanationDecisionRead | None = None
    dedupe: ExplanationDedupeRead | None = None
    correlation: ExplanationCorrelationRead | None = None
    investigation: ExplanationInvestigationRead


# ---------------------------------------------------------------------------
# Pure builder
# ---------------------------------------------------------------------------


def _alert_section(record: PersistedAlert) -> ExplanationAlertRead:
    canonical = record.canonical
    rule = canonical.source_event.rule
    agent = canonical.source_event.agent
    asset = None
    if canonical.asset is not None:
        asset = {
            "name": canonical.asset.name,
            "tier": canonical.asset.tier,
            "owner": canonical.asset.owner,
        }
    return ExplanationAlertRead(
        alert_id=str(record.alert_id),
        source=record.source,
        received_at=record.received_at.isoformat(),
        created_at=record.created_at.isoformat(),
        rule=ExplanationRuleRead(
            id=rule.id,
            level=rule.level,
            description=rule.description,
            groups=list(rule.groups),
        ),
        agent=ExplanationAgentRead(id=agent.id, name=agent.name, ip=agent.ip),
        asset=asset,
        location=canonical.source_event.location,
    )


def _detection_section(record: PersistedAlert) -> ExplanationDetectionRead:
    rule = record.canonical.source_event.rule
    mitre: dict[str, Any] | None = None
    if rule.mitre:
        redacted = redact_mapping(dict(rule.mitre))
        if isinstance(redacted, dict) and redacted:
            mitre = redacted
    return ExplanationDetectionRead(
        rule_id=rule.id,
        rule_description=rule.description,
        groups=list(rule.groups),
        mitre=mitre,
    )


def _factor_kind(points: int) -> Literal["positive", "zero", "negative"]:
    if points > 0:
        return "positive"
    if points < 0:
        return "negative"
    return "zero"


def _score_section(record: PersistedAlert) -> ExplanationScoreRead | None:
    risk = record.canonical.risk
    if risk is None:
        return None
    decision = record.canonical.decision
    severity = decision.severity.value if decision is not None and decision.severity else None

    factors = [
        ExplanationScoreFactorRead(
            name=factor.name,
            points=factor.points,
            max=factor.max,
            detail=factor.detail,
            kind=_factor_kind(factor.points),
        )
        for factor in risk.factors
    ]
    total = sum(factor.points for factor in risk.factors)
    reconciles = risk.score == _clamp(total)

    notes: list[str] = []
    if risk.degraded:
        notes.append(
            "assessment is the degraded rule-severity-only fallback "
            "(the full scoring engine failed at scoring time)"
        )
    if total != risk.score and reconciles:
        notes.append(f"raw factor sum {total} clipped to the 0-100 score contract")
    if not reconciles:
        notes.append(
            "stored score does not equal the clipped factor sum; the stored score is authoritative"
        )

    return ExplanationScoreRead(
        policy_version=risk.engine_version,
        score=risk.score,
        tier=risk.tier.value,
        severity=severity,
        degraded=risk.degraded,
        summary=risk.summary,
        factors=factors,
        factor_points_total=total,
        reconciles=reconciles,
        notes=notes,
    )


def _decision_section(record: PersistedAlert) -> ExplanationDecisionRead | None:
    decision = record.canonical.decision
    if decision is None:
        return None
    return ExplanationDecisionRead(
        # Limitation (explanation.v1): the decision policy version is not
        # persisted with the alert, so it is returned as null rather than
        # guessed from the currently configured policy.
        policy_version=None,
        action=decision.action.value,
        severity=decision.severity.value if decision.severity else None,
        reasons=list(decision.reasons),
        runbook=decision.runbook,
        decided_at=_iso(decision.decided_at),
    )


def _dedupe_status_from_audit(audit_records: Sequence[AuditRecord], *, alert_id: str) -> str | None:
    """The authoritative per-alert dedupe status from ``alert.created``.

    The ingest audit entry records ``dedupe_status`` in its ``after``
    snapshot; later entries win (there is exactly one per alert in practice,
    so this is deterministic either way).
    """
    status: str | None = None
    for record in audit_records:
        if record.action != ACTION_ALERT_CREATED or record.entity_id != alert_id:
            continue
        after = record.after or {}
        candidate = after.get("dedupe_status")
        if isinstance(candidate, str):
            status = candidate
    return status


def _dedupe_section(
    record: PersistedAlert,
    *,
    group_state: GroupState | None,
    audit_records: Sequence[AuditRecord],
) -> ExplanationDedupeRead:
    canonical = record.canonical
    dedupe = canonical.dedupe

    event_identity = record.event_identity
    if dedupe is not None and dedupe.event_identity:
        event_identity = dedupe.event_identity

    delivery_count: int | None = None
    content_variants: int | None = None
    if group_state is not None and event_identity is not None:
        event = group_state.events.get(event_identity)
        if event is not None:
            delivery_count = event.delivery_count
            content_variants = event.content_variants

    # Group-level absorbed-duplicate counter: the currently stored value
    # (the alert's persisted record freezes it at scoring time, so later
    # absorptions would otherwise be invisible next to ``delivery_count``).
    duplicate_deliveries: int | None = None
    if group_state is not None:
        duplicate_deliveries = group_state.duplicate_deliveries
    elif dedupe is not None:
        duplicate_deliveries = dedupe.duplicate_deliveries

    dedupe_status = _dedupe_status_from_audit(audit_records, alert_id=str(record.alert_id))
    is_exact_duplicate = None if dedupe_status is None else dedupe_status == "exact_duplicate"

    return ExplanationDedupeRead(
        group_key=record.dedupe_group_key,
        event_identity=event_identity,
        dedupe_status=dedupe_status,
        is_exact_duplicate=is_exact_duplicate,
        delivery_count=delivery_count,
        content_variants=content_variants,
        duplicate_deliveries=duplicate_deliveries,
        occurrences=dedupe.occurrences if dedupe is not None else None,
        generation=dedupe.generation if dedupe is not None else None,
        first_seen=_iso(dedupe.first_seen) if dedupe is not None else None,
        last_seen=_iso(dedupe.last_seen) if dedupe is not None else None,
    )


def _correlation_section(
    record: PersistedAlert,
    *,
    context: CorrelationContextRecord | None,
    members: Sequence[CorrelationMemberSummary],
) -> ExplanationCorrelationRead | None:
    if context is None:
        return None
    own_evidence: list[ExplanationCorrelationEvidenceRead] = []
    for member in members:
        if member.alert_id != record.alert_id:
            continue
        own_evidence = [
            ExplanationCorrelationEvidenceRead(
                evidence_type=item.evidence_type,
                value=item.value,
                reason=evidence_reason(item.evidence_type, item.value),
                peer_alert_id=item.peer_alert_id,
            )
            for item in member.evidence
        ]
        break
    return ExplanationCorrelationRead(
        context_id=context.context_id,
        linked_alert_ids=[str(m.alert_id) for m in members if m.alert_id != record.alert_id],
        evidence=own_evidence,
    )


def _ioc_reads(record: PersistedAlert) -> list[ExplanationIocRead]:
    reads: list[ExplanationIocRead] = []
    for ioc in record.canonical.iocs:
        reads.append(
            ExplanationIocRead(
                type=ioc.type.value,
                value=ioc.value,
                enrichment=redact_mapping(dict(ioc.enrichment)),
                provenance=[
                    {
                        "field": item.field,
                        "extractor": item.extractor,
                        "location": item.location,
                    }
                    for item in ioc.provenance
                ],
            )
        )
    return reads


def _investigation_section(
    record: PersistedAlert,
    *,
    incident: Incident | None,
    audit_records: Sequence[AuditRecord],
) -> ExplanationInvestigationRead:
    incident_read = None
    if incident is not None:
        incident_read = ExplanationIncidentRead(
            incident_id=incident.incident_id,
            status=incident.status.value,
            severity=incident.severity.value,
        )
    timeline = build_timeline(audit_records)
    truncated = len(timeline) > MAX_AUDIT_EVENTS
    return ExplanationInvestigationRead(
        iocs=_ioc_reads(record),
        enrichment_status=record.canonical.enrichment_status,
        incident=incident_read,
        audit_events=timeline[:MAX_AUDIT_EVENTS],
        audit_events_truncated=truncated,
    )


def build_explanation(
    *,
    record: PersistedAlert,
    group_state: GroupState | None,
    incident: Incident | None,
    context: CorrelationContextRecord | None,
    members: Sequence[CorrelationMemberSummary],
    audit_records: Sequence[AuditRecord],
) -> ExplanationRead:
    """Assemble the deterministic explanation for one persisted alert.

    Pure and side-effect free: identical inputs yield identical output
    (content **and** ordering). Every field is a projection of an
    already-persisted fact; absent facts become explicit ``null``. No I/O,
    no clock reads, no network, no LLM calls, no re-scoring, no re-deciding.
    """
    return ExplanationRead(
        explanation_version=EXPLANATION_VERSION,
        alert_id=str(record.alert_id),
        alert=_alert_section(record),
        detection=_detection_section(record),
        score=_score_section(record),
        decision=_decision_section(record),
        dedupe=_dedupe_section(record, group_state=group_state, audit_records=audit_records),
        correlation=_correlation_section(record, context=context, members=members),
        investigation=_investigation_section(
            record, incident=incident, audit_records=audit_records
        ),
    )


__all__ = [
    "EXPLANATION_VERSION",
    "MAX_AUDIT_EVENTS",
    "ExplanationAlertRead",
    "ExplanationCorrelationEvidenceRead",
    "ExplanationCorrelationRead",
    "ExplanationDecisionRead",
    "ExplanationDedupeRead",
    "ExplanationDetectionRead",
    "ExplanationIncidentRead",
    "ExplanationInvestigationRead",
    "ExplanationIocRead",
    "ExplanationRead",
    "ExplanationRuleRead",
    "ExplanationScoreFactorRead",
    "ExplanationScoreRead",
    "build_explanation",
]
