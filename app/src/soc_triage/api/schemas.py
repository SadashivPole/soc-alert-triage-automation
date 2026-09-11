"""Pydantic response models for the Phase 3.3 read APIs.

All GET surfaces return these models — never ORM objects (ARCHITECTURE.md
§12). Field names follow the existing snake_case / ISO-8601 conventions
used by ingest, feedback, and the incident status PATCH endpoint.

Security (SECURITY.md §5, §7): serializers drop ``full_log``, credentials,
tokens, and other secret-bearing keys. List views stay compact; detail
views add IOC summaries and trimmed source-event metadata, still without
raw logs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

# Secret-redaction lives in ``core.redaction`` (a cross-cutting concern) so
# domain-level projections — e.g. the Phase 6.5 explanation builder — can
# apply the exact same policy without importing the API layer
# (ARCHITECTURE.md §12). Re-exported here so existing import sites
# (``api.incidents``, tests) are unchanged.
from ..core.redaction import _SENSITIVE_FRAGMENTS, redact_mapping  # noqa: F401
from ..correlation.evidence import EVIDENCE_TYPE_ORDER, EvidenceType, evidence_reason
from ..models.canonical import CanonicalAlert
from ..models.incident import Incident
from ..models.records import (
    CorrelationContextRecord,
    CorrelationMemberSummary,
    PersistedAlert,
    TimelineEvent,
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


class Pagination(BaseModel):
    """Stable limit/offset page descriptor."""

    model_config = {"frozen": True}

    limit: int
    offset: int
    total: int
    has_more: bool


def make_pagination(*, limit: int, offset: int, total: int) -> Pagination:
    """Build a pagination block (``has_more`` when another page exists)."""
    return Pagination(
        limit=limit,
        offset=offset,
        total=total,
        has_more=offset + limit < total,
    )


class RuleSummary(BaseModel):
    """Safe rule metadata (no raw log)."""

    model_config = {"frozen": True}

    id: str
    level: int
    description: str
    groups: list[str] = Field(default_factory=list)


class AgentSummary(BaseModel):
    """Safe agent metadata."""

    model_config = {"frozen": True}

    id: str
    name: str
    ip: str | None = None


class RiskSummary(BaseModel):
    """Compact risk view for list rows."""

    model_config = {"frozen": True}

    score: int
    tier: str


class RiskDetail(BaseModel):
    """Full explainable risk assessment (still no raw payloads)."""

    model_config = {"frozen": True}

    score: int
    tier: str
    engine_version: str
    degraded: bool = False
    summary: str = ""
    factors: list[dict[str, Any]] = Field(default_factory=list)


class DecisionSummary(BaseModel):
    """Compact decision view for list rows."""

    model_config = {"frozen": True}

    action: str
    severity: str | None = None


class DecisionDetail(BaseModel):
    """Full routing decision."""

    model_config = {"frozen": True}

    action: str
    severity: str | None = None
    reasons: list[str] = Field(default_factory=list)
    runbook: str | None = None
    decided_at: str | None = None


class DedupeSummary(BaseModel):
    """Recurrence / idempotency summary (no raw event payload)."""

    model_config = {"frozen": True}

    group_key: str
    occurrences: int
    generation: int
    duplicate_deliveries: int = 0
    event_identity: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None


class IOCReadSummary(BaseModel):
    """Analyst-safe IOC view: type/value/enrichment, no raw offsets."""

    model_config = {"frozen": True}

    type: str
    value: str
    enrichment: dict[str, Any] = Field(default_factory=dict)
    provenance: list[dict[str, Any]] = Field(default_factory=list)


class AlertSummary(BaseModel):
    """One alert row in ``GET /api/v1/alerts``."""

    model_config = {"frozen": True}

    alert_id: str
    source: str
    received_at: str
    created_at: str
    incident_id: str | None = None
    rule: RuleSummary
    agent: AgentSummary
    risk: RiskSummary | None = None
    decision: DecisionSummary | None = None
    dedupe: DedupeSummary | None = None
    enrichment_status: str | None = None


class AlertDetail(BaseModel):
    """Safe alert representation for ``GET /api/v1/alerts/{alert_id}``."""

    model_config = {"frozen": True}

    alert_id: str
    source: str
    received_at: str
    created_at: str
    incident_id: str | None = None
    rule: RuleSummary
    agent: AgentSummary
    asset: dict[str, Any] | None = None
    location: str | None = None
    source_event: dict[str, Any] = Field(default_factory=dict)
    risk: RiskDetail | None = None
    decision: DecisionDetail | None = None
    dedupe: DedupeSummary | None = None
    enrichment_status: str | None = None
    iocs: list[IOCReadSummary] = Field(default_factory=list)


class AlertListResponse(BaseModel):
    """Paginated alert list."""

    model_config = {"frozen": True}

    items: list[AlertSummary]
    pagination: Pagination


class IncidentSummary(BaseModel):
    """One incident row in ``GET /api/v1/incidents``."""

    model_config = {"frozen": True}

    incident_id: str
    status: str
    severity: str
    primary_alert_id: str
    dedupe_group_key: str
    created_at: str
    updated_at: str
    acknowledged_at: str | None = None
    resolved_at: str | None = None


class LinkedAlertSummary(BaseModel):
    """Compact linked-alert view on an incident detail payload."""

    model_config = {"frozen": True}

    alert_id: str
    received_at: str
    rule_id: str
    rule_level: int
    agent_id: str
    agent_name: str
    risk_score: int | None = None
    risk_tier: str | None = None
    decision_action: str | None = None
    is_primary: bool = False


class IncidentDetail(BaseModel):
    """Incident metadata plus linked-alert summaries (no raw payloads)."""

    model_config = {"frozen": True}

    incident_id: str
    status: str
    severity: str
    primary_alert_id: str
    dedupe_group_key: str
    created_at: str
    updated_at: str
    acknowledged_at: str | None = None
    resolved_at: str | None = None
    linked_alert_count: int
    primary_alert: LinkedAlertSummary | None = None
    linked_alerts: list[LinkedAlertSummary] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    """Paginated incident list."""

    model_config = {"frozen": True}

    items: list[IncidentSummary]
    pagination: Pagination


class IncidentTimelineResponse(BaseModel):
    """Chronological incident timeline (read-only)."""

    model_config = {"frozen": True}

    incident_id: str
    events: list[TimelineEvent]


class CorrelationMemberEvidenceRead(BaseModel):
    """One pairwise evidence item explaining a member's inclusion."""

    model_config = {"frozen": True}

    evidence_type: str
    value: str
    reason: str
    peer_alert_id: str


class CorrelationMemberRead(BaseModel):
    """One member alert of a correlation context (no raw payloads).

    Carries the alert's own ``dedupe_group_key`` / ``incident_id`` so the
    three relationships an alert can have (recurrence group, incident,
    correlation context) stay visibly distinct.
    """

    model_config = {"frozen": True}

    alert_id: str
    received_at: str
    joined_at: str
    rule_id: str
    rule_level: int
    agent_id: str
    agent_name: str
    dedupe_group_key: str
    incident_id: str | None = None
    risk_tier: str | None = None
    decision_action: str | None = None
    evidence: list[CorrelationMemberEvidenceRead] = Field(default_factory=list)


class CorrelationEvidenceRead(BaseModel):
    """Context-level evidence: one shared attribute and the alerts it relates."""

    model_config = {"frozen": True}

    evidence_type: str
    value: str
    reason: str
    related_alert_ids: list[str]
    first_seen: str
    last_seen: str


class CorrelationContextSummaryRead(BaseModel):
    """One context row in ``GET /api/v1/correlations``."""

    model_config = {"frozen": True}

    context_id: str
    created_at: str
    updated_at: str
    first_seen: str
    last_seen: str
    member_count: int


class CorrelationContextDetailRead(BaseModel):
    """Full correlation context for the detail endpoints (read-only)."""

    model_config = {"frozen": True}

    context_id: str
    created_at: str
    updated_at: str
    first_seen: str
    last_seen: str
    member_count: int
    members: list[CorrelationMemberRead] = Field(default_factory=list)
    evidence: list[CorrelationEvidenceRead] = Field(default_factory=list)


class CorrelationListResponse(BaseModel):
    """Paginated correlation context list."""

    model_config = {"frozen": True}

    items: list[CorrelationContextSummaryRead]
    pagination: Pagination


def _rule_summary(canonical: CanonicalAlert) -> RuleSummary:
    rule = canonical.source_event.rule
    return RuleSummary(
        id=rule.id,
        level=rule.level,
        description=rule.description,
        groups=list(rule.groups),
    )


def _agent_summary(canonical: CanonicalAlert) -> AgentSummary:
    agent = canonical.source_event.agent
    return AgentSummary(id=agent.id, name=agent.name, ip=agent.ip)


def _dedupe_summary(canonical: CanonicalAlert, *, group_key: str) -> DedupeSummary:
    dedupe = canonical.dedupe
    if dedupe is None:
        return DedupeSummary(group_key=group_key, occurrences=1, generation=1)
    return DedupeSummary(
        group_key=dedupe.group_key,
        occurrences=dedupe.occurrences,
        generation=dedupe.generation,
        duplicate_deliveries=dedupe.duplicate_deliveries,
        event_identity=dedupe.event_identity,
        first_seen=_iso(dedupe.first_seen),
        last_seen=_iso(dedupe.last_seen),
    )


def _risk_summary(canonical: CanonicalAlert) -> RiskSummary | None:
    if canonical.risk is None:
        return None
    return RiskSummary(score=canonical.risk.score, tier=canonical.risk.tier.value)


def _risk_detail(canonical: CanonicalAlert) -> RiskDetail | None:
    risk = canonical.risk
    if risk is None:
        return None
    return RiskDetail(
        score=risk.score,
        tier=risk.tier.value,
        engine_version=risk.engine_version,
        degraded=risk.degraded,
        summary=risk.summary,
        factors=[
            {
                "name": factor.name,
                "points": factor.points,
                "max": factor.max,
                "detail": factor.detail,
            }
            for factor in risk.factors
        ],
    )


def _decision_summary(canonical: CanonicalAlert) -> DecisionSummary | None:
    if canonical.decision is None:
        return None
    return DecisionSummary(
        action=canonical.decision.action.value,
        severity=canonical.decision.severity.value if canonical.decision.severity else None,
    )


def _decision_detail(canonical: CanonicalAlert) -> DecisionDetail | None:
    decision = canonical.decision
    if decision is None:
        return None
    return DecisionDetail(
        action=decision.action.value,
        severity=decision.severity.value if decision.severity else None,
        reasons=list(decision.reasons),
        runbook=decision.runbook,
        decided_at=_iso(decision.decided_at),
    )


def _ioc_summaries(canonical: CanonicalAlert) -> list[IOCReadSummary]:
    summaries: list[IOCReadSummary] = []
    for ioc in canonical.iocs:
        provenance = [
            {
                "field": item.field,
                "extractor": item.extractor,
                "location": item.location,
            }
            for item in ioc.provenance
        ]
        summaries.append(
            IOCReadSummary(
                type=ioc.type.value,
                value=ioc.value,
                enrichment=redact_mapping(dict(ioc.enrichment)),
                provenance=provenance,
            )
        )
    return summaries


def _source_event_safe(canonical: CanonicalAlert) -> dict[str, Any]:
    """Rule/agent/location/data/syscheck — never ``full_log``."""
    event = canonical.source_event
    return {
        "rule": _rule_summary(canonical).model_dump(mode="json"),
        "agent": _agent_summary(canonical).model_dump(mode="json"),
        "location": event.location,
        "data": redact_mapping(dict(event.data)),
        "syscheck": redact_mapping(dict(event.syscheck)),
    }


def alert_summary_from_record(record: PersistedAlert) -> AlertSummary:
    """List-row projection of a persisted alert."""
    canonical = record.canonical
    return AlertSummary(
        alert_id=str(record.alert_id),
        source=record.source,
        received_at=record.received_at.isoformat(),
        created_at=record.created_at.isoformat(),
        incident_id=record.incident_id,
        rule=_rule_summary(canonical),
        agent=_agent_summary(canonical),
        risk=_risk_summary(canonical),
        decision=_decision_summary(canonical),
        dedupe=_dedupe_summary(canonical, group_key=record.dedupe_group_key),
        enrichment_status=canonical.enrichment_status,
    )


def alert_detail_from_record(record: PersistedAlert) -> AlertDetail:
    """Detail projection of a persisted alert (no ``full_log``, no secrets)."""
    canonical = record.canonical
    asset = None
    if canonical.asset is not None:
        asset = {
            "name": canonical.asset.name,
            "tier": canonical.asset.tier,
            "owner": canonical.asset.owner,
        }
    return AlertDetail(
        alert_id=str(record.alert_id),
        source=record.source,
        received_at=record.received_at.isoformat(),
        created_at=record.created_at.isoformat(),
        incident_id=record.incident_id,
        rule=_rule_summary(canonical),
        agent=_agent_summary(canonical),
        asset=asset,
        location=canonical.source_event.location,
        source_event=_source_event_safe(canonical),
        risk=_risk_detail(canonical),
        decision=_decision_detail(canonical),
        dedupe=_dedupe_summary(canonical, group_key=record.dedupe_group_key),
        enrichment_status=canonical.enrichment_status,
        iocs=_ioc_summaries(canonical),
    )


def incident_summary_from_domain(incident: Incident) -> IncidentSummary:
    """List-row projection of a persisted incident."""
    return IncidentSummary(
        incident_id=incident.incident_id,
        status=incident.status.value,
        severity=incident.severity.value,
        primary_alert_id=str(incident.primary_alert_id),
        dedupe_group_key=incident.dedupe_group_key,
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
        acknowledged_at=_iso(incident.acknowledged_at),
        resolved_at=_iso(incident.resolved_at),
    )


def linked_alert_summary(record: PersistedAlert, *, primary_alert_id: UUID) -> LinkedAlertSummary:
    """Compact linked-alert row for incident detail."""
    canonical = record.canonical
    return LinkedAlertSummary(
        alert_id=str(record.alert_id),
        received_at=record.received_at.isoformat(),
        rule_id=record.rule_id,
        rule_level=record.rule_level,
        agent_id=record.agent_id,
        agent_name=record.agent_name,
        risk_score=canonical.risk.score if canonical.risk is not None else None,
        risk_tier=canonical.risk.tier.value if canonical.risk is not None else None,
        decision_action=canonical.decision.action.value if canonical.decision is not None else None,
        is_primary=record.alert_id == primary_alert_id,
    )


def incident_detail_from_domain(
    incident: Incident, *, linked_alerts: list[PersistedAlert]
) -> IncidentDetail:
    """Incident detail with linked-alert summaries (primary first)."""
    summaries = [
        linked_alert_summary(record, primary_alert_id=incident.primary_alert_id)
        for record in linked_alerts
    ]
    summaries.sort(key=lambda item: (not item.is_primary, item.received_at, item.alert_id))
    primary = next((item for item in summaries if item.is_primary), None)
    return IncidentDetail(
        incident_id=incident.incident_id,
        status=incident.status.value,
        severity=incident.severity.value,
        primary_alert_id=str(incident.primary_alert_id),
        dedupe_group_key=incident.dedupe_group_key,
        created_at=incident.created_at.isoformat(),
        updated_at=incident.updated_at.isoformat(),
        acknowledged_at=_iso(incident.acknowledged_at),
        resolved_at=_iso(incident.resolved_at),
        linked_alert_count=len(summaries),
        primary_alert=primary,
        linked_alerts=summaries,
    )


def _evidence_sort_key(evidence_type: str, value: str) -> tuple[int, str]:
    """Deterministic evidence ordering: type order (fixed), then value."""
    try:
        order = EVIDENCE_TYPE_ORDER.index(EvidenceType(evidence_type))
    except ValueError:  # unknown stored type (schema drift) sorts last
        order = len(EVIDENCE_TYPE_ORDER)
    return (order, value)


def _correlation_member_read(member: CorrelationMemberSummary) -> CorrelationMemberRead:
    """Member row with its pairwise evidence (reasons derived on read)."""
    return CorrelationMemberRead(
        alert_id=str(member.alert_id),
        received_at=member.received_at.isoformat(),
        joined_at=member.joined_at.isoformat(),
        rule_id=member.rule_id,
        rule_level=member.rule_level,
        agent_id=member.agent_id,
        agent_name=member.agent_name,
        dedupe_group_key=member.dedupe_group_key,
        incident_id=member.incident_id,
        risk_tier=member.risk_tier,
        decision_action=member.decision_action,
        evidence=[
            CorrelationMemberEvidenceRead(
                evidence_type=item.evidence_type,
                value=item.value,
                reason=evidence_reason(item.evidence_type, item.value),
                peer_alert_id=item.peer_alert_id,
            )
            for item in member.evidence
        ],
    )


def correlation_context_summary_from_record(
    context: CorrelationContextRecord,
) -> CorrelationContextSummaryRead:
    """List-row projection of a correlation context."""
    return CorrelationContextSummaryRead(
        context_id=context.context_id,
        created_at=context.created_at.isoformat(),
        updated_at=context.updated_at.isoformat(),
        first_seen=context.first_seen.isoformat(),
        last_seen=context.last_seen.isoformat(),
        member_count=context.member_count,
    )


def correlation_detail_from_records(
    context: CorrelationContextRecord, members: list[CorrelationMemberSummary]
) -> CorrelationContextDetailRead:
    """Detail projection: members plus aggregated, explainable evidence.

    Context-level evidence aggregates the stored pairwise items: every
    distinct ``(evidence_type, value)`` pair with the alerts it relates and
    the ``received_at`` span of those alerts. Ordering is deterministic
    everywhere (members oldest-first, evidence by type order then value).
    """
    member_rows = sorted(members, key=lambda item: (item.received_at, item.alert_id))
    received = {str(member.alert_id): member.received_at for member in member_rows}

    aggregated: dict[tuple[str, str], dict[str, Any]] = {}
    for member in member_rows:
        for item in member.evidence:
            key = (item.evidence_type, item.value)
            entry = aggregated.setdefault(
                key,
                {
                    "evidence_type": item.evidence_type,
                    "value": item.value,
                    "related": set(),
                },
            )
            entry["related"].add(str(member.alert_id))
            entry["related"].add(item.peer_alert_id)

    evidence_rows: list[CorrelationEvidenceRead] = []
    for key in sorted(aggregated, key=lambda pair: _evidence_sort_key(*pair)):
        entry = aggregated[key]
        related_ids = sorted(alert_id for alert_id in entry["related"] if alert_id in received)
        timestamps = [received[alert_id] for alert_id in related_ids]
        evidence_rows.append(
            CorrelationEvidenceRead(
                evidence_type=entry["evidence_type"],
                value=entry["value"],
                reason=evidence_reason(entry["evidence_type"], entry["value"]),
                related_alert_ids=related_ids,
                first_seen=min(timestamps).isoformat() if timestamps else "",
                last_seen=max(timestamps).isoformat() if timestamps else "",
            )
        )

    return CorrelationContextDetailRead(
        context_id=context.context_id,
        created_at=context.created_at.isoformat(),
        updated_at=context.updated_at.isoformat(),
        first_seen=context.first_seen.isoformat(),
        last_seen=context.last_seen.isoformat(),
        member_count=len(member_rows),
        members=[_correlation_member_read(member) for member in member_rows],
        evidence=evidence_rows,
    )


__all__ = [
    "AlertDetail",
    "AlertListResponse",
    "AlertSummary",
    "CorrelationContextDetailRead",
    "CorrelationContextSummaryRead",
    "CorrelationEvidenceRead",
    "CorrelationListResponse",
    "CorrelationMemberEvidenceRead",
    "CorrelationMemberRead",
    "IncidentDetail",
    "IncidentListResponse",
    "IncidentSummary",
    "IncidentTimelineResponse",
    "Pagination",
    "alert_detail_from_record",
    "alert_summary_from_record",
    "correlation_context_summary_from_record",
    "correlation_detail_from_records",
    "incident_detail_from_domain",
    "incident_summary_from_domain",
    "make_pagination",
    "redact_mapping",
]
