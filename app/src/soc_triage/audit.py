"""Append-only audit trail (Phase 1D + 2B).

Implements ARCHITECTURE.md §15: an append-only ``audit_log`` recording
*who/what/when/before→after* for every meaningful state change. The table
itself is an append-only system of record — repositories expose insert
access only.

Audit policy lives here, next to the data: :func:`audit_entries_for_decision`
maps one deduplication decision onto the audit entries it produces. Entries
carry **small structured snapshots** (counts, ids, timestamps, status) —
never raw alert payloads and never anything resembling a secret
(SECURITY.md §5, §7).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from .ingest.deduplication import DedupeStatus, DeliveryDecision
from .models.assessment import Decision, RiskAssessment
from .models.incident import Incident, IncidentStatus

# --- Audit vocabulary ------------------------------------------------------

#: Components acting on behalf of the pipeline (the "who").
ACTOR_INGEST = "ingest"
ACTOR_SCORING = "scoring"
ACTOR_DECISION = "decisions"
ACTOR_N8N = "n8n"
ACTOR_ANALYST = "analyst"
ACTOR_SYSTEM = "system"

ENTITY_ALERT = "alert"
ENTITY_DEDUPE_GROUP = "dedupe_group"
ENTITY_INCIDENT = "incident"
ENTITY_NOTIFICATION = "notification"
ENTITY_FEEDBACK = "feedback"

#: "What" — stable action names (surfaced in logs, consoles, and digests).
ACTION_ALERT_CREATED = "alert.created"
ACTION_DUPLICATE_ABSORBED = "alert.duplicate_absorbed"
ACTION_GENERATION_STARTED = "dedupe.generation_started"
ACTION_CONTENT_DIVERGENCE = "alert.content_divergence"
ACTION_ALERT_SCORED = "alert.scored"
ACTION_ALERT_DECIDED = "alert.decided"

# Phase 3.1 — automatic incident creation
ACTION_INCIDENT_CREATED = "incident.created"

# Phase 3.2 — incident lifecycle
ACTION_INCIDENT_STATUS_UPDATED = "incident.status_updated"
ACTION_INCIDENT_ESCALATED = "incident.escalated"
ACTION_INCIDENT_CONTAINMENT_REQUESTED = "incident.containment_requested"

# Phase 2B — n8n SOAR integration
ACTION_NOTIFICATION_ATTEMPT = "notification.attempt"
ACTION_NOTIFICATION_DELIVERED = "notification.delivered"
ACTION_NOTIFICATION_FAILED = "notification.failed"
ACTION_NOTIFICATION_SKIPPED = "notification.skipped"
ACTION_NOTIFICATION_DUPLICATE_SUPPRESSED = "notification.duplicate_suppressed"
ACTION_FEEDBACK_RECEIVED = "feedback.received"


class AuditEntry(BaseModel):
    """One append-only audit record, ready for persistence."""

    model_config = {"frozen": True}

    actor: str
    action: str
    entity_type: str
    entity_id: str
    before: dict[str, Any] | None = Field(default=None)
    after: dict[str, Any] | None = Field(default=None)


def _generation_snapshot(decision: DeliveryDecision, key: str) -> dict[str, Any]:
    group = decision.group_before if key == "before" else decision.group
    if group is None:
        return {}
    return {
        "generation": group.generation,
        "occurrences": group.occurrences,
        "duplicate_deliveries": group.duplicate_deliveries,
        "first_seen": group.first_seen.isoformat() if group.first_seen is not None else None,
        "last_seen": group.last_seen.isoformat() if group.last_seen is not None else None,
    }


def audit_entries_for_decision(decision: DeliveryDecision) -> list[AuditEntry]:
    """Map a deduplication decision onto its audit entries.

    * new/repeated event  → ``alert.created`` (plus ``dedupe.generation_started``
      whenever a new generation begins, including a group's first event);
    * exact duplicate    → ``alert.duplicate_absorbed`` (evidence preserved:
      the delivery is counted, not discarded);
    * divergent re-delivery → ``alert.content_divergence`` (warning-level
      evidence of a mismatched identity).
    """
    entries: list[AuditEntry] = []
    alert_id: UUID = decision.record.alert_id

    if decision.generation_started:
        entries.append(
            AuditEntry(
                actor=ACTOR_INGEST,
                action=ACTION_GENERATION_STARTED,
                entity_type=ENTITY_DEDUPE_GROUP,
                entity_id=decision.group.group_key,
                before=_generation_snapshot(decision, "before") or None,
                after=_generation_snapshot(decision, "after"),
            )
        )

    if decision.status is not DedupeStatus.EXACT_DUPLICATE:
        entries.append(
            AuditEntry(
                actor=ACTOR_INGEST,
                action=ACTION_ALERT_CREATED,
                entity_type=ENTITY_ALERT,
                entity_id=str(alert_id),
                after={
                    "alert_id": str(alert_id),
                    "event_identity": decision.record.event_identity,
                    "dedupe_group": decision.group.group_key,
                    "dedupe_status": decision.status.value,
                    "occurrences": decision.group.occurrences,
                    "generation": decision.group.generation,
                },
            )
        )

    if decision.status is DedupeStatus.EXACT_DUPLICATE:
        before = (
            {
                "delivery_count": decision.record_before.delivery_count,
                "duplicate_deliveries": (
                    decision.group_before.duplicate_deliveries
                    if decision.group_before is not None
                    else 0
                ),
            }
            if decision.record_before is not None
            else None
        )
        entries.append(
            AuditEntry(
                actor=ACTOR_INGEST,
                action=ACTION_DUPLICATE_ABSORBED,
                entity_type=ENTITY_ALERT,
                entity_id=str(alert_id),
                before=before,
                after={
                    "alert_id": str(alert_id),
                    "delivery_count": decision.record.delivery_count,
                    "duplicate_deliveries": decision.group.duplicate_deliveries,
                },
            )
        )

    if decision.content_diverged:
        entries.append(
            AuditEntry(
                actor=ACTOR_INGEST,
                action=ACTION_CONTENT_DIVERGENCE,
                entity_type=ENTITY_ALERT,
                entity_id=str(alert_id),
                after={
                    "alert_id": str(alert_id),
                    "dedupe_group": decision.group.group_key,
                    "content_variants": decision.record.content_variants,
                },
            )
        )

    return entries


def _risk_snapshot(risk: RiskAssessment | None) -> dict[str, Any] | None:
    """A small structured snapshot of a risk assessment (no raw data).

    Keeps audit rows compact and secret-free (SECURITY.md §5, §7): the score,
    tier, engine version, and per-factor points only — not the full detail
    strings or alert payload.
    """
    if risk is None:
        return None
    return {
        "score": risk.score,
        "tier": risk.tier.value,
        "engine_version": risk.engine_version,
        "degraded": risk.degraded,
        "factors": {factor.name: factor.points for factor in risk.factors},
    }


def _decision_snapshot(decision: Decision | None) -> dict[str, Any] | None:
    """A small structured snapshot of a decision (no raw data)."""
    if decision is None:
        return None
    return {
        "action": decision.action.value,
        "severity": decision.severity.value if decision.severity is not None else None,
        "reasons": list(decision.reasons),
    }


def audit_entries_for_assessment(
    alert_id: UUID,
    *,
    risk: RiskAssessment,
    decision: Decision,
    previous_risk: RiskAssessment | None = None,
    previous_decision: Decision | None = None,
) -> list[AuditEntry]:
    """Map one score+decision assessment onto its append-only audit entries.

    Emits ``alert.scored`` and ``alert.decided`` records. ``previous_*``
    populate the ``before`` snapshot when this is a re-assessment (e.g. a
    recurrence-escalation re-score, ARCHITECTURE.md §9); on the first
    assessment ``before`` is ``None``. This is the system of record for "why
    did the SOC bot score X and route to Y".
    """
    return [
        AuditEntry(
            actor=ACTOR_SCORING,
            action=ACTION_ALERT_SCORED,
            entity_type=ENTITY_ALERT,
            entity_id=str(alert_id),
            before=_risk_snapshot(previous_risk),
            after=_risk_snapshot(risk),
        ),
        AuditEntry(
            actor=ACTOR_DECISION,
            action=ACTION_ALERT_DECIDED,
            entity_type=ENTITY_ALERT,
            entity_id=str(alert_id),
            before=_decision_snapshot(previous_decision),
            after=_decision_snapshot(decision),
        ),
    ]


def audit_entries_for_incident(incident: Incident) -> list[AuditEntry]:
    """Map an automatic incident creation onto its audit entry (Phase 3.1).

    Emits ``incident.created`` with a small structured snapshot (ids,
    severity, status, dedupe group) — no raw payloads (SECURITY.md §5, §7).
    ``entity_id`` is the human-readable incident id.
    """
    return [
        AuditEntry(
            actor=ACTOR_DECISION,
            action=ACTION_INCIDENT_CREATED,
            entity_type=ENTITY_INCIDENT,
            entity_id=incident.incident_id,
            after={
                "incident_id": incident.incident_id,
                "alert_id": str(incident.primary_alert_id),
                "severity": incident.severity.value,
                "status": incident.status.value,
                "dedupe_group_key": incident.dedupe_group_key,
            },
        )
    ]


def _incident_status_snapshot(
    incident_id: str,
    *,
    status: IncidentStatus,
    acknowledged_at: datetime | None = None,
    resolved_at: datetime | None = None,
) -> dict[str, Any]:
    """Small structured lifecycle snapshot (ids + timestamps only, Phase 3.2)."""
    return {
        "incident_id": incident_id,
        "status": status.value,
        "acknowledged_at": acknowledged_at.isoformat() if acknowledged_at is not None else None,
        "resolved_at": resolved_at.isoformat() if resolved_at is not None else None,
    }


def audit_entries_for_incident_status(
    *,
    incident: Incident,
    previous_status: IncidentStatus,
    actor: str,
    notes: str | None = None,
) -> list[AuditEntry]:
    """Map one incident lifecycle transition onto its audit entries (Phase 3.2).

    Emits ``incident.status_updated`` with the acting analyst, the incident
    id, and the **before/after** lifecycle state (including the lifecycle
    timestamps after the change). When the new state is ``escalated``, an
    additional ``incident.escalated`` entry records the same change for
    escalation-specific consumers. Snapshots are small and structured —
    never raw alert payloads and never secrets (SECURITY.md §5, §7);
    optional analyst ``notes`` are included as provided (callers bound them).
    """
    before = {"status": previous_status.value}
    after = _incident_status_snapshot(
        incident.incident_id,
        status=incident.status,
        acknowledged_at=incident.acknowledged_at,
        resolved_at=incident.resolved_at,
    )
    if notes:
        after["notes"] = notes
    entries = [
        AuditEntry(
            actor=actor,
            action=ACTION_INCIDENT_STATUS_UPDATED,
            entity_type=ENTITY_INCIDENT,
            entity_id=incident.incident_id,
            before=before,
            after=after,
        )
    ]
    if incident.status is IncidentStatus.ESCALATED:
        entries.append(
            AuditEntry(
                actor=actor,
                action=ACTION_INCIDENT_ESCALATED,
                entity_type=ENTITY_INCIDENT,
                entity_id=incident.incident_id,
                before=before,
                after=after,
            )
        )
    return entries


def audit_entries_for_incident_containment_request(
    *,
    incident_id: str,
    alert_id: UUID,
    actor: str,
) -> list[AuditEntry]:
    """Record an approval-required containment request against an incident.

    A ``contain_requested`` analyst verdict never changes the incident state
    and never executes containment (ADR-8: human approval required). The
    approval email itself is sent by the n8n workflow (WF5); this entry is
    the incident-side record that a containment approval was requested and
    is pending — and that nothing was executed.
    """
    return [
        AuditEntry(
            actor=actor,
            action=ACTION_INCIDENT_CONTAINMENT_REQUESTED,
            entity_type=ENTITY_INCIDENT,
            entity_id=incident_id,
            before=None,
            after={
                "incident_id": incident_id,
                "alert_id": str(alert_id),
                "requested_by": actor,
                "state": "approval_required",
                "containment_executed": False,
            },
        )
    ]


def audit_entries_for_notification(
    alert_id: UUID,
    *,
    status: str,
    http_status: int | None = None,
    error_type: str | None = None,
    attempts: int = 0,
    payload_hash: str | None = None,
    webhook_host: str | None = None,
    duration_ms: int = 0,
    duplicate_suppressed: bool = False,
) -> list[AuditEntry]:
    """Map a notification result onto audit entries (Phase 2B).

    Emits ``notification.attempt`` always, plus ``delivered`` / ``failed`` /
    ``skipped`` / ``duplicate_suppressed``. All fields are safe (no secrets,
    no full payload).
    """
    entries: list[AuditEntry] = []

    entries.append(
        AuditEntry(
            actor=ACTOR_N8N,
            action=ACTION_NOTIFICATION_ATTEMPT,
            entity_type=ENTITY_NOTIFICATION,
            entity_id=str(alert_id),
            after={
                "alert_id": str(alert_id),
                "status": status,
                "http_status": http_status,
                "attempts": attempts,
                "payload_hash": payload_hash,
                "webhook_host": webhook_host,
            },
        )
    )

    if duplicate_suppressed:
        entries.append(
            AuditEntry(
                actor=ACTOR_N8N,
                action=ACTION_NOTIFICATION_DUPLICATE_SUPPRESSED,
                entity_type=ENTITY_NOTIFICATION,
                entity_id=str(alert_id),
                after={
                    "alert_id": str(alert_id),
                    "reason": "already_delivered",
                },
            )
        )
        return entries

    if status == "delivered":
        entries.append(
            AuditEntry(
                actor=ACTOR_N8N,
                action=ACTION_NOTIFICATION_DELIVERED,
                entity_type=ENTITY_NOTIFICATION,
                entity_id=str(alert_id),
                after={
                    "alert_id": str(alert_id),
                    "http_status": http_status,
                    "attempts": attempts,
                    "duration_ms": duration_ms,
                    "webhook_host": webhook_host,
                },
            )
        )
    elif status == "failed":
        entries.append(
            AuditEntry(
                actor=ACTOR_N8N,
                action=ACTION_NOTIFICATION_FAILED,
                entity_type=ENTITY_NOTIFICATION,
                entity_id=str(alert_id),
                after={
                    "alert_id": str(alert_id),
                    "http_status": http_status,
                    "error_type": error_type,
                    "attempts": attempts,
                    "duration_ms": duration_ms,
                    "webhook_host": webhook_host,
                },
            )
        )
    elif status == "skipped":
        entries.append(
            AuditEntry(
                actor=ACTOR_SYSTEM,
                action=ACTION_NOTIFICATION_SKIPPED,
                entity_type=ENTITY_NOTIFICATION,
                entity_id=str(alert_id),
                after={
                    "alert_id": str(alert_id),
                    "reason": "n8n_disabled_or_duplicate",
                },
            )
        )

    return entries


def audit_entries_for_feedback(
    alert_id: UUID,
    *,
    verdict: str,
    actor: str,
) -> list[AuditEntry]:
    """Map a feedback receipt onto an audit entry (Phase 2B)."""
    return [
        AuditEntry(
            actor=ACTOR_ANALYST,
            action=ACTION_FEEDBACK_RECEIVED,
            entity_type=ENTITY_FEEDBACK,
            entity_id=str(alert_id),
            after={
                "alert_id": str(alert_id),
                "verdict": verdict,
                "actor": actor,
            },
        )
    ]


__all__ = [
    "ACTION_ALERT_CREATED",
    "ACTION_ALERT_DECIDED",
    "ACTION_ALERT_SCORED",
    "ACTION_CONTENT_DIVERGENCE",
    "ACTION_DUPLICATE_ABSORBED",
    "ACTION_FEEDBACK_RECEIVED",
    "ACTION_GENERATION_STARTED",
    "ACTION_INCIDENT_CONTAINMENT_REQUESTED",
    "ACTION_INCIDENT_CREATED",
    "ACTION_INCIDENT_ESCALATED",
    "ACTION_INCIDENT_STATUS_UPDATED",
    "ACTION_NOTIFICATION_ATTEMPT",
    "ACTION_NOTIFICATION_DELIVERED",
    "ACTION_NOTIFICATION_DUPLICATE_SUPPRESSED",
    "ACTION_NOTIFICATION_FAILED",
    "ACTION_NOTIFICATION_SKIPPED",
    "ACTOR_ANALYST",
    "ACTOR_DECISION",
    "ACTOR_INGEST",
    "ACTOR_N8N",
    "ACTOR_SCORING",
    "ACTOR_SYSTEM",
    "ENTITY_ALERT",
    "ENTITY_DEDUPE_GROUP",
    "ENTITY_FEEDBACK",
    "ENTITY_INCIDENT",
    "ENTITY_NOTIFICATION",
    "AuditEntry",
    "audit_entries_for_assessment",
    "audit_entries_for_decision",
    "audit_entries_for_feedback",
    "audit_entries_for_incident",
    "audit_entries_for_incident_containment_request",
    "audit_entries_for_incident_status",
    "audit_entries_for_notification",
]
