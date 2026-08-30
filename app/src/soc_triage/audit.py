"""Append-only audit trail (Phase 1D).

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

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from .ingest.deduplication import DedupeStatus, DeliveryDecision
from .models.assessment import Decision, RiskAssessment

# --- Audit vocabulary ------------------------------------------------------

#: Components acting on behalf of the pipeline (the "who").
ACTOR_INGEST = "ingest"
ACTOR_SCORING = "scoring"
ACTOR_DECISION = "decisions"

ENTITY_ALERT = "alert"
ENTITY_DEDUPE_GROUP = "dedupe_group"

#: "What" — stable action names (surfaced in logs, consoles, and digests).
ACTION_ALERT_CREATED = "alert.created"
ACTION_DUPLICATE_ABSORBED = "alert.duplicate_absorbed"
ACTION_GENERATION_STARTED = "dedupe.generation_started"
ACTION_CONTENT_DIVERGENCE = "alert.content_divergence"
ACTION_ALERT_SCORED = "alert.scored"
ACTION_ALERT_DECIDED = "alert.decided"


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


__all__ = [
    "ACTION_ALERT_CREATED",
    "ACTION_ALERT_DECIDED",
    "ACTION_ALERT_SCORED",
    "ACTION_CONTENT_DIVERGENCE",
    "ACTION_DUPLICATE_ABSORBED",
    "ACTION_GENERATION_STARTED",
    "ACTOR_DECISION",
    "ACTOR_INGEST",
    "ACTOR_SCORING",
    "ENTITY_ALERT",
    "ENTITY_DEDUPE_GROUP",
    "AuditEntry",
    "audit_entries_for_assessment",
    "audit_entries_for_decision",
]
