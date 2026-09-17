"""Late-enrichment reassessment workflow.

This module owns the deterministic re-assessment path used when enrichment
arrives after an alert already has a risk assessment.

Persistence, incident lifecycle changes, and notifications are intentionally
handled by the caller so this service remains focused on orchestration.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import sessionmaker

from ..db.session import session_scope
from ..decisions.router import DecisionEngine
from ..enrichment import EnrichmentChain, EnrichmentContext
from ..models.assessment import Decision, RiskAssessment
from ..models.canonical import CanonicalAlert
from ..models.ioc import IOC, ioc_sort_key
from ..models.repositories import AlertRepository
from ..scoring.engine import RiskScorer
from .assessment_persistence import AssessmentPersistResult, persist_assessment


@dataclass(frozen=True)
class LateEnrichmentResult:
    """Result of enriching and re-assessing one persisted alert."""

    canonical: CanonicalAlert
    previous_risk: RiskAssessment | None
    previous_decision: Decision | None


def _enrichment_fingerprint(iocs: Sequence[IOC]) -> tuple[tuple[str, str, str], ...]:
    """Timestamp-insensitive fingerprint of the per-indicator enrichment state.

    One entry per ``(indicator key, provider)`` pair: the provider record with
    its volatile ``timestamp`` field removed, canonically serialized. The
    timestamp is excluded because live retries of a *failed* lookup stamp a
    fresh one on every attempt (definitive cache replays, in contrast, keep
    their original timestamp byte-identically), while it is never a scoring or
    decision input. Two enrichment runs with the same content therefore
    compare equal, which is what makes "the same enrichment never re-scores
    an alert twice" hold (Phase 2.7A idempotency guard).

    Order-insensitive by construction: indicators are folded in
    ``ioc_sort_key`` order and providers in sorted-name order, so the
    fingerprint is stable across runs regardless of merge order.
    """
    parts: list[tuple[str, str, str]] = []
    for ioc in sorted(iocs, key=ioc_sort_key):
        for provider in sorted(ioc.enrichment):
            record = dict(ioc.enrichment[provider])
            record.pop("timestamp", None)
            parts.append(
                (ioc.key, provider, json.dumps(record, sort_keys=True, separators=(",", ":")))
            )
    return tuple(parts)


class LateEnrichmentService:
    """Run enrichment and deterministic score/decision re-assessment."""

    def __init__(
        self,
        enrichment_chain: EnrichmentChain,
        scorer: RiskScorer,
        decider: DecisionEngine,
    ) -> None:
        self._enrichment_chain = enrichment_chain
        self._scorer = scorer
        self._decider = decider

    def reassess(
        self,
        canonical: CanonicalAlert,
        *,
        decided_at: datetime | None = None,
    ) -> LateEnrichmentResult:
        """Enrich ``canonical`` and recompute its risk and decision."""

        enrichment = self._enrichment_chain.enrich(
            canonical.iocs,
            context=EnrichmentContext(
                alert_id=canonical.alert_id,
                source=canonical.source,
                received_at=canonical.received_at,
                dedupe_group=(canonical.dedupe.group_key if canonical.dedupe is not None else None),
            ),
        )

        enriched = canonical.model_copy(
            update={
                "iocs": list(enrichment.iocs),
                "enrichment_status": enrichment.status.value,
            }
        )

        previous_risk = canonical.risk
        previous_decision = canonical.decision

        risk = self._scorer.score(enriched)
        decision = self._decider.decide(
            risk,
            alert=enriched,
            decided_at=decided_at or enriched.received_at,
        )

        reassessed = enriched.model_copy(
            update={
                "risk": risk,
                "decision": decision,
            }
        )

        return LateEnrichmentResult(
            canonical=reassessed,
            previous_risk=previous_risk,
            previous_decision=previous_decision,
        )

    def reassess_persisted(
        self,
        session_factory: sessionmaker,
        *,
        alert_id: UUID,
        decided_at: datetime | None = None,
    ) -> tuple[LateEnrichmentResult, AssessmentPersistResult]:
        """Re-enrich, re-score, re-decide, and persist one alert of record."""

        with session_scope(session_factory) as session:
            persisted = AlertRepository(session).get_alert(alert_id)

        if persisted is None:
            raise LookupError(f"alert {alert_id} not found")

        result = self.reassess(
            persisted.canonical,
            decided_at=decided_at,
        )

        if result.canonical.risk is None or result.canonical.decision is None:
            raise RuntimeError("reassessment produced an incomplete assessment")

        persistence = persist_assessment(
            session_factory,
            alert_id=alert_id,
            canonical=result.canonical,
            risk=result.canonical.risk,
            decision=result.canonical.decision,
            dedupe_group_key=persisted.dedupe_group_key,
            occurred_at=decided_at or result.canonical.received_at,
            previous_risk=result.previous_risk,
            previous_decision=result.previous_decision,
        )

        return result, persistence

    def reassess_persisted_if_changed(
        self,
        session_factory: sessionmaker,
        *,
        alert_id: UUID,
        decided_at: datetime | None = None,
    ) -> tuple[LateEnrichmentResult, AssessmentPersistResult] | None:
        """Re-enrich one persisted alert; re-assess only if the enrichment changed.

        Phase 2.7A idempotency guard for the automatic late-enrichment
        trigger. The freshly produced enrichment (one chain run, exactly as
        in :meth:`reassess`) is compared against the enrichment already
        persisted on the alert of record via
        :func:`_enrichment_fingerprint` — insensitive to the volatile
        per-record ``timestamp``:

        * **unchanged** (cache replays, retried identical failures, no new
          verdicts) → returns ``None`` without scoring, persisting or
          appending audit rows; the same enrichment never re-scores an alert
          twice;
        * **changed** (a late definitive verdict, a changed verdict, a
          newly enabled provider) → the authoritative re-assessment and the
          atomic :func:`persist_assessment` run exactly as in
          :meth:`reassess_persisted` (same incident create/attach path,
          same ``before``/``after`` audit snapshots).

        Raises:
            LookupError: if ``alert_id`` is not persisted.
        """
        with session_scope(session_factory) as session:
            persisted = AlertRepository(session).get_alert(alert_id)

        if persisted is None:
            raise LookupError(f"alert {alert_id} not found")

        canonical = persisted.canonical
        enrichment = self._enrichment_chain.enrich(
            canonical.iocs,
            context=EnrichmentContext(
                alert_id=canonical.alert_id,
                source=canonical.source,
                received_at=canonical.received_at,
                dedupe_group=(canonical.dedupe.group_key if canonical.dedupe is not None else None),
            ),
        )

        if _enrichment_fingerprint(enrichment.iocs) == _enrichment_fingerprint(canonical.iocs):
            # No new information: strict no-op (no score, no write, no audit).
            return None

        enriched = canonical.model_copy(
            update={
                "iocs": list(enrichment.iocs),
                "enrichment_status": enrichment.status.value,
            }
        )

        previous_risk = canonical.risk
        previous_decision = canonical.decision

        risk = self._scorer.score(enriched)
        decision = self._decider.decide(
            risk,
            alert=enriched,
            decided_at=decided_at or enriched.received_at,
        )

        reassessed = enriched.model_copy(
            update={
                "risk": risk,
                "decision": decision,
            }
        )

        if risk is None or decision is None:
            raise RuntimeError("reassessment produced an incomplete assessment")

        persistence = persist_assessment(
            session_factory,
            alert_id=alert_id,
            canonical=reassessed,
            risk=risk,
            decision=decision,
            dedupe_group_key=persisted.dedupe_group_key,
            occurred_at=decided_at or reassessed.received_at,
            previous_risk=previous_risk,
            previous_decision=previous_decision,
        )

        return (
            LateEnrichmentResult(
                canonical=reassessed,
                previous_risk=previous_risk,
                previous_decision=previous_decision,
            ),
            persistence,
        )


__all__ = [
    "LateEnrichmentResult",
    "LateEnrichmentService",
]
