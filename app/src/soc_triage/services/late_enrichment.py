"""Late-enrichment reassessment workflow.

This module owns the deterministic re-assessment path used when enrichment
arrives after an alert already has a risk assessment.

Persistence, incident lifecycle changes, and notifications are intentionally
handled by the caller so this service remains focused on orchestration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from ..decisions.router import DecisionEngine
from ..enrichment import EnrichmentChain, EnrichmentContext
from ..models.assessment import Decision, RiskAssessment
from ..db.session import session_scope
from ..models.canonical import CanonicalAlert
from ..models.repositories import AlertRepository
from .assessment_persistence import AssessmentPersistResult, persist_assessment
from ..scoring.engine import RiskScorer


@dataclass(frozen=True)
class LateEnrichmentResult:
    """Result of enriching and re-assessing one persisted alert."""

    canonical: CanonicalAlert
    previous_risk: RiskAssessment | None
    previous_decision: Decision | None


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
                dedupe_group=(
                    canonical.dedupe.group_key
                    if canonical.dedupe is not None
                    else None
                ),
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
        session_factory,
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


__all__ = [
    "LateEnrichmentResult",
    "LateEnrichmentService",
]
