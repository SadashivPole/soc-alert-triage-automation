from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock

from tests.conftest import make_canonical_alert, make_ioc

from soc_triage.decisions import DecisionEngine, default_decision_policy
from soc_triage.enrichment import (
    EnrichmentContext,
    EnrichmentOutcome,
    EnrichmentStatus,
)
from soc_triage.models.assessment import RiskAssessment
from soc_triage.scoring import RiskScorer, default_scoring_policy
from soc_triage.services.late_enrichment import LateEnrichmentService

DECIDED_AT = datetime(2026, 8, 29, 10, 15, 0, tzinfo=UTC)


def test_reassess_merges_late_enrichment_and_preserves_previous_assessment() -> None:
    """Late enrichment replaces IOC enrichment and returns prior assessment state."""

    alert = make_canonical_alert(
        iocs=[make_ioc("203.0.113.10")],
        enrichment_status="skipped",
    )

    previous_risk = RiskAssessment(
        score=12,
        tier="low",
        engine_version="scoring.v2",
        factors=(),
        summary="Previous assessment.",
    )

    previous_decision = alert.decision

    alert = alert.model_copy(
        update={
            "risk": previous_risk,
            "decision": previous_decision,
        }
    )

    enriched_ioc = alert.iocs[0].model_copy(
        update={
            "enrichment": {
                "fake": {
                    "reputation": "malicious",
                }
            }
        }
    )

    outcome = EnrichmentOutcome(
        status=EnrichmentStatus.COMPLETE,
        iocs=(enriched_ioc,),
    )

    chain = Mock()
    chain.enrich.return_value = outcome

    scorer = RiskScorer(default_scoring_policy())
    decider = DecisionEngine(default_decision_policy())

    service = LateEnrichmentService(chain, scorer, decider)

    result = service.reassess(alert, decided_at=DECIDED_AT)

    assert result.previous_risk is previous_risk
    assert result.previous_decision is previous_decision

    assert result.canonical.enrichment_status == "complete"
    assert result.canonical.iocs[0].enrichment == {"fake": {"reputation": "malicious"}}

    assert result.canonical.risk is not None
    assert result.canonical.decision is not None

    chain.enrich.assert_called_once()

    context = chain.enrich.call_args.kwargs["context"]

    assert isinstance(context, EnrichmentContext)
    assert context.alert_id == alert.alert_id
    assert context.source == alert.source
    assert context.received_at == alert.received_at


def test_reassess_passes_existing_dedupe_group_to_enrichment() -> None:
    alert = make_canonical_alert(
        iocs=[make_ioc("203.0.113.10")],
    )

    outcome = EnrichmentOutcome(
        status=EnrichmentStatus.SKIPPED,
        iocs=tuple(alert.iocs),
    )

    chain = Mock()
    chain.enrich.return_value = outcome

    service = LateEnrichmentService(
        chain,
        RiskScorer(default_scoring_policy()),
        DecisionEngine(default_decision_policy()),
    )

    service.reassess(alert, decided_at=DECIDED_AT)

    context = chain.enrich.call_args.kwargs["context"]

    assert context.dedupe_group == (alert.dedupe.group_key if alert.dedupe is not None else None)


def test_reassess_uses_supplied_decision_timestamp() -> None:
    alert = make_canonical_alert()

    outcome = EnrichmentOutcome(
        status=EnrichmentStatus.SKIPPED,
        iocs=tuple(alert.iocs),
    )

    chain = Mock()
    chain.enrich.return_value = outcome

    decider = Mock()
    decision = Mock()
    decider.decide.return_value = decision

    service = LateEnrichmentService(
        chain,
        RiskScorer(default_scoring_policy()),
        decider,
    )

    result = service.reassess(alert, decided_at=DECIDED_AT)

    assert result.canonical.decision is decision

    decider.decide.assert_called_once()

    args = decider.decide.call_args
    assert args.kwargs["alert"].alert_id == result.canonical.alert_id
    assert args.args[0] == result.canonical.risk
    assert args.kwargs["alert"].risk is None
    assert args.kwargs["alert"].decision is None
    assert args.kwargs["decided_at"] == DECIDED_AT
