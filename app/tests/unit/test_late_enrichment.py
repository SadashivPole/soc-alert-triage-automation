from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tests.conftest import make_canonical_alert, make_ioc

from soc_triage.db.session import session_scope
from soc_triage.decisions import DecisionEngine, default_decision_policy
from soc_triage.enrichment import (
    EnrichmentContext,
    EnrichmentOutcome,
    EnrichmentStatus,
)
from soc_triage.models.assessment import RiskAssessment
from soc_triage.models.canonical import CanonicalAlert
from soc_triage.models.ioc import IOC, IOCType
from soc_triage.models.orm import Alert, Base
from soc_triage.models.repositories import AlertRepository, AuditRepository
from soc_triage.scoring import RiskScorer, default_scoring_policy
from soc_triage.services.late_enrichment import LateEnrichmentService, _enrichment_fingerprint

DECIDED_AT = datetime(2026, 8, 29, 10, 15, 0, tzinfo=UTC)

RECEIVED_AT = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Phase 2.7A — timestamp-insensitive enrichment fingerprint
# ---------------------------------------------------------------------------


def _vt_payload(*, lookup_status: str, timestamp: str, malicious: int = 0) -> dict:
    """A VirusTotal lookup record shaped like the provider's output."""
    return {
        "provider": "virustotal",
        "indicator_type": "ipv4",
        "lookup_status": lookup_status,
        "timestamp": timestamp,
        "result": (
            {
                "malicious": malicious,
                "suspicious": 0,
                "harmless": 3,
                "undetected": 7,
                "reputation": -5 if malicious else 0,
            }
            if lookup_status == "found"
            else {}
        ),
    }


def test_fingerprint_equal_for_identical_enrichment() -> None:
    record = _vt_payload(lookup_status="found", timestamp="2026-09-17T09:00:00+00:00", malicious=10)
    iocs_a = [make_ioc("203.0.113.10", enrichment={"virustotal": dict(record)})]
    iocs_b = [make_ioc("203.0.113.10", enrichment={"virustotal": dict(record)})]
    assert _enrichment_fingerprint(iocs_a) == _enrichment_fingerprint(iocs_b)


def test_fingerprint_insensitive_to_timestamp_changes() -> None:
    """Anti-spam core: retried failed lookups stamp a fresh timestamp on every
    attempt; the fingerprint must not treat that as new information."""
    iocs_a = [
        make_ioc(
            "203.0.113.10",
            enrichment={
                "virustotal": _vt_payload(
                    lookup_status="timeout", timestamp="2026-09-17T09:00:00+00:00"
                )
            },
        )
    ]
    iocs_b = [
        make_ioc(
            "203.0.113.10",
            enrichment={
                "virustotal": _vt_payload(
                    lookup_status="timeout", timestamp="2026-09-17T10:00:00+00:00"
                )
            },
        )
    ]
    assert _enrichment_fingerprint(iocs_a) == _enrichment_fingerprint(iocs_b)


def test_fingerprint_changes_when_lookup_status_changes() -> None:
    iocs_before = [
        make_ioc(
            "203.0.113.10",
            enrichment={
                "virustotal": _vt_payload(
                    lookup_status="timeout", timestamp="2026-09-17T09:00:00+00:00"
                )
            },
        )
    ]
    iocs_after = [
        make_ioc(
            "203.0.113.10",
            enrichment={
                "virustotal": _vt_payload(
                    lookup_status="found", timestamp="2026-09-17T09:00:00+00:00", malicious=10
                )
            },
        )
    ]
    assert _enrichment_fingerprint(iocs_before) != _enrichment_fingerprint(iocs_after)


def test_fingerprint_changes_when_result_changes() -> None:
    iocs_before = [
        make_ioc(
            "203.0.113.10",
            enrichment={
                "virustotal": _vt_payload(
                    lookup_status="found", timestamp="2026-09-17T09:00:00+00:00", malicious=5
                )
            },
        )
    ]
    iocs_after = [
        make_ioc(
            "203.0.113.10",
            enrichment={
                "virustotal": _vt_payload(
                    lookup_status="found", timestamp="2026-09-17T09:00:00+00:00", malicious=10
                )
            },
        )
    ]
    assert _enrichment_fingerprint(iocs_before) != _enrichment_fingerprint(iocs_after)


def test_fingerprint_ignores_indicator_and_provider_order() -> None:
    ioc_a = make_ioc(
        "203.0.113.10",
        enrichment={
            "virustotal": _vt_payload(
                lookup_status="found", timestamp="2026-09-17T09:00:00+00:00", malicious=10
            ),
            "misp": {
                "provider": "misp",
                "lookup_status": "not_found",
                "timestamp": "2026-09-17T09:00:00+00:00",
            },
        },
    )
    ioc_b = make_ioc(
        "23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f",
        type=IOCType.SHA256,
        enrichment={
            "misp": {
                "provider": "misp",
                "lookup_status": "not_found",
                "timestamp": "2026-09-17T09:00:00+00:00",
            }
        },
    )
    assert _enrichment_fingerprint([ioc_a, ioc_b]) == _enrichment_fingerprint([ioc_b, ioc_a])


def test_fingerprint_empty_for_unenriched_iocs() -> None:
    assert _enrichment_fingerprint([]) == ()
    assert _enrichment_fingerprint([make_ioc("203.0.113.10")]) == ()


# ---------------------------------------------------------------------------
# Phase 2.7A — reassess_persisted_if_changed guard
# ---------------------------------------------------------------------------


@pytest.fixture
def alert_session_factory(tmp_path: Path) -> sessionmaker:
    """A fresh SQLite database with the full schema (one per test)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'late_enrichment.db'}")
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


def _persisted_alert(
    *,
    enrichment: dict,
    enrichment_status: str,
) -> tuple[CanonicalAlert, CanonicalAlert]:
    """Build an assessed canonical alert; return (assessed, without_assessment)."""
    ioc = make_ioc("203.0.113.10", enrichment=enrichment)
    base = make_canonical_alert(
        iocs=[ioc],
        enrichment_status=enrichment_status,
        received_at=RECEIVED_AT,
    )
    scorer = RiskScorer(default_scoring_policy())
    decider = DecisionEngine(default_decision_policy())
    risk = scorer.score(base)
    decision = decider.decide(risk, alert=base, decided_at=base.received_at)
    return base, base.model_copy(update={"risk": risk, "decision": decision})


def _store_alert(session_factory: sessionmaker, canonical: CanonicalAlert) -> None:
    with session_scope(session_factory) as session:
        session.add(
            Alert(
                alert_id=canonical.alert_id,
                source=canonical.source,
                received_at=canonical.received_at,
                dedupe_group_key=(
                    canonical.dedupe.group_key if canonical.dedupe is not None else "wazuh:5710:001"
                ),
                event_identity=(
                    canonical.dedupe.event_identity
                    if canonical.dedupe is not None
                    else "wazuh:test:5710:001"
                ),
                rule_id=canonical.source_event.rule.id,
                rule_level=canonical.source_event.rule.level,
                agent_id=canonical.source_event.agent.id,
                agent_name=canonical.source_event.agent.name,
                normalized_payload=canonical.model_dump(mode="json"),
                created_at=canonical.received_at,
            )
        )


def _chain_returning(iocs: tuple[IOC, ...], status_value: str) -> Mock:
    chain = Mock()
    chain.enrich.return_value = SimpleNamespace(
        status=SimpleNamespace(value=status_value),
        iocs=iocs,
    )
    return chain


def test_reassess_persisted_if_changed_noop_when_enrichment_unchanged(
    alert_session_factory: sessionmaker,
) -> None:
    """Same enrichment content (fresh failure timestamp) → strict no-op."""
    _, assessed = _persisted_alert(
        enrichment={
            "virustotal": _vt_payload(
                lookup_status="timeout", timestamp="2026-09-17T09:00:00+00:00"
            )
        },
        enrichment_status="failed",
    )
    _store_alert(alert_session_factory, assessed)

    # The chain retries the lookup: identical failure, fresh timestamp.
    retried_ioc = assessed.iocs[0].model_copy(
        update={
            "enrichment": {
                "virustotal": _vt_payload(
                    lookup_status="timeout", timestamp="2026-09-17T10:00:00+00:00"
                )
            }
        }
    )
    chain = _chain_returning((retried_ioc,), "failed")
    scorer = Mock()
    decider = Mock()
    service = LateEnrichmentService(chain, scorer, decider)

    result = service.reassess_persisted_if_changed(
        alert_session_factory,
        alert_id=assessed.alert_id,
        decided_at=RECEIVED_AT,
    )

    assert result is None
    chain.enrich.assert_called_once()
    scorer.score.assert_not_called()
    decider.decide.assert_not_called()
    with session_scope(alert_session_factory) as session:
        audits = AuditRepository(session).all()
        row = AlertRepository(session).get_alert(assessed.alert_id)
    assert audits == []
    assert row is not None
    assert row.canonical.model_dump(mode="json") == assessed.model_dump(mode="json")


def test_reassess_persisted_if_changed_rescores_when_new_verdict_arrives(
    alert_session_factory: sessionmaker,
) -> None:
    """A late definitive verdict → exactly one re-score with before/after audit."""
    _, assessed = _persisted_alert(
        enrichment={
            "virustotal": _vt_payload(
                lookup_status="timeout", timestamp="2026-09-17T09:00:00+00:00"
            )
        },
        enrichment_status="failed",
    )
    previous_score = assessed.risk.score if assessed.risk is not None else None
    previous_action = assessed.decision.action.value if assessed.decision is not None else None
    _store_alert(alert_session_factory, assessed)

    late_ioc = assessed.iocs[0].model_copy(
        update={
            "enrichment": {
                "virustotal": _vt_payload(
                    lookup_status="found", timestamp="2026-09-17T10:00:00+00:00", malicious=10
                )
            }
        }
    )
    chain = _chain_returning((late_ioc,), "complete")
    service = LateEnrichmentService(
        chain,
        RiskScorer(default_scoring_policy()),
        DecisionEngine(default_decision_policy()),
    )

    result = service.reassess_persisted_if_changed(
        alert_session_factory,
        alert_id=assessed.alert_id,
        decided_at=RECEIVED_AT,
    )

    assert result is not None
    reassessment, persistence = result
    assert persistence.persisted is True
    # The persisted canonical is a JSON round-trip: values are equal,
    # instances are not.
    assert reassessment.previous_risk == assessed.risk
    assert reassessment.previous_decision == assessed.decision
    assert reassessment.canonical.risk is not None
    assert reassessment.canonical.decision is not None
    assert reassessment.canonical.risk.score != previous_score
    assert reassessment.canonical.iocs[0].enrichment["virustotal"]["lookup_status"] == "found"

    with session_scope(alert_session_factory) as session:
        audits = AuditRepository(session).all()
        row = AlertRepository(session).get_alert(assessed.alert_id)
    assert row is not None
    assert row.canonical.risk is not None
    assert row.canonical.risk.score == reassessment.canonical.risk.score
    scored = [entry for entry in audits if entry.action == "alert.scored"]
    decided = [entry for entry in audits if entry.action == "alert.decided"]
    assert len(scored) == 1
    assert len(decided) == 1
    assert scored[0].before is not None
    assert scored[0].before["score"] == previous_score
    assert scored[0].after["score"] == reassessment.canonical.risk.score
    assert decided[0].before["action"] == previous_action
    assert decided[0].after["action"] == reassessment.canonical.decision.action.value


def test_reassess_persisted_if_changed_missing_alert_raises(
    alert_session_factory: sessionmaker,
) -> None:
    service = LateEnrichmentService(
        Mock(),
        RiskScorer(default_scoring_policy()),
        DecisionEngine(default_decision_policy()),
    )

    with pytest.raises(LookupError):
        service.reassess_persisted_if_changed(
            alert_session_factory,
            alert_id=uuid4(),
            decided_at=RECEIVED_AT,
        )


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
