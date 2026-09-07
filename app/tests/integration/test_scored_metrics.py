"""Phase 3.7 Task D7 — scoring/decision metric instrumentation tests.

Covers the approved ``soc_triage_alerts_scored{tier, decision, degraded}``
counter, wired at the ingest score+decide+persist boundary using the D2
:class:`~soc_triage.core.metrics.MetricsRegistry`:

* A. label correctness — every ``RiskTier`` / ``DecisionAction`` value maps to
   its own series, ``degraded`` is strictly ``0``/``1`` for pipeline values,
   and hostile/free-form values can never become labels;
* B. exact increments — one increment per newly scored+decided alert, one per
   repeated re-score, none for exact duplicates (which never undergo
   scoring/decision processing), and independent series per combination;
* C. degraded behavior — ``complete``/``partial``/``failed``/``skipped``
   enrichment stays ``degraded=0`` (established semantics: enrichment status
   is a scoring factor, never a degraded flag); ``degraded=1`` only for the
   rule-severity-only engine fallback (ARCHITECTURE.md §16);
* D. regression invariants — metrics-enabled vs metrics-disabled twin apps
   produce identical responses, scores, decisions, persisted alert fields,
   dedupe state and audit rows;
* E. failure isolation — a raising metrics recorder never changes the ingest
   response or the persisted score/decision/audit;
* F. cardinality — only approved tier/decision/degraded combinations appear
   in the exposition; no dynamic identifiers or free-form strings.

Reads the app-scoped registry directly (never the process-global REGISTRY).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from soc_triage.api import alerts as alerts_module
from soc_triage.core.config import Settings
from soc_triage.core.metrics import (
    DECISION_ACTIONS,
    RISK_TIERS,
    UNKNOWN,
    MetricsRegistry,
)
from soc_triage.enrichment import EnrichmentChain
from soc_triage.enrichment.providers import (
    EnrichmentContext,
    EnrichmentStatus,
    ProviderEnrichment,
)
from soc_triage.main import create_app
from soc_triage.models.assessment import DecisionAction, RiskTier
from soc_triage.models.ioc import IOC
from soc_triage.scoring import engine as scoring_engine

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
from tests.conftest import TEST_INGEST_KEY  # noqa: E402


def _load_sample(name: str) -> dict[str, Any]:
    """Load one synthetic Wazuh sample payload."""
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


def _auth() -> dict[str, str]:
    """Ingest auth header (test API key)."""
    return {"X-API-Key": TEST_INGEST_KEY}


def _ingest(client: TestClient, payload: dict[str, Any]):
    """Post one ingest payload and return the raw response."""
    return client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())


def _scored_series(registry) -> dict[tuple[str, str, str], float]:
    """Return ``{(tier, decision, degraded): value}`` for the scored counter.

    Works for both an app-scoped registry (``app.state.metrics.registry``)
    and a bare :class:`MetricsRegistry`.
    """
    for collector in registry.collect():
        if collector.name == "soc_triage_alerts_scored":
            # Counter families also carry a ``*_created`` sample (creation
            # timestamp); only the ``_total`` sample is a counter increment.
            return {
                (sample.labels["tier"], sample.labels["decision"], sample.labels["degraded"]): (
                    sample.value
                )
                for sample in collector.samples
                if sample.name == "soc_triage_alerts_scored_total"
            }
    return {}


def _rows(app, sql: str) -> list[tuple[Any, ...]]:
    """Run one read-only query against the app's engine."""
    engine = app.state.db_engine
    with engine.connect() as connection:
        return list(connection.execute(text(sql)))


def _persisted_risk_decision(app) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load the (single) alert of record's persisted risk/decision JSON."""
    row = json.loads(_rows(app, "SELECT normalized_payload FROM alerts")[0][0])
    return row["risk"], row["decision"]


def _audit_shape(app) -> list[tuple[str, str, str]]:
    """Audit rows projected to deterministic (actor, action, entity_type)."""
    rows = _rows(app, "SELECT actor, action, entity_type FROM audit_log ORDER BY id")
    return [(r[0], r[1], r[2]) for r in rows]


def _assessment_audit_rows(app) -> list[dict[str, Any]]:
    """Full deterministic content of the assessment audit rows (D7 scope).

    The dedupe/ingest audit rows embed the per-app random alert id and
    wall-clock timestamps (pre-existing, excluded); the assessment rows are
    timestamps/id-free and must be byte-identical across the twins.
    """
    rows = _rows(
        app,
        "SELECT action, before, after FROM audit_log "
        "WHERE action IN ('alert.scored', 'alert.decided') ORDER BY id",
    )
    return [
        {
            "action": r[0],
            "before": json.loads(r[1]) if r[1] is not None else None,
            "after": json.loads(r[2]) if r[2] is not None else None,
        }
        for r in rows
    ]


def _fingerprint(body: dict[str, Any]) -> dict[str, Any]:
    """Deterministic response projection (ids/timestamps excluded)."""
    return {
        "status": body.get("status"),
        "duplicate": body.get("duplicate"),
        "dedupe_status": body.get("dedupe_status"),
        "enrichment_status": body.get("enrichment_status"),
        "risk_score": body.get("risk", {}).get("score") if body.get("risk") else None,
        "risk_tier": body.get("risk", {}).get("tier") if body.get("risk") else None,
        "risk_engine_version": body.get("risk", {}).get("engine_version")
        if body.get("risk")
        else None,
        "risk_degraded": body.get("risk", {}).get("degraded") if body.get("risk") else None,
        "decision_action": body.get("decision", {}).get("action") if body.get("decision") else None,
        "decision_severity": body.get("decision", {}).get("severity")
        if body.get("decision")
        else None,
        "dedupe_occurrences": body.get("dedupe", {}).get("occurrences"),
    }


class _FakeProvider:
    """Minimal offline enrichment provider driving a fixed outcome."""

    def __init__(self, name: str, status: EnrichmentStatus, *, fail: bool = False) -> None:
        self._name = name
        self._status = status
        self._fail = fail

    @property
    def name(self) -> str:
        return self._name

    @property
    def enabled(self) -> bool:
        return True

    def enrich(
        self,
        iocs: Sequence[IOC],
        *,
        context: EnrichmentContext,  # noqa: ARG002 - part of the provider contract
    ) -> ProviderEnrichment:
        if self._fail:
            raise RuntimeError("injected provider failure")
        return ProviderEnrichment(
            provider=self._name,
            status=self._status,
            results={ioc.key: {"mock": {"lookup_status": "found"}} for ioc in iocs},
            notes=["synthetic enrichment"],
        )


def _install_chain(client: TestClient, providers: list[Any]) -> None:
    """Swap the app's enrichment chain (no provider metrics are emitted yet)."""
    client.app.state.enrichment_chain = EnrichmentChain(providers)


def _twin_app(tmp_path: Path, *, metrics_enabled: bool):
    """A second, isolated app with the same config; the metrics toggle differs."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=f"sqlite:///{tmp_path / 'twin.db'}",
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token="test-callback-token-not-a-real-secret",
        n8n_webhook_token="",
        n8n_webhook_url="",
        metrics_enabled=metrics_enabled,
    )
    return create_app(settings=settings)


# ---------------------------------------------------------------------------
# A. Label correctness
# ---------------------------------------------------------------------------


def test_every_tier_and_decision_value_maps_to_its_own_series() -> None:
    """All 5 tiers, 4 decisions and both degraded values resolve exactly."""
    for tier in RISK_TIERS:
        for decision in DECISION_ACTIONS:
            for degraded, expected in ((False, "0"), (True, "1")):
                registry = MetricsRegistry()
                registry.record_alert_scored(
                    tier=tier,
                    decision=decision,
                    degraded=degraded,
                )
                assert _scored_series(registry.registry) == {(tier, decision, expected): 1.0}, (
                    tier,
                    decision,
                    expected,
                )
                # No other combination materialized for this single record.
                assert sum(_scored_series(registry.registry).values()) == 1.0


def test_hostile_values_never_become_labels() -> None:
    """Free-form/hostile inputs collapse to fixed fallbacks, never exposition."""
    sentinel = "leak-me-12345-hostile-value"
    registry = MetricsRegistry()
    registry.record_alert_scored(tier=sentinel, decision=sentinel, degraded="not-a-bool")
    registry.record_alert_scored(tier="high", decision="open_incident", degraded=sentinel)

    exposition = registry.render_text()
    assert sentinel not in exposition
    # Bounded fallbacks only: tier/decision → unknown; degraded → unknown too.
    assert _scored_series(registry.registry) == {
        (UNKNOWN, UNKNOWN, UNKNOWN): 1.0,
        ("high", "open_incident", UNKNOWN): 1.0,
    }


def test_real_pipeline_degraded_label_is_strictly_zero_or_one(client, app) -> None:
    """A real ingest only ever emits 0/1 for the degraded label."""
    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    assert response.json()["risk"]["degraded"] is False
    series = _scored_series(app.state.metrics.registry)
    assert series == {(RiskTier.LOW.value, DecisionAction.MONITOR.value, "0"): 1.0}
    assert all(degraded in {"0", "1"} for (_, _, degraded) in series)


# ---------------------------------------------------------------------------
# B. Exact increments
# ---------------------------------------------------------------------------


def test_representative_alert_increments_scored_exactly_once(client, app) -> None:
    """One new alert → exactly one scored increment, one combination only."""
    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    assert response.json()["dedupe_status"] == "new_generation"
    series = _scored_series(app.state.metrics.registry)
    assert series == {(RiskTier.LOW.value, DecisionAction.MONITOR.value, "0"): 1.0}
    assert sum(series.values()) == 1.0


def test_repeated_alert_increments_expected_semantic_series(client, app) -> None:
    """Each distinct event re-scores: 2 low/monitor + 1 escalated medium/queue_l1."""
    base = _load_sample("01_wazuh_ssh_brute_force.json")
    first = _ingest(client, base)
    second = _ingest(client, dict(base, id="1770000000.100002"))
    third = _ingest(client, dict(base, id="1770000000.100003"))
    assert first.status_code == second.status_code == third.status_code == 202
    assert [r.json()["dedupe_status"] for r in (first, second, third)] == [
        "new_generation",
        "repeated",
        "repeated",
    ]
    # Recurrence escalation moves the third event to medium → queue_l1, and
    # each scoring run records exactly one increment for its own series.
    expected = {
        (RiskTier.LOW.value, DecisionAction.MONITOR.value, "0"): 2.0,
        (RiskTier.MEDIUM.value, DecisionAction.QUEUE_L1.value, "0"): 1.0,
    }
    assert _scored_series(app.state.metrics.registry) == expected
    assert sum(expected.values()) == 3.0


def test_exact_duplicate_creates_no_phantom_scored_event(client, app) -> None:
    """Exact duplicates are echoed, never re-scored, and never counted."""
    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    first = _ingest(client, payload)
    assert first.status_code == 202
    duplicate = _ingest(client, payload)
    assert duplicate.status_code == 200
    assert duplicate.json()["dedupe_status"] == "exact_duplicate"
    assert duplicate.json()["risk"] == first.json()["risk"]
    assert duplicate.json()["decision"] == first.json()["decision"]

    series = _scored_series(app.state.metrics.registry)
    assert series == {(RiskTier.LOW.value, DecisionAction.MONITOR.value, "0"): 1.0}
    assert sum(series.values()) == 1.0
    # The duplicate delivery is still counted as a processed outcome (D6),
    # proving the two counters measure different semantic events.
    assert (
        app.state.metrics.registry.get_sample_value(
            "soc_triage_alerts_processed_total",
            {"outcome": "exact_duplicate"},
        )
        == 1.0
    )


def test_multiple_alerts_produce_independent_expected_series(client, app) -> None:
    """Different alerts accumulate independent per-combination counters."""
    assert _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json")).status_code == 202
    assert _ingest(client, _load_sample("03_wazuh_fim_etc_passwd_change.json")).status_code == 202

    series = _scored_series(app.state.metrics.registry)
    assert series == {
        (RiskTier.LOW.value, DecisionAction.MONITOR.value, "0"): 1.0,
        (RiskTier.MEDIUM.value, DecisionAction.QUEUE_L1.value, "0"): 1.0,
    }
    assert sum(series.values()) == 2.0


# ---------------------------------------------------------------------------
# C. Degraded behavior
# ---------------------------------------------------------------------------


def test_enrichment_statuses_never_set_the_degraded_flag(client, app) -> None:
    """Skipped/complete/partial/failed enrichment stays degraded=0.

    Established semantics (ARCHITECTURE.md §8, §16): enrichment status is a
    bounded scoring *factor*; ``RiskAssessment.degraded`` means only the
    rule-severity-only engine fallback. Metric recording invents no new
    meaning for ``degraded``.
    """
    # Distinct alert payloads so every run is a new generation (enrichment
    # status is what varies; recurrence would only add noise).
    skipped = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    _install_chain(client, [_FakeProvider("fake-complete", EnrichmentStatus.COMPLETE)])
    complete = _ingest(client, _load_sample("03_wazuh_fim_etc_passwd_change.json"))
    _install_chain(
        client,
        [
            _FakeProvider("fake-complete", EnrichmentStatus.COMPLETE),
            _FakeProvider("fake-failing", EnrichmentStatus.FAILED, fail=True),
        ],
    )
    partial = _ingest(client, _load_sample("05_wazuh_web_sql_injection.json"))
    _install_chain(client, [_FakeProvider("fake-failing", EnrichmentStatus.FAILED, fail=True)])
    failed = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))

    runs = [
        (skipped, "skipped"),
        (complete, "complete"),
        (partial, "partial"),
        (failed, "failed"),
    ]
    for response, expected_status in runs:
        assert response.status_code == 202, (expected_status, response.text)
        assert response.json()["enrichment_status"] == expected_status
        # The degraded flag is engine-fallback only; enrichment status never
        # re-labels it, and the score/decision still flow normally.
        assert response.json()["risk"]["degraded"] is False
        assert response.json()["risk"]["tier"] in {tier.value for tier in RiskTier}
        assert response.json()["decision"]["action"] in {action.value for action in DecisionAction}

    series = _scored_series(app.state.metrics.registry)
    # Every scored alert carries degraded=0; the alert-level statuses produced
    # the established score/tier/decision distribution for these samples
    # (01: 43 low/monitor, 03+complete: 68 medium/queue_l1, 05+partial: 61
    # medium/queue_l1, 02: 27 low/monitor).
    assert series == {
        (RiskTier.LOW.value, DecisionAction.MONITOR.value, "0"): 2.0,
        (RiskTier.MEDIUM.value, DecisionAction.QUEUE_L1.value, "0"): 2.0,
    }
    assert all(degraded == "0" for (_, _, degraded) in series)


def test_engine_fallback_records_degraded_one(client, app, monkeypatch) -> None:
    """Full-engine failure → the existing degraded fallback, degraded=1."""

    def boom(*_args: object, **_kwargs: object) -> Any:
        raise RuntimeError("injected scoring engine failure")

    monkeypatch.setattr(scoring_engine, "score_alert", boom)

    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    body = response.json()
    # Rule level 5 → severity-only fallback score 14 → informational → monitor.
    assert body["risk"]["degraded"] is True
    assert body["risk"]["score"] == 14
    assert body["risk"]["tier"] == RiskTier.INFORMATIONAL.value
    assert body["decision"]["action"] == DecisionAction.MONITOR.value

    series = _scored_series(app.state.metrics.registry)
    assert series == {
        (RiskTier.INFORMATIONAL.value, DecisionAction.MONITOR.value, "1"): 1.0,
    }
    assert sum(series.values()) == 1.0


# ---------------------------------------------------------------------------
# D. Regression invariants — metrics enabled vs disabled twins
# ---------------------------------------------------------------------------


def test_scored_ingest_identical_with_and_without_metrics(tmp_path, client, app) -> None:
    """Twins must agree on response, score, decision, DB, dedupe and audit."""
    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    with TestClient(_twin_app(tmp_path, metrics_enabled=False)) as twin:
        # Same deterministic sequence on both apps: new generation, exact
        # duplicate delivery, then a distinct recurrence event (re-scored).
        sequence = [payload, payload, dict(payload, id="1770000000.100002")]
        for theirs_payload in sequence:
            ours = _ingest(client, theirs_payload)
            theirs = twin.post(
                "/api/v1/alerts/ingest",
                json=theirs_payload,
                headers={"X-API-Key": TEST_INGEST_KEY},
            )
            assert ours.status_code == theirs.status_code
            assert _fingerprint(ours.json()) == _fingerprint(theirs.json())
            assert ours.json()["risk"] == theirs.json()["risk"]
            ours_decision = dict(ours.json()["decision"])
            theirs_decision = dict(theirs.json()["decision"])
            ours_decision.pop("decided_at", None)
            theirs_decision.pop("decided_at", None)
            assert ours_decision == theirs_decision

        # Identical persisted alert fields (risk always; decision minus clock).
        ours_risk, ours_decision = _persisted_risk_decision(app)
        theirs_risk, theirs_decision = _persisted_risk_decision(twin.app)
        assert ours_risk == theirs_risk
        ours_decision.pop("decided_at", None)
        theirs_decision.pop("decided_at", None)
        assert ours_decision == theirs_decision

        # Identical dedupe / event / alert / audit row counts.
        for table in ("alerts", "alert_events", "alert_dedupe_groups", "audit_log"):
            assert _rows(app, f"SELECT COUNT(*) FROM {table}") == _rows(
                twin.app, f"SELECT COUNT(*) FROM {table}"
            ), table

        # Identical audit rows: deterministic shape for every row and full
        # content for the assessment rows (dedupe rows carry the per-app
        # random alert id and wall-clock timestamps — pre-existing, excluded).
        assert _audit_shape(app) == _audit_shape(twin.app)
        assert _assessment_audit_rows(app) == _assessment_audit_rows(twin.app)

        # Only the metrics differ: the enabled twin has exactly the expected
        # scored series (new generation + repeated re-score; the exact
        # duplicate adds nothing); the disabled twin has no metrics surface.
        assert _scored_series(app.state.metrics.registry) == {
            (RiskTier.LOW.value, DecisionAction.MONITOR.value, "0"): 2.0,
        }
        assert not hasattr(twin.app.state, "metrics")


# ---------------------------------------------------------------------------
# E. Failure isolation
# ---------------------------------------------------------------------------


def test_forced_metrics_failure_never_changes_scored_ingest(client, app, monkeypatch) -> None:
    """A raising metrics recorder cannot alter the response or persisted data."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected scored-metrics failure")

    monkeypatch.setattr(MetricsRegistry, "_increment", boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", boom)

    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert body["dedupe_status"] == "new_generation"
    # Deterministic golden values are untouched by the forced recorder failure.
    assert body["risk"]["score"] == 43
    assert body["risk"]["tier"] == RiskTier.LOW.value
    assert body["risk"]["degraded"] is False
    assert body["decision"]["action"] == DecisionAction.MONITOR.value
    assert body["incident_id"] is None

    # Persisted score/decision and assessment audit rows are unchanged too.
    risk, decision = _persisted_risk_decision(app)
    assert risk["score"] == 43
    assert risk["degraded"] is False
    assert decision["action"] == DecisionAction.MONITOR.value
    actions = {row[0] for row in _rows(app, "SELECT action FROM audit_log")}
    assert {"alert.scored", "alert.decided"} <= actions


def test_failed_assessment_persistence_records_no_scored_event(client, app, monkeypatch) -> None:
    """The scored counter fires only after the assessment transaction commits."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise OperationalError(
            "UPDATE normalized_payload",
            {},
            sqlite3.OperationalError("injected persistence failure"),
        )

    monkeypatch.setattr(alerts_module.AlertRepository, "update_normalized_payload", boom)

    response = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    # Existing fail-open contract is preserved: the alert id is already durable
    # (created by dedupe) and ingest still returns 202; only the assessment
    # persistence rolled back atomically.
    assert response.status_code == 202
    assert response.json()["incident_id"] is None

    # No scored increment, no assessment audit rows (atomic rollback).
    assert _scored_series(app.state.metrics.registry) == {}
    assert _rows(
        app, "SELECT COUNT(*) FROM audit_log WHERE action IN ('alert.scored', 'alert.decided')"
    ) == [(0,)]


# ---------------------------------------------------------------------------
# F. Cardinality
# ---------------------------------------------------------------------------


def test_exposition_contains_only_approved_scored_combinations(client, app, monkeypatch) -> None:
    """After a mixed pipeline run, only bounded label values are exposed."""
    first = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert first.status_code == 202
    duplicate = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert duplicate.status_code == 200
    medium = _ingest(client, _load_sample("03_wazuh_fim_etc_passwd_change.json"))
    assert medium.status_code == 202
    high = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))
    assert high.status_code == 202
    assert high.json()["incident_id"] is not None

    # A distinct recurrence event with a broken scoring engine: the existing
    # degraded fallback must surface as degraded=1 (ARCHITECTURE.md §16).
    def boom(*_args: object, **_kwargs: object) -> Any:
        raise RuntimeError("injected scoring engine failure")

    monkeypatch.setattr(scoring_engine, "score_alert", boom)
    degraded = _ingest(
        client,
        dict(_load_sample("01_wazuh_ssh_brute_force.json"), id="1770000000.100002"),
    )
    assert degraded.status_code == 202
    assert degraded.json()["risk"]["degraded"] is True

    series = _scored_series(app.state.metrics.registry)
    # Every observed combination is inside the approved finite vocabulary.
    for tier, decision, degraded_flag in series:
        assert tier in RISK_TIERS, tier
        assert decision in DECISION_ACTIONS, decision
        assert degraded_flag in {"0", "1"}, degraded_flag

    exposition = app.state.metrics.render_text()
    # Dynamic identifiers/free-form values from the run never leak as label
    # values (labels are enum-sourced only). Label values are always quoted in
    # the text exposition, so quoting avoids false positives against numeric
    # ``*_created`` timestamps.
    dynamic_values = [
        first.json()["alert_id"],
        duplicate.json()["alert_id"],
        medium.json()["alert_id"],
        high.json()["alert_id"],
        degraded.json()["alert_id"],
        high.json()["incident_id"],
        "5710",  # rule id (sample 01)
        "550",  # rule id (sample 03)
        "87105",  # rule id (sample 04)
        "001",  # agent id (sample 01)
        "002",  # agent id (sample 03)
        "003",  # agent id (sample 04)
        "203.0.113.50",  # IOC value (sample 01)
        "wazuh:5710:001",  # dedupe group key (sample 01)
        "C:\\Users\\jdoe-lab\\Downloads\\invoice_tracker.exe",  # IOC path (sample 04)
    ]
    for value in dynamic_values:
        assert f'"{value}"' not in exposition, value

    # All sample series resolve to exactly the expected combinations.
    assert series == {
        (RiskTier.LOW.value, DecisionAction.MONITOR.value, "0"): 1.0,
        (RiskTier.MEDIUM.value, DecisionAction.QUEUE_L1.value, "0"): 1.0,
        (RiskTier.HIGH.value, DecisionAction.OPEN_INCIDENT.value, "0"): 1.0,
        (RiskTier.INFORMATIONAL.value, DecisionAction.MONITOR.value, "1"): 1.0,
    }
