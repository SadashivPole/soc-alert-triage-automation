"""Phase 3.7 Task D8 — enrichment metric instrumentation tests.

Covers the approved enrichment metric surface wired at the enrichment
chain's semantic outcome boundary using the D2
:class:`~soc_triage.core.metrics.MetricsRegistry`:

* A. alert-level status — ``complete``/``partial``/``failed``/``skipped``
   recorded exactly once per enrichment attempt;
* B. provider outcomes — one per ``ProviderOutcome`` actually returned by the
   chain, bounded registered-name allowlist, unknown names collapse to the
   fixed fallback;
* C. zero-external fallback — disabled/no-op enrichment still produces the
   skipped series and behaves exactly as before;
* D. failure/partial — provider fail-open and partial aggregation are
   represented exactly, exception messages never become labels;
* E. security/cardinality — synthetic IOC values/IDs/URLs/error text never
   appear in the exposition; every label is in the approved vocabularies;
* F. non-load-bearing regression — metrics-enabled vs disabled twins behave
   identically;
* G. failure isolation — a raising recorder never changes enrichment,
   scoring, decision, response or persistence.

Reads the app-scoped registry directly (never the process-global REGISTRY).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.conftest import TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.core.metrics import (
    ENRICHMENT_STATUSES,
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

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _load_sample(name: str) -> dict[str, Any]:
    """Load one synthetic Wazuh sample payload."""
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


def _auth() -> dict[str, str]:
    """Ingest auth header (test API key)."""
    return {"X-API-Key": TEST_INGEST_KEY}


def _ingest(client: TestClient, payload: dict[str, Any]):
    """Post one ingest payload and return the raw response."""
    return client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers=_auth(),
    )


def _enrichment_series(registry) -> dict[str, float]:
    """Return ``{status: value}`` for the alert-level enrichment counter."""
    for collector in registry.collect():
        if collector.name == "soc_triage_enrichment_status":
            return {
                sample.labels["status"]: sample.value
                for sample in collector.samples
                if sample.name == "soc_triage_enrichment_status_total"
            }
    return {}


def _provider_series(registry) -> dict[tuple[str, str], float]:
    """Return ``{(provider, status): value}`` for provider outcomes."""
    for collector in registry.collect():
        if collector.name == "soc_triage_enrichment_provider_outcomes":
            return {
                (sample.labels["provider"], sample.labels["status"]): sample.value
                for sample in collector.samples
                if sample.name == "soc_triage_enrichment_provider_outcomes_total"
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


def _fingerprint(body: dict[str, Any]) -> dict[str, Any]:
    """Deterministic response projection (ids/timestamps excluded)."""
    return {
        "status": body.get("status"),
        "duplicate": body.get("duplicate"),
        "dedupe_status": body.get("dedupe_status"),
        "enrichment_status": body.get("enrichment_status"),
        "risk_score": body.get("risk", {}).get("score") if body.get("risk") else None,
        "risk_tier": body.get("risk", {}).get("tier") if body.get("risk") else None,
        "risk_degraded": body.get("risk", {}).get("degraded") if body.get("risk") else None,
        "decision_action": body.get("decision", {}).get("action") if body.get("decision") else None,
        "dedupe_occurrences": body.get("dedupe", {}).get("occurrences"),
    }


class _FakeProvider:
    """Minimal offline enrichment provider driving a fixed outcome.

    ``name`` must be one of the names registered at app startup (noop,
    virustotal, misp) to pass the D2 provider allowlist; tests that want an
    unregistered name deliberately pass one to prove fallback behavior.
    """

    def __init__(
        self,
        name: str,
        status: EnrichmentStatus,
        *,
        fail: bool = False,
    ) -> None:
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
    """Swap the app's enrichment chain (allowed names stay registered)."""
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
# A. Alert-level status — exactly once per enrichment attempt
# ---------------------------------------------------------------------------


def test_complete_enrichment_increments_exactly_once(client, app) -> None:
    """Every provider answers → alert-level complete, one increment only."""
    _install_chain(
        client,
        [_FakeProvider("virustotal", EnrichmentStatus.COMPLETE)],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "complete"
    assert _enrichment_series(app.state.metrics.registry) == {"complete": 1.0}


def test_partial_enrichment_increments_exactly_once(client, app) -> None:
    """Mixed provider outcome → alert-level partial, one increment only."""
    _install_chain(
        client,
        [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.FAILED, fail=True),
        ],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "partial"
    assert _enrichment_series(app.state.metrics.registry) == {"partial": 1.0}


def test_failed_enrichment_increments_exactly_once(client, app) -> None:
    """Every enabled provider fails → alert-level failed, one increment only."""
    _install_chain(
        client,
        [_FakeProvider("misp", EnrichmentStatus.FAILED, fail=True)],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "failed"
    assert _enrichment_series(app.state.metrics.registry) == {"failed": 1.0}


def test_skipped_enrichment_increments_exactly_once(client, app) -> None:
    """Default (all providers disabled) → alert-level skipped, one increment."""
    response = _ingest(
        client,
        _load_sample("01_wazuh_ssh_brute_force.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "skipped"
    assert _enrichment_series(app.state.metrics.registry) == {"skipped": 1.0}


def test_no_duplicate_alert_level_increment_within_one_attempt(client, app) -> None:
    """One enrichment run yields exactly one alert-level status total."""
    _install_chain(
        client,
        [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.FAILED, fail=True),
        ],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202

    series = _enrichment_series(app.state.metrics.registry)

    assert series == {"partial": 1.0}
    assert sum(series.values()) == 1.0


# ---------------------------------------------------------------------------
# B. Provider outcomes
# ---------------------------------------------------------------------------


def test_each_registered_provider_emits_exactly_one_expected_outcome(
    client,
    app,
) -> None:
    """Two registered providers → two provider outcome increments."""
    _install_chain(
        client,
        [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.COMPLETE),
        ],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202
    assert _provider_series(app.state.metrics.registry) == {
        ("virustotal", "complete"): 1.0,
        ("misp", "complete"): 1.0,
    }


def test_multiple_providers_create_expected_bounded_series(client, app) -> None:
    """Mixed outcomes produce the exact bounded per-provider series."""
    _install_chain(
        client,
        [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.FAILED, fail=True),
        ],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "partial"
    assert _provider_series(app.state.metrics.registry) == {
        ("virustotal", "complete"): 1.0,
        ("misp", "failed"): 1.0,
    }


def test_unknown_provider_names_cannot_create_arbitrary_series(
    client,
    app,
) -> None:
    """Unregistered provider names collapse to the fixed fallback series."""
    hostile_name = "attacker-controlled-provider-7f2a"

    _install_chain(
        client,
        [_FakeProvider(hostile_name, EnrichmentStatus.COMPLETE)],
    )

    response = _ingest(
        client,
        _load_sample("01_wazuh_ssh_brute_force.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "complete"

    series = _provider_series(app.state.metrics.registry)

    # Bounded fallback series only; no series for the hostile name.
    assert series == {(UNKNOWN, "complete"): 1.0}
    assert hostile_name not in app.state.metrics.render_text()


def test_provider_status_values_remain_bounded() -> None:
    """Hostile status values collapse to the fixed fallback at the registry."""
    registry = MetricsRegistry(provider_names=("virustotal",))

    registry.record_enrichment_provider_outcome(
        provider="virustotal",
        status="not-a-status; rm -rf /",
    )

    series = _provider_series(registry.registry)

    assert series == {("virustotal", UNKNOWN): 1.0}

    exposition = registry.render_text()

    assert "not-a-status" not in exposition


# ---------------------------------------------------------------------------
# C. Zero-external fallback
# ---------------------------------------------------------------------------


def test_disabled_chain_records_skipped_status_and_provider_outcomes(
    client,
    app,
) -> None:
    """Zero-external mode: skipped alert status + one skipped per provider."""
    assert {p.name for p in app.state.enrichment_chain.providers if p.enabled} == set()

    response = _ingest(
        client,
        _load_sample("01_wazuh_ssh_brute_force.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "skipped"
    assert _enrichment_series(app.state.metrics.registry) == {"skipped": 1.0}

    # The chain returns one ProviderOutcome per registered provider
    # (disabled providers are represented as skipped by the existing chain).
    assert _provider_series(app.state.metrics.registry) == {
        ("noop", "skipped"): 1.0,
        ("virustotal", "skipped"): 1.0,
        ("misp", "skipped"): 1.0,
    }


def test_metrics_disabled_mode_behaves_exactly_as_before(tmp_path) -> None:
    """A metrics-disabled app with the default chain: identical result, no state."""
    payload = _load_sample("01_wazuh_ssh_brute_force.json")

    with TestClient(_twin_app(tmp_path, metrics_enabled=False)) as twin:
        response = twin.post(
            "/api/v1/alerts/ingest",
            json=payload,
            headers={"X-API-Key": TEST_INGEST_KEY},
        )

        assert response.status_code == 202

        body = response.json()

        assert body["enrichment_status"] == "skipped"
        assert body["risk"]["score"] == 43
        assert body["risk"]["tier"] == RiskTier.LOW.value
        assert body["decision"]["action"] == DecisionAction.MONITOR.value
        assert not hasattr(twin.app.state, "metrics")


# ---------------------------------------------------------------------------
# D. Failure / partial behavior
# ---------------------------------------------------------------------------


def test_provider_failure_increments_proper_provider_and_status(
    client,
    app,
) -> None:
    """A raising provider → failed status for that provider; never a raise."""
    _install_chain(
        client,
        [_FakeProvider("misp", EnrichmentStatus.FAILED, fail=True)],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "failed"
    assert _provider_series(app.state.metrics.registry) == {("misp", "failed"): 1.0}


def test_partial_enrichment_flows_to_scoring_and_decisions(client, app) -> None:
    """Partial aggregation is represented correctly and the pipeline proceeds."""
    _install_chain(
        client,
        [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.FAILED, fail=True),
        ],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202

    body = response.json()

    assert body["enrichment_status"] == "partial"
    assert body["risk"]["tier"] == RiskTier.HIGH.value
    assert body["decision"]["action"] == DecisionAction.OPEN_INCIDENT.value
    assert _enrichment_series(app.state.metrics.registry) == {"partial": 1.0}

    assert _provider_series(app.state.metrics.registry) == {
        ("virustotal", "complete"): 1.0,
        ("misp", "failed"): 1.0,
    }


def test_exception_messages_never_become_metric_values(client, app) -> None:
    """Provider error text is folded into the outcome, never a label/value."""
    sentinel = "provider-secret-exception-message-51f2"

    class _ErrorProvider(_FakeProvider):
        def enrich(
            self,
            iocs: Sequence[IOC],  # noqa: ARG002 - part of the contract
            *,
            context: EnrichmentContext,  # noqa: ARG002 - part of the contract
        ) -> ProviderEnrichment:
            raise RuntimeError(sentinel)

    _install_chain(
        client,
        [_ErrorProvider("misp", EnrichmentStatus.FAILED)],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202
    assert response.json()["enrichment_status"] == "failed"

    exposition = app.state.metrics.render_text()

    assert sentinel not in exposition
    assert _provider_series(app.state.metrics.registry) == {("misp", "failed"): 1.0}


# ---------------------------------------------------------------------------
# E. Security / cardinality
# ---------------------------------------------------------------------------


def test_metrics_never_expose_identifiers_iocs_or_urls(client, app) -> None:
    """A mixed run's exposition contains only bounded enum/allowlisted labels."""
    _install_chain(
        client,
        [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.FAILED, fail=True),
        ],
    )

    first = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert first.status_code == 202
    assert first.json()["enrichment_status"] == "partial"

    # A second run with a hostile provider name (falls back to UNKNOWN)
    # and the default disabled chain (all skipped).
    _install_chain(
        client,
        [
            _FakeProvider("not-registered-zyx", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.COMPLETE),
        ],
    )

    second = _ingest(
        client,
        _load_sample("01_wazuh_ssh_brute_force.json"),
    )

    assert second.status_code == 202

    exposition = app.state.metrics.render_text()

    dynamic_values = [
        first.json()["alert_id"],
        second.json()["alert_id"],
        first.json()["incident_id"],
        "87105",
        "003",
        "001",
        "203.0.113.50",
        "bc478d7a48bfab117da4b9bdcb5aee36",
        "87c151c211facd64c46da2004bccfc31f52128bd",
        "23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f",
        "https://www.virustotal.com/gui/file/"
        "23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f/detection",
        r"C:\Users\jdoe-lab\Downloads\invoice_tracker.exe",
        "attacker-controlled-provider-7f2a",
        "not-registered-zyx",
    ]

    # Label values are always quoted in the text exposition, so quoting avoids
    # false positives against numeric ``*_created`` timestamps.
    for value in dynamic_values:
        assert f'"{value}"' not in exposition, value

    # Structure: every provider label is in the registered allowlist (+ the
    # single bounded fallback) and every status label is in the enum.
    provider_series = _provider_series(app.state.metrics.registry)

    allowed_providers = {
        "noop",
        "virustotal",
        "misp",
        UNKNOWN,
    }

    for provider, status in provider_series:
        assert provider in allowed_providers, provider
        assert status in ENRICHMENT_STATUSES, status

    assert provider_series == {
        ("virustotal", "complete"): 1.0,
        ("misp", "failed"): 1.0,
        (UNKNOWN, "complete"): 1.0,
        ("misp", "complete"): 1.0,
    }


# ---------------------------------------------------------------------------
# F. Non-load-bearing regression — enabled vs disabled twins
# ---------------------------------------------------------------------------


def test_enrichment_pipeline_identical_with_and_without_metrics(
    tmp_path,
    client,
    app,
) -> None:
    """Same enabled enrichment chain on both twins: identical everything."""
    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")

    with TestClient(_twin_app(tmp_path, metrics_enabled=False)) as twin:
        # Install the same partial-outcome chain into both apps.
        providers = [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.FAILED, fail=True),
        ]

        _install_chain(client, providers)
        twin.app.state.enrichment_chain = EnrichmentChain(providers)

        ours = _ingest(client, payload)

        theirs = twin.post(
            "/api/v1/alerts/ingest",
            json=payload,
            headers={"X-API-Key": TEST_INGEST_KEY},
        )

        assert ours.status_code == theirs.status_code == 202
        assert _fingerprint(ours.json()) == _fingerprint(theirs.json())
        assert ours.json()["risk"] == theirs.json()["risk"]

        ours_decision = dict(ours.json()["decision"])
        theirs_decision = dict(theirs.json()["decision"])

        ours_decision.pop("decided_at", None)
        theirs_decision.pop("decided_at", None)

        assert ours_decision == theirs_decision

        # Same persisted alert state (risk/decision), dedupe and audit counts.
        ours_risk, ours_decision = _persisted_risk_decision(app)
        theirs_risk, theirs_decision = _persisted_risk_decision(twin.app)

        assert ours_risk == theirs_risk

        ours_decision.pop("decided_at", None)
        theirs_decision.pop("decided_at", None)

        assert ours_decision == theirs_decision

        for table in (
            "alerts",
            "alert_events",
            "alert_dedupe_groups",
            "audit_log",
        ):
            assert _rows(
                app,
                f"SELECT COUNT(*) FROM {table}",
            ) == _rows(
                twin.app,
                f"SELECT COUNT(*) FROM {table}",
            ), table

        assert _rows(
            app,
            "SELECT actor, action FROM audit_log ORDER BY id",
        ) == _rows(
            twin.app,
            "SELECT actor, action FROM audit_log ORDER BY id",
        )

        # Only the metrics surface differs.
        assert _enrichment_series(app.state.metrics.registry) == {"partial": 1.0}

        assert not hasattr(twin.app.state, "metrics")


# ---------------------------------------------------------------------------
# G. Failure isolation
# ---------------------------------------------------------------------------


def test_forced_recorder_failure_never_breaks_enrichment(
    client,
    app,
    monkeypatch,
) -> None:
    """A raising metrics recorder cannot alter enrichment or its results."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected enrichment metrics failure")

    monkeypatch.setattr(
        MetricsRegistry,
        "_increment",
        boom,
    )

    _install_chain(
        client,
        [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.FAILED, fail=True),
        ],
    )

    response = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
    )

    assert response.status_code == 202

    body = response.json()

    assert body["enrichment_status"] == "partial"
    assert body["risk"]["tier"] == RiskTier.HIGH.value
    assert body["decision"]["action"] == DecisionAction.OPEN_INCIDENT.value

    risk, decision = _persisted_risk_decision(app)

    assert risk["tier"] == RiskTier.HIGH.value
    assert decision["action"] == DecisionAction.OPEN_INCIDENT.value

    actions = {
        row[0]
        for row in _rows(
            app,
            "SELECT action FROM audit_log",
        )
    }

    assert {"alert.scored", "alert.decided"} <= actions

    # The zero-external fallback path is equally intact under a forced failure.
    _install_chain(client, [])

    fallback = _ingest(
        client,
        _load_sample("01_wazuh_ssh_brute_force.json"),
    )

    assert fallback.status_code == 202
    assert fallback.json()["enrichment_status"] == "skipped"
    assert fallback.json()["risk"]["score"] == 43
    assert fallback.json()["decision"]["action"] == DecisionAction.MONITOR.value
