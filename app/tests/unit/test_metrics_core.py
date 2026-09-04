"""Unit tests for the app-scoped metrics core (Phase 3.7, Task D2).

Covers the metrics-core contract (ARCHITECTURE.md §15, ADR-9):

* metric names/types follow the approved ``soc_triage_`` catalog;
* every label value is drawn from a bounded, allowlisted vocabulary
  (hostile/secret-like inputs collapse to fixed fallbacks and never appear
  in the exposition);
* recording behavior (counters, histograms, gauges) is exact and
  deterministic;
* each :class:`MetricsRegistry` owns a private registry — state never leaks
  between instances and the process-global default ``REGISTRY`` is never
  touched;
* recording and rendering never raise into the application pipeline.

No FastAPI/Starlette import may exist in the metrics core (layer rule,
ARCHITECTURE.md §12), asserted as a static source check.
"""

from __future__ import annotations

from pathlib import Path

import prometheus_client
import pytest
from prometheus_client import CollectorRegistry

from soc_triage.core import metrics as metrics_module
from soc_triage.core.metrics import (
    DECISION_ACTIONS,
    DEDUPE_OUTCOMES,
    ENRICHMENT_STATUSES,
    FEEDBACK_VERDICTS,
    INCIDENT_STATUSES,
    INGEST_REJECT_REASONS,
    N8N_OUTCOMES,
    RISK_TIERS,
    SWEEPER_RESULTS,
    UNKNOWN,
    UNMATCHED_ROUTE,
    MetricsRegistry,
)

#: The full approved Phase 3.7 catalog: family name → Prometheus type.
EXPECTED_METRICS = {
    "soc_triage_alert_processing_duration_seconds": "histogram",
    "soc_triage_alerts_processed": "counter",
    "soc_triage_alerts_scored": "counter",
    "soc_triage_database_up": "gauge",
    "soc_triage_enrichment_provider_outcomes": "counter",
    "soc_triage_enrichment_status": "counter",
    "soc_triage_feedback": "counter",
    "soc_triage_http_request_duration_seconds": "histogram",
    "soc_triage_http_requests": "counter",
    "soc_triage_incident_auto_close": "counter",
    "soc_triage_incident_transitions": "counter",
    "soc_triage_ingest_rejections": "counter",
    "soc_triage_migrations_applied": "gauge",
    "soc_triage_n8n_notification_duration_seconds": "histogram",
    "soc_triage_n8n_notifications": "counter",
    "soc_triage_sweeper_passes": "counter",
    "soc_triage_up": "gauge",
}

SECRET_SENTINEL = "sup3r-s3cret-canary-value"
IOC_SENTINEL = "203.0.113.66"


def _collected(registry: CollectorRegistry) -> dict[str, object]:
    """Map metric family name → Prometheus ``Metric`` object."""
    return {metric.name: metric for metric in registry.collect()}


def _sample_value(registry: CollectorRegistry, name: str, labels: dict[str, str]) -> float | None:
    """Return the current value of one exposition sample (or None)."""
    return registry.get_sample_value(name, labels)


def test_metric_names_and_types_match_approved_catalog() -> None:
    """Every family from the Phase 3.7 catalog exists with the right type."""
    registry = MetricsRegistry()
    collected = _collected(registry.registry)
    assert set(collected) == set(EXPECTED_METRICS)
    for name, expected_type in EXPECTED_METRICS.items():
        metric = collected[name]
        assert metric.type == expected_type, f"{name}: expected {expected_type}"
        assert name.startswith("soc_triage_")
    # Histograms must expose count/sum/bucket samples; counters their _total.
    assert _sample_value(registry.registry, "soc_triage_up", {}) == 1.0


def test_registry_is_not_the_process_global_default() -> None:
    """App metrics must never be registered on the global default registry."""
    registry = MetricsRegistry()
    registry.record_alerts_processed("new_generation")
    registry.record_http_request(method="POST", route="/api/v1/alerts/ingest", status_code=202)
    for name in EXPECTED_METRICS:
        assert prometheus_client.REGISTRY.get_sample_value(name, {}) is None, name
    # The app registry is the only place the metric exists after recording.
    assert (
        _sample_value(
            registry.registry, "soc_triage_alerts_processed_total", {"outcome": "new_generation"}
        )
        == 1.0
    )


def test_fresh_registry_isolates_metrics_between_instances() -> None:
    """Two registries never share counter state (per-app isolation)."""
    first = MetricsRegistry()
    second = MetricsRegistry()
    first.record_alerts_processed("repeated")
    first.record_alerts_processed("repeated")
    assert (
        _sample_value(first.registry, "soc_triage_alerts_processed_total", {"outcome": "repeated"})
        == 2.0
    )
    assert (
        _sample_value(second.registry, "soc_triage_alerts_processed_total", {"outcome": "repeated"})
        is None
    )
    assert _sample_value(second.registry, "soc_triage_up", {}) == 1.0


def test_counters_increment_exactly_per_record() -> None:
    """Recording increments the expected counter for each labeled outcome."""
    registry = MetricsRegistry()
    registry.record_alerts_processed("new_generation")
    registry.record_alerts_processed("exact_duplicate")
    registry.record_alerts_processed("exact_duplicate")
    registry.record_ingest_rejection("schema_invalid")
    registry.record_alert_scored(tier="high", decision="open_incident", degraded=False)
    registry.record_alert_scored(tier="high", decision="open_incident", degraded=False)
    registry.record_enrichment_status("partial")
    registry.record_n8n_notification("delivered")
    registry.record_feedback("true_positive")
    registry.record_incident_transition(from_status="open", to_status="investigating")
    registry.record_incident_auto_close("closed")
    registry.record_sweeper_pass("completed")
    registry.record_enrichment_provider_outcome(provider="virustotal", status="complete")
    registry.record_http_request(method="POST", route="/api/v1/alerts/ingest", status_code=202)

    expected = [
        ("soc_triage_alerts_processed_total", {"outcome": "new_generation"}, 1.0),
        ("soc_triage_alerts_processed_total", {"outcome": "exact_duplicate"}, 2.0),
        ("soc_triage_ingest_rejections_total", {"reason": "schema_invalid"}, 1.0),
        (
            "soc_triage_alerts_scored_total",
            {"tier": "high", "decision": "open_incident", "degraded": "0"},
            2.0,
        ),
        ("soc_triage_enrichment_status_total", {"status": "partial"}, 1.0),
        (
            "soc_triage_enrichment_provider_outcomes_total",
            {"provider": "virustotal", "status": "complete"},
            1.0,
        ),
        ("soc_triage_n8n_notifications_total", {"outcome": "delivered"}, 1.0),
        ("soc_triage_feedback_total", {"verdict": "true_positive"}, 1.0),
        (
            "soc_triage_incident_transitions_total",
            {"from_status": "open", "to_status": "investigating"},
            1.0,
        ),
        ("soc_triage_incident_auto_close_total", {"outcome": "closed"}, 1.0),
        ("soc_triage_sweeper_passes_total", {"result": "completed"}, 1.0),
        (
            "soc_triage_http_requests_total",
            {"method": "POST", "route": UNMATCHED_ROUTE, "status": "202"},
            1.0,
        ),
    ]
    for name, labels, value in expected:
        assert _sample_value(registry.registry, name, labels) == value, (name, labels)


def test_histograms_and_gauges_record_deterministically() -> None:
    """Histogram count/sum and gauge values are exact for recorded input."""
    registry = MetricsRegistry(static_routes=("/health",))
    registry.observe_alert_processing(0.25)
    registry.observe_alert_processing(0.5)
    registry.observe_http_duration(method="GET", route="/health", seconds=0.01)
    registry.observe_n8n_notification(0.75)
    registry.set_database_up(True)
    registry.set_migrations_applied(True)

    assert (
        _sample_value(
            registry.registry,
            "soc_triage_alert_processing_duration_seconds_count",
            {},
        )
        == 2.0
    )
    assert _sample_value(
        registry.registry,
        "soc_triage_alert_processing_duration_seconds_sum",
        {},
    ) == pytest.approx(0.75)
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_http_request_duration_seconds_count",
            {"method": "GET", "route": "/health"},
        )
        == 1.0
    )
    assert _sample_value(
        registry.registry,
        "soc_triage_n8n_notification_duration_seconds_sum",
        {},
    ) == pytest.approx(0.75)
    assert _sample_value(registry.registry, "soc_triage_database_up", {}) == 1.0
    assert _sample_value(registry.registry, "soc_triage_migrations_applied", {}) == 1.0
    registry.set_database_up(False)
    assert _sample_value(registry.registry, "soc_triage_database_up", {}) == 0.0


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ("new_generation", "new_generation"),
        ("repeated", "repeated"),
        ("exact_duplicate", "exact_duplicate"),
        ("whatever-new", UNKNOWN),
        ("", UNKNOWN),
        ("a" * 5000, UNKNOWN),
        (None, UNKNOWN),  # type: ignore[arg-type]
    ],
)
def test_alerts_processed_labels_are_bounded(outcome: object, expected: str) -> None:
    """Unknown/hostile outcomes collapse to the fixed ``unknown`` label."""
    registry = MetricsRegistry()
    registry.record_alerts_processed(outcome)  # type: ignore[arg-type]
    assert (
        _sample_value(registry.registry, "soc_triage_alerts_processed_total", {"outcome": expected})
        == 1.0
    )
    exposition = registry.render_text()
    assert f'outcome="{expected}"' in exposition


def test_route_and_method_and_status_labels_are_sanitized() -> None:
    """Routes only accept templates/allowlisted statics; status stays 100-599."""
    registry = MetricsRegistry(static_routes=("/health", "/ready"))
    # Concrete path with an identifier: must collapse (cardinality guard).
    registry.record_http_request(
        method="GET",
        route="/api/v1/alerts/3f9d2b1e-aaaa-bbbb",
        status_code=200,
    )
    # Unknown method + query-bearing path + invalid status: all sanitized.
    registry.record_http_request(
        method="BREW",
        route=f"/api/v1/alerts?token={SECRET_SENTINEL}",
        status_code=999,
    )
    # Lowercased method is normalized; None status falls back to unknown.
    registry.record_http_request(
        method="post",
        route="/health",
        status_code=None,  # type: ignore[arg-type]
    )
    # Secret as a route segment: sanitized; numeric-string status accepted.
    registry.record_http_request(
        method="GET",
        route=f"/{SECRET_SENTINEL}",
        status_code="503",
    )
    # A genuine route template is the only accepted non-static route.
    registry.record_http_request(
        method="GET",
        route="/api/v1/alerts/{alert_id}",
        status_code=200,
    )

    exposition = registry.render_text()
    assert SECRET_SENTINEL not in exposition
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": UNMATCHED_ROUTE, "status": "200"},
        )
        == 1.0
    )
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_http_requests_total",
            {"method": UNKNOWN, "route": UNMATCHED_ROUTE, "status": UNKNOWN},
        )
        == 1.0
    )
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_http_requests_total",
            {"method": "POST", "route": "/health", "status": UNKNOWN},
        )
        == 1.0
    )
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": UNMATCHED_ROUTE, "status": "503"},
        )
        == 1.0
    )
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": "/api/v1/alerts/{alert_id}", "status": "200"},
        )
        == 1.0
    )


def test_hostile_values_never_reach_the_exposition() -> None:
    """Secrets, IOC values and free text never appear as metric labels."""
    registry = MetricsRegistry(provider_names=("noop", "virustotal"))
    registry.record_alerts_processed(SECRET_SENTINEL)
    registry.record_ingest_rejection(SECRET_SENTINEL)
    registry.record_alert_scored(tier=SECRET_SENTINEL, decision="open_incident", degraded=True)
    registry.record_enrichment_status(SECRET_SENTINEL)
    registry.record_enrichment_provider_outcome(provider=SECRET_SENTINEL, status="complete")
    registry.record_n8n_notification(SECRET_SENTINEL)
    registry.record_feedback(SECRET_SENTINEL)
    registry.record_incident_transition(from_status=SECRET_SENTINEL, to_status="open")
    registry.record_incident_auto_close(SECRET_SENTINEL)
    registry.record_sweeper_pass(SECRET_SENTINEL)
    registry.set_database_up(SECRET_SENTINEL)  # type: ignore[arg-type]

    exposition = registry.render_text()
    assert SECRET_SENTINEL not in exposition
    assert IOC_SENTINEL not in exposition
    # Every hostile value collapsed to the fixed fallback; nothing new appeared.
    assert exposition.count(f'"{UNKNOWN}"') >= 8


def test_provider_names_are_registered_vocabulary_only() -> None:
    """Provider labels respect the registered-name vocabulary (if provided)."""
    registry = MetricsRegistry(provider_names=("noop", "virustotal", "misp"))
    registry.record_enrichment_provider_outcome(provider="virustotal", status="complete")
    registry.record_enrichment_provider_outcome(provider="misp", status="skipped")
    registry.record_enrichment_provider_outcome(provider="buddy", status="complete")
    registry.record_enrichment_provider_outcome(provider="Bad-Provider", status="complete")
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_enrichment_provider_outcomes_total",
            {"provider": "virustotal", "status": "complete"},
        )
        == 1.0
    )
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_enrichment_provider_outcomes_total",
            {"provider": "misp", "status": "skipped"},
        )
        == 1.0
    )
    assert (
        _sample_value(
            registry.registry,
            "soc_triage_enrichment_provider_outcomes_total",
            {"provider": UNKNOWN, "status": "complete"},
        )
        == 2.0
    )


def test_duration_observations_sanitize_invalid_inputs() -> None:
    """Negative/non-numeric/NaN durations collapse to 0.0; never raise."""
    registry = MetricsRegistry()
    registry.observe_alert_processing(-1.5)
    registry.observe_alert_processing(float("nan"))
    registry.observe_alert_processing("not-a-number")
    registry.observe_alert_processing(0.25)
    assert (
        _sample_value(registry.registry, "soc_triage_alert_processing_duration_seconds_count", {})
        == 4.0
    )
    assert _sample_value(
        registry.registry, "soc_triage_alert_processing_duration_seconds_sum", {}
    ) == pytest.approx(0.25)


def test_recording_never_raises_into_the_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing apply step is swallowed (logged by type) — no exception escapes."""
    registry = MetricsRegistry()

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected metrics failure")

    monkeypatch.setattr(MetricsRegistry, "_increment", boom)
    monkeypatch.setattr(MetricsRegistry, "_observe", boom)
    monkeypatch.setattr(MetricsRegistry, "_apply_gauge", boom)

    # Every record/set helper must complete without raising.
    registry.record_http_request(method="POST", route="/api/v1/alerts/ingest", status_code=202)
    registry.observe_http_duration(method="GET", route="/health", seconds=0.01)
    registry.record_ingest_rejection("schema_invalid")
    registry.record_alerts_processed("new_generation")
    registry.observe_alert_processing(0.1)
    registry.record_alert_scored(tier="high", decision="open_incident", degraded=False)
    registry.record_enrichment_status("complete")
    registry.record_enrichment_provider_outcome(provider="noop", status="complete")
    registry.record_n8n_notification("delivered")
    registry.observe_n8n_notification(0.1)
    registry.record_feedback("true_positive")
    registry.record_incident_transition(from_status="open", to_status="resolved")
    registry.record_incident_auto_close("closed")
    registry.record_sweeper_pass("completed")
    registry.set_up(True)
    registry.set_database_up(True)
    registry.set_migrations_applied(True)


def test_render_text_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exposition failures degrade to an empty string instead of raising."""
    registry = MetricsRegistry()

    def boom(*_args: object, **_kwargs: object) -> bytes:
        raise RuntimeError("render failure")

    monkeypatch.setattr(metrics_module, "generate_latest", boom)
    assert registry.render_text() == ""


def test_vocabularies_match_domain_enums() -> None:
    """Bounded vocabularies mirror the application's domain enum values."""
    assert {"new_generation", "exact_duplicate", "repeated"} == DEDUPE_OUTCOMES
    assert {"skipped", "complete", "partial", "failed"} == ENRICHMENT_STATUSES
    assert {"informational", "low", "medium", "high", "critical"} == RISK_TIERS
    assert {"suppress", "monitor", "queue_l1", "open_incident"} == DECISION_ACTIONS
    assert {"delivered", "failed", "skipped", "duplicate_suppressed"} == N8N_OUTCOMES
    assert {
        "true_positive",
        "false_positive",
        "benign",
        "escalate",
        "acknowledged",
        "resolved",
        "contain_requested",
    } == FEEDBACK_VERDICTS
    assert {
        "open",
        "investigating",
        "acknowledged",
        "escalated",
        "resolved",
        "false_positive",
    } == INCIDENT_STATUSES
    assert {
        "malformed_json",
        "schema_invalid",
        "identity_invalid",
        "payload_too_large",
        "auth_failed",
        "storage_unavailable",
    } == INGEST_REJECT_REASONS
    assert {"completed", "failed"} == SWEEPER_RESULTS


def test_metrics_core_never_imports_fastapi() -> None:
    """Layer rule: the metrics core must not import FastAPI/Starlette."""
    source = Path(metrics_module.__file__).read_text(encoding="utf-8")
    assert "from fastapi" not in source
    assert "import fastapi" not in source
    assert "from starlette" not in source
    assert "import starlette" not in source
