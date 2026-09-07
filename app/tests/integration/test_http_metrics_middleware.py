"""Phase 3.7 Task D5 — HTTP request metrics middleware tests.

Covers the middleware contract (ARCHITECTURE.md §15, ADR-9):

* counters/histograms increment per request with correct bounded labels;
* method labels are bounded (exotic methods -> ``unknown``);
* route labels are FastAPI route templates — never concrete identifier
  paths, query strings, or raw URLs;
* unmatched routes are labeled ``unmatched`` safely;
* status labels stay bounded to HTTP status codes;
* scraping /metrics is not recursive/self-amplifying (one increment per
  scrape, static label, no new label series);
* a metrics-recording failure can never break a normal request;
* existing endpoint responses/status codes are unchanged (plus the whole
  suite re-run).

Assertions read the app-scoped registry directly (never the process-global
default registry).
"""

from __future__ import annotations

import re
from uuid import uuid4

from fastapi.testclient import TestClient

from soc_triage.api.middleware import MetricsMiddleware
from soc_triage.core.metrics import MetricsRegistry

TEST_CALLBACK_TOKEN = "test-callback-token-not-a-real-secret"
UNKNOWN = "unknown"
UNMATCHED_ROUTE = "unmatched"


def sample_value(app, name: str, labels: dict[str, str]) -> float | None:
    """Read one exposition sample from the app-scoped registry."""
    return app.state.metrics.registry.get_sample_value(name, labels)


def route_labels_in(app) -> set[str]:
    """All distinct ``route="..."`` label values in the current exposition."""
    text = app.state.metrics.render_text()
    return set(re.findall(r'route="([^"]+)"', text))


def http_label_values_in(app) -> set[str]:
    """All method/route/status label values emitted by HTTP metrics."""
    text = app.state.metrics.render_text()
    return set(re.findall(r'(?:method|route|status)="([^"]+)"', text))


def test_request_counter_increments_per_request(client: TestClient, app) -> None:
    """Each request increments the counter with method/route/status labels."""
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 200
    assert (
        sample_value(
            app,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": "/health", "status": "200"},
        )
        == 2.0
    )


def test_latency_histogram_count_increments(client: TestClient, app) -> None:
    """The duration histogram records one observation per request."""
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert (
        sample_value(
            app,
            "soc_triage_http_request_duration_seconds_count",
            {"method": "GET", "route": "/health"},
        )
        == 1.0
    )
    assert (
        sample_value(
            app,
            "soc_triage_http_request_duration_seconds_count",
            {"method": "GET", "route": "/ready"},
        )
        == 1.0
    )
    # The observation value is non-negative (monotonic clock, sanitized).
    assert (
        sample_value(
            app,
            "soc_triage_http_request_duration_seconds_sum",
            {"method": "GET", "route": "/health"},
        )
        >= 0.0
    )


def test_method_labels_are_bounded(client: TestClient, app) -> None:
    """An exotic method collapses to the bounded ``unknown`` label."""
    response = client.request("BREW", "/health")
    assert response.status_code == 405
    assert (
        sample_value(
            app,
            "soc_triage_http_requests_total",
            {"method": UNKNOWN, "route": "/health", "status": "405"},
        )
        == 1.0
    )


def test_route_labels_use_templates_never_concrete_identifiers(client: TestClient, app) -> None:
    """A concrete alert UUID in the path maps to the route template label."""
    alert_uuid = str(uuid4())
    response = client.get(
        f"/api/v1/alerts/{alert_uuid}",
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    assert response.status_code == 404  # matched route, alert unknown
    assert (
        sample_value(
            app,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": "/api/v1/alerts/{alert_id}", "status": "404"},
        )
        == 1.0
    )
    # The concrete UUID never appears as a label or anywhere in the exposition.
    exposition = app.state.metrics.render_text()
    assert alert_uuid not in exposition
    assert "/api/v1/alerts/{alert_id}" in exposition
    assert alert_uuid not in route_labels_in(app)


def test_unmatched_route_is_safe(client: TestClient, app) -> None:
    """An unknown path is labeled ``unmatched`` and still reports its 404."""
    response = client.get("/api/v1/definitely-not-a-route")
    assert response.status_code == 404
    assert (
        sample_value(
            app,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": UNMATCHED_ROUTE, "status": "404"},
        )
        == 1.0
    )
    # Raw query strings and concrete paths never leak into labels.
    client.get("/api/v1/alerts?limit=999999")
    client.get("/api/v1/alerts?token=super-secret-query-value")
    # Validate the actual HTTP metric labels, not the entire exposition.
    # Numeric sample values are arbitrary floating-point measurements and may
    # legitimately contain the same digits as the test query value.
    label_values = http_label_values_in(app)
    assert "999999" not in label_values
    assert "super-secret-query-value" not in label_values
    assert all("?" not in value for value in label_values)


def test_status_labels_remain_bounded_http_codes(client: TestClient, app) -> None:
    """Exposed statuses are ordinary HTTP codes (200/401/404 ...)."""
    assert client.post("/api/v1/alerts/ingest", json={}).status_code == 401
    assert client.get("/health").status_code == 200
    assert client.get("/nope").status_code == 404
    assert (
        sample_value(
            app,
            "soc_triage_http_requests_total",
            {"method": "POST", "route": "/api/v1/alerts/ingest", "status": "401"},
        )
        == 1.0
    )
    assert (
        sample_value(
            app,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": "/health", "status": "200"},
        )
        == 1.0
    )
    assert (
        sample_value(
            app,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": UNMATCHED_ROUTE, "status": "404"},
        )
        == 1.0
    )
    # Every observed status label is a three-digit HTTP code.
    exposition = app.state.metrics.render_text()
    statuses = set(re.findall(r'status="([^"]+)"', exposition))
    assert statuses <= {"200", "401", "404", "405"}


def test_metrics_scrape_is_not_recursive_or_self_amplifying(client: TestClient, app) -> None:
    """Scraping /metrics adds exactly one bounded series per scrape."""
    before = route_labels_in(app)
    first = client.get("/metrics")
    assert first.status_code == 200
    after_first = route_labels_in(app)
    second = client.get("/metrics")
    assert second.status_code == 200
    after_second = route_labels_in(app)

    # One increment per scrape, labeled with the static /metrics route.
    assert (
        sample_value(
            app,
            "soc_triage_http_requests_total",
            {"method": "GET", "route": "/metrics", "status": "200"},
        )
        == 2.0
    )
    # No new label series appeared from scraping (no amplification).
    assert after_first == before | {"/metrics"}
    assert after_second == after_first
    # Bounded: every route label is a known static route or template.
    assert route_labels_in(app) <= {
        "/metrics",
        "/health",
        "/ready",
        "/api/v1/alerts/ingest",
        "/api/v1/alerts/{alert_id}",
        "/api/v1/alerts",
        UNMATCHED_ROUTE,
    }


def test_record_failure_cannot_break_a_normal_request(client: TestClient, monkeypatch) -> None:
    """A metrics-recording defect must never change the request outcome."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected middleware metrics failure")

    monkeypatch.setattr(MetricsRegistry, "record_http_request", boom)
    monkeypatch.setattr(MetricsRegistry, "observe_http_duration", boom)

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["content-type"].startswith("application/json")


def test_middleware_record_hook_failure_cannot_break_request(
    client: TestClient, monkeypatch
) -> None:
    """Even a failure in the middleware's own record hook stays harmless."""

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected record hook failure")

    monkeypatch.setattr(MetricsMiddleware, "_record", boom)

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_existing_endpoint_contracts_unchanged(client: TestClient) -> None:
    """Existing responses/status codes are identical with the middleware on."""
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/api/v1/does-not-exist").json()["error"]["code"] == "not_found"
    assert client.post("/api/v1/alerts/ingest", json={}).status_code == 401
    # OpenAPI stays unchanged and /metrics stays hidden.
    assert "/metrics" not in client.get("/openapi.json").json()["paths"]
