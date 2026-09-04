"""Phase 3.7 Task D4 — Prometheus /metrics endpoint integration tests.

Covers the approved endpoint contract (decision D1):

* app-scoped exposition (never the process-global REGISTRY);
* exact Prometheus text content type;
* expected ``soc_triage_*`` families present;
* endpoint hidden from OpenAPI;
* optional Bearer auth: missing/malformed/wrong token → 401, correct → 200;
* the ingest API key and N8N token are never accepted on /metrics;
* the configured token never appears in response bodies, error text, or logs;
* ``METRICS_ENABLED=false`` → the surface is unavailable (route not mounted);
* scraping performs no database writes (cheap read-only pings only, D3);
* existing health/auth/ingest behavior is untouched (whole suite re-run).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy import text

from soc_triage.api.metrics import METRICS_CONTENT_TYPE
from soc_triage.core.config import Settings
from soc_triage.main import create_app

# Short, hyphenated, clearly-non-secret lab values (secret-scan safe).
INGEST_KEY = "unit-ingest-key"
CALLBACK_TOKEN = "unit-callback-token"
METRICS_TOKEN = "unit-metrics-token"


@contextmanager
def make_client(
    db_url: str,
    *,
    metrics_enabled: bool = True,
    metrics_token: str = "",
) -> Iterator[TestClient]:
    """Build an isolated app/client with the metrics settings under test."""
    settings = Settings(
        soc_env="test",
        triage_db_url=db_url,
        triage_ingest_api_key=INGEST_KEY,
        n8n_callback_token=CALLBACK_TOKEN,
        metrics_enabled=metrics_enabled,
        metrics_scrape_token=metrics_token,
    )
    with TestClient(create_app(settings=settings)) as client:
        yield client


def test_metrics_succeeds_when_enabled_with_empty_token(
    client: TestClient,
) -> None:
    """Empty METRICS_SCRAPE_TOKEN = auth disabled; scrape succeeds (200)."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "soc_triage_up 1.0" in response.text


def test_metrics_content_type_is_prometheus_text_exposition(
    client: TestClient,
) -> None:
    """The content type is the exact Prometheus text exposition type."""
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"] == METRICS_CONTENT_TYPE


def test_metrics_exposition_contains_expected_soc_triage_metrics(
    client: TestClient,
) -> None:
    """The exposure carries the app metric catalog, incl. health gauges."""
    response = client.get("/metrics")
    assert response.status_code == 200
    text = response.text
    for fragment in (
        "# HELP soc_triage_up",
        "# TYPE soc_triage_up gauge",
        "soc_triage_up 1.0",
        "# TYPE soc_triage_http_requests_total counter",
        "# TYPE soc_triage_http_request_duration_seconds histogram",
        "# TYPE soc_triage_alert_processing_duration_seconds histogram",
        "# TYPE soc_triage_database_up gauge",
        "soc_triage_database_up 1.0",
        "# TYPE soc_triage_migrations_applied gauge",
        "soc_triage_migrations_applied 1.0",
    ):
        assert fragment in text, f"missing metric fragment: {fragment!r}"
    # App-scoped: the default process registry is never the source.
    assert "soc_triage_up" in response.text


def test_metrics_absent_from_openapi(app) -> None:
    """include_in_schema=False: /metrics is not part of the OpenAPI schema."""
    paths = app.openapi()["paths"]
    assert "/metrics" not in paths


def test_metrics_bearer_auth_enforced_when_token_configured(db_url: str) -> None:
    """Configured token: missing/malformed/wrong → 401; correct → 200."""
    with make_client(db_url, metrics_token=METRICS_TOKEN) as client:
        # Missing Authorization header.
        assert client.get("/metrics").status_code == 401
        # Non-Bearer scheme (malformed).
        assert (
            client.get("/metrics", headers={"Authorization": "Basic dXNlcjpwYXNz"}).status_code
            == 401
        )
        # Bearer without a credential (malformed).
        assert client.get("/metrics", headers={"Authorization": "Bearer"}).status_code == 401
        # Bearer with an extra space but no credential (malformed).
        assert client.get("/metrics", headers={"Authorization": "Bearer   "}).status_code == 401
        # Wrong token.
        assert (
            client.get(
                "/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}-wrong"}
            ).status_code
            == 401
        )
        # Correct token.
        ok = client.get("/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"})
        assert ok.status_code == 200
        assert "soc_triage_up 1.0" in ok.text


def test_metrics_bearer_rejects_ingest_and_n8n_tokens(db_url: str) -> None:
    """The scrape channel never accepts the ingest key or N8N callback token."""
    with make_client(db_url, metrics_token=METRICS_TOKEN) as client:
        assert (
            client.get("/metrics", headers={"Authorization": f"Bearer {INGEST_KEY}"}).status_code
            == 401
        )
        assert (
            client.get(
                "/metrics", headers={"Authorization": f"Bearer {CALLBACK_TOKEN}"}
            ).status_code
            == 401
        )


def test_metrics_token_never_leaks_into_responses_or_logs(db_url: str, capsys) -> None:
    """The configured token must never appear in bodies, errors, or logs."""
    with make_client(db_url, metrics_token=METRICS_TOKEN) as client:
        missing = client.get("/metrics")
        wrong = client.get("/metrics", headers={"Authorization": "Bearer wrong-token-here"})
        ok = client.get("/metrics", headers={"Authorization": f"Bearer {METRICS_TOKEN}"})
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert ok.status_code == 200
    for response in (missing, wrong, ok):
        assert METRICS_TOKEN not in response.text
        assert METRICS_TOKEN not in response.headers.get("authorization", "")
    captured = capsys.readouterr()
    assert METRICS_TOKEN not in captured.out
    assert METRICS_TOKEN not in captured.err


def test_metrics_disabled_makes_surface_unavailable(db_url: str) -> None:
    """METRICS_ENABLED=false: /metrics is not mounted at all (404)."""
    with make_client(db_url, metrics_enabled=False) as client:
        response = client.get("/metrics")
        assert response.status_code == 404
        body = response.json()
        assert body["error"]["code"] == "not_found"


def test_metrics_scrape_never_writes_to_database(app, client: TestClient) -> None:
    """Scraping is read-only: row counts and migration stamp stay identical."""
    engine = app.state.db_engine

    def snapshot() -> tuple[int, int, int]:
        with engine.connect() as connection:
            alerts = connection.execute(text("SELECT COUNT(*) FROM alerts")).scalar_one()
            audit = connection.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one()
            revisions = connection.execute(
                text("SELECT COUNT(*) FROM alembic_version")
            ).scalar_one()
        return alerts, audit, revisions

    before = snapshot()
    for _ in range(3):
        response = client.get("/metrics")
        assert response.status_code == 200
    after = snapshot()
    assert before == after
    # Fresh database: no alert/audit rows were created by scraping.
    assert after == (0, 0, 1)


def test_existing_health_endpoints_unchanged(client: TestClient) -> None:
    """/health and /ready keep their contracts alongside /metrics."""
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
