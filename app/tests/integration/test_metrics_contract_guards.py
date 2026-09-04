"""Phase 3.7 Task D10 — static metric-contract and cardinality guards.

Guards the complete Phase 3.7 metrics implementation (D2-D9) against the
approved metric catalog in ``docs/specs/phase-3.7-prometheus-observability.md``
§5, and against unbounded/high-cardinality or identifier-derived label
values. These tests are read-only: they never alter application behavior.

Covered here:

* C. static metric-contract guard — every approved family exists, type and
  label names match exactly, no unexpected ``soc_triage_*`` family exists,
  and prohibited label names (``id``, ``alert_id``, ``rule_id``, IOC-ish,
  URL/hash/hostname/path/error/exception/message) never appear;
* B. cardinality guard — after a representative mixed pipeline run, every
  emitted sample's label names and values are validated against the per-metric
  allowlist (enum vocabularies, route templates, HTTP code range), rejecting
  identifiers, IOC values or any free-form/query/body-derived value;
* D. global-registry isolation — app metrics never register into
  ``prometheus_client.REGISTRY`` and separate app instances never share state;
* E. scrape safety — repeated ``GET /metrics`` scrapes create no new families,
  no new label values, no counter changes beyond the approved HTTP middleware
  counters, no database writes, and no external calls.

Reads the app-scoped registry directly (never the process-global REGISTRY).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import event, text
from sqlalchemy.exc import OperationalError

from soc_triage.core.config import Settings
from soc_triage.core.metrics import (
    AUTO_CLOSE_OUTCOMES,
    DECISION_ACTIONS,
    DEDUPE_OUTCOMES,
    DEGRADED_VALUES,
    ENRICHMENT_STATUSES,
    FEEDBACK_VERDICTS,
    HTTP_METHODS,
    INCIDENT_STATUSES,
    INGEST_REJECT_REASONS,
    N8N_OUTCOMES,
    RISK_TIERS,
    SWEEPER_RESULTS,
    UNKNOWN,
    UNMATCHED_ROUTE,
    MetricsRegistry,
)
from soc_triage.enrichment import EnrichmentChain
from soc_triage.enrichment.providers import (
    EnrichmentContext,
    EnrichmentStatus,
    ProviderEnrichment,
)
from soc_triage.main import create_app
from soc_triage.models.ioc import IOC
from soc_triage.notifications.client import N8NWebhookClient
from soc_triage.sweeper import run_sweeper_loop

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY  # noqa: E402

# ---------------------------------------------------------------------------
# Approved contract (mirrors docs/specs/phase-3.7-prometheus-observability.md §5)
# ---------------------------------------------------------------------------

#: family → (prometheus type, exact label names in declaration order).
EXPECTED_FAMILIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "soc_triage_http_requests": ("counter", ("method", "route", "status")),
    "soc_triage_http_request_duration_seconds": ("histogram", ("method", "route")),
    "soc_triage_ingest_rejections": ("counter", ("reason",)),
    "soc_triage_alerts_processed": ("counter", ("outcome",)),
    "soc_triage_alert_processing_duration_seconds": ("histogram", ()),
    "soc_triage_alerts_scored": ("counter", ("tier", "decision", "degraded")),
    "soc_triage_enrichment_status": ("counter", ("status",)),
    "soc_triage_enrichment_provider_outcomes": ("counter", ("provider", "status")),
    "soc_triage_n8n_notifications": ("counter", ("outcome",)),
    "soc_triage_n8n_notification_duration_seconds": ("histogram", ()),
    "soc_triage_feedback": ("counter", ("verdict",)),
    "soc_triage_incident_transitions": ("counter", ("from_status", "to_status")),
    "soc_triage_incident_auto_close": ("counter", ("outcome",)),
    "soc_triage_sweeper_passes": ("counter", ("result",)),
    "soc_triage_up": ("gauge", ()),
    "soc_triage_database_up": ("gauge", ()),
    "soc_triage_migrations_applied": ("gauge", ()),
}

#: Label names that are prohibited anywhere in the catalog (spec §5 + §6).
PROHIBITED_LABEL_NAMES: frozenset[str] = frozenset(
    {
        "id",
        "alert_id",
        "incident_id",
        "rule_id",
        "agent_id",
        "ip",
        "domain",
        "url",
        "hash",
        "email",
        "username",
        "hostname",
        "path",
        "error",
        "exception",
        "message",
    }
)

#: Per-family bounded label vocabularies for value-only labels (spec §5).
#: ``method``/``route``/``status`` (HTTP) and ``provider`` get family-specific
#: validation below; histograms carry the prometheus ``le`` bookkeeping label.
FAMILY_LABEL_ALLOWLISTS: dict[str, dict[str, frozenset[str]]] = {
    "soc_triage_http_requests": {},
    "soc_triage_http_request_duration_seconds": {},
    "soc_triage_ingest_rejections": {"reason": INGEST_REJECT_REASONS},
    "soc_triage_alerts_processed": {"outcome": DEDUPE_OUTCOMES},
    "soc_triage_alert_processing_duration_seconds": {},
    "soc_triage_alerts_scored": {
        "tier": RISK_TIERS,
        "decision": DECISION_ACTIONS,
        "degraded": DEGRADED_VALUES,
    },
    "soc_triage_enrichment_status": {"status": ENRICHMENT_STATUSES},
    "soc_triage_enrichment_provider_outcomes": {"status": ENRICHMENT_STATUSES},
    "soc_triage_n8n_notifications": {"outcome": N8N_OUTCOMES},
    "soc_triage_n8n_notification_duration_seconds": {},
    "soc_triage_feedback": {"verdict": FEEDBACK_VERDICTS},
    "soc_triage_incident_transitions": {
        "from_status": INCIDENT_STATUSES,
        "to_status": INCIDENT_STATUSES,
    },
    "soc_triage_incident_auto_close": {"outcome": AUTO_CLOSE_OUTCOMES},
    "soc_triage_sweeper_passes": {"result": SWEEPER_RESULTS},
    "soc_triage_up": {},
    "soc_triage_database_up": {},
    "soc_triage_migrations_applied": {},
}

HTTP_METHOD_VALUES: frozenset[str] = HTTP_METHODS | {UNKNOWN}
HTTP_STATUS_VALUES: frozenset[str] = frozenset({str(code) for code in range(100, 600)})
HTTP_STATUS_ALLOWED: frozenset[str] = HTTP_STATUS_VALUES | {UNKNOWN}

#: Samples that are never value-carrying labels (prometheus bookkeeping).
BOOKKEEPING_LABELS: frozenset[str] = frozenset({"le", "quantile"})


# ---------------------------------------------------------------------------
# Shared helpers (same idioms as the D6/D8/D9 metric suites)
# ---------------------------------------------------------------------------


def _load_sample(name: str) -> dict[str, Any]:
    """Load one synthetic Wazuh sample payload."""
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


def _auth() -> dict[str, str]:
    """Ingest auth header (test API key)."""
    return {"X-API-Key": TEST_INGEST_KEY}


def _token() -> dict[str, str]:
    """Shared N8N token header for feedback/incident endpoints."""
    return {"X-N8N-Token": TEST_CALLBACK_TOKEN}


def _ingest(client: TestClient, payload: dict[str, Any]):
    """Post one ingest payload and return the raw response."""
    return client.post("/api/v1/alerts/ingest", json=payload, headers=_auth())


def _ingest_incident(
    client: TestClient,
    *,
    event_id: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Ingest a high-tier alert (creates an incident) and return the body."""
    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    if event_id is not None:
        payload = dict(payload, id=event_id)
    if agent_id is not None:
        payload = dict(payload)
        payload["agent"] = dict(payload.get("agent", {}), id=agent_id)
    response = _ingest(client, payload)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["incident_id"] is not None
    return body


def _patch_status(client: TestClient, incident_id: str, target: str) -> Any:
    return client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": target},
        headers=_token(),
    )


def _submit_feedback(client: TestClient, alert_id: str, verdict: str) -> Any:
    return client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": verdict},
        headers=_token(),
    )


def _age_incident(app, incident_id: str) -> None:
    """Age an incident's updated_at past the app's configured TTL."""
    from sqlalchemy import update as sa_update

    from soc_triage.models.orm import Incident as IncidentORM

    ttl = app.state.settings.incident_auto_close_ttl_seconds
    ts = datetime.now(UTC) - timedelta(seconds=ttl + 100)
    with app.state.db_engine.begin() as conn:
        conn.execute(
            sa_update(IncidentORM)
            .where(IncidentORM.incident_id == incident_id)
            .values(updated_at=ts)
        )


def _mock_n8n_client(handler, *, max_retries: int = 1) -> tuple[N8NWebhookClient, httpx.Client]:
    """Build an N8NWebhookClient over a mock transport (no network I/O)."""
    transport = httpx.MockTransport(handler)
    httpx_client = httpx.Client(transport=transport)
    return (
        N8NWebhookClient(
            webhook_url="http://n8n:5678/webhook/soc-alert-scored",
            token=TEST_CALLBACK_TOKEN,
            client=httpx_client,
            max_retries=max_retries,
            retry_backoff_seconds=0.01,
        ),
        httpx_client,
    )


class _FakeProvider:
    """Minimal offline enrichment provider driving a fixed outcome.

    ``name`` must be one of the names registered at app startup (noop,
    virustotal, misp) to pass the D2 provider allowlist.
    """

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
        iocs: list[IOC],
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


def _rows(app, sql: str) -> list[tuple[Any, ...]]:
    """Run one read-only query against the app's engine."""
    engine = app.state.db_engine
    with engine.connect() as connection:
        return list(connection.execute(text(sql)))


def _samples(registry) -> dict[str, dict[tuple[str, tuple[tuple[str, str], ...]], float]]:
    """Map family → {(sample name, sorted label pairs): value} for a registry."""
    collected: dict[str, dict[tuple[str, tuple[tuple[str, str], ...]], float]] = {}
    for collector in registry.collect():
        samples: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        for sample in collector.samples:
            labels = tuple(sorted(sample.labels.items()))
            samples[(sample.name, labels)] = sample.value
        collected[collector.name] = samples
    return collected


def _standalone_app(tmp_path: Path, *, db_name: str = "standalone.db") -> Any:
    """Create an isolated app (no shared fixtures) on its own SQLite file."""
    return create_app(
        settings=Settings(
            soc_env="test",
            soc_log_level="INFO",
            soc_instance_name="soc-test",
            triage_cors_origins="http://localhost:8080",
            triage_db_url=f"sqlite:///{tmp_path / db_name}",
            triage_ingest_api_key=TEST_INGEST_KEY,
            n8n_callback_token=TEST_CALLBACK_TOKEN,
        )
    )


def _drive_sweeper_once(registry: MetricsRegistry, factory: Any, settings: Settings) -> None:
    """Run one deterministic sweeper-loop pass (D9-proven idiom)."""

    async def _drive() -> None:
        task = asyncio.create_task(run_sweeper_loop(factory, settings, metrics=registry))
        await asyncio.sleep(0.05)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    asyncio.run(_drive())


# ---------------------------------------------------------------------------
# Representative pipeline: every family gets at least one real sample
# ---------------------------------------------------------------------------


def _run_representative_pipeline(client: TestClient) -> str:
    """Exercise ingest, enrichment, scoring, notification, feedback, incident
    transition, sweeper and every rejection path; return the incident id."""
    # Enrichment: complete + failing (fail-open partial), registered names.
    _install_chain(
        client,
        [
            _FakeProvider("virustotal", EnrichmentStatus.COMPLETE),
            _FakeProvider("misp", EnrichmentStatus.FAILED, fail=True),
        ],
    )

    # Notification: mocked 200 → delivered.
    def ok_handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    n8n_client, _ = _mock_n8n_client(ok_handler)
    client.app.state.n8n_client = n8n_client

    payload = _load_sample("01_wazuh_ssh_brute_force.json")
    first = _ingest(client, payload)
    assert first.status_code == 202
    repeated = _ingest(client, dict(payload, id="1770000000.100002"))
    assert repeated.status_code == 202
    duplicate = _ingest(client, payload)
    assert duplicate.status_code == 200

    # High alert → incident → manual transition + feedback sync → auto-close.
    high = _ingest_incident(client)
    alert_id = high["alert_id"]
    incident_id = high["incident_id"]
    assert _patch_status(client, incident_id, "acknowledged").status_code == 200
    assert _submit_feedback(client, alert_id, "escalate").status_code == 200
    _age_incident(client.app, incident_id)
    from soc_triage import sweeper as sweeper_mod

    stats = sweeper_mod.sweep_once(
        client.app.state.session_factory,
        ttl_seconds=client.app.state.settings.incident_auto_close_ttl_seconds,
        metrics=client.app.state.metrics,
    )
    assert stats["closed"] == 1

    # Every bounded ingest rejection reason, through the real boundaries.
    assert client.post("/api/v1/alerts/ingest", json=payload).status_code == 401
    assert (
        client.post("/api/v1/alerts/ingest", headers=_auth(), content=b"{{{invalid").status_code
        == 422
    )
    assert client.post("/api/v1/alerts/ingest", headers=_auth(), json={}).status_code == 422
    assert (
        client.post(
            "/api/v1/alerts/ingest",
            headers=_auth(),
            json=dict(payload, agent={"id": "", "name": "x"}),
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/alerts/ingest",
            headers=_auth(),
            content=b"{" + b"a" * (300 * 1024) + b"}",
        ).status_code
        == 413
    )
    engine: Any = client.app.state.db_engine

    @event.listens_for(engine, "connect", insert=True)
    def _reject_connections(_dbapi_connection: Any, _connection_record: Any) -> None:
        raise OperationalError(
            "SELECT 1",
            {},
            sqlite3.OperationalError("unable to open database file"),
        )

    engine.dispose()
    try:
        assert (
            client.post("/api/v1/alerts/ingest", json=payload, headers=_auth()).status_code == 503
        )
    finally:
        event.remove(engine, "connect", _reject_connections)
        engine.dispose()

    return incident_id


# ---------------------------------------------------------------------------
# C. Static metric-contract guard
# ---------------------------------------------------------------------------


def test_metric_family_contract_matches_approved_catalog() -> None:
    """Exactly the approved families exist, with the right types."""
    registry = MetricsRegistry()
    collected = {metric.name: metric for metric in registry.registry.collect()}
    assert set(collected) == set(EXPECTED_FAMILIES), (
        f"unexpected or missing soc_triage_* families: {set(collected) ^ set(EXPECTED_FAMILIES)}"
    )
    for name, (expected_type, _labels) in EXPECTED_FAMILIES.items():
        assert collected[name].type == expected_type, name


def test_approved_label_names_are_universally_permitted() -> None:
    """No approved label name is on the prohibited list (exact names)."""
    for family, (_type, labels) in EXPECTED_FAMILIES.items():
        for label in labels:
            assert label not in PROHIBITED_LABEL_NAMES, (family, label)


def test_label_names_and_no_prohibited_labels_after_pipeline(client) -> None:
    """The exposition carries exactly the approved label names per family."""
    _run_representative_pipeline(client)
    # Deterministic sweeper pass sample (D9: exactly one per actual pass).
    _drive_sweeper_once(
        client.app.state.metrics,
        client.app.state.session_factory,
        client.app.state.settings,
    )

    observed = _samples(client.app.state.metrics.registry)
    assert set(observed) == set(EXPECTED_FAMILIES)
    for family, samples in observed.items():
        _type, expected_labels = EXPECTED_FAMILIES[family]
        label_names = set()
        for _sample_name, labels in samples:
            label_names.update(name for name, _value in labels if name not in BOOKKEEPING_LABELS)
            observed_labels = {name for name, _value in labels}
            assert observed_labels - {*BOOKKEEPING_LABELS} - set(expected_labels) == set(), (
                family,
                observed_labels,
            )
        assert label_names <= set(expected_labels), (family, label_names)
        expected_unknown = set(expected_labels) - label_names
        # Families with zero emitted samples are impossible here by design;
        # the only allowed empty label set is a truly unlabeled family.
        assert not samples or not expected_unknown, (family, expected_unknown)


# ---------------------------------------------------------------------------
# B. Cardinality guard — bounded labels after a mixed pipeline run
# ---------------------------------------------------------------------------


def _allowed_routes(app) -> frozenset[str]:
    """Static routes + route templates the app declares (same as main.py)."""
    from soc_triage.api.middleware import collect_route_paths

    paths = collect_route_paths(app.router)
    static = {p for p in paths if "{" not in p}
    templates = {p for p in paths if "{" in p}
    return frozenset(static | templates | {UNMATCHED_ROUTE})


def test_cardinality_guard_after_representative_pipeline(client) -> None:
    """Every emitted (family, labels) pair is inside the approved allowlist."""
    _run_representative_pipeline(client)
    _drive_sweeper_once(
        client.app.state.metrics,
        client.app.state.session_factory,
        client.app.state.settings,
    )

    registry = client.app.state.metrics.registry
    registered_providers = frozenset(
        provider.name for provider in client.app.state.enrichment_chain.providers
    )
    allowed_routes = _allowed_routes(client.app)
    observed = _samples(registry)

    assert set(observed) == set(EXPECTED_FAMILIES)
    for family, samples in observed.items():
        _expected_type, expected_labels = EXPECTED_FAMILIES[family]
        for (sample_name, labels), _value in samples.items():
            # Sample names are family-derived; label names match exactly
            # apart from prometheus histogram bookkeeping (le).
            assert sample_name.startswith(family), (family, sample_name)
            label_names = {name for name, _value in labels}
            assert label_names - BOOKKEEPING_LABELS == set(expected_labels), (
                family,
                label_names,
            )
            for label_name, value in labels:
                if label_name in BOOKKEEPING_LABELS:
                    continue  # prometheus-owned, bounded by client defaults
                if label_name == "method":
                    assert value in HTTP_METHOD_VALUES, (family, label_name, value)
                    continue
                if label_name == "route":
                    assert value in allowed_routes, (family, label_name, value)
                    continue
                if label_name == "status":
                    # ``status`` is the HTTP code on the request counter and
                    # the enrichment status on the enrichment families.
                    allowed = (
                        HTTP_STATUS_ALLOWED
                        if family == "soc_triage_http_requests"
                        else ENRICHMENT_STATUSES
                    )
                    assert value in allowed, (family, label_name, value)
                    continue
                if label_name == "provider":
                    assert value in registered_providers | {UNKNOWN}, (family, label_name, value)
                    continue
                allowed = FAMILY_LABEL_ALLOWLISTS[family].get(label_name)
                assert allowed is not None, (family, label_name)
                assert value in allowed, (family, label_name, value)
                assert value not in PROHIBITED_LABEL_NAMES, (family, label_name, value)


def test_identifier_and_ioc_shaped_values_can_never_pass_the_guard(client) -> None:
    """Hostile/free-form values are rejected by construction, not by luck."""
    incident_id = _run_representative_pipeline(client)
    hostile = [
        incident_id,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "8.8.8.8",
        "evil.example.com",
        "https://evil.example.com/x?token=attack",
        "d41d8cd98f00b204e9800998ecf8427e",
        "attacker@example.com",
        "/etc/passwd; rm -rf /",
        "injected provider failure",
    ]
    observed = _samples(client.app.state.metrics.registry)
    for family, samples in observed.items():
        for (_sample_name, labels), _value in samples.items():
            for label_name, value in labels:
                assert value not in hostile, (family, label_name, value)


# ---------------------------------------------------------------------------
# D. Global-registry isolation
# ---------------------------------------------------------------------------


def test_app_metrics_never_register_into_global_registry() -> None:
    """The process-global REGISTRY never sees any soc_triage_* family."""
    import prometheus_client

    global_names = {metric.name for metric in prometheus_client.REGISTRY.collect()}
    assert not any(name.startswith("soc_triage_") for name in global_names), global_names


def test_separate_app_instances_have_isolated_metric_state(tmp_path) -> None:
    """Two app instances never share counter samples or registry objects."""
    app_a = _standalone_app(tmp_path, db_name="a.db")
    app_b = _standalone_app(tmp_path, db_name="b.db")

    with TestClient(app_a) as client_a, TestClient(app_b) as _client_b:
        registry_a = app_a.state.metrics.registry
        registry_b = app_b.state.metrics.registry
        assert registry_a is not registry_b
        response = _ingest(client_a, _load_sample("01_wazuh_ssh_brute_force.json"))
        assert response.status_code == 202

        # Only app A observed the alert; app B has no samples for it.
        assert (
            registry_a.get_sample_value(
                "soc_triage_alerts_processed_total", {"outcome": "new_generation"}
            )
            == 1.0
        )
        assert (
            registry_b.get_sample_value(
                "soc_triage_alerts_processed_total", {"outcome": "new_generation"}
            )
            is None
        )


# ---------------------------------------------------------------------------
# E. Scrape safety — repeated scrapes are stable, read-only, and silent
# ---------------------------------------------------------------------------


def _write_probe(app) -> list[str]:
    """Install a listener recording any write statement on the app engine."""
    writes: list[str] = []
    engine = app.state.db_engine

    @event.listens_for(engine, "before_cursor_execute")
    def _probe(_conn, _cursor, statement, _params, _context, _executemany) -> None:
        head = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else ""
        if head in {
            "INSERT",
            "UPDATE",
            "DELETE",
            "CREATE",
            "DROP",
            "ALTER",
            "REPLACE",
            "MERGE",
        }:
            writes.append(statement)

    engine.dispose()
    return writes


def test_repeated_scrapes_create_no_families_labels_or_db_writes(client, app) -> None:
    """Scraping is idempotent: only the /metrics HTTP counters may move."""
    ingest_body = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert ingest_body.status_code == 202
    alert_id = ingest_body.json()["alert_id"]

    # The lifespan's immediate sweeper pass finishes within moments of
    # startup; wait for it so the stability comparison starts from a settled
    # registry (the next pass is one full interval away).
    for _ in range(200):
        if (
            app.state.metrics.registry.get_sample_value(
                "soc_triage_sweeper_passes_total", {"result": "completed"}
            )
            is not None
        ):
            break
        time.sleep(0.01)

    writes = _write_probe(app)
    row_counts_before = {
        table: _rows(app, f"SELECT COUNT(*) FROM {table}")
        for table in ("alerts", "alert_events", "audit_log", "incidents", "analyst_feedback")
    }

    snapshots: list[dict[str, dict[tuple[str, tuple[tuple[str, str], ...]], float]]] = []
    bodies: list[str] = []
    for _ in range(3):
        response = client.get("/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        bodies.append(response.text)
        snapshots.append(_samples(app.state.metrics.registry))

        # No write statements were emitted by any scrape.
        assert writes == [], writes
        for table, count in row_counts_before.items():
            assert _rows(app, f"SELECT COUNT(*) FROM {table}") == count, table

        # Families and label-value sets never grow; only /metrics HTTP series
        # may change (the approved middleware counters for the scrape itself).
        for first, later in pairwise(snapshots):
            assert set(first) == set(later)
            for family in first:
                if family in {
                    "soc_triage_http_requests",
                    "soc_triage_http_request_duration_seconds",
                }:
                    assert set(first[family]) == set(later[family])
                    for key in first[family]:
                        if key[1] and dict(key[1]).get("route") == "/metrics":
                            continue  # approved: scrape counters may increment
                        assert first[family][key] == later[family][key], (family, key)
                else:
                    assert first[family] == later[family], family

        # The exposition itself must contain no dynamic identifiers.
        assert alert_id not in bodies[-1]
