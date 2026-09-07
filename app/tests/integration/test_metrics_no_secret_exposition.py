"""Phase 3.7 Task D10 â€” no-secret exposition guards (synthetic canaries).

The security guard for the approved Phase 3.7 metrics surface. Synthetic
secret canaries in realistic locations (environment/config values, API-key
like, N8N token like, metrics scrape token, DB URL/password-like, webhook
URL-like) plus synthetic alert data canaries (alert/incident/wazuh IDs,
IPv4, domain, URL, MD5/SHA1/SHA256, email, username, file path, full_log,
provenance, provider exception/error text) are pushed through the real
pipeline â€” ingest, duplicate/repeated ingest, enrichment, scoring/decision,
notification, feedback, incident transition, sweeper â€” and through repeated
``GET /metrics`` scrapes. The guard asserts that none of the sensitive
values ever reaches the exposition, the registry label sets, or an
unexpected family.

The application is never weakened or sanitized: canaries are ordinary
alert/config values; the guard only observes metric output. All canaries
are obviously fake and segment-separated so a plain source scan cannot
mistake them for real credentials (``scripts/check_secrets.sh`` stays
green without exclusions).

Reads the app-scoped registry directly (never the process-global REGISTRY).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient

from soc_triage.core.config import Settings
from soc_triage.enrichment import EnrichmentChain
from soc_triage.enrichment.providers import EnrichmentContext, EnrichmentStatus, ProviderEnrichment
from soc_triage.main import create_app
from soc_triage.models.ioc import IOC
from soc_triage.notifications.client import N8NWebhookClient
from soc_triage.sweeper import sweep_once

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Synthetic canaries (obviously fake; every value is alnum-run-short)
# ---------------------------------------------------------------------------

# Secret-like configuration canaries (never stored in Git).
API_KEY_CANARY = "d10-ak-3f21-9c04-n0treal"
FETCH_TOKEN_CANARY = "d10-scrape-2b8e-5a17-n0treal"
CALLBACK_TOKEN_CANARY = "d10-callback-6d3a-9e22-n0treal"
DB_PASSWORD_CANARY = "db-pw-8c3f-77aa-n0treal"
VT_KEY_CANARY = "vtkey-4d19-b2cc-n0treal"
WEBHOOK_URL_CANARY = "http://n8n.d10-lab.invalid:5678/webhook/hook-3f62?key=wh-9c4d-n0treal"

# Synthetic alert-data canaries (IOC-like, identifier-like). Identifier
# values carry a distinctive prefix so a short numeric substring can never
# false-positive against timestamps in the exposition.
EVENT_ID_CANARY = "d10-1770000000-900001"
RULE_ID_CANARY = "d10-rule-99501"
AGENT_ID_CANARY = "d10-agent-042"
IP_CANARY = "198.51.100.77"
DOMAIN_CANARY = "evil-example-d10.invalid"
URL_CANARY = "https://evil-example-d10.invalid/malware.exe?ref=d10-3f62"
EMAIL_CANARY = "analyst-d10@example.invalid"
USERNAME_CANARY = "svc-d10-triage"
MD5_CANARY = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
SHA1_CANARY = "d1e2f3a4b5c60718293a4b5c6d7e8f90a1b2c3d4"
SHA256_CANARY = "e1f2a3b4c5d60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
FILE_PATH_CANARY = r"C:\Users\d10-supplier\Downloads\payload_d10.exe"
FULL_LOG_CANARY = (
    "D10 synthetic: downloaded payload_d10.exe from evil-example-d10.invalid "
    "via https://evil-example-d10.invalid/malware.exe"
)
PROVENANCE_CANARY = "d10-prov-chain:0007:9c4d:agent-042"
PROVIDER_ERROR_CANARY = "d10-provider-fault-3f62c1aa: invalid upstream"
QUERY_CANARY = "q-d10-5b9e-77aa"
HEADER_CANARY = "hdr-d10-31f7-88bb"

#: Every sensitive string the guard asserts absent from the exposition.
ALL_CANARIES: tuple[str, ...] = (
    API_KEY_CANARY,
    FETCH_TOKEN_CANARY,
    CALLBACK_TOKEN_CANARY,
    DB_PASSWORD_CANARY,
    VT_KEY_CANARY,
    EVENT_ID_CANARY,
    RULE_ID_CANARY,
    AGENT_ID_CANARY,
    IP_CANARY,
    DOMAIN_CANARY,
    URL_CANARY,
    EMAIL_CANARY,
    USERNAME_CANARY,
    MD5_CANARY,
    SHA1_CANARY,
    SHA256_CANARY,
    FILE_PATH_CANARY,
    FULL_LOG_CANARY,
    PROVENANCE_CANARY,
    PROVIDER_ERROR_CANARY,
    QUERY_CANARY,
    HEADER_CANARY,
    "n8n.d10-lab.invalid",  # webhook URL host
    "hook-3f62",  # webhook URL path segment
)


# ---------------------------------------------------------------------------
# Pipeline fixtures
# ---------------------------------------------------------------------------


def _load_sample(name: str) -> dict[str, Any]:
    """Load one synthetic Wazuh sample payload."""
    with (FIXTURES_DIR / name).open() as f:
        return json.load(f)


def _canary_payload(base: dict[str, Any], *, event_id: str) -> dict[str, Any]:
    """Deep-copy a sample and inject every alert-data canary we guard."""
    payload = copy.deepcopy(base)
    payload["id"] = event_id
    payload["rule"]["id"] = RULE_ID_CANARY
    payload["agent"]["id"] = AGENT_ID_CANARY
    payload["agent"]["name"] = USERNAME_CANARY
    payload["agent"]["ip"] = IP_CANARY
    payload["data"]["srcip"] = IP_CANARY
    payload["data"]["dstip"] = "203.0.113.99"
    payload["data"]["hostname"] = DOMAIN_CANARY
    payload["data"]["url"] = URL_CANARY
    payload["data"]["srcuser"] = EMAIL_CANARY
    payload["data"]["dstuser"] = USERNAME_CANARY
    payload["data"]["md5"] = MD5_CANARY
    payload["data"]["sha1"] = SHA1_CANARY
    payload["data"]["sha256"] = SHA256_CANARY
    payload["data"]["file_path"] = FILE_PATH_CANARY
    payload["data"]["provenance"] = PROVENANCE_CANARY
    payload["full_log"] = FULL_LOG_CANARY
    # Extra (schema allow) fields â€” extractor never sees them as labels.
    payload["d10_provenance"] = PROVENANCE_CANARY
    payload["d10_provider_context"] = {"trace": PROVIDER_ERROR_CANARY}
    return payload


class _FakeProvider:
    """Offline enrichment provider; optional injected failure text."""

    def __init__(self, name: str, *, fail: bool = False) -> None:
        self._name = name
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
            # Realistic provider failure text â€” must never become a label.
            raise RuntimeError(PROVIDER_ERROR_CANARY)
        return ProviderEnrichment(
            provider=self._name,
            status=EnrichmentStatus.COMPLETE,
            results={ioc.key: {"raw": {"exception": PROVIDER_ERROR_CANARY}} for ioc in iocs},
            notes=[PROVIDER_ERROR_CANARY, "d10 synthetic enrichment"],
        )


def _install_canary_pipeline(client: TestClient) -> None:
    """Install offline providers and a mock n8n client (never network I/O)."""
    client.app.state.enrichment_chain = EnrichmentChain(
        [
            _FakeProvider("virustotal"),
            _FakeProvider("misp", fail=True),
        ]
    )

    def ok_handler(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(ok_handler)
    n8n_client = N8NWebhookClient(
        webhook_url=WEBHOOK_URL_CANARY,
        token=CALLBACK_TOKEN_CANARY,
        client=httpx.Client(transport=transport),
        max_retries=1,
        retry_backoff_seconds=0.01,
    )
    client.app.state.n8n_client = n8n_client


def _canary_app(tmp_path: Path) -> Any:
    """An app whose config locations are themselves canary values."""
    return create_app(
        settings=Settings(
            soc_env="test",
            soc_log_level="INFO",
            soc_instance_name="soc-d10-guard",
            triage_cors_origins="http://localhost:8080",
            # DB URL with a credential-like query parameter (SQLite ignores it).
            triage_db_url=(f"sqlite:///{tmp_path / 'd10.db'}?password={DB_PASSWORD_CANARY}"),
            triage_ingest_api_key=API_KEY_CANARY,
            n8n_callback_token=CALLBACK_TOKEN_CANARY,
            n8n_webhook_token="",
            metrics_scrape_token=FETCH_TOKEN_CANARY,
            virustotal_api_key=VT_KEY_CANARY,
            n8n_webhook_url=WEBHOOK_URL_CANARY,
        )
    )


def _ingest(client: TestClient, payload: dict[str, Any], **kwargs: Any):
    """Post one ingest payload with the canary API key."""
    return client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers=kwargs.pop("headers", {"X-API-Key": API_KEY_CANARY}),
        **kwargs,
    )


def _samples(registry) -> dict[str, dict[tuple[str, tuple[tuple[str, str], ...]], float]]:
    """Map family -> {(sample name, sorted label pairs): value} for a registry."""
    collected: dict[str, dict[tuple[str, tuple[tuple[str, str], ...]], float]] = {}
    for collector in registry.collect():
        samples: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        for sample in collector.samples:
            labels = tuple(sorted(sample.labels.items()))
            samples[(sample.name, labels)] = sample.value
        collected[collector.name] = samples
    return collected


def _run_canary_pipeline(client: TestClient) -> str:
    """Drive canary data through every instrumented path; return incident id."""
    base = _load_sample("01_wazuh_ssh_brute_force.json")
    first = _ingest(client, _canary_payload(base, event_id=EVENT_ID_CANARY))
    assert first.status_code == 202, first.text
    repeated = _ingest(client, _canary_payload(base, event_id="1770000000.900002"))
    assert repeated.status_code == 202
    assert repeated.json()["dedupe_status"] == "repeated"
    duplicate = _ingest(client, _canary_payload(base, event_id=EVENT_ID_CANARY))
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True

    # High alert -> incident -> transition -> feedback -> auto-close.
    high_payload = _canary_payload(
        _load_sample("04_wazuh_malware_hash_virustotal.json"),
        event_id="1770000000.900004",
    )
    high = _ingest(client, high_payload)
    assert high.status_code == 202, high.text
    body = high.json()
    alert_id = body["alert_id"]
    incident_id = body["incident_id"]
    assert incident_id is not None

    assert (
        client.patch(
            f"/api/v1/incidents/{incident_id}/status",
            json={"status": "acknowledged"},
            headers={"X-N8N-Token": CALLBACK_TOKEN_CANARY},
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/alerts/{alert_id}/feedback",
            json={"verdict": "escalate"},
            headers={"X-N8N-Token": CALLBACK_TOKEN_CANARY},
        ).status_code
        == 200
    )

    # Query/header canaries ride on a valid request (never become labels).
    query_response = _ingest(
        client,
        _canary_payload(base, event_id="1770000000.900003"),
        headers={
            "X-API-Key": API_KEY_CANARY,
            "X-D10-Canary": HEADER_CANARY,
        },
        params={"q": QUERY_CANARY, "token": QUERY_CANARY},
    )
    assert query_response.status_code == 202

    # Rejection canaries: malformed body with canary text, oversized body,
    # and a missing/forged credential.
    assert (
        client.post(
            "/api/v1/alerts/ingest",
            headers={"X-API-Key": API_KEY_CANARY, "X-D10-Canary": HEADER_CANARY},
            content=("{" + PROVENANCE_CANARY + '"invalid').encode(),
        ).status_code
        == 422
    )
    # ~512 KiB of canary text: over the 256 KiB body limit.
    oversized = b"{" + PROVIDER_ERROR_CANARY.encode() * 14000 + b"}"
    assert (
        client.post(
            "/api/v1/alerts/ingest",
            headers={"X-API-Key": API_KEY_CANARY},
            content=oversized,
        ).status_code
        == 413
    )
    assert (
        client.post(
            "/api/v1/alerts/ingest",
            json=_canary_payload(base, event_id="1770000000.900005"),
            headers={"X-API-Key": "wrong-d10-key-0000"},
        ).status_code
        == 401
    )

    # Age and auto-close the incident through the real sweeper.
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import update as sa_update

    from soc_triage.models.orm import Incident as IncidentORM

    ttl = client.app.state.settings.incident_auto_close_ttl_seconds
    with client.app.state.db_engine.begin() as conn:
        conn.execute(
            sa_update(IncidentORM)
            .where(IncidentORM.incident_id == incident_id)
            .values(updated_at=datetime.now(UTC) - timedelta(seconds=ttl + 100))
        )
    stats = sweep_once(
        client.app.state.session_factory,
        ttl_seconds=ttl,
        metrics=client.app.state.metrics,
    )
    assert stats["closed"] == 1
    return incident_id


def _assert_canary_free(body: str, context: str) -> None:
    """Assert the exposition carries no canary substring."""
    for canary in ALL_CANARIES:
        assert canary not in body, (context, canary)


# ---------------------------------------------------------------------------
# A. No-secret exposition â€” full pipeline with canaries, authenticated scrape
# ---------------------------------------------------------------------------


def test_no_secret_exposition_after_full_canary_pipeline(tmp_path) -> None:
    """Synthetic secrets/IOCs through every path never reach /metrics."""
    app = _canary_app(tmp_path)
    with TestClient(app) as client:
        _install_canary_pipeline(client)
        incident_id = _run_canary_pipeline(client)

        # Unauthenticated scrape: 401, and even the error must not echo the
        # configured token.
        denied = client.get("/metrics")
        assert denied.status_code == 401
        assert FETCH_TOKEN_CANARY not in denied.text

        # Authenticated scrapes: text exposition, none of the canaries.
        bodies: list[str] = []
        for _ in range(3):
            response = client.get(
                "/metrics",
                headers={"Authorization": f"Bearer {FETCH_TOKEN_CANARY}"},
            )
            assert response.status_code == 200
            assert response.headers["content-type"].startswith(
                "text/plain; version=0.0.4; charset=utf-8"
            )
            bodies.append(response.text)
            _assert_canary_free(response.text, "scrape")

        # The registry label sets themselves carry no canary, no identifier
        # shape, and no free-form value (whitespace/URL/email markers).
        observed = _samples(app.state.metrics.registry)
        for family, samples in observed.items():
            for (sample_name, labels), _value in samples.items():
                assert sample_name.startswith(family), (family, sample_name)
                for label_name, value in labels:
                    assert value not in ALL_CANARIES, (family, label_name, value)
                    if label_name in {"route", "provider", "method", "status"}:
                        continue
                    assert " " not in value, (family, value)
                    assert "@" not in value, (family, value)
                    assert "://" not in value, (family, value)
                    assert "?" not in value and "=" not in value, (family, value)
                    assert "\\" not in value, (family, value)

        # Every pipeline path produced its approved family (nothing new).
        assert set(observed) == {
            "soc_triage_http_requests",
            "soc_triage_http_request_duration_seconds",
            "soc_triage_ingest_rejections",
            "soc_triage_alerts_processed",
            "soc_triage_alert_processing_duration_seconds",
            "soc_triage_alerts_scored",
            "soc_triage_enrichment_status",
            "soc_triage_enrichment_provider_outcomes",
            "soc_triage_n8n_notifications",
            "soc_triage_n8n_notification_duration_seconds",
            "soc_triage_feedback",
            "soc_triage_incident_transitions",
            "soc_triage_incident_auto_close",
            "soc_triage_sweeper_passes",
            "soc_triage_up",
            "soc_triage_database_up",
            "soc_triage_migrations_applied",
        }

        # The app-generated incident id is dynamic and must never leak either.
        assert incident_id not in bodies[-1]


def test_canary_values_never_reach_exposition_through_metadata_labels() -> None:
    """Direct registry stress: hostiles collapse to the fixed fallback."""
    from soc_triage.core.metrics import UNKNOWN, MetricsRegistry

    registry = MetricsRegistry(provider_names=("noop", "virustotal", "misp"))
    hostiles = [
        API_KEY_CANARY,
        FETCH_TOKEN_CANARY,
        CALLBACK_TOKEN_CANARY,
        DB_PASSWORD_CANARY,
        VT_KEY_CANARY,
        WEBHOOK_URL_CANARY,
        EVENT_ID_CANARY,
        RULE_ID_CANARY,
        AGENT_ID_CANARY,
        IP_CANARY,
        DOMAIN_CANARY,
        URL_CANARY,
        EMAIL_CANARY,
        USERNAME_CANARY,
        MD5_CANARY,
        SHA1_CANARY,
        SHA256_CANARY,
        FILE_PATH_CANARY,
        FULL_LOG_CANARY,
        PROVENANCE_CANARY,
        PROVIDER_ERROR_CANARY,
        QUERY_CANARY,
        HEADER_CANARY,
    ]
    for hostile in hostiles:
        registry.record_alerts_processed(hostile)
        registry.record_ingest_rejection(hostile)
        registry.record_alert_scored(tier=hostile, decision=hostile, degraded=True)
        registry.record_enrichment_status(hostile)
        registry.record_enrichment_provider_outcome(provider=hostile, status="complete")
        registry.record_n8n_notification(hostile)
        registry.record_feedback(hostile)
        registry.record_incident_transition(from_status=hostile, to_status=hostile)
        registry.record_incident_auto_close(hostile)
        registry.record_sweeper_pass(hostile)
        registry.record_http_request(method="BREW", route=hostile, status_code=999)

    exposition = registry.render_text()
    _assert_canary_free(exposition, "direct registry")
    # Every hostile value collapsed to the bounded fallback (no new series).
    assert exposition.count(f'"{UNKNOWN}"') >= len(hostiles)


def test_scrape_token_failure_paths_do_not_leak_the_token(tmp_path) -> None:
    """Missing/malformed/wrong Bearer 401s never echo the configured token."""
    app = _canary_app(tmp_path)
    with TestClient(app) as client:
        _install_canary_pipeline(client)
        for headers in (
            {},
            {"Authorization": "Basic dXNlcjpwYXNz"},
            {"Authorization": f"Bearer wrong-{FETCH_TOKEN_CANARY}"},
            {"X-Metrics-Token": FETCH_TOKEN_CANARY},
        ):
            response = client.get("/metrics", headers=headers)
            assert response.status_code == 401
            assert FETCH_TOKEN_CANARY not in response.text
            assert CALLBACK_TOKEN_CANARY not in response.text
            assert API_KEY_CANARY not in response.text


def test_query_path_and_header_canaries_never_become_labels(tmp_path) -> None:
    """A hostile request path/query/header stays out of the exposition."""
    app = _canary_app(tmp_path)
    with TestClient(app) as client:
        _install_canary_pipeline(client)

        # Path canary against the alerts detail route (route template; the
        # identifier is rejected by path validation, never a label).
        response = client.get(
            f"/api/v1/alerts/{QUERY_CANARY}",
            headers={"X-N8N-Token": CALLBACK_TOKEN_CANARY},
        )
        assert response.status_code == 422
        response = client.get(
            "/api/v1/incidents?q=" + QUERY_CANARY,
            headers={"X-N8N-Token": CALLBACK_TOKEN_CANARY},
        )
        assert response.status_code == 200

        scrape = client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {FETCH_TOKEN_CANARY}"},
        )
        assert scrape.status_code == 200
        _assert_canary_free(scrape.text, "path/query/header")
        for label in _samples(app.state.metrics.registry)["soc_triage_http_requests"]:
            for name, value in label[1]:
                assert QUERY_CANARY not in value, (name, value)
                assert HEADER_CANARY not in value, (name, value)
