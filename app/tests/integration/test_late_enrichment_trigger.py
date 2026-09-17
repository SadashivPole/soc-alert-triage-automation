"""Phase 2.7A integration tests: the automatic late-enrichment trigger.

Covers the trigger contract against a real (temp) SQLite database:

* disabled by default (no sweep task; the ingest path is unaffected);
* lifespan start/stop when enabled;
* a new definitive verdict (late enrichment) re-scores the persisted alert
  exactly once, through the existing atomic ``persist_assessment`` path
  (``alert.scored`` / ``alert.decided`` with before/after snapshots);
* anti-spam: retried identical failures (fresh timestamps every attempt)
  never re-score — the fingerprint is timestamp-insensitive;
* cache-disabled live retry (``LATE_ENRICHMENT_SWEEP`` with response cache
  off: the sweep's provider retry is the observation surface);
* the real enrichment chain + real response cache as the observation
  surface (fully offline: cache hits only, zero outbound lookups in the
  sandbox — a +25 intel delta proves the cache path);
* incident reuse on late re-assessment (existing open incident attached,
  no second ``incident.created``);
* restart safety: a repeat sweep — and a fresh app instance on the same
  database — are strict no-ops (the persisted alert payload is the state);
* the ingest path is never blocked by a slow sweep pass (blocking work runs
  in a worker thread off the event loop).

The sweep is driven synchronously via ``sweep_once`` for determinism (same
strategy as the Phase 3.4 sweeper tests); the async periodic loop is
exercised by the lifespan start/stop test and the non-blocking test.

Scripted chains: where a test needs a specific enrichment history,
``app.state.enrichment_chain`` is rebound to a :class:`StatefulEnrichmentChain`
*before* ingest (the ingest endpoint resolves the chain per request from
``app.state``), so the persisted alert carries the scripted enrichment and
the sweep's fingerprint comparison is meaningful.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.session import session_scope
from soc_triage.enrichment import EnrichmentOutcome, EnrichmentStatus, extract_iocs
from soc_triage.enrichment.threat_intel import LookupRecord, LookupStatus
from soc_triage.ingest.normalizer import normalize_wazuh_alert
from soc_triage.ingest.schemas import WazuhAlert
from soc_triage.main import create_app
from soc_triage.models.ioc import IOC
from soc_triage.models.repositories import AlertRepository, AuditRepository, IncidentRepository
from soc_triage.services.late_enrichment import LateEnrichmentService
from soc_triage.services.late_enrichment_sweep import sweep_once

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}

TEST_LOOKBACK_SECONDS = 3600
TEST_INTERVAL_SECONDS = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings(db_url: str, *, enabled: bool = True, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "soc_env": "test",
        "soc_log_level": "INFO",
        "soc_instance_name": "soc-test",
        "triage_cors_origins": "http://localhost:8080",
        "triage_db_url": db_url,
        "triage_ingest_api_key": TEST_INGEST_KEY,
        "n8n_callback_token": TEST_CALLBACK_TOKEN,
        "n8n_webhook_token": "",
        "n8n_webhook_url": "",
        "triage_allowlist_path": "",
        "triage_asset_inventory_path": "",
        "late_enrichment_sweep_enabled": enabled,
        "late_enrichment_sweep_interval_seconds": TEST_INTERVAL_SECONDS,
        "late_enrichment_lookback_seconds": TEST_LOOKBACK_SECONDS,
    }
    base.update(overrides)
    return Settings(**base)


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _ingest(client: TestClient, name: str, *, event_id: str | None = None) -> dict[str, Any]:
    payload = _load_sample(name)
    if event_id is not None:
        payload = dict(payload, id=event_id)
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code == 202, response.text
    return response.json()


def _fixture_iocs(name: str) -> list[IOC]:
    """Extract the fixture's indicators without any network or app state."""
    wazuh = WazuhAlert.model_validate(_load_sample(name))
    canonical = normalize_wazuh_alert(wazuh, received_at=datetime.now(UTC))
    return extract_iocs(canonical)


def _service(client: TestClient, chain: Any) -> LateEnrichmentService:
    return LateEnrichmentService(chain, client.app.state.scorer, client.app.state.decider)


def _sweep(client: TestClient, chain: Any) -> dict[str, int]:
    """One deterministic sweep pass (real now, configured lookback)."""
    return sweep_once(
        client.app.state.session_factory,
        service=_service(client, chain),
        lookback_seconds=client.app.state.settings.late_enrichment_lookback_seconds,
    )


def _audits(client: TestClient) -> list[Any]:
    with session_scope(client.app.state.session_factory) as session:
        return AuditRepository(session).all()


def _incidents(client: TestClient) -> list[Any]:
    with session_scope(client.app.state.session_factory) as session:
        return IncidentRepository(session).all()


def _alert_row(client: TestClient, alert_id: UUID) -> Any:
    with session_scope(client.app.state.session_factory) as session:
        return AlertRepository(session).get_alert(alert_id)


def _scored_alerts(audits: list[Any], alert_id: UUID) -> list[Any]:
    return [e for e in audits if e.entity_id == str(alert_id) and e.action == "alert.scored"]


def _decided_alerts(audits: list[Any], alert_id: UUID) -> list[Any]:
    return [e for e in audits if e.entity_id == str(alert_id) and e.action == "alert.decided"]


def _vt_record(
    ioc: IOC, *, lookup_status: str, timestamp: str, malicious: int = 0
) -> dict[str, Any]:
    """A VirusTotal lookup record shaped like the provider's sanitized output."""
    return {
        "provider": "virustotal",
        "indicator_type": ioc.type.value,
        "lookup_status": lookup_status,
        "timestamp": timestamp,
        "result": (
            {
                "malicious": malicious,
                "suspicious": 0,
                "harmless": 3,
                "undetected": 7,
                "reputation": -10,
            }
            if lookup_status == "found"
            else {}
        ),
    }


class StatefulEnrichmentChain:
    """Deterministic enrichment chain with scripted per-call behavior.

    Each ``step`` is ``(chain, iocs) -> EnrichmentOutcome`` (the same result
    type the real chain returns, including the ``providers`` tuple the
    ingest metrics read).
    Calls advance through the steps in order; the last step repeats forever.
    Steps may record per-call timestamps on the chain (the anti-spam tests
    rely on failed lookups stamping a fresh timestamp on every call, like
    real provider retries do).
    """

    def __init__(self, steps: list[Callable[[StatefulEnrichmentChain, list[Any]], Any]]) -> None:
        self._steps = steps
        self.calls = 0
        self.timestamps: list[str] = []

    def enrich(self, iocs: list[Any], *, context: Any) -> Any:  # noqa: ARG002
        self.calls += 1
        step = self._steps[min(self.calls - 1, len(self._steps) - 1)]
        return step(self, iocs)


def _fail_step(chain: StatefulEnrichmentChain, iocs: list[Any]) -> Any:
    """Every lookup times out; the retry timestamp is fresh on each call."""
    timestamp = f"2026-09-17T{chain.calls:02d}:00:00+00:00"
    chain.timestamps.append(timestamp)
    out = [
        ioc.model_copy(
            update={
                "enrichment": {
                    "virustotal": _vt_record(ioc, lookup_status="timeout", timestamp=timestamp)
                }
            }
        )
        for ioc in iocs
    ]
    return EnrichmentOutcome(status=EnrichmentStatus.FAILED, iocs=tuple(out))


def _found_step(malicious: int = 10) -> Callable[[StatefulEnrichmentChain, list[Any]], Any]:
    def step(_chain: StatefulEnrichmentChain, iocs: list[Any]) -> Any:
        out = [
            ioc.model_copy(
                update={
                    "enrichment": {
                        "virustotal": _vt_record(
                            ioc,
                            lookup_status="found",
                            timestamp="2026-09-17T09:00:00+00:00",
                            malicious=malicious,
                        )
                    }
                }
            )
            for ioc in iocs
        ]
        return EnrichmentOutcome(status=EnrichmentStatus.COMPLETE, iocs=tuple(out))

    return step


def _cache_record(ioc: IOC, *, status: str, ts: datetime, malicious: int = 0) -> LookupRecord:
    return LookupRecord(
        provider="virustotal",
        indicator_type=ioc.type.value,
        lookup_status=LookupStatus(status),
        timestamp=ts.isoformat(),
        result=(
            {
                "malicious": malicious,
                "suspicious": 0,
                "harmless": 3,
                "undetected": 7,
                "reputation": -10,
            }
            if status == "found"
            else {}
        ),
    )


# ---------------------------------------------------------------------------
# Disabled by default + lifecycle
# ---------------------------------------------------------------------------


def test_disabled_by_default_no_sweep_task(client: TestClient) -> None:
    """Default settings: the service is bound but no sweep task exists, and
    the ingest pipeline is exactly as before Phase 2.7A."""
    assert client.app.state.late_enrichment_task is None
    assert isinstance(client.app.state.late_enrichment_service, LateEnrichmentService)

    first = _ingest(client, "16_ordinary_web_request.json")
    assert first["status"] == "accepted"
    assert first["risk"] is not None
    assert first["decision"] is not None
    assert first["enrichment_status"] == "skipped"  # no providers configured


def test_lifespan_starts_and_stops_sweep_task_when_enabled(db_url: str) -> None:
    """The background task is created at startup and cancelled at shutdown."""
    with TestClient(create_app(settings=_settings(db_url))) as client:
        task = client.app.state.late_enrichment_task
        assert task is not None
        assert not task.done()

    # After the TestClient context exits, the lifespan finally block has run.
    assert task.done()
    assert task.cancelled() or task.exception() is None


# ---------------------------------------------------------------------------
# The trigger: new definitive verdict → exactly one re-score
# ---------------------------------------------------------------------------


def test_new_definitive_verdict_triggers_exactly_one_rescore(db_url: str) -> None:
    """A verdict that arrived after the initial assessment re-scores the old
    alert exactly once, through the existing persist/audit/incident path."""
    with TestClient(create_app(settings=_settings(db_url))) as client:
        # Ingest uses the same scripted chain as the sweep: first delivery
        # fails enrichment (pre-intel 63/queue_l1), second (a distinct event
        # in the same dedupe group) already sees the verdict.
        chain = StatefulEnrichmentChain([_fail_step, _found_step()])
        client.app.state.enrichment_chain = chain

        first = _ingest(client, "03_wazuh_fim_etc_passwd_change.json", event_id="evt-late-a")
        assert first["risk"]["score"] == 63  # pre-intel golden (Phase 2.6)
        assert first["decision"]["action"] == "queue_l1"
        assert first["enrichment_status"] == "failed"
        assert first["incident_id"] is None

        second = _ingest(client, "03_wazuh_fim_etc_passwd_change.json", event_id="evt-late-b")
        assert second["alert_id"] != first["alert_id"]
        # 63 base + 25 intel (capped) + 5 complete enrichment.
        assert second["risk"]["score"] == 93
        assert second["decision"]["action"] == "open_incident"
        assert second["incident_id"] is not None

        alert_id = UUID(first["alert_id"])
        stats = _sweep(client, chain)
        assert stats == {"candidates": 2, "reassessed": 1, "unchanged": 1, "errors": 0}

        row = _alert_row(client, alert_id)
        assert row is not None
        assert row.canonical.risk is not None
        assert row.canonical.risk.score == 93
        assert row.canonical.decision is not None
        assert row.canonical.decision.action.value == "open_incident"
        assert row.incident_id == second["incident_id"]  # sibling's incident

        audits = _audits(client)
        created = [entry for entry in audits if entry.action == "alert.created"]
        scored = _scored_alerts(audits, alert_id)
        decided = _decided_alerts(audits, alert_id)
        # The sweep never creates a new alert, and re-scores exactly once.
        assert len(created) == 2
        assert len(scored) == 2
        assert len(decided) == 2
        assert scored[-1].before is not None
        assert scored[-1].before["score"] == 63
        assert scored[-1].after["score"] == 93
        assert decided[-1].before["action"] == "queue_l1"
        assert decided[-1].after["action"] == "open_incident"

        # The escalated alert reuses its sibling's open incident.
        incidents = _incidents(client)
        assert len(incidents) == 1
        assert incidents[0].incident_id == second["incident_id"]
        assert len([entry for entry in audits if entry.action == "incident.created"]) == 1

        # A further pass with the same verdict is a strict no-op.
        assert _sweep(client, chain) == {
            "candidates": 2,
            "reassessed": 0,
            "unchanged": 2,
            "errors": 0,
        }


# ---------------------------------------------------------------------------
# Idempotency / anti-spam
# ---------------------------------------------------------------------------


def test_repeated_failed_lookups_never_rescore(db_url: str) -> None:
    """Retried identical failures stamp a fresh timestamp on every attempt;
    the fingerprint treats them as 'no new information' — no re-score, no
    new audit rows, and the persisted payload stays byte-identical."""
    with TestClient(create_app(settings=_settings(db_url))) as client:
        chain = StatefulEnrichmentChain([_fail_step])
        client.app.state.enrichment_chain = chain

        first = _ingest(client, "01_wazuh_ssh_brute_force.json")
        assert first["enrichment_status"] == "failed"
        alert_id = UUID(first["alert_id"])
        payload_before = _alert_row(client, alert_id).canonical.model_dump(mode="json")

        stats1 = _sweep(client, chain)
        stats2 = _sweep(client, chain)
        assert stats1 == {"candidates": 1, "reassessed": 0, "unchanged": 1, "errors": 0}
        assert stats2 == stats1

        # Three lookups happened (ingest + two sweeps) with three distinct
        # failure timestamps — and still zero re-assessments.
        assert chain.calls == 3
        assert chain.timestamps == [
            "2026-09-17T01:00:00+00:00",
            "2026-09-17T02:00:00+00:00",
            "2026-09-17T03:00:00+00:00",
        ]

        row = _alert_row(client, alert_id)
        assert row.canonical.model_dump(mode="json") == payload_before
        audits = _audits(client)
        assert len([entry for entry in audits if entry.action == "alert.scored"]) == 1
        assert len([entry for entry in audits if entry.action == "alert.decided"]) == 1
        assert _incidents(client) == []


# ---------------------------------------------------------------------------
# Retry paths
# ---------------------------------------------------------------------------


def test_cache_disabled_live_retry(db_url: str) -> None:
    """With the response cache disabled, the sweep's live provider retry picks
    up the late verdict (ARCHITECTURE.md §7.3 background-retry guarantee)."""
    with TestClient(create_app(settings=_settings(db_url))) as client:
        assert client.app.state.enrichment_cache is None  # cache disabled (default)
        chain = StatefulEnrichmentChain([_fail_step, _found_step()])
        client.app.state.enrichment_chain = chain

        first = _ingest(client, "03_wazuh_fim_etc_passwd_change.json")
        assert first["risk"]["score"] == 63
        assert first["decision"]["action"] == "queue_l1"
        alert_id = UUID(first["alert_id"])

        stats = _sweep(client, chain)
        assert stats == {"candidates": 1, "reassessed": 1, "unchanged": 0, "errors": 0}

        row = _alert_row(client, alert_id)
        assert row.canonical.risk is not None
        assert row.canonical.risk.score == 93
        assert row.canonical.decision is not None
        assert row.canonical.decision.action.value == "open_incident"
        assert row.incident_id is not None
        assert len(_incidents(client)) == 1

        # Next pass: the verdict is already applied — strict no-op.
        assert _sweep(client, chain) == {
            "candidates": 1,
            "reassessed": 0,
            "unchanged": 1,
            "errors": 0,
        }


def test_real_chain_and_cache_are_the_observation_surface(db_url: str) -> None:
    """A refreshed cache verdict, served cache-first by the real provider,
    re-scores the old alert — fully offline (zero outbound lookups in the
    sandbox: any live lookup would have failed, and the +25 would not appear).

    The periodic task is left disabled here on purpose: this test drives one
    deterministic pass with the real chain as the observation surface (the
    loop's lifecycle and threading are covered by dedicated tests).
    """
    with TestClient(
        create_app(
            settings=_settings(
                db_url,
                enabled=False,
                virustotal_api_key="vt-lab-key-not-a-real-secret",
                triage_enrichment_cache_enabled=True,
            )
        )
    ) as client:
        cache = client.app.state.enrichment_cache
        assert cache is not None
        assert client.app.state.late_enrichment_task is None

        iocs = _fixture_iocs("04_wazuh_malware_hash_virustotal.json")
        assert iocs

        # Earlier lookups (a prior alert) answered not_found and are cached.
        t0 = datetime(2026, 9, 17, 10, 0, 0, tzinfo=UTC)
        for ioc in iocs:
            cache.put("virustotal", ioc, _cache_record(ioc, status="not_found", ts=t0), now=t0)

        first = _ingest(client, "04_wazuh_malware_hash_virustotal.json")
        alert_id = UUID(first["alert_id"])
        score_before = first["risk"]["score"]
        # Level-12 rule: an incident opens regardless of intel.
        assert first["decision"]["action"] == "open_incident"
        incident_before = first["incident_id"]
        assert incident_before is not None
        # Cache hits only — the provider made no outbound call.
        assert first["enrichment_status"] == "complete"

        # A later lookup (e.g. a repeat alert) refreshes the verdict to found.
        t1 = datetime(2026, 9, 17, 11, 0, 0, tzinfo=UTC)
        for ioc in iocs:
            cache.put(
                "virustotal", ioc, _cache_record(ioc, status="found", ts=t1, malicious=10), now=t1
            )

        service = LateEnrichmentService(
            client.app.state.enrichment_chain,  # the real chain (real VT provider)
            client.app.state.scorer,
            client.app.state.decider,
        )
        stats = sweep_once(
            client.app.state.session_factory,
            service=service,
            lookback_seconds=client.app.state.settings.late_enrichment_lookback_seconds,
        )
        assert stats == {"candidates": 1, "reassessed": 1, "unchanged": 0, "errors": 0}

        row = _alert_row(client, alert_id)
        assert row.canonical.risk is not None
        assert row.incident_id == incident_before  # same incident reused
        assert len(_incidents(client)) == 1

        audits = _audits(client)
        scored = _scored_alerts(audits, alert_id)
        assert len(scored) == 2
        assert scored[-1].before["score"] == score_before
        # The intel factor moved from 0 to the 25-point cap (three hash
        # awards of 15 each); the total score rises by that delta unless
        # the overall 100 clamp engages (fixture 04's high base score).
        assert scored[-1].before["factors"]["threat_intel"] == 0
        assert scored[-1].after["factors"]["threat_intel"] == 25
        assert scored[-1].after["score"] == min(100, score_before + 25)
        assert row.canonical.risk.score > score_before

        # And the refreshed verdict is now the persisted state: a repeat pass
        # (even through the app's own service, real chain + cache) no-ops.
        assert sweep_once(
            client.app.state.session_factory,
            service=client.app.state.late_enrichment_service,
            lookback_seconds=client.app.state.settings.late_enrichment_lookback_seconds,
        ) == {"candidates": 1, "reassessed": 0, "unchanged": 1, "errors": 0}


# ---------------------------------------------------------------------------
# Incident semantics
# ---------------------------------------------------------------------------


def test_late_rescore_reuses_existing_open_incident(db_url: str) -> None:
    """A re-score that stays ``open_incident`` attaches to the existing open
    incident — no second incident, no second ``incident.created``."""
    with TestClient(create_app(settings=_settings(db_url))) as client:
        # Both states are definitive verdicts; the malicious counts cross the
        # award cap boundary (0 -> 4*15 capped at 25), so the score strictly
        # rises while the decision stays open_incident.
        chain = StatefulEnrichmentChain([_found_step(malicious=0), _found_step(malicious=10)])
        client.app.state.enrichment_chain = chain

        first = _ingest(client, "04_wazuh_malware_hash_virustotal.json")
        assert first["decision"]["action"] == "open_incident"
        incident_id = first["incident_id"]
        assert incident_id is not None
        alert_id = UUID(first["alert_id"])
        score_before = first["risk"]["score"]

        stats = _sweep(client, chain)
        assert stats == {"candidates": 1, "reassessed": 1, "unchanged": 0, "errors": 0}

        row = _alert_row(client, alert_id)
        assert row.canonical.risk is not None
        assert row.canonical.decision is not None
        assert row.canonical.decision.action.value == "open_incident"
        assert row.incident_id == incident_id  # attached, not re-created

        assert len(_incidents(client)) == 1
        audits = _audits(client)
        assert len([entry for entry in audits if entry.action == "incident.created"]) == 1
        scored = _scored_alerts(audits, alert_id)
        assert len(scored) == 2
        # The intel factor crossed the cap boundary (0 -> 25); the decision
        # stays open_incident, so the existing incident is reused.
        assert scored[-1].before["factors"]["threat_intel"] == 0
        assert scored[-1].after["factors"]["threat_intel"] == 25
        assert scored[-1].after["score"] > score_before

        # Same verdict again — strict no-op.
        assert _sweep(client, chain) == {
            "candidates": 1,
            "reassessed": 0,
            "unchanged": 1,
            "errors": 0,
        }


# ---------------------------------------------------------------------------
# Restart safety
# ---------------------------------------------------------------------------


def test_repeat_and_restart_sweeps_are_strict_noops(db_url: str) -> None:
    """All state lives in the persisted alert payload: a repeat sweep — and a
    fresh app instance (restart) on the same database — re-derive candidates
    and no-op, adding no audit rows and no incidents."""
    with TestClient(create_app(settings=_settings(db_url))) as client_a:
        chain = StatefulEnrichmentChain([_fail_step, _found_step()])
        client_a.app.state.enrichment_chain = chain
        first = _ingest(client_a, "03_wazuh_fim_etc_passwd_change.json")
        alert_id = UUID(first["alert_id"])

        stats = _sweep(client_a, chain)
        assert stats == {"candidates": 1, "reassessed": 1, "unchanged": 0, "errors": 0}
        scored_after_pass = len(
            [entry for entry in _audits(client_a) if entry.action == "alert.scored"]
        )
        incidents_after_pass = len(_incidents(client_a))
        assert scored_after_pass == 2
        assert incidents_after_pass == 1

    # "Crash + restart": a fresh application instance on the same database.
    with TestClient(create_app(settings=_settings(db_url))) as client_b:
        chain_b = StatefulEnrichmentChain([_found_step()])
        stats = _sweep(client_b, chain_b)
        assert stats == {"candidates": 1, "reassessed": 0, "unchanged": 1, "errors": 0}
        assert len(_scored_alerts(_audits(client_b), alert_id)) == 2
        assert len([entry for entry in _audits(client_b) if entry.action == "alert.scored"]) == (
            scored_after_pass
        )
        assert len(_incidents(client_b)) == incidents_after_pass


# ---------------------------------------------------------------------------
# Ingest isolation
# ---------------------------------------------------------------------------


def test_ingest_not_blocked_by_slow_sweep_pass(db_url: str) -> None:
    """A sweep pass parked inside enrichment (worker thread) must not block
    the API: while the sweep is still in flight, the event loop still serves
    requests promptly (blocking work runs via asyncio.to_thread)."""
    with TestClient(create_app(settings=_settings(db_url))) as client:
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        class SlowChain:
            """Enrichment that parks inside ``enrich`` until released."""

            def enrich(self, iocs: list[Any], *, context: Any) -> Any:  # noqa: ARG002
                entered.set()
                release.wait(timeout=10)
                finished.set()
                # No new information: the persisted enrichment is unchanged.
                return EnrichmentOutcome(status=EnrichmentStatus.COMPLETE, iocs=tuple(iocs))

        # The loop resolves the service from app.state per pass — rebind it
        # so the next periodic pass parks inside enrichment.
        client.app.state.late_enrichment_service = LateEnrichmentService(
            SlowChain(),
            client.app.state.scorer,
            client.app.state.decider,
        )

        # Create a sweep candidate; the periodic pass (interval 1s) will pick
        # it up and enter the slow enrichment.
        response = client.post(
            "/api/v1/alerts/ingest",
            json=_load_sample("16_ordinary_web_request.json"),
            headers=AUTH_HEADERS,
        )
        assert response.status_code == 202, response.text

        assert entered.wait(timeout=10), "sweep pass never entered the chain"

        # The sweep thread is still inside enrichment while the event loop
        # serves a request promptly: the sweep runs off the event loop.
        started = time.monotonic()
        health = client.get("/health")
        elapsed = time.monotonic() - started
        assert health.status_code == 200
        assert elapsed < 5
        assert not finished.is_set()

        release.set()
        assert finished.wait(timeout=10)
