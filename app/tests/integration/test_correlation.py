"""Phase 6.4 integration tests: cross-alert correlation end-to-end.

Drives the real pipeline (ingest → dedupe → score → persist → correlate)
against a temp SQLite database through the application's normal startup
path, then asserts on the persisted contexts and the read-only correlation
API. Deterministic FakeClock throughout — no sleeping.

Scenario matrix (DEVELOPMENT_PLAN.md 6.4):

* A  exact duplicate      → no new context, no new membership (idempotent echo)
* B  same rule+agent      → recurrence; dedupe unchanged; correlation distinct
* C  different rule+agent → correlates only when the evidence policy permits
* D  different rule+agent, shared IOC → correlates through the indicator
* E  same host outside the window → no correlation (boundary inclusive)
* F  shared IOC outside the window  → no correlation
* G  no supported shared evidence   → no correlation
* H  multiple evidence     → deterministic evidence list and ordering
* I  duplicate delivery    → no duplicate membership (service idempotency)
* J  cross-context isolation; evidence-driven merge keeps one context
* K  persistence           → contexts survive an application restart
* L  API                   → read-only, deterministic, authenticated
* M  security              → no full_log/secrets/credentials in responses
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.session import session_scope
from soc_triage.main import create_app
from soc_triage.models.repositories import AuditRepository, DedupeStateRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
READ_HEADERS = {"X-N8N-Token": TEST_CALLBACK_TOKEN}

CONTEXT_ID_RE = re.compile(r"^CORR-\d{4}-\d{2}-\d{2}-\d{4}$")

SHA_A = "23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f"
SHA_B = "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7081"


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _ingest(client: TestClient, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _synthetic(
    *,
    event_id: str,
    rule_id: str,
    rule_level: int = 5,
    agent_id: str,
    agent_name: str = "synthetic-host",
    mitre_ids: list[str] | None = None,
    srcip: str | None = None,
    dstip: str | None = None,
    sha256: str | None = None,
    full_log: str | None = None,
) -> dict[str, Any]:
    """A minimal valid Wazuh alert with exactly the evidence knobs tests need."""
    data: dict[str, Any] = {}
    if srcip is not None:
        data["srcip"] = srcip
    if dstip is not None:
        data["dstip"] = dstip
    if sha256 is not None:
        data["virustotal"] = {"found": "1", "sha256": sha256}
    rule: dict[str, Any] = {
        "id": rule_id,
        "level": rule_level,
        "description": f"synthetic rule {rule_id}",
    }
    if mitre_ids is not None:
        rule["mitre"] = {"id": mitre_ids}
    payload: dict[str, Any] = {
        "id": event_id,
        "rule": rule,
        "agent": {"id": agent_id, "name": agent_name},
        "location": "/var/log/synthetic.log",
    }
    if data:
        payload["data"] = data
    if full_log is not None:
        payload["full_log"] = full_log
    return payload


class FakeClock:
    """Deterministic clock (no real sleeping)."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, *, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    fake = FakeClock(datetime(2026, 8, 29, 10, 0, 0, tzinfo=UTC))
    monkeypatch.setattr("soc_triage.api.alerts._utc_now", fake.now)
    return fake


def _correlation_rows(client: TestClient) -> list[tuple[str, str]]:
    """Raw (context_id, alert_id) membership rows, deterministically ordered."""
    with client.app.state.db_engine.connect() as conn:
        return [
            (row[0], row[1])
            for row in conn.execute(
                text(
                    "SELECT cm.context_id, CAST(cm.alert_id AS TEXT) "
                    "FROM correlation_members cm ORDER BY cm.context_id, cm.id"
                )
            ).fetchall()
        ]


def _context_ids(client: TestClient) -> list[str]:
    with client.app.state.db_engine.connect() as conn:
        return [
            row[0]
            for row in conn.execute(
                text("SELECT context_id FROM correlation_contexts ORDER BY context_id")
            ).fetchall()
        ]


def _detail(client: TestClient, context_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/correlations/{context_id}", headers=READ_HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def _list_contexts(client: TestClient) -> dict[str, Any]:
    response = client.get("/api/v1/correlations", headers=READ_HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# A / I — duplicates never create or duplicate correlation state
# ---------------------------------------------------------------------------


def test_exact_duplicate_never_creates_or_extends_a_context(
    client: TestClient, clock: FakeClock
) -> None:
    first = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert first["correlation_context_id"] is None  # nothing to correlate yet
    clock.advance(seconds=10)
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    context_id = second["correlation_context_id"]
    assert context_id is not None and CONTEXT_ID_RE.match(context_id)
    assert _detail(client, context_id)["member_count"] == 2

    # Exact re-delivery of the first payload: idempotent echo, no new state.
    clock.advance(seconds=10)
    duplicate = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    assert duplicate["duplicate"] is True
    assert duplicate["alert_id"] == first["alert_id"]
    # The original alert's membership is echoed, never re-created.
    assert duplicate["correlation_context_id"] == context_id
    assert _detail(client, context_id)["member_count"] == 2
    assert len(_correlation_rows(client)) == 2
    assert _context_ids(client) == [context_id]


def test_repeated_correlate_calls_are_idempotent(client: TestClient, clock: FakeClock) -> None:
    _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    clock.advance(seconds=10)
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    context_id = second["correlation_context_id"]
    assert context_id is not None

    # Re-running the correlation step for an already-member alert is a no-op.
    correlator = client.app.state.correlator
    result = correlator.correlate(alert_id=UUID(second["alert_id"]), received_at=clock.now())
    assert result is None
    assert len(_correlation_rows(client)) == 2
    assert _detail(client, context_id)["member_count"] == 2


# ---------------------------------------------------------------------------
# B — recurrence stays dedupe; correlation stays correlation
# ---------------------------------------------------------------------------


def test_recurrence_remains_dedupe_and_never_becomes_correlation(
    client: TestClient, clock: FakeClock
) -> None:
    base = _load_sample("01_wazuh_ssh_brute_force.json")
    first = _ingest(client, base)
    clock.advance(seconds=30)
    repeated = _ingest(client, dict(base, id="1770000000.999001"))

    # Dedupe/recurrence behavior is unchanged.
    assert repeated["dedupe_status"] == "repeated"
    assert repeated["dedupe"]["occurrences"] == 2
    assert repeated["dedupe"]["group_key"] == "wazuh:5710:001"
    # Same rule+agent recurrence never creates a correlation context:
    # that relationship is already expressed by the dedupe group.
    assert first["correlation_context_id"] is None
    assert repeated["correlation_context_id"] is None
    assert _context_ids(client) == []
    assert len(_correlation_rows(client)) == 0

    # The recurrence alert is still a distinct alert of record.
    assert repeated["alert_id"] != first["alert_id"]


def test_recurrence_sibling_joins_context_only_through_shared_evidence(
    client: TestClient, clock: FakeClock
) -> None:
    """Correlation adds context for a recurrence only via another distinct alert."""
    base = _load_sample("01_wazuh_ssh_brute_force.json")
    _ingest(client, base)
    clock.advance(seconds=10)
    _ingest(client, dict(base, id="1770000000.999002"))  # recurrence sibling
    clock.advance(seconds=10)
    success = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))

    context_id = success["correlation_context_id"]
    assert context_id is not None
    detail = _detail(client, context_id)
    # The context contains the two distinct brute-force events (both share the
    # source IP with the success event) — each membership is evidence-backed.
    assert detail["member_count"] == 3
    groups = {member["dedupe_group_key"] for member in detail["members"]}
    assert groups == {"wazuh:5710:001", "wazuh:5715:001"}
    # Dedupe state is untouched by any of this.
    with session_scope(client.app.state.session_factory) as session:
        state = DedupeStateRepository(session).group_state("wazuh:5710:001")
        assert state is not None
        assert state.occurrences == 2


# ---------------------------------------------------------------------------
# C — different rule + same agent: policy-gated
# ---------------------------------------------------------------------------


def test_same_agent_plus_shared_technique_correlates(client: TestClient, clock: FakeClock) -> None:
    a = _synthetic(
        event_id="1770000000.200001",
        rule_id="5710",
        agent_id="001",
        mitre_ids=["T1110"],
    )
    b = _synthetic(
        event_id="1770000000.200002",
        rule_id="5719",
        agent_id="001",
        mitre_ids=["T1110"],
    )
    _ingest(client, a)
    clock.advance(seconds=10)
    second = _ingest(client, b)

    context_id = second["correlation_context_id"]
    assert context_id is not None
    detail = _detail(client, context_id)
    evidence_types = [item["evidence_type"] for item in detail["evidence"]]
    assert evidence_types == ["same_agent", "shared_technique"]
    assert [item["reason"] for item in detail["evidence"]] == [
        "same agent 001",
        "shared MITRE ATT&CK technique T1110",
    ]


def test_same_agent_alone_never_correlates(client: TestClient, clock: FakeClock) -> None:
    """Agent-only correlation is deliberately insufficient (noise guard)."""
    _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))  # agent 001, T1110, .50
    clock.advance(seconds=10)
    # Same agent, different rule, different technique, different source IP.
    sqli = _ingest(client, _load_sample("05_wazuh_web_sql_injection.json"))  # agent 001, T1190, .77
    assert sqli["correlation_context_id"] is None
    assert _context_ids(client) == []


# ---------------------------------------------------------------------------
# D — different rule + different agent, shared IOC
# ---------------------------------------------------------------------------


def test_shared_hash_across_different_rule_and_agent_correlates(
    client: TestClient, clock: FakeClock
) -> None:
    a = _synthetic(event_id="1770000000.300001", rule_id="550", agent_id="002", sha256=SHA_A)
    b = _synthetic(event_id="1770000000.300002", rule_id="87105", agent_id="003", sha256=SHA_A)
    _ingest(client, a)
    clock.advance(seconds=10)
    second = _ingest(client, b)

    context_id = second["correlation_context_id"]
    assert context_id is not None
    detail = _detail(client, context_id)
    assert detail["member_count"] == 2
    shared = [item for item in detail["evidence"] if item["evidence_type"] == "shared_ioc"]
    assert shared == [
        {
            "evidence_type": "shared_ioc",
            "value": f"sha256:{SHA_A}",
            "reason": f"shared indicator sha256:{SHA_A}",
            "related_alert_ids": sorted(m["alert_id"] for m in detail["members"]),
            "first_seen": detail["first_seen"],
            "last_seen": detail["last_seen"],
        }
    ]


def test_same_rule_different_agents_with_shared_source_ip_correlates(
    client: TestClient, clock: FakeClock
) -> None:
    _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))  # 5710 / agent 001
    clock.advance(seconds=10)
    spread = _ingest(
        client, _load_sample("07_wazuh_ssh_brute_force_recurrence.json")
    )  # 5710 / agent 005

    context_id = spread["correlation_context_id"]
    assert context_id is not None
    detail = _detail(client, context_id)
    evidence_types = [item["evidence_type"] for item in detail["evidence"]]
    # Same detection on two hosts from one source IP: the rule, the technique
    # it maps to, and the source IP itself are all shared, all explainable.
    assert evidence_types == ["same_rule", "shared_technique", "shared_source_ip"]
    assert detail["evidence"][2]["value"] == "203.0.113.50"


def test_destination_ip_evidence_correlates(client: TestClient, clock: FakeClock) -> None:
    a = _synthetic(
        event_id="1770000000.310001", rule_id="100", agent_id="001", dstip="198.51.100.9"
    )
    b = _synthetic(
        event_id="1770000000.310002", rule_id="200", agent_id="002", dstip="198.51.100.9"
    )
    _ingest(client, a)
    clock.advance(seconds=10)
    second = _ingest(client, b)
    assert second["correlation_context_id"] is not None
    detail = _detail(client, second["correlation_context_id"])
    assert [item["evidence_type"] for item in detail["evidence"]] == ["shared_destination_ip"]


# ---------------------------------------------------------------------------
# E / F — window boundaries (inclusive at the boundary, out past it)
# ---------------------------------------------------------------------------


def test_same_host_outside_correlation_window_does_not_correlate(
    client: TestClient, clock: FakeClock
) -> None:
    _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    clock.advance(seconds=901)  # default window is 900 s
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    assert second["correlation_context_id"] is None
    assert _context_ids(client) == []


def test_window_boundary_is_inclusive(client: TestClient, clock: FakeClock) -> None:
    _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    clock.advance(seconds=900)  # exactly at the window edge
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    assert second["correlation_context_id"] is not None


def test_shared_ioc_outside_correlation_window_does_not_correlate(
    client: TestClient, clock: FakeClock
) -> None:
    _ingest(
        client,
        _synthetic(event_id="1770000000.320001", rule_id="550", agent_id="002", sha256=SHA_B),
    )
    clock.advance(seconds=901)
    second = _ingest(
        client,
        _synthetic(event_id="1770000000.320002", rule_id="87105", agent_id="003", sha256=SHA_B),
    )
    assert second["correlation_context_id"] is None
    assert _context_ids(client) == []


def test_correlation_window_is_independently_configurable(db_url: str) -> None:
    """TRIAGE_CORRELATION_WINDOW_SECONDS is its own knob, not the dedupe window."""
    settings = Settings(
        soc_env="test",
        soc_log_level="WARNING",
        triage_db_url=db_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        triage_correlation_window_seconds=60,
    )
    app = create_app(settings=settings)
    fake = FakeClock(datetime(2026, 8, 29, 10, 0, 0, tzinfo=UTC))
    with TestClient(app) as client, pytest.MonkeyPatch().context() as monkeypatch:
        monkeypatch.setattr("soc_triage.api.alerts._utc_now", fake.now)
        # 61 s apart: outside the 60 s correlation window → no context.
        _ingest(
            client,
            _synthetic(event_id="1770000000.400001", rule_id="100", agent_id="001", sha256=SHA_B),
        )
        fake.advance(seconds=61)
        second = _ingest(
            client,
            _synthetic(event_id="1770000000.400002", rule_id="200", agent_id="002", sha256=SHA_B),
        )
        assert second["correlation_context_id"] is None

        # A different pair 59 s apart (inside the window) correlates — proving
        # the knob bounds correlation without touching the 900 s dedupe window.
        fake.advance(seconds=100)
        _ingest(
            client,
            _synthetic(
                event_id="1770000000.400003", rule_id="300", agent_id="003", srcip="203.0.113.70"
            ),
        )
        fake.advance(seconds=59)
        fourth = _ingest(
            client,
            _synthetic(
                event_id="1770000000.400004", rule_id="400", agent_id="004", srcip="203.0.113.70"
            ),
        )
        assert fourth["correlation_context_id"] is not None


# ---------------------------------------------------------------------------
# G — no supported shared evidence
# ---------------------------------------------------------------------------


def test_unrelated_alerts_never_correlate(client: TestClient, clock: FakeClock) -> None:
    _ingest(client, _load_sample("03_wazuh_fim_etc_passwd_change.json"))  # rule 550 / agent 002
    clock.advance(seconds=10)
    second = _ingest(
        client, _load_sample("06_wazuh_windows_user_created.json")
    )  # 60180 / agent 004
    assert second["correlation_context_id"] is None
    assert _context_ids(client) == []
    # The uncorrelated alert has no context on the nested endpoint either.
    response = client.get(f"/api/v1/alerts/{second['alert_id']}/correlation", headers=READ_HEADERS)
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# H — multiple evidence, deterministic ordering
# ---------------------------------------------------------------------------


def test_multiple_evidence_is_deterministic_and_explainable(
    client: TestClient, clock: FakeClock
) -> None:
    first = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    clock.advance(seconds=10)
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    context_id = second["correlation_context_id"]
    assert context_id is not None

    detail = _detail(client, context_id)
    # Aggregated evidence: fixed type order, then value; members oldest-first.
    assert [item["evidence_type"] for item in detail["evidence"]] == [
        "same_agent",
        "shared_source_ip",
    ]
    assert detail["members"][0]["alert_id"] == first["alert_id"]
    assert detail["members"][1]["alert_id"] == second["alert_id"]
    # Each member's pairwise evidence names its peer and a human reason.
    for member in detail["members"]:
        peers = {item["peer_alert_id"] for item in member["evidence"]}
        assert peers == {first["alert_id"], second["alert_id"]} - {member["alert_id"]}
        for item in member["evidence"]:
            assert item["reason"]
    # Aggregated evidence relates both alerts and spans their reception times.
    for item in detail["evidence"]:
        assert item["related_alert_ids"] == sorted([first["alert_id"], second["alert_id"]])
        assert item["first_seen"] == detail["first_seen"]
        assert item["last_seen"] == detail["last_seen"]


# ---------------------------------------------------------------------------
# J — cross-context isolation + evidence-driven merge
# ---------------------------------------------------------------------------


def test_unrelated_contexts_stay_isolated(client: TestClient, clock: FakeClock) -> None:
    # Context 1: brute force → success (shared source IP 203.0.113.50).
    _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    clock.advance(seconds=10)
    _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    # Context 2: same SQL injection detection on two agents (198.51.100.77).
    clock.advance(seconds=10)
    _ingest(client, _load_sample("05_wazuh_web_sql_injection.json"))  # agent 001
    clock.advance(seconds=10)
    sqli_b = _ingest(client, _load_sample("10_wazuh_web_sql_injection_staging.json"))  # agent 007

    contexts = _list_contexts(client)["items"]
    assert len(contexts) == 2
    assert {item["member_count"] for item in contexts} == {2}
    # No overlap: the SQL-injection pair never touches the SSH pair even
    # though one alert shares an agent with them (agent alone is insufficient).
    detail = _detail(client, sqli_b["correlation_context_id"])
    assert {member["rule_id"] for member in detail["members"]} == {"31103"}


def test_bridging_alert_merges_contexts_deterministically(
    client: TestClient, clock: FakeClock
) -> None:
    # Context 1: shared source IP.
    a = _ingest(
        client,
        _synthetic(
            event_id="1770000000.500001", rule_id="100", agent_id="001", srcip="203.0.113.60"
        ),
    )
    clock.advance(seconds=10)
    b = _ingest(
        client,
        _synthetic(
            event_id="1770000000.500002", rule_id="200", agent_id="002", srcip="203.0.113.60"
        ),
    )
    ctx1 = b["correlation_context_id"]
    assert ctx1 is not None and a["correlation_context_id"] is None
    # Context 2: shared hash.
    clock.advance(seconds=10)
    c = _ingest(
        client,
        _synthetic(event_id="1770000000.500003", rule_id="300", agent_id="003", sha256=SHA_A),
    )
    clock.advance(seconds=10)
    d = _ingest(
        client,
        _synthetic(event_id="1770000000.500004", rule_id="400", agent_id="004", sha256=SHA_A),
    )
    ctx2 = d["correlation_context_id"]
    assert ctx2 is not None and ctx2 != ctx1
    assert c["correlation_context_id"] is None

    # Bridge alert: shares the source IP with ctx1 members AND the hash with
    # ctx2 members — within the window of both.
    clock.advance(seconds=10)
    bridge = _ingest(
        client,
        _synthetic(
            event_id="1770000000.500005",
            rule_id="500",
            agent_id="005",
            srcip="203.0.113.60",
            sha256=SHA_A,
        ),
    )
    merged = bridge["correlation_context_id"]
    # Deterministic: the earlier-created context wins.
    assert merged == ctx1
    assert _context_ids(client) == [ctx1]
    detail = _detail(client, merged)
    assert detail["member_count"] == 5
    # The absorbed context is gone (404), never silently queryable.
    assert client.get(f"/api/v1/correlations/{ctx2}", headers=READ_HEADERS).status_code == 404
    # The merge is audited.
    with session_scope(client.app.state.session_factory) as session:
        merged_entries = [
            entry
            for entry in AuditRepository(session).all()
            if entry.action == "correlation.contexts_merged"
        ]
    assert len(merged_entries) == 1
    assert merged_entries[0].after == {
        "kept_context_id": ctx1,
        "merged_context_id": ctx2,
        "bridge_alert_id": bridge["alert_id"],
    }


# ---------------------------------------------------------------------------
# K — persistence across restart
# ---------------------------------------------------------------------------


def test_correlation_contexts_survive_application_restart(db_url: str) -> None:
    def make_app() -> TestClient:
        settings = Settings(
            soc_env="test",
            soc_log_level="WARNING",
            triage_db_url=db_url,
            triage_ingest_api_key=TEST_INGEST_KEY,
            n8n_callback_token=TEST_CALLBACK_TOKEN,
        )
        return TestClient(create_app(settings=settings))

    with make_app() as client:
        fake = FakeClock(datetime(2026, 8, 29, 11, 0, 0, tzinfo=UTC))
        with pytest.MonkeyPatch().context() as monkeypatch:
            monkeypatch.setattr("soc_triage.api.alerts._utc_now", fake.now)
            _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
            fake.advance(seconds=10)
            second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
        context_id = second["correlation_context_id"]
        assert context_id is not None

    # A brand-new application instance over the same database sees the
    # context exactly as it was persisted.
    with make_app() as client:
        listed = _list_contexts(client)["items"]
        assert [item["context_id"] for item in listed] == [context_id]
        detail = _detail(client, context_id)
        assert detail["member_count"] == 2
        response = client.get(
            f"/api/v1/alerts/{second['alert_id']}/correlation", headers=READ_HEADERS
        )
        assert response.status_code == 200
        assert response.json()["context_id"] == context_id

        # And correlation continues into the restored context.
        fake = FakeClock(datetime(2026, 8, 29, 11, 5, 0, tzinfo=UTC))
        with pytest.MonkeyPatch().context() as monkeypatch:
            monkeypatch.setattr("soc_triage.api.alerts._utc_now", fake.now)
            third = _ingest(
                client,
                _synthetic(
                    event_id="1770000000.600003",
                    rule_id="600",
                    agent_id="009",
                    srcip="203.0.113.50",
                ),
            )
        assert third["correlation_context_id"] == context_id
        assert _detail(client, context_id)["member_count"] == 3


# ---------------------------------------------------------------------------
# L — API surface
# ---------------------------------------------------------------------------


def test_correlation_api_is_read_only_authenticated_and_deterministic(
    client: TestClient, clock: FakeClock
) -> None:
    _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    clock.advance(seconds=10)
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    context_id = second["correlation_context_id"]

    # Auth is required (same shared-token channel as the other read APIs).
    assert client.get("/api/v1/correlations").status_code == 401
    assert client.get(f"/api/v1/correlations/{context_id}", headers={}).status_code == 401
    assert client.get(f"/api/v1/alerts/{second['alert_id']}/correlation").status_code == 401

    # List is paginated and newest-first.
    listed = _list_contexts(client)
    assert listed["pagination"]["total"] == 1
    assert listed["items"][0]["context_id"] == context_id
    assert listed["items"][0]["member_count"] == 2

    # Unknown ids return structured 404s.
    missing = client.get("/api/v1/correlations/CORR-1999-01-01-9999", headers=READ_HEADERS)
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"

    # GET never appends audit rows (read-only, like the other read APIs).
    with session_scope(client.app.state.session_factory) as session:
        before = len(AuditRepository(session).all())
    _list_contexts(client)
    _detail(client, context_id)
    client.get(f"/api/v1/alerts/{second['alert_id']}/correlation", headers=READ_HEADERS)
    with session_scope(client.app.state.session_factory) as session:
        after = len(AuditRepository(session).all())
    assert after == before


# ---------------------------------------------------------------------------
# M — security: no raw logs / secrets in the correlation surface
# ---------------------------------------------------------------------------


def test_correlation_api_never_exposes_full_log_or_secrets(
    client: TestClient, clock: FakeClock
) -> None:
    secret_password = "hunter2-super-secret-password"
    secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.fake"
    payload_a = _synthetic(
        event_id="1770000000.700001",
        rule_id="100",
        agent_id="001",
        srcip="203.0.113.90",
        full_log=f"sshd[1234]: Failed password for root from 203.0.113.90 password={secret_password} token={secret_token}",
    )
    payload_b = _synthetic(
        event_id="1770000000.700002",
        rule_id="200",
        agent_id="002",
        srcip="203.0.113.90",
        full_log="sshd[1235]: Failed password for root from 203.0.113.90",
    )
    _ingest(client, payload_a)
    clock.advance(seconds=10)
    second = _ingest(client, payload_b)
    context_id = second["correlation_context_id"]
    assert context_id is not None

    for path in (
        "/api/v1/correlations",
        f"/api/v1/correlations/{context_id}",
        f"/api/v1/alerts/{second['alert_id']}/correlation",
    ):
        body = client.get(path, headers=READ_HEADERS).text
        assert "full_log" not in body
        assert secret_password not in body
        assert secret_token not in body
        assert "password" not in body.lower()

    # The evidence surface carries only normalized indicators and ids.
    detail = _detail(client, context_id)
    assert [item["value"] for item in detail["evidence"]] == ["203.0.113.90"]


# ---------------------------------------------------------------------------
# Regression protection — dedupe / incidents / distinct alerts
# ---------------------------------------------------------------------------


def test_dedupe_recurrence_counters_unchanged_by_correlation(
    client: TestClient, clock: FakeClock
) -> None:
    base = _load_sample("01_wazuh_ssh_brute_force.json")
    _ingest(client, base)
    clock.advance(seconds=10)
    _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))  # context forms
    clock.advance(seconds=10)
    recurrence = _ingest(client, dict(base, id="1770000000.800003"))

    # Recurrence semantics are exactly the Phase 1C/1D contract.
    assert recurrence["dedupe_status"] == "repeated"
    assert recurrence["dedupe"]["occurrences"] == 2
    assert recurrence["dedupe"]["generation"] == 1
    assert recurrence["dedupe"]["duplicate_deliveries"] == 0
    # A duplicate delivery still only bumps delivery counters.
    clock.advance(seconds=5)
    duplicate = _ingest(client, dict(base, id="1770000000.800003"))
    assert duplicate["duplicate"] is True
    assert duplicate["dedupe"]["occurrences"] == 2  # never inflated by duplicates


def test_incidents_remain_independent_of_correlation_contexts(
    client: TestClient, clock: FakeClock
) -> None:
    # Two critical alerts on different agents sharing the same malware hash:
    # correlated into one context, but each keeps its own incident.
    first = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))
    clock.advance(seconds=10)
    second = _ingest(client, _load_sample("09_wazuh_malware_hash_critical_server.json"))

    assert first["decision"]["action"] == "open_incident"
    assert second["decision"]["action"] == "open_incident"
    # Two distinct dedupe groups → two distinct incidents (no auto-merge).
    assert first["incident_id"] != second["incident_id"]

    context_id = second["correlation_context_id"]
    assert context_id is not None
    detail = _detail(client, context_id)
    assert detail["member_count"] == 2
    # Members surface their own incident and dedupe linkage, unchanged.
    incidents = {member["incident_id"] for member in detail["members"]}
    assert incidents == {first["incident_id"], second["incident_id"]}
    groups = {member["dedupe_group_key"] for member in detail["members"]}
    assert groups == {"wazuh:87105:003", "wazuh:87105:006"}

    # The incident board itself is untouched by correlation.
    incidents_list = client.get("/api/v1/incidents", headers=READ_HEADERS).json()
    assert incidents_list["pagination"]["total"] == 2
    for incident in incidents_list["items"]:
        linked = client.get(
            f"/api/v1/incidents/{incident['incident_id']}", headers=READ_HEADERS
        ).json()
        assert linked["linked_alert_count"] == 1


def test_correlated_alerts_remain_distinct_alerts(client: TestClient, clock: FakeClock) -> None:
    first = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    clock.advance(seconds=10)
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    context_id = second["correlation_context_id"]
    assert context_id is not None

    # Both alerts are individually addressable, distinct records.
    assert first["alert_id"] != second["alert_id"]
    for alert_id, rule_id in ((first["alert_id"], "5710"), (second["alert_id"], "5715")):
        response = client.get(f"/api/v1/alerts/{alert_id}", headers=READ_HEADERS)
        assert response.status_code == 200
        body = response.json()
        assert body["rule"]["id"] == rule_id
        assert body["dedupe"]["group_key"] == f"wazuh:{rule_id}:001"
        assert body["incident_id"] is None  # monitor-tier alerts: no incident

    # And they are both listed as separate rows.
    alerts = client.get("/api/v1/alerts", headers=READ_HEADERS).json()
    assert alerts["pagination"]["total"] == 2


def test_audit_entries_are_written_for_correlation_changes(
    client: TestClient, clock: FakeClock
) -> None:
    _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    clock.advance(seconds=10)
    second = _ingest(client, _load_sample("02_wazuh_ssh_brute_force_success.json"))
    context_id = second["correlation_context_id"]

    with session_scope(client.app.state.session_factory) as session:
        entries = AuditRepository(session).all()
    correlation_entries = [entry for entry in entries if entry.actor == "correlation"]
    actions = [entry.action for entry in correlation_entries]
    assert actions == [
        "correlation.context_created",
        "correlation.alert_linked",
        "correlation.alert_linked",
    ]
    # Audit rows are small, entity-scoped snapshots (no payloads).
    for entry in correlation_entries:
        assert entry.entity_type == "correlation_context"
        assert entry.entity_id == context_id
        assert entry.before is None
    linked = [entry for entry in correlation_entries if entry.action == "correlation.alert_linked"]
    assert {entry.after["alert_id"] for entry in linked} == {
        # both founding members are recorded
        *{m["alert_id"] for m in _detail(client, context_id)["members"]}
    }
