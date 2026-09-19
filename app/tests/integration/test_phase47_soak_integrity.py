"""Phase 4.7 soak-integrity integration tests (CI-runnable).

``scripts/phase47_soak.py`` is a Windows/Docker-lab wall-clock instrument: it
POSTs synthetic alerts to the ingest endpoint through subprocess ``curl.exe``
and reports throughput/latency. It is *not* runnable in this Linux/CI sandbox
(no Docker daemon, no ``curl.exe``), and it varies only ``payload["id"]`` — so
every request belongs to the same ``rule.id + agent.id`` dedupe group and the
harness exercises an acute recurrence/burst pattern around one identity rather
than a spread of independent identities (see
``docs/specs/phase-4.7-soak-runbook.md``).

This module is the CI-runnable complement: it drives the **real**
``POST /api/v1/alerts/ingest`` application path (FastAPI ``TestClient`` → the
same normalize → extract → enrich → dedupe → score → persist pipeline the
service runs) against a temporary SQLite test database, and demonstrates the
integrity contract the live soak depends on:

* a spread of *distinct* identities across ``rule.id`` and ``agent.id`` is
  accepted and yields distinct alert rows — no collapse into one dedupe group;
* an exact re-delivery is idempotent per the application's response contract
  (HTTP 200 ``duplicate: true``, the original ``alert_id``, no new row);
* alert-row and per-event dedupe counters in the database prove deduplication
  rather than merely inferring it from response codes.

Throughput/timing here is **diagnostic evidence only** — it is printed with an
explicit "not a benchmark" label and is never asserted as an SLA. The one
bounded wall-clock assertion is a coarse CI stability guard (catch pathological
stalls), deliberately orders of magnitude looser than any performance claim.
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import distinct, func, select
from tests.conftest import TEST_INGEST_KEY

from soc_triage.db.session import session_scope
from soc_triage.models.orm import Alert, AlertEvent
from soc_triage.models.repositories import DedupeStateRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
FIXTURE_NAME = "01_wazuh_ssh_brute_force.json"

AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}

#: Distinct identities the integrity spread exercises. Each pair produces its
#: own ``wazuh:{rule.id}:{agent.id}`` dedupe group, so N deliveries create N
#: independent alerts rather than one recurrence burst.
SPREAD_IDENTITIES: tuple[tuple[str, str], ...] = (
    ("5710", "001"),
    ("5710", "002"),
    ("5710", "003"),
    ("5710", "004"),
    ("5710", "005"),
    ("5710", "006"),
    ("5710", "007"),
    ("5715", "001"),
    ("5715", "002"),
    ("5715", "003"),
    ("550", "001"),
    ("550", "002"),
    ("31103", "001"),
    ("31103", "002"),
    ("60180", "001"),
    ("60180", "002"),
)


def _load_fixture() -> dict:
    with (FIXTURES_DIR / FIXTURE_NAME).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _spread_payload(template: dict, rule_id: str, agent_id: str, run_id: str, seq: int) -> dict:
    """One synthetic alert with a distinct identity and a unique event id.

    Unlike the protected harness (which changes only ``id``), this varies
    ``rule.id`` and ``agent.id`` so each delivery is an independent dedupe
    group, and changes ``id`` so each delivery is a distinct event inside that
    group.
    """
    payload = copy.deepcopy(template)
    payload["id"] = f"soak-integrity-{run_id}-{seq:08d}"
    payload["rule"]["id"] = rule_id
    payload["agent"]["id"] = agent_id
    payload["agent"]["name"] = f"soak-host-{agent_id}"
    return payload


def _db_rows(client: TestClient, table: type) -> int:
    """Count rows directly through the app's own session factory."""
    with session_scope(client.app.state.session_factory) as session:
        return session.execute(select(func.count()).select_from(table)).scalar_one()


def test_spread_identities_ingest_accepted_and_distinct(client: TestClient) -> None:
    """A spread across rule.id/agent.id is accepted and creates distinct alerts.

    This is the integrity invariant the 10k/day soak silently depends on: the
    ingest path must *not* collapse distinct identities into one dedupe group.
    """
    template = _load_fixture()
    run_id = uuid.uuid4().hex[:12]
    alert_ids: list[str] = []

    for seq, (rule_id, agent_id) in enumerate(SPREAD_IDENTITIES, start=1):
        payload = _spread_payload(template, rule_id, agent_id, run_id, seq)
        response = client.post(
            "/api/v1/alerts/ingest",
            json=payload,
            headers=AUTH_HEADERS,
        )
        assert response.status_code == 202, response.text
        body = response.json()
        assert body["status"] == "accepted"
        assert body["duplicate"] is False
        assert body["dedupe_status"] == "new_generation"
        assert "alert_id" in body
        alert_ids.append(body["alert_id"])

    # Every delivery produced its own alert identity and its own dedupe group.
    assert len(set(alert_ids)) == len(SPREAD_IDENTITIES)
    assert _db_rows(client, Alert) == len(SPREAD_IDENTITIES)

    # Distinct event identities too: no two deliveries share an idempotency key.
    with session_scope(client.app.state.session_factory) as session:
        distinct_identities = session.execute(
            select(func.count(distinct(Alert.event_identity)))
        ).scalar_one()
    assert distinct_identities == len(SPREAD_IDENTITIES)


def test_exact_redelivery_is_idempotent_without_new_rows(client: TestClient) -> None:
    """Exact re-delivery returns the original alert and creates no new row.

    Uses the application's actual response contract: HTTP 200, ``duplicate:
    true``, ``dedupe_status: exact_duplicate``, and the *original* alert_id.
    """
    template = _load_fixture()
    run_id = uuid.uuid4().hex[:12]
    payloads = [
        _spread_payload(template, rule_id, agent_id, run_id, seq)
        for seq, (rule_id, agent_id) in enumerate(SPREAD_IDENTITIES, start=1)
    ]

    first_ids: dict[tuple[str, str], str] = {}
    for payload, (rule_id, agent_id) in zip(payloads, SPREAD_IDENTITIES, strict=True):
        first = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
        assert first.status_code == 202, first.text
        first_ids[(rule_id, agent_id)] = first.json()["alert_id"]

    rows_after_first = _db_rows(client, Alert)

    for payload, (rule_id, agent_id) in zip(payloads, SPREAD_IDENTITIES, strict=True):
        again = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
        assert again.status_code == 200, again.text
        body = again.json()
        assert body["status"] == "duplicate"
        assert body["duplicate"] is True
        assert body["dedupe_status"] == "exact_duplicate"
        assert body["alert_id"] == first_ids[(rule_id, agent_id)]

    # No duplicate alert identities, no duplicate rows: dedup = absorption.
    assert _db_rows(client, Alert) == rows_after_first == len(SPREAD_IDENTITIES)
    with session_scope(client.app.state.session_factory) as session:
        distinct_identities = session.execute(
            select(func.count(distinct(Alert.event_identity)))
        ).scalar_one()
    assert distinct_identities == len(SPREAD_IDENTITIES)


def test_database_counters_prove_deduplication(client: TestClient) -> None:
    """Occurrence/event counters in the DB demonstrate (not infer) dedup.

    After one delivery + one exact re-delivery per identity: each group tracks
    ``occurrences == 1`` (no recurrence inflation from duplicates),
    ``duplicate_deliveries == 1``, and each ``alert_events`` row has
    ``delivery_count == 2`` for exactly one alert row.
    """
    template = _load_fixture()
    run_id = uuid.uuid4().hex[:12]
    payloads = [
        _spread_payload(template, rule_id, agent_id, run_id, seq)
        for seq, (rule_id, agent_id) in enumerate(SPREAD_IDENTITIES, start=1)
    ]

    for payload in payloads:
        assert (
            client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS).status_code
            == 202
        )
    for payload in payloads:
        assert (
            client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS).status_code
            == 200
        )

    with session_scope(client.app.state.session_factory) as session:
        repository = DedupeStateRepository(session)

        for _, (rule_id, agent_id) in enumerate(SPREAD_IDENTITIES, start=1):
            group_key = f"wazuh:{rule_id}:{agent_id}"
            group = repository.group_state(group_key)
            assert group is not None, group_key
            assert group.occurrences == 1, (group_key, group.occurrences)
            assert group.duplicate_deliveries == 1, (group_key, group.duplicate_deliveries)

        delivery_counts = session.execute(select(AlertEvent.delivery_count)).scalars().all()
        assert sorted(delivery_counts) == [2] * len(SPREAD_IDENTITIES)


def test_same_identity_repeats_increment_occurrences_not_rows(client: TestClient) -> None:
    """Distinct events *within* one group are recurrences: occurrences, not rows.

    This mirrors what the protected harness actually exercises (it changes only
    ``payload["id"]``, so every delivery is the same rule+agent group): three
    distinct event ids in one group become three alert rows and one dedupe
    group whose ``occurrences`` reaches 3 — recurrence, demonstrated in the DB.
    """
    run_id = uuid.uuid4().hex[:12]
    template = _load_fixture()
    base = copy.deepcopy(template)

    group_key = None
    for seq in (1, 2, 3):
        payload = copy.deepcopy(base)
        payload["id"] = f"soak-integrity-{run_id}-burst-{seq:08d}"  # harness-style: id only
        response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
        assert response.status_code == 202, response.text
        group_key = response.json()["dedupe"]["group_key"]

    assert group_key == "wazuh:5710:001"
    assert _db_rows(client, Alert) == 3

    with session_scope(client.app.state.session_factory) as session:
        group = DedupeStateRepository(session).group_state(group_key)
        assert group is not None
        assert group.occurrences == 3
        assert group.duplicate_deliveries == 0


def test_spread_ingest_wall_clock_is_bounded_for_ci(client: TestClient) -> None:
    """A coarse CI stability guard around a spread ingest (never an SLA).

    The asserted bound (30 s) is orders of magnitude looser than any
    performance claim: it catches pathological stalls in the in-process
    pipeline, nothing more. Throughput is printed as diagnostic evidence only.
    """
    template = _load_fixture()
    run_id = uuid.uuid4().hex[:12]

    started = time.perf_counter()
    for seq, (rule_id, agent_id) in enumerate(SPREAD_IDENTITIES, start=1):
        payload = _spread_payload(template, rule_id, agent_id, run_id, seq)
        response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
        assert response.status_code == 202, response.text
    elapsed = time.perf_counter() - started

    count = len(SPREAD_IDENTITIES)
    throughput = count / elapsed if elapsed > 0 else 0.0

    # Diagnostic evidence only — explicitly not a benchmark, never an SLA.
    print(
        "\n[phase47-soak-integrity][diagnostic, NOT a benchmark] "
        f"accepted {count} distinct-identity alerts in {elapsed:.3f}s "
        f"({throughput:.2f} alerts/s in-process TestClient)"
    )

    assert elapsed < 30.0, (
        f"spread ingest of {count} alerts took {elapsed:.2f}s; "
        "this is a CI stability guard, not a performance threshold"
    )
