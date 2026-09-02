"""Phase 3.1 integration tests: incident persistence + automatic creation.

Covers the required incident contract on a real (temp) SQLite database through
the same startup path the service uses (engine + Alembic migrations):

* high alert → automatic SEV2 open incident
* critical alert → automatic SEV1 open incident
* low/medium alerts → no incident
* incident id format ``INC-YYYY-MM-DD-NNNN`` (sequential per UTC date)
* recurring/deduplicated alerts attach to the existing open incident
  (no second open incident)
* incidents survive an application restart
* ``incident.created`` append-only audit entry
* incident ↔ primary alert linking (both FK directions)
* migration upgrades an existing (pre-incident) database cleanly
* incident creation is atomic with the assessment persistence transaction
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from alembic import command as alembic_command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from tests.conftest import TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.engine import ALEMBIC_SCRIPT_LOCATION, create_app_engine, run_migrations
from soc_triage.db.session import session_scope
from soc_triage.main import create_app
from soc_triage.models.repositories import AuditRepository, IncidentRepository

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}

INCIDENT_ID_RE = re.compile(r"^INC-\d{4}-\d{2}-\d{2}-\d{4}$")


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text())


def _critical_payload(*, agent_id: str = "003", agent_name: str = "hr-wks-04") -> dict[str, Any]:
    """Sample 04 (malware hash) on a critical-tier asset → SEV1."""
    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")
    payload["agent"] = {"id": agent_id, "name": agent_name, "labels": {"asset_tier": "critical"}}
    return payload


def _ingest(client: TestClient, payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _incidents(client: TestClient) -> list[Any]:
    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        return IncidentRepository(session).all()


def _incident_rows(client: TestClient) -> list[tuple[Any, ...]]:
    """Raw incident rows (incident_id, status, severity, primary_alert_id, group)."""
    with client.app.state.db_engine.connect() as conn:
        return [
            (row[0], row[1], row[2], str(UUID(row[3])), row[4])
            for row in conn.execute(
                text(
                    "SELECT incident_id, status, severity, primary_alert_id, dedupe_group_key "
                    "FROM incidents ORDER BY incident_id"
                )
            ).fetchall()
        ]


def _alert_links(client: TestClient) -> list[tuple[str, str | None]]:
    """Raw (alert_id, incident_id) pairs from the alerts table."""
    with client.app.state.db_engine.connect() as conn:
        return [
            (str(UUID(row[0])), row[1])
            for row in conn.execute(text("SELECT alert_id, incident_id FROM alerts")).fetchall()
        ]


def _audit(client: TestClient) -> list[Any]:
    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        return AuditRepository(session).all()


class FakeClock:
    """Deterministic clock for time/date-sensitive tests (no real sleeping)."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, *, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Automatic creation by tier
# ---------------------------------------------------------------------------


def test_high_alert_creates_sev2_incident(client: TestClient) -> None:
    body = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))

    # Decision contract: high → open_incident SEV2.
    assert body["risk"]["tier"] == "high"
    assert body["decision"]["action"] == "open_incident"
    assert body["decision"]["severity"] == "SEV2"
    assert body["incident_id"] is not None
    assert INCIDENT_ID_RE.match(body["incident_id"])

    rows = _incident_rows(client)
    assert len(rows) == 1
    incident_id, status, severity, primary_alert_id, group_key = rows[0]
    assert incident_id == body["incident_id"]
    assert status == "open"
    assert severity == "SEV2"
    assert UUID(primary_alert_id) == UUID(body["alert_id"])
    assert group_key == "wazuh:87105:003"


def test_critical_alert_creates_sev1_incident(client: TestClient) -> None:
    body = _ingest(client, _critical_payload())

    assert body["risk"]["tier"] == "critical"
    assert body["decision"]["action"] == "open_incident"
    assert body["decision"]["severity"] == "SEV1"
    assert body["incident_id"] is not None

    row = _incident_rows(client)[0]
    assert row[0] == body["incident_id"]
    assert row[1] == "open"
    assert row[2] == "SEV1"
    assert row[4] == "wazuh:87105:003"


def test_low_and_medium_alerts_create_no_incident(client: TestClient) -> None:
    low = _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))
    medium = _ingest(client, _load_sample("03_wazuh_fim_etc_passwd_change.json"))

    assert low["decision"]["action"] == "monitor"
    assert medium["decision"]["action"] == "queue_l1"
    assert low["incident_id"] is None
    assert medium["incident_id"] is None
    assert _incidents(client) == []
    assert "incident.created" not in [entry.action for entry in _audit(client)]


# ---------------------------------------------------------------------------
# Incident id format & per-UTC-date sequencing
# ---------------------------------------------------------------------------


def test_incident_id_is_sequential_per_utc_date(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock(datetime(2026, 8, 29, 10, 0, 0, tzinfo=UTC))
    monkeypatch.setattr("soc_triage.api.alerts._utc_now", clock.now)

    # Same UTC date, two distinct dedupe groups → 0001 then 0002.
    first = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))
    second = _ingest(
        client,
        _load_sample("04_wazuh_malware_hash_virustotal.json")
        | {"agent": {"id": "009", "name": "hr-wks-09"}},
    )
    assert first["incident_id"] == "INC-2026-08-29-0001"
    assert second["incident_id"] == "INC-2026-08-29-0002"

    # Next UTC date resets the sequence.
    clock.advance(seconds=24 * 3600)
    third = _ingest(client, _critical_payload(agent_id="010", agent_name="hr-wks-10"))
    assert third["incident_id"] == "INC-2026-08-30-0001"

    for incident_id in (first["incident_id"], second["incident_id"], third["incident_id"]):
        assert INCIDENT_ID_RE.match(incident_id)


# ---------------------------------------------------------------------------
# Dedupe / recurrence linking
# ---------------------------------------------------------------------------


def test_repeated_and_deduplicated_alerts_share_one_open_incident(
    client: TestClient,
) -> None:
    base = _load_sample("04_wazuh_malware_hash_virustotal.json")
    repeated = dict(base, id="1770000000.100099")

    first = _ingest(client, base)
    assert first["dedupe_status"] == "new_generation"
    assert first["incident_id"] is not None

    # Distinct event, same rule+agent (a recurrence): attach, don't duplicate.
    second = _ingest(client, repeated)
    assert second["dedupe_status"] == "repeated"
    assert second["incident_id"] == first["incident_id"]

    # Exact re-delivery of the original event: idempotent echo, same incident.
    duplicate = client.post("/api/v1/alerts/ingest", json=base, headers=AUTH_HEADERS)
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert duplicate.json()["incident_id"] == first["incident_id"]

    rows = _incident_rows(client)
    assert len(rows) == 1
    assert rows[0][0] == first["incident_id"]
    # Both distinct alerts are linked to the single incident.
    assert len(_alert_links(client)) == 2
    assert all(link[1] == first["incident_id"] for link in _alert_links(client))
    # Only one incident.created audit entry.
    created = [e for e in _audit(client) if e.action == "incident.created"]
    assert len(created) == 1


# ---------------------------------------------------------------------------
# Restart persistence
# ---------------------------------------------------------------------------


def test_incident_survives_application_restart(db_url: str) -> None:
    def _settings() -> Settings:
        return Settings(
            soc_env="test",
            soc_log_level="WARNING",
            soc_instance_name="soc-test",
            triage_cors_origins="http://localhost:8080",
            triage_db_url=db_url,
            triage_ingest_api_key=TEST_INGEST_KEY,
            n8n_callback_token="test-callback-token-not-a-real-secret",
        )

    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")

    # --- First process lifetime ---
    with TestClient(create_app(settings=_settings())) as client_a:
        first = _ingest(client_a, payload)
        assert first["incident_id"] is not None

    # --- Second process lifetime: fresh engine over the same file ---
    with TestClient(create_app(settings=_settings())) as client_b:
        incident = _incidents(client_b)
        assert len(incident) == 1
        restored = incident[0]
        assert restored.incident_id == first["incident_id"]
        assert restored.status.value == "open"
        assert restored.severity.value == "SEV2"

        factory = client_b.app.state.session_factory
        with session_scope(factory) as session:
            repo = IncidentRepository(session)
            assert repo.open_for_group("wazuh:87105:003") is not None
            by_alert = repo.for_alert(UUID(first["alert_id"]))
            assert by_alert is not None
            assert by_alert.incident_id == first["incident_id"]

        # Exact re-delivery after restart: idempotent, same incident, no new row.
        duplicate = client_b.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
        assert duplicate.status_code == 200
        assert duplicate.json()["incident_id"] == first["incident_id"]
        assert len(_incidents(client_b)) == 1


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_incident_created_audit_entry_exists(client: TestClient) -> None:
    body = _ingest(client, _critical_payload())

    created = [e for e in _audit(client) if e.action == "incident.created"]
    assert len(created) == 1
    entry = created[0]
    assert entry.actor == "decisions"
    assert entry.entity_type == "incident"
    assert entry.entity_id == body["incident_id"]
    assert entry.before is None
    assert entry.after == {
        "incident_id": body["incident_id"],
        "alert_id": body["alert_id"],
        "severity": "SEV1",
        "status": "open",
        "dedupe_group_key": "wazuh:87105:003",
    }

    # Sequence: scored → decided → incident.created, all append-only.
    actions = [e.action for e in _audit(client)]
    assert actions.index("alert.scored") < actions.index("alert.decided")
    assert actions.index("alert.decided") < actions.index("incident.created")


# ---------------------------------------------------------------------------
# Primary alert linking
# ---------------------------------------------------------------------------


def test_incident_is_linked_to_primary_alert(client: TestClient) -> None:
    body = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))

    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        repo = IncidentRepository(session)
        incident = repo.get(body["incident_id"])
        assert incident is not None
        assert incident.primary_alert_id == UUID(body["alert_id"])
        by_alert = repo.for_alert(UUID(body["alert_id"]))
        assert by_alert is not None
        assert by_alert.incident_id == body["incident_id"]
        assert repo.open_for_group("wazuh:87105:003") is not None

    assert _alert_links(client) == [(body["alert_id"], body["incident_id"])]
    assert _incident_rows(client)[0][3] == body["alert_id"]


def test_incident_repository_lookup_and_error_paths(client: TestClient) -> None:
    """Repository reads return None/counts and defensive LookupErrors."""
    from uuid import uuid4

    from soc_triage.models.assessment import DecisionSeverity

    factory = client.app.state.session_factory
    with session_scope(factory) as session:
        repo = IncidentRepository(session)
        assert repo.get("INC-2099-01-01-0001") is None
        assert repo.count() == 0
        assert repo.all(limit=1) == []
        # Attach to an incident that does not exist → LookupError.
        with pytest.raises(LookupError, match="incident"):
            repo.attach(alert_id=uuid4(), incident_id="INC-2099-01-01-0001")
        # Create for an alert that does not exist → LookupError (no partial row).
        with pytest.raises(LookupError, match="alert"):
            repo.create(
                alert_id=uuid4(),
                severity=DecisionSeverity.SEV2,
                dedupe_group_key="wazuh:x:y",
                occurred_at=datetime(2026, 9, 2, 10, 0, tzinfo=UTC),
            )
    assert _incidents(client) == []


# ---------------------------------------------------------------------------
# Migration against an existing database
# ---------------------------------------------------------------------------


def test_migration_upgrades_existing_database(db_url: str) -> None:
    """A pre-incident database upgrades cleanly; legacy data stays intact."""
    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)  # to head
    # Revert to the previous revision to simulate an existing Phase 2B DB.
    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.downgrade(config, "b2c3d4e5f6a7")

    alert_id = "00000000-0000-0000-0000-000000000001"
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO alerts (alert_id, source, received_at, dedupe_group_key, "
                "event_identity, rule_id, rule_level, agent_id, agent_name, "
                "normalized_payload, created_at) VALUES "
                "(:alert_id, 'wazuh', '2026-08-29 10:00:00.000000', 'wazuh:5710:001', "
                "'wazuh:legacy:5710:001', '5710', 5, '001', 'web-prod-01', '{}', "
                "'2026-08-29 10:00:00.000000')"
            ),
            {"alert_id": alert_id},
        )
        conn.execute(
            text(
                "INSERT INTO alert_dedupe_groups (group_key, occurrences, generation, "
                "first_seen, last_seen, duplicate_deliveries, updated_at) VALUES "
                "('wazuh:5710:001', 1, 1, '2026-08-29 10:00:00.000000', "
                "'2026-08-29 10:00:00.000000', 0, '2026-08-29 10:00:00.000000')"
            )
        )

    # Upgrade to head (the incident migration) and verify no legacy data was lost.
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    with engine.connect() as conn:
        tables = [
            row[0]
            for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        ]
        assert "incidents" in tables
        legacy = conn.execute(
            text("SELECT alert_id, incident_id FROM alerts WHERE alert_id = :aid"),
            {"aid": alert_id},
        ).fetchone()
        assert legacy is not None
        assert legacy[1] is None  # legacy alerts stay unattached (nullable column)
        columns = [row[1] for row in conn.execute(text("PRAGMA table_info(alerts)"))]
        assert "incident_id" in columns
    engine.dispose()

    # And the upgraded DB is fully operational: a high alert creates an incident.
    settings = Settings(
        soc_env="test",
        soc_log_level="WARNING",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=db_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token="test-callback-token-not-a-real-secret",
    )
    with TestClient(create_app(settings=settings)) as client:
        body = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))
        assert body["incident_id"] is not None
        assert len(_incidents(client)) == 1


# ---------------------------------------------------------------------------
# Atomicity
# ---------------------------------------------------------------------------


def test_incident_creation_is_atomic_with_assessment_persistence(client: TestClient) -> None:
    """If the unit of work fails, the incident is not half-created."""
    engine = client.app.state.db_engine
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TRIGGER incident_audit_fail BEFORE INSERT ON audit_log "
                "WHEN NEW.action = 'incident.created' "
                "BEGIN SELECT RAISE(ABORT, 'simulated incident audit failure'); END"
            )
        )

    body = _ingest(client, _load_sample("04_wazuh_malware_hash_virustotal.json"))
    # Best-effort assessment persistence: the failure is contained (202), the
    # alert stays durable, and NO incident/link/audit rows half-survived.
    assert body["incident_id"] is None
    assert _incidents(client) == []
    assert _incident_rows(client) == []
    assert _alert_links(client) == [(body["alert_id"], None)]
    assert "incident.created" not in [e.action for e in _audit(client)]

    with engine.begin() as conn:
        conn.execute(text("DROP TRIGGER incident_audit_fail"))
    # A distinct event now completes the flow cleanly.
    recovered = _ingest(
        client, dict(_load_sample("04_wazuh_malware_hash_virustotal.json"), id="1770000000.100099")
    )
    assert recovered["incident_id"] is not None
    assert len(_incidents(client)) == 1
