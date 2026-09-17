from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from tests.conftest import TEST_INGEST_KEY

from soc_triage.db.session import session_scope
from soc_triage.models.repositories import (
    AlertRepository,
    AuditRepository,
    IncidentRepository,
)
from soc_triage.services.late_enrichment import LateEnrichmentService

AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class ControlledEnrichmentChain:
    """Deterministic late-enrichment chain for integration tests."""

    def __init__(self) -> None:
        self.calls = 0

    def enrich(self, iocs, *, context):  # noqa: ARG002
        self.calls += 1

        enriched = []

        for ioc in iocs:
            enrichment = {
                "virustotal": {
                    "provider": "virustotal",
                    "indicator_type": ioc.type.value,
                    "lookup_status": "found",
                    "timestamp": "2026-09-17T00:00:00+00:00",
                    "result": {
                        "malicious": 10,
                        "suspicious": 0,
                        "harmless": 0,
                        "reputation": -10,
                    },
                }
            }

            enriched.append(
                ioc.model_copy(
                    update={"enrichment": enrichment},
                )
            )

        return SimpleNamespace(
            status=SimpleNamespace(value="complete"),
            iocs=tuple(enriched),
        )


def _load_sample(name: str) -> dict:
    """Load one canonical integration fixture."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _ingest(client: TestClient, payload: dict) -> dict:
    """Ingest one alert through the real API pipeline."""
    response = client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers=AUTH_HEADERS,
    )

    assert response.status_code in {200, 202}, response.text
    return response.json()


def test_late_enrichment_reassesses_and_persists_same_alert(
    client: TestClient,
) -> None:
    """Late enrichment updates the assessment without replacing the alert."""

    payload = _load_sample(
        "01_wazuh_ssh_brute_force.json",
    )

    first = _ingest(client, payload)

    alert_id = UUID(first["alert_id"])
    original_score = first["risk"]["score"]
    original_action = first["decision"]["action"]

    factory: sessionmaker = client.app.state.session_factory

    # Verify the original alert is persisted and contains an IOC.
    with session_scope(factory) as session:
        stored_before = AlertRepository(session).get_alert(alert_id)

    assert stored_before is not None
    assert stored_before.alert_id == alert_id
    assert stored_before.canonical.iocs

    chain = ControlledEnrichmentChain()

    service = LateEnrichmentService(
        chain,
        client.app.state.scorer,
        client.app.state.decider,
    )

    result, persistence = service.reassess_persisted(
        factory,
        alert_id=alert_id,
    )

    assert persistence.persisted is True
    assert chain.calls == 1

    assert result.canonical.alert_id == alert_id
    assert result.canonical.risk is not None
    assert result.canonical.decision is not None

    # Late enrichment must change the assessment.
    assert result.canonical.risk.score != original_score

    # The same alert remains the alert of record.
    with session_scope(factory) as session:
        stored_after = AlertRepository(session).get_alert(alert_id)
        all_audits = AuditRepository(session).all()

    assert stored_after is not None
    assert stored_after.alert_id == alert_id

    assert stored_after.canonical.risk is not None
    assert stored_after.canonical.risk.score == result.canonical.risk.score

    assert stored_after.canonical.decision is not None
    assert stored_after.canonical.decision.action.value == result.canonical.decision.action.value

    alert_audits = [row for row in all_audits if row.entity_id == str(alert_id)]

    scored = [row for row in alert_audits if row.action == "alert.scored"]

    decided = [row for row in alert_audits if row.action == "alert.decided"]

    created = [row for row in alert_audits if row.action == "alert.created"]

    # Late reassessment must not create another alert.
    assert len(created) == 1

    # One assessment from initial ingest + one from late enrichment.
    assert len(scored) == 2
    assert len(decided) == 2

    # Score transition must contain before/after snapshots.
    assert scored[-1].before is not None
    assert scored[-1].after is not None
    assert scored[-1].before["score"] == original_score
    assert scored[-1].after["score"] == result.canonical.risk.score

    # Decision transition must contain before/after snapshots.
    assert decided[-1].before is not None
    assert decided[-1].after is not None
    assert decided[-1].before["action"] == original_action
    assert decided[-1].after["action"] == result.canonical.decision.action.value


def test_late_enrichment_reuses_existing_open_incident(
    client: TestClient,
) -> None:
    """An already-open incident is reused during reassessment."""

    payload = _load_sample(
        "04_wazuh_malware_hash_virustotal.json",
    )

    first = _ingest(client, payload)

    assert first["decision"]["action"] == "open_incident"
    assert first["incident_id"] is not None

    alert_id = UUID(first["alert_id"])
    original_incident_id = first["incident_id"]

    factory: sessionmaker = client.app.state.session_factory

    # Verify the original incident exists and is linked to the alert.
    with session_scope(factory) as session:
        incident_repo = IncidentRepository(session)

        original_incident = incident_repo.get(original_incident_id)
        linked_incident = incident_repo.for_alert(alert_id)

    assert original_incident is not None
    assert original_incident.status.value == "open"
    assert linked_incident is not None
    assert linked_incident.incident_id == original_incident_id

    chain = ControlledEnrichmentChain()

    service = LateEnrichmentService(
        chain,
        client.app.state.scorer,
        client.app.state.decider,
    )

    result, persistence = service.reassess_persisted(
        factory,
        alert_id=alert_id,
    )

    assert persistence.persisted is True
    assert chain.calls == 1

    assert result.canonical.decision is not None
    assert result.canonical.decision.action.value == "open_incident"

    # The existing incident must be reused.
    assert persistence.incident_id == original_incident_id

    with session_scope(factory) as session:
        incident_repo = IncidentRepository(session)

        incidents = incident_repo.all()
        linked_incident_after = incident_repo.for_alert(alert_id)
        audits = AuditRepository(session).all()

    assert len(incidents) == 1
    assert incidents[0].incident_id == original_incident_id

    assert linked_incident_after is not None
    assert linked_incident_after.incident_id == original_incident_id

    # No second incident.created event is allowed.
    incident_created = [row for row in audits if row.action == "incident.created"]

    assert len(incident_created) == 1
    assert incident_created[0].entity_id == original_incident_id


def test_late_enrichment_can_open_incident_from_queue_l1(
    client: TestClient,
) -> None:
    """Late enrichment can escalate a non-incident alert into an incident."""

    payload = _load_sample(
        "03_wazuh_fim_etc_passwd_change.json",
    )

    first = _ingest(client, payload)

    # Existing golden contract for this scenario.
    assert first["risk"]["score"] == 63
    assert first["risk"]["tier"] == "medium"
    assert first["decision"]["action"] == "queue_l1"
    assert first["incident_id"] is None

    alert_id = UUID(first["alert_id"])
    factory: sessionmaker = client.app.state.session_factory

    # Confirm no incident exists before late enrichment.
    with session_scope(factory) as session:
        incidents_before = IncidentRepository(session).all()

    assert incidents_before == []

    chain = ControlledEnrichmentChain()

    service = LateEnrichmentService(
        chain,
        client.app.state.scorer,
        client.app.state.decider,
    )

    result, persistence = service.reassess_persisted(
        factory,
        alert_id=alert_id,
    )

    assert persistence.persisted is True
    assert chain.calls == 1

    assert result.canonical.risk is not None
    assert result.canonical.decision is not None

    # The enriched threat-intelligence evidence must cross the
    # incident-opening threshold.
    assert result.canonical.risk.score >= 70
    assert result.canonical.decision.action.value == "open_incident"

    assert persistence.incident_id is not None

    with session_scope(factory) as session:
        incident_repo = IncidentRepository(session)

        incidents_after = incident_repo.all()
        linked_incident = incident_repo.for_alert(alert_id)
        audits = AuditRepository(session).all()

    # Exactly one incident must be created for the transition.
    assert len(incidents_after) == 1
    assert incidents_after[0].incident_id == persistence.incident_id

    assert linked_incident is not None
    assert linked_incident.incident_id == persistence.incident_id
    assert linked_incident.status.value == "open"

    incident_created = [row for row in audits if row.action == "incident.created"]

    assert len(incident_created) == 1
    assert incident_created[0].entity_id == persistence.incident_id
