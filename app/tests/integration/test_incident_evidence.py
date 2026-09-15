"""Phase 4.3 integration tests: incident investigation evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from tests.conftest import TEST_INGEST_KEY

from soc_triage.api.dependencies import get_scorer
from soc_triage.models.assessment import RiskAssessment, RiskTier, ScoreFactor

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

AUTH_HEADERS = {
    "X-API-Key": TEST_INGEST_KEY,
}

INCIDENT_HEADERS = {
    "X-N8N-Token": "test-callback-token-not-a-real-secret",
}


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


class _EvidenceTestScorer:
    """Deterministic HIGH/SEV2 scorer for evidence integration tests."""

    def __init__(self) -> None:
        self._risk = RiskAssessment(
            score=73,
            tier=RiskTier.HIGH,
            engine_version="scoring.v2",
            factors=(
                ScoreFactor(
                    name="evidence_test",
                    points=73,
                    max=100,
                    detail="deterministic incident-evidence integration test",
                ),
            ),
            summary="Incident evidence integration test score 73 (high).",
            degraded=False,
        )

    def score(self, _alert: Any) -> RiskAssessment:
        return self._risk


def _create_incident(client: TestClient) -> str:
    """Create one real persisted incident through the ingest API."""

    client.app.dependency_overrides[get_scorer] = lambda: _EvidenceTestScorer()

    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")

    payload["id"] = "1770000000.950001"

    payload["agent"] = {
        **payload.get("agent", {}),
        "id": "evidence-001",
        "name": "evidence-test-host",
    }

    response = client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 202, response.text

    body = response.json()

    assert body["incident_id"] is not None
    assert body["risk"]["score"] == 73
    assert body["risk"]["tier"] == "high"
    assert body["decision"]["action"] == "open_incident"

    return body["incident_id"]


def test_incident_evidence_returns_alert_and_ioc_data(
    client: TestClient,
) -> None:
    incident_id = _create_incident(client)

    response = client.get(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 200, response.text

    body = response.json()

    assert body["incident_id"] == incident_id
    assert body["alert_count"] == 1
    assert body["ioc_count"] >= 1
    assert len(body["alerts"]) == 1
    assert len(body["iocs"]) >= 1

    assert body["alerts"][0]["incident_id"] == incident_id

    for ioc in body["iocs"]:
        assert "type" in ioc
        assert "value" in ioc


def test_incident_evidence_is_deterministically_ordered(
    client: TestClient,
) -> None:
    incident_id = _create_incident(client)

    first = client.get(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers=INCIDENT_HEADERS,
    )

    second = client.get(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers=INCIDENT_HEADERS,
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()


def test_incident_evidence_does_not_expose_full_log(
    client: TestClient,
) -> None:
    incident_id = _create_incident(client)

    response = client.get(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 200

    body = response.json()
    serialized = json.dumps(body).lower()

    assert "full_log" not in serialized


def test_unknown_incident_returns_404(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/incidents/INC-2099-12-31-9999/evidence",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 404


def test_incident_evidence_requires_auth(
    client: TestClient,
) -> None:
    incident_id = _create_incident(client)

    response = client.get(
        f"/api/v1/incidents/{incident_id}/evidence",
    )

    assert response.status_code == 401
