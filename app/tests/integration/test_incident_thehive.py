from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest
from fastapi.testclient import TestClient

from soc_triage.api import incident_thehive
from soc_triage.api.dependencies import get_app_settings, get_scorer
from soc_triage.api.incident_thehive import (
    ACTION_INCIDENT_THEHIVE_EXPORTED,
    router,
)
from soc_triage.db.session import session_scope
from soc_triage.models.assessment import RiskAssessment, RiskTier, ScoreFactor
from soc_triage.models.repositories import AuditRepository
from soc_triage.thehive import TheHiveAuthenticationError

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

INCIDENT_HEADERS = {
    "X-N8N-Token": "test-callback-token-not-a-real-secret",
}

AUTH_HEADERS = {
    "X-API-Key": "test-ingest-key-not-a-real-secret",
}


class FakeSettings:
    thehive_url = "https://thehive.test"
    thehive_verify_tls = True
    thehive_timeout_seconds = 5.0
    thehive_organisation = "test-org"

    class _Secret:
        def get_secret_value(self) -> str:
            return "test-api-key"

    thehive_api_key = _Secret()


class FakeCaseResult:
    case_id = "case-123"


class FakeTheHiveClient:
    created_cases: ClassVar[list[dict[str, Any]]] = []
    created_observables: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    def create_case(
        self,
        *,
        title: str,
        description: str,
        severity: int,
        tlp: int,
        pap: int,
    ) -> FakeCaseResult:
        self.__class__.created_cases.append(
            {
                "title": title,
                "description": description,
                "severity": severity,
                "tlp": tlp,
                "pap": pap,
            }
        )
        return FakeCaseResult()

    def create_observable(
        self,
        *,
        case_id: str,
        data_type: str,
        data: str,
        message: str | None = None,
    ) -> dict[str, str]:
        self.__class__.created_observables.append(
            {
                "case_id": case_id,
                "data_type": data_type,
                "data": data,
                "message": message,
            }
        )
        return {"_id": "observable-1"}


class _TheHiveTestScorer:
    """Deterministic HIGH/SEV2 scorer for TheHive export tests."""

    def __init__(self) -> None:
        self._risk = RiskAssessment(
            score=73,
            tier=RiskTier.HIGH,
            engine_version="scoring.v2",
            factors=(
                ScoreFactor(
                    name="thehive_test",
                    points=73,
                    max=100,
                    detail="deterministic TheHive integration test score 73",
                ),
            ),
            summary="TheHive integration test score 73 (high).",
            degraded=False,
        )

    def score(self, _alert: Any) -> RiskAssessment:
        return self._risk


def _load_sample(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def cleanup_overrides() -> Any:
    FakeTheHiveClient.created_cases.clear()
    FakeTheHiveClient.created_observables.clear()
    yield


def _audit_entries(client: TestClient) -> list[Any]:
    with session_scope(client.app.state.session_factory) as session:
        return AuditRepository(session).all()


@pytest.fixture
def incident_id(client: TestClient) -> str:
    """Create one real persisted incident through the ingest API."""

    client.app.dependency_overrides[get_scorer] = lambda: _TheHiveTestScorer()

    payload = _load_sample("04_wazuh_malware_hash_virustotal.json")

    payload["id"] = "1770000000.960001"
    payload["agent"] = {
        **payload.get("agent", {}),
        "id": "thehive-test-001",
        "name": "thehive-test-host",
    }

    response = client.post(
        "/api/v1/alerts/ingest",
        json=payload,
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 202, response.text

    body = response.json()
    assert body["incident_id"] is not None

    return body["incident_id"]


def test_route_exists() -> None:
    paths = [route.path for route in router.routes]
    assert "/api/v1/incidents/{incident_id}/thehive" in paths


def test_unconfigured_thehive_returns_503(
    client: TestClient,
) -> None:
    class UnconfiguredSettings(FakeSettings):
        thehive_url = ""

    client.app.dependency_overrides[get_app_settings] = lambda: UnconfiguredSettings()

    response = client.post(
        "/api/v1/incidents/INC-DOES-NOT-MATTER/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == ("integration_not_configured")


def test_export_creates_case_and_audit(
    client: TestClient,
    incident_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client.app.dependency_overrides[get_app_settings] = lambda: FakeSettings()

    monkeypatch.setattr(
        incident_thehive,
        "TheHiveClient",
        FakeTheHiveClient,
    )

    response = client.post(
        f"/api/v1/incidents/{incident_id}/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 201, response.text

    body = response.json()

    assert body["incident_id"] == incident_id
    assert body["case_id"] == "case-123"
    assert body["created"] is True
    assert body["duplicate"] is False
    assert isinstance(body["observable_count"], int)

    assert len(FakeTheHiveClient.created_cases) == 1
    assert len(FakeTheHiveClient.created_observables) == (body["observable_count"])

    exported = [
        entry
        for entry in _audit_entries(client)
        if entry.action == ACTION_INCIDENT_THEHIVE_EXPORTED and entry.entity_id == incident_id
    ]

    assert len(exported) == 1
    assert exported[0].after["case_id"] == "case-123"
    assert exported[0].after["observable_count"] == (body["observable_count"])


def test_repeated_export_returns_existing_case_without_duplicate(
    client: TestClient,
    incident_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client.app.dependency_overrides[get_app_settings] = lambda: FakeSettings()

    monkeypatch.setattr(
        incident_thehive,
        "TheHiveClient",
        FakeTheHiveClient,
    )

    first = client.post(
        f"/api/v1/incidents/{incident_id}/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert first.status_code == 201, first.text
    assert len(FakeTheHiveClient.created_cases) == 1

    second = client.post(
        f"/api/v1/incidents/{incident_id}/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert second.status_code == 200, second.text

    body = second.json()

    assert body["incident_id"] == incident_id
    assert body["case_id"] == "case-123"
    assert body["created"] is False
    assert body["duplicate"] is True

    assert len(FakeTheHiveClient.created_cases) == 1


def test_authentication_error_class_is_available() -> None:
    assert issubclass(TheHiveAuthenticationError, Exception)
