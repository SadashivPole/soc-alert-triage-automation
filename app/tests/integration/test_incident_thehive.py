from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, ClassVar

import pytest
from fastapi.testclient import TestClient

from soc_triage.api import incident_thehive
from soc_triage.api.dependencies import get_app_settings, get_scorer
from soc_triage.api.incident_thehive import (
    ACTION_INCIDENT_THEHIVE_EXPORTED,
    _export_locks,
    _incident_export_lock,
    router,
)
from soc_triage.db.session import session_scope
from soc_triage.models.assessment import RiskAssessment, RiskTier, ScoreFactor
from soc_triage.models.repositories import AuditRepository
from soc_triage.thehive import (
    CASE_TAG_PREFIX,
    TheHiveAuthenticationError,
    TheHiveUnavailableError,
)

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
    #: Cases "already present in TheHive" (seeded by a test, or registered by
    #: ``create_case`` the way a real TheHive would).
    existing_cases: ClassVar[list[dict[str, Any]]] = []
    #: Incident ids passed to the D2 lookup, in call order.
    lookups: ClassVar[list[str]] = []
    #: When True the D2 lookup raises, to exercise the fail-open path.
    lookup_error: ClassVar[bool] = False

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
        tags: Sequence[str] = (),
    ) -> FakeCaseResult:
        self.__class__.created_cases.append(
            {
                "title": title,
                "description": description,
                "severity": severity,
                "tlp": tlp,
                "pap": pap,
                "tags": list(tags),
            }
        )
        # Mirror TheHive's own state so a later D2 lookup can find this case.
        self.__class__.existing_cases.append(
            {
                "_id": FakeCaseResult.case_id,
                "title": title,
                "tags": list(tags),
                "createdAt": 1,
            }
        )
        return FakeCaseResult()

    def find_case_by_incident(self, incident_id: str) -> str | None:
        """D2 lookup: match the durable tag or the incident id in the title."""

        self.__class__.lookups.append(incident_id)

        if type(self).lookup_error:
            raise TheHiveUnavailableError("simulated lookup failure")

        marker = f"{CASE_TAG_PREFIX}{incident_id}"

        for case in self.__class__.existing_cases:
            if marker in (case.get("tags") or []) or incident_id in str(case.get("title") or ""):
                return str(case["_id"])

        return None

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
    FakeTheHiveClient.existing_cases.clear()
    FakeTheHiveClient.lookups.clear()
    FakeTheHiveClient.lookup_error = False
    yield


def _audit_entries(client: TestClient) -> list[Any]:
    with session_scope(client.app.state.session_factory) as session:
        return AuditRepository(session).all()


def _export_rows(client: TestClient, incident_id: str) -> list[Any]:
    """``incident.thehive_exported`` audit rows for one incident."""

    return [
        entry
        for entry in _audit_entries(client)
        if entry.action == ACTION_INCIDENT_THEHIVE_EXPORTED and entry.entity_id == incident_id
    ]


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

    # D2: the new case carries the durable incident tag.
    assert FakeTheHiveClient.created_cases[0]["tags"] == [f"{CASE_TAG_PREFIX}{incident_id}"]

    # First export: audit miss -> exactly one lookup, which finds nothing.
    assert FakeTheHiveClient.lookups == [incident_id]

    exported = _export_rows(client, incident_id)

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

    # The audit fast path must not consult TheHive at all.
    FakeTheHiveClient.lookups.clear()

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
    assert FakeTheHiveClient.lookups == []  # no TheHive query on the fast path


class FlakyTheHiveClient(FakeTheHiveClient):
    """TheHive creates the case, then the call fails before the audit commit."""

    fail_after_create: ClassVar[bool] = True

    def create_case(self, **kwargs: Any) -> FakeCaseResult:
        result = super().create_case(**kwargs)

        if type(self).fail_after_create:
            # The case now exists in TheHive (super() registered it) but the
            # route never reaches its audit append: the D2 orphan window.
            raise TheHiveUnavailableError("simulated timeout after case creation")

        return result


def test_retry_after_lost_response_recovers_case_instead_of_orphaning(
    client: TestClient,
    incident_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D2 regression: case created, response lost, no audit row -> retry must not duplicate."""

    client.app.dependency_overrides[get_app_settings] = lambda: FakeSettings()
    monkeypatch.setattr(incident_thehive, "TheHiveClient", FlakyTheHiveClient)

    FlakyTheHiveClient.fail_after_create = True

    first = client.post(
        f"/api/v1/incidents/{incident_id}/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert first.status_code == 503
    assert len(FlakyTheHiveClient.created_cases) == 1  # TheHive HAS the case
    assert _export_rows(client, incident_id) == []  # ...but the audit row was lost

    FlakyTheHiveClient.fail_after_create = False

    second = client.post(
        f"/api/v1/incidents/{incident_id}/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert second.status_code == 200, second.text

    body = second.json()

    assert body["case_id"] == "case-123"
    assert body["created"] is False
    assert body["duplicate"] is True

    # THE assertion that proves D2 is fixed: no second case was created.
    assert len(FlakyTheHiveClient.created_cases) == 1

    rows = _export_rows(client, incident_id)

    assert len(rows) == 1
    assert rows[0].after["case_id"] == "case-123"
    assert rows[0].after["recovered"] is True

    # The written audit row restores the normal fast path.
    FlakyTheHiveClient.lookups.clear()

    third = client.post(
        f"/api/v1/incidents/{incident_id}/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert third.status_code == 200
    assert FlakyTheHiveClient.lookups == []


def test_recovers_legacy_untagged_case_by_title(
    client: TestClient,
    incident_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cases created before the D2 tag existed are found via the title."""

    client.app.dependency_overrides[get_app_settings] = lambda: FakeSettings()
    monkeypatch.setattr(incident_thehive, "TheHiveClient", FakeTheHiveClient)

    FakeTheHiveClient.existing_cases.append(
        {
            "_id": "~4128",
            "title": f"SOC Incident {incident_id} [SEV2]",
            "tags": [],
            "createdAt": 1,
        }
    )

    response = client.post(
        f"/api/v1/incidents/{incident_id}/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 200, response.text

    body = response.json()

    assert body["case_id"] == "~4128"
    assert body["created"] is False
    assert body["duplicate"] is True

    # Nothing new was created and the existing case was not modified.
    assert FakeTheHiveClient.created_cases == []

    rows = _export_rows(client, incident_id)

    assert len(rows) == 1
    assert rows[0].after["case_id"] == "~4128"
    assert rows[0].after["recovered"] is True


def test_lookup_failure_is_fail_open(
    client: TestClient,
    incident_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TheHive lookup error must not block a legitimate export."""

    client.app.dependency_overrides[get_app_settings] = lambda: FakeSettings()
    monkeypatch.setattr(incident_thehive, "TheHiveClient", FakeTheHiveClient)

    FakeTheHiveClient.lookup_error = True

    response = client.post(
        f"/api/v1/incidents/{incident_id}/thehive",
        headers=INCIDENT_HEADERS,
    )

    assert response.status_code == 201, response.text
    assert len(FakeTheHiveClient.created_cases) == 1
    assert _export_rows(client, incident_id)[0].after["case_id"] == "case-123"


def test_same_incident_export_lock_serialises() -> None:
    """Concurrent exports of one incident never run the critical section together."""

    async def _drive() -> tuple[int, int]:
        active = 0
        peak = 0

        async def _worker() -> None:
            nonlocal active, peak

            async with _incident_export_lock("INC-LOCK-SAME"):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(*(_worker() for _ in range(5)))

        return peak, active

    peak, active = asyncio.run(_drive())

    assert peak == 1  # same incident: strictly serialised
    assert active == 0
    assert _export_locks == {}  # ref-counted mapping does not leak


def test_different_incidents_do_not_serialise() -> None:
    """The lock is per incident: unrelated exports stay concurrent."""

    async def _drive() -> int:
        active = 0
        peak = 0

        async def _worker(incident_id: str) -> None:
            nonlocal active, peak

            async with _incident_export_lock(incident_id):
                active += 1
                peak = max(peak, active)
                await asyncio.sleep(0.01)
                active -= 1

        await asyncio.gather(*(_worker(f"INC-LOCK-{index}") for index in range(5)))

        return peak

    assert asyncio.run(_drive()) == 5
    assert _export_locks == {}


def test_authentication_error_class_is_available() -> None:
    assert issubclass(TheHiveAuthenticationError, Exception)
