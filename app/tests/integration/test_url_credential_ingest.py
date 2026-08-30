"""Phase 2A hardening: URL credential-leak regression at the ingest API.

Runs the real pipeline (normalize → extract → enrich → dedupe → score → decide
→ persist → audit) with a credential-bearing typed URL field and proves the
secret never appears in any surface the pipeline writes:

* IOC value and ``IOCProvenance.raw_value`` (the ``iocs`` array);
* the persisted/echoed ``normalized`` canonical payload;
* the full API response;
* the persisted alert of record (``normalized_payload`` column);
* append-only audit records;
* structured logs.

No external providers are enabled (default config), so no network I/O occurs.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from tests.conftest import TEST_INGEST_KEY

from soc_triage.db.session import session_scope
from soc_triage.models.repositories import AlertRepository, AuditRepository

AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
SECRET = "SuperSecret123"
CREDENTIAL_URL = f"https://analyst:{SECRET}@example.com/login"
SANITIZED_URL = "https://example.com/login"


def _payload() -> dict[str, Any]:
    return {
        "id": "1770000000.910001",
        "rule": {
            "level": 12,
            "description": "credential URL in data.url",
            "id": "99998",
            "groups": ["malware"],
        },
        "agent": {"id": "010", "name": "host-010"},
        "data": {"url": CREDENTIAL_URL},
    }


def _ingest(client: TestClient) -> dict[str, Any]:
    response = client.post("/api/v1/alerts/ingest", json=_payload(), headers=AUTH_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _audit_rows(client: TestClient) -> list[Any]:
    factory: sessionmaker = client.app.state.session_factory
    with session_scope(factory) as session:
        return AuditRepository(session).all()


def test_credential_url_never_reaches_iocs_value_or_raw_value(client: TestClient) -> None:
    body = _ingest(client)

    urls = [ioc for ioc in body["iocs"] if ioc["type"] == "url"]
    assert [(ioc["value"], ioc["provenance"][0]["raw_value"]) for ioc in urls] == [
        (SANITIZED_URL, SANITIZED_URL)
    ]
    assert SECRET not in json.dumps(body["iocs"])


def test_credential_url_never_reaches_normalized_payload_or_response(client: TestClient) -> None:
    body = _ingest(client)

    assert body["normalized"]["source_event"]["data"]["url"] == SANITIZED_URL
    assert SECRET not in json.dumps(body["normalized"])
    assert SECRET not in json.dumps(body)


def test_credential_url_never_persisted_in_alert_of_record(client: TestClient) -> None:
    body = _ingest(client)
    factory: sessionmaker = client.app.state.session_factory
    with session_scope(factory) as session:
        stored = AlertRepository(session).get(UUID(body["alert_id"]))

    assert stored is not None
    assert SECRET not in stored.model_dump_json()
    assert stored.source_event.data["url"] == SANITIZED_URL


def test_credential_url_never_reaches_audit_records(client: TestClient) -> None:
    _ingest(client)

    for row in _audit_rows(client):
        assert SECRET not in json.dumps(row.before)
        assert SECRET not in json.dumps(row.after)


def test_credential_url_never_reaches_logs(client: TestClient, capsys: Any) -> None:
    _ingest(client)

    captured = capsys.readouterr()
    # The ingest path emits structured logs (application_started, alert_ingested,
    # alert_scored, …) — assert they exist so this check is not vacuous.
    assert captured.out
    assert SECRET not in captured.out
    assert SECRET not in captured.err
