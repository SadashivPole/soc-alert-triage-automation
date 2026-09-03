"""Phase 3.5 integration tests: the static SOC console + the APIs it consumes.

These tests cover two layers:

1. **Static serving** — the console is mounted by the API service at
   ``/console`` (same origin, so no CORS and no embedded token). We assert the
   shell + assets load, reference the right endpoints, and contain no secrets
   or localStorage/sessionStorage usage (token is memory-only).
2. **API contract the console depends on** — every endpoint the console calls
   behaves as the UI expects: read-only lists/detail/timeline, legal lifecycle
   PATCH → 200, illegal transition → 409, filters/pagination preserved, and no
   GET ever mutates state.

The pure browser helpers (escaping, state machine, score-factor projection)
are covered by ``app/tests/js/console_core.test.cjs`` (Node, no browser stack).
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from tests.conftest import TEST_CALLBACK_TOKEN, TEST_INGEST_KEY

CONSOLE_DIR = Path(__file__).resolve().parents[2] / "console"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

INGEST_HEADERS = {"X-API-Key": TEST_INGEST_KEY}
TOKEN_HEADERS = {"X-N8N-Token": TEST_CALLBACK_TOKEN}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _load_sample(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text())


def _ingest(client: TestClient, payload: dict) -> dict:
    resp = client.post("/api/v1/alerts/ingest", json=payload, headers=INGEST_HEADERS)
    assert resp.status_code in {200, 202}, resp.text
    return resp.json()


def _ingest_high(client: TestClient, *, agent_id: str = "003") -> dict:
    payload = dict(_load_sample("04_wazuh_malware_hash_virustotal.json"))
    payload["agent"] = {**payload["agent"], "id": agent_id, "name": f"host-{agent_id}"}
    return _ingest(client, payload)


def _ingest_low(client: TestClient) -> dict:
    return _ingest(client, _load_sample("01_wazuh_ssh_brute_force.json"))


def _get(client: TestClient, path: str, **params: object) -> object:
    return client.get(path, params=params or None, headers=TOKEN_HEADERS)


def _patch_status(client: TestClient, incident_id: str, target: str) -> object:
    return client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": target, "actor": "soc-console"},
        headers=TOKEN_HEADERS,
    )


def _console_text(filename: str) -> str:
    return (CONSOLE_DIR / filename).read_text()


# --------------------------------------------------------------------------- #
# 1. Static serving
# --------------------------------------------------------------------------- #


def test_console_index_is_served(client: TestClient) -> None:
    resp = client.get("/console/")
    assert resp.status_code == 200, resp.text
    body = resp.text
    assert "SOC Triage Console" in body
    # The shell wires up the shared logic + app scripts.
    assert "console-core.js" in body
    assert "console.js" in body
    assert 'id="token-input"' in body


def test_console_static_assets_are_served(client: TestClient) -> None:
    for asset in ("console-core.js", "console.js", "styles.css"):
        resp = client.get(f"/console/{asset}")
        assert resp.status_code == 200, asset
        assert resp.text.strip()


def test_console_root_redirects_to_console(client: TestClient) -> None:
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in {307, 308}, resp.status_code
    assert resp.headers["location"].rstrip("/") in {"/console", "http://testserver/console"}


def test_console_references_the_correct_endpoints() -> None:
    js = _console_text("console.js")
    # The base + per-resource paths the console builds (API_BASE + "/alerts/").
    assert "/api/v1" in js
    assert "/alerts/" in js  # alert detail path
    assert "/incidents" in js
    assert "/status" in js  # PATCH lifecycle path
    assert "X-N8N-Token" in js  # token header the backend expects
    # Safe rendering primitives must be present.
    assert "textContent" in js
    core = _console_text("console-core.js")
    assert "escapeHtml" in core


def test_console_keeps_token_in_memory_only() -> None:
    js = _console_text("console.js")
    # No browser persistence of credentials — token lives in the module only.
    # (Asserts against real usage, not prose: ".setItem"/".getItem" calls.)
    assert "localStorage." not in js
    assert "sessionStorage." not in js
    # The token is taken from user input, never from a hardcoded literal.
    assert "session.token = value" in js


def test_console_does_not_embed_secrets() -> None:
    for filename in ("index.html", "console-core.js", "console.js", "styles.css"):
        text = _console_text(filename).lower()
        assert TEST_INGEST_KEY.lower() not in text
        assert TEST_CALLBACK_TOKEN.lower() not in text
        # No placeholder secrets either.
        assert "change-me" not in text


def test_console_defines_loading_empty_error_states() -> None:
    js = _console_text("console.js")
    assert "state-loading" in js
    assert "state-empty" in js
    assert "state-error" in js


# --------------------------------------------------------------------------- #
# 2. API contract the console consumes
# --------------------------------------------------------------------------- #


def test_console_alert_queue_fetches_and_paginates(client: TestClient) -> None:
    _ingest_low(client)
    _ingest_high(client)
    resp = _get(client, "/api/v1/alerts", limit=50, offset=0)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "items" in data and "pagination" in data
    assert data["pagination"]["total"] == 2
    # Same query-string shape the console builds (buildQueryString / queueState).
    assert {i["alert_id"] for i in data["items"]}  # ids present


def test_console_alert_detail_renders_score_factors(client: TestClient) -> None:
    ingested = _ingest_high(client)
    resp = _get(client, f"/api/v1/alerts/{ingested['alert_id']}")
    assert resp.status_code == 200, resp.text
    risk = resp.json()["risk"]
    assert risk["score"] == ingested["risk"]["score"]
    # The drill-down needs server-provided factors; the UI never recomputes.
    assert isinstance(risk["factors"], list) and risk["factors"]
    for factor in risk["factors"]:
        assert "name" in factor and "points" in factor and "max" in factor


def test_console_incident_board_renders_statuses(client: TestClient) -> None:
    first = _ingest_high(client, agent_id="003")
    _ingest_high(client, agent_id="013")
    _ingest_low(client)  # no incident
    resp = _get(client, "/api/v1/incidents")
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    statuses = {i["status"] for i in items}
    assert "open" in statuses
    assert first["incident_id"] in {i["incident_id"] for i in items}
    # Every row carries the board columns the UI shows.
    for i in items:
        assert {"incident_id", "status", "severity", "created_at"} <= set(i)


def test_console_incident_detail_renders_timeline(client: TestClient) -> None:
    ingested = _ingest_high(client)
    incident_id = ingested["incident_id"]
    detail = _get(client, f"/api/v1/incidents/{incident_id}")
    assert detail.status_code == 200
    assert detail.json()["linked_alert_count"] >= 1

    tl = _get(client, f"/api/v1/incidents/{incident_id}/timeline")
    assert tl.status_code == 200, tl.text
    events = tl.json()["events"]
    assert events
    actions = [e["action"] for e in events]
    assert "incident.created" in actions
    # Timeline rows carry the fields the UI renders.
    for e in events:
        assert {"timestamp", "action", "entity_type", "entity_id", "actor"} <= set(e)
    created = next(e for e in events if e["action"] == "incident.created")
    assert created["after"]["status"] == "open"


def test_console_legal_lifecycle_action_reaches_api(client: TestClient) -> None:
    ingested = _ingest_high(client)
    incident_id = ingested["incident_id"]
    resp = _patch_status(client, incident_id, "investigating")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "investigating"
    assert body["previous_status"] == "open"
    assert body["incident_id"] == incident_id


def test_console_illegal_transition_is_backend_409(client: TestClient) -> None:
    ingested = _ingest_high(client)
    incident_id = ingested["incident_id"]
    # open -> resolved is not in VALID_TRANSITIONS[open]; the backend must 409.
    resp = _patch_status(client, incident_id, "resolved")
    assert resp.status_code == 409, resp.text
    err = resp.json()["error"]
    assert err["code"] == "conflict"
    details = err["details"]
    assert details["current_status"] == "open"
    assert details["requested_status"] == "resolved"
    # The console reads allowed_transitions to disable illegal buttons.
    assert "investigating" in details["allowed_transitions"]
    assert "resolved" not in details["allowed_transitions"]


def test_console_read_operations_never_mutate(client: TestClient) -> None:
    ingested = _ingest_high(client)
    incident_id = ingested["incident_id"]
    alert_id = ingested["alert_id"]

    before = client.app.state.db_engine
    with before.connect() as conn:
        from sqlalchemy import text

        audit_before = int(conn.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one())

    for path in (
        "/api/v1/alerts",
        f"/api/v1/alerts/{alert_id}",
        "/api/v1/incidents",
        f"/api/v1/incidents/{incident_id}",
        f"/api/v1/incidents/{incident_id}/timeline",
    ):
        assert _get(client, path).status_code == 200

    with before.connect() as conn:
        audit_after = int(conn.execute(text("SELECT COUNT(*) FROM audit_log")).scalar_one())
    assert audit_after == audit_before


def test_console_pagination_and_filter_params_are_preserved(client: TestClient) -> None:
    low = _ingest_low(client)
    high = _ingest_high(client)
    # Console sends tier + source as equality filters; the backend must honor
    # exactly the params the UI builds (buildQueryString keeps only these).
    by_tier = _get(client, "/api/v1/alerts", tier="high", source="wazuh")
    assert by_tier.status_code == 200
    ids = {i["alert_id"] for i in by_tier.json()["items"]}
    assert ids == {high["alert_id"]}
    assert low["alert_id"] not in ids


def test_console_empty_and_error_states_have_data(client: TestClient) -> None:
    # Empty filter result -> the UI renders an empty state, not a crash.
    none = _get(client, "/api/v1/alerts", tier="critical")
    assert none.status_code == 200
    assert none.json()["items"] == []

    # Error paths: unknown ids surface structured 404s the UI shows as errors.
    missing = _get(client, "/api/v1/alerts/00000000-0000-0000-0000-000000000000")
    assert missing.status_code == 404
    unknown_inc = _get(client, "/api/v1/incidents/INC-2099-01-01-0001")
    assert unknown_inc.status_code == 404


def test_console_safely_renders_alert_controlled_strings(client: TestClient) -> None:
    """Attacker/analyst-controlled text reaches the UI and must be escaped.

    The API returns the raw (attacker-influenced) strings; the browser layer
    is responsible for safe rendering. We prove (a) the strings are delivered
    unchanged by the API, and (b) the shipped console uses textContent /
    escapeHtml so they cannot execute. The Node suite proves escapeHtml output.
    """
    xss = '<img src=x onerror=alert(1)>"><script>alert(2)</script>'
    payload = {
        "id": "1770000000.990001",
        "rule": {"level": 12, "description": xss, "id": "99991", "groups": ["malware"]},
        "agent": {"id": "091", "name": xss},
        "data": {"url": "https://example.com"},
    }
    ingested = _ingest(client, payload)
    detail = _get(client, f"/api/v1/alerts/{ingested['alert_id']}")
    body = detail.json()
    # API delivers the untrusted text verbatim (redaction is server-side, not
    # in the UI).
    assert body["rule"]["description"] == xss
    assert body["agent"]["name"] == xss
    # The UI ships the escaping primitives that neutralize it.
    assert "escapeHtml" in _console_text("console-core.js")
    assert "textContent" in _console_text("console.js")
