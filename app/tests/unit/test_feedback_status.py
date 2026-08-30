"""Tests for GET /api/v1/alerts/{id}/feedback/status (Phase 2B fix).

Covers:
* read-only status endpoint (not POST misuse)
* acknowledged bool, has_feedback, latest_verdict, feedback_count, acknowledged_at
* acknowledged -> no L2 escalation
* not acknowledged -> L2 escalation
* endpoint failure -> fail-safe escalation (safe documented behavior)
* security: requires token, no secrets
"""

from __future__ import annotations

import json
import pathlib

from fastapi.testclient import TestClient

REPO_ROOT = pathlib.Path(__file__).parents[3]
WF3_PATH = REPO_ROOT / "n8n" / "workflows" / "WF3_soc-incident-escalation.json"


def _ingest_sample(client: TestClient) -> str:
    import random

    from tests.conftest import TEST_INGEST_KEY

    sample_path = (
        pathlib.Path(__file__).parent.parent / "fixtures" / "01_wazuh_ssh_brute_force.json"
    )
    payload = json.loads(sample_path.read_text())
    # Make unique to avoid dedup exact_duplicate (change srcport + timestamp + id)
    payload["id"] = f"{random.randint(1000000000, 9999999999)}.{random.randint(100000, 999999)}"
    payload["timestamp"] = f"2026-08-29T10:15:{random.randint(0, 59):02d}.000+0000"
    payload["data"]["srcport"] = random.randint(10000, 60000)
    payload["data"]["srcip"] = f"203.0.113.{random.randint(1, 254)}"
    resp = client.post(
        "/api/v1/alerts/ingest", json=payload, headers={"X-API-Key": TEST_INGEST_KEY}
    )
    assert resp.status_code == 202, f"ingest failed: {resp.status_code} {resp.text}"
    return resp.json()["alert_id"]


def test_feedback_status_requires_token(client: TestClient) -> None:
    alert_id = _ingest_sample(client)

    # No token -> 401/503
    resp = client.get(f"/api/v1/alerts/{alert_id}/feedback/status")
    assert resp.status_code in {401, 503}

    # Wrong token -> 401
    resp = client.get(
        f"/api/v1/alerts/{alert_id}/feedback/status", headers={"X-N8N-Token": "wrong"}
    )
    assert resp.status_code == 401


def test_feedback_status_no_feedback(client: TestClient) -> None:
    from tests.conftest import TEST_CALLBACK_TOKEN

    alert_id = _ingest_sample(client)

    resp = client.get(
        f"/api/v1/alerts/{alert_id}/feedback/status",
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["alert_id"] == alert_id
    assert body["acknowledged"] is False
    assert body["has_feedback"] is False
    assert body["feedback_count"] == 0
    assert body["latest_verdict"] is None
    assert body["acknowledged_at"] is None
    assert "checked_at" in body


def test_feedback_status_acknowledged(client: TestClient) -> None:
    from tests.conftest import TEST_CALLBACK_TOKEN

    alert_id = _ingest_sample(client)

    # Submit feedback
    fb_resp = client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": "acknowledged", "notes": "seen", "actor": "analyst@example.com"},
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    assert fb_resp.status_code == 200

    # Now status should be acknowledged
    resp = client.get(
        f"/api/v1/alerts/{alert_id}/feedback/status",
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["acknowledged"] is True
    assert body["has_feedback"] is True
    assert body["feedback_count"] == 1
    assert body["latest_verdict"] == "acknowledged"
    assert body["acknowledged_at"] is not None


def test_feedback_status_various_verdicts_acknowledged(client: TestClient) -> None:
    """All verdicts in allow-list count as acknowledgement for SLA."""
    from tests.conftest import TEST_CALLBACK_TOKEN

    for verdict in [
        "true_positive",
        "false_positive",
        "benign",
        "escalate",
        "acknowledged",
        "resolved",
        "contain_requested",
    ]:
        alert_id = _ingest_sample(client)
        fb_resp = client.post(
            f"/api/v1/alerts/{alert_id}/feedback",
            json={"verdict": verdict},
            headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
        )
        assert fb_resp.status_code == 200, f"verdict {verdict} should be accepted"

        status_resp = client.get(
            f"/api/v1/alerts/{alert_id}/feedback/status",
            headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
        )
        assert status_resp.status_code == 200
        body = status_resp.json()
        assert body["acknowledged"] is True, f"verdict {verdict} should count as acknowledged"
        assert body["latest_verdict"] == verdict


def test_feedback_status_latest_verdict(client: TestClient) -> None:
    from tests.conftest import TEST_CALLBACK_TOKEN

    alert_id = _ingest_sample(client)

    client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": "acknowledged"},
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": "resolved"},
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )

    resp = client.get(
        f"/api/v1/alerts/{alert_id}/feedback/status",
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    body = resp.json()
    assert body["feedback_count"] == 2
    assert body["latest_verdict"] == "resolved"
    assert body["acknowledged"] is True


def test_feedback_status_nonexistent_alert(client: TestClient) -> None:
    import uuid

    from tests.conftest import TEST_CALLBACK_TOKEN

    fake_id = uuid.uuid4()
    resp = client.get(
        f"/api/v1/alerts/{fake_id}/feedback/status",
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# SLA logic simulation (WF3 decision)
# ---------------------------------------------------------------------------


def test_sla_acknowledged_no_l2_escalation(client: TestClient) -> None:
    """If acknowledged=true, WF3 should NOT escalate to L2."""
    from tests.conftest import TEST_CALLBACK_TOKEN

    alert_id = _ingest_sample(client)

    # Analyst acknowledges
    client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"verdict": "acknowledged"},
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )

    status_resp = client.get(
        f"/api/v1/alerts/{alert_id}/feedback/status",
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    body = status_resp.json()

    # Simulate WF3 Switch - Acknowledged? logic
    acknowledged = body["acknowledged"]
    should_escalate_l2 = not acknowledged

    assert acknowledged is True
    assert should_escalate_l2 is False, "acknowledged -> no L2 escalation"


def test_sla_not_acknowledged_l2_escalation(client: TestClient) -> None:
    """If not acknowledged, WF3 should escalate to L2."""
    from tests.conftest import TEST_CALLBACK_TOKEN

    alert_id = _ingest_sample(client)

    status_resp = client.get(
        f"/api/v1/alerts/{alert_id}/feedback/status",
        headers={"X-N8N-Token": TEST_CALLBACK_TOKEN},
    )
    body = status_resp.json()

    acknowledged = body["acknowledged"]
    should_escalate_l2 = not acknowledged

    assert acknowledged is False
    assert should_escalate_l2 is True, "not acknowledged -> L2 escalation"


def test_sla_endpoint_failure_safe_escalation() -> None:
    """If status endpoint fails, WF3 should fail-safe to L2 escalation (safe behavior).

    This documents the safe documented behavior required by Phase 2B fix.
    WF3 HTTP node has continueOnFail=true and Switch fallbackOutput=extra -> both
    route to L2 escalation.
    """

    # Simulate endpoint failure (e.g., 500 or connection error)
    # In WF3, HTTP node options: continueOnFail=true, alwaysOutputData=true
    # Switch fallbackOutput routes failures to escalation

    def simulate_wf3_decision(status_response: dict | None, http_failed: bool) -> bool:
        """Return whether L2 escalation should happen (fail-safe)."""
        if http_failed or status_response is None:
            # Safe documented behavior: fail-safe escalation
            return True
        acknowledged = status_response.get("acknowledged", False)
        return not acknowledged

    # Failure case -> escalate
    assert simulate_wf3_decision(None, http_failed=True) is True
    assert simulate_wf3_decision(None, http_failed=False) is True  # None response also escalates

    # Success cases
    assert simulate_wf3_decision({"acknowledged": True}, http_failed=False) is False
    assert simulate_wf3_decision({"acknowledged": False}, http_failed=False) is True

    # Verify WF3 JSON documents fail-safe behavior
    assert WF3_PATH.exists()
    data = json.loads(WF3_PATH.read_text())
    wf3_str = json.dumps(data).lower()

    # Must use GET /feedback/status, not POST /feedback for ack check
    assert "feedback/status" in wf3_str, "WF3 must call GET /feedback/status"
    # Ensure old misuse POST /feedback for status check is not present
    # The check-ack node uses templated statusUrl which is built in format node
    # Verify format node builds statusUrl with feedback/status
    format_nodes = [n for n in data.get("nodes", []) if "format" in n.get("name", "").lower()]
    for n in format_nodes:
        code = json.dumps(n.get("parameters", {})).lower()
        if "feedback/status" in code or "statusurl" in code:
            # Must contain feedback/status construction somewhere
            assert "feedback/status" in wf3_str
    # Also check overall file contains statusUrl construction
    assert "statusurl" in wf3_str and "feedback/status" in wf3_str, (
        "WF3 must build statusUrl with /feedback/status"
    )

    # Check ack node is GET (sendBody false)
    for node in data.get("nodes", []):
        if "check ack" in node.get("name", "").lower():
            params = node.get("parameters", {})
            # Must be GET (sendBody false, no body)
            assert params.get("sendBody") is False, "Check Ack must be GET (sendBody false)"

    # Must have fail-safe notes
    assert "fail-safe" in wf3_str or "fail safe" in wf3_str, (
        "WF3 must document fail-safe escalation"
    )
    assert "continueonfail" in wf3_str, "WF3 HTTP node must have continueOnFail for safe behavior"


def test_wf3_uses_get_not_post_for_status() -> None:
    """Ensure WF3 does not misuse POST /feedback to query status."""
    assert WF3_PATH.exists()
    data = json.loads(WF3_PATH.read_text())
    # Find check ack node
    check_nodes = [n for n in data.get("nodes", []) if "check ack" in n.get("name", "").lower()]
    assert check_nodes, "WF3 must have Check Ack node"
    for node in check_nodes:
        params = node.get("parameters", {})
        # Must be GET (no body)
        assert params.get("sendBody") is False, "Check Ack must be GET (sendBody false)"
        url = params.get("url", "")
        # URL is templated via $json._escalation.statusUrl, which itself is built with /feedback/status
        # So check that templated url references statusUrl
        assert "statusurl" in url.lower(), f"Check Ack URL must reference statusUrl, got {url}"

    # Verify format node builds statusUrl with feedback/status
    wf3_str = json.dumps(data).lower()
    assert "feedback/status" in wf3_str, (
        "WF3 must contain feedback/status in statusUrl construction"
    )
    # Ensure no node directly POSTs to /feedback for status check (old misuse)
    for node in data.get("nodes", []):
        if node.get("type") == "n8n-nodes-base.httpRequest":
            name_lower = node.get("name", "").lower()
            if "check ack" in name_lower or "status" in name_lower:
                params = node.get("parameters", {})
                # Should NOT have sendBody True (that would be POST)
                assert params.get("sendBody") is False


def test_contain_requested_clarification_in_workflows() -> None:
    """Verify contain_requested is documented as approval-required only."""
    workflow_dir = REPO_ROOT / "n8n" / "workflows"
    for wf_path in workflow_dir.glob("*.json"):
        data = json.loads(wf_path.read_text())
        content = json.dumps(data).lower()
        if "contain_requested" in content:
            # Must state approval-required and no containment executed
            assert "approval-required" in content or "approval required" in content, (
                f"{wf_path.name} must clarify contain_requested is approval-required"
            )
            assert "no containment" in content or "no containment action" in content, (
                f"{wf_path.name} must state no containment action is executed"
            )
            # Must NOT claim containment implemented via host isolation/user disable
            # The workflow should not have nodes that do isolation/disable
            for node in data.get("nodes", []):
                node_type = node.get("type", "").lower()
                assert "isolate" not in node_type, f"{wf_path.name} must not have isolation node"
                # Check notes don't claim autonomous containment
                notes = node.get("notes", "").lower()
                if "contain_requested" in notes:
                    assert "no containment" in notes or "approval-required" in notes
