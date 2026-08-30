"""Security tests for n8n integration (Phase 2B).

Covers:
* no secrets committed in workflow JSONs
* no raw API keys in workflow exports
* no unnecessary full_log forwarding
* no destructive actions
* no autonomous containment
* secret leakage in payloads and logs
"""

from __future__ import annotations

import json
import pathlib

REPO_ROOT = pathlib.Path(__file__).parents[3]
WORKFLOW_DIR = REPO_ROOT / "n8n" / "workflows"


def _load_workflows() -> list[pathlib.Path]:
    if not WORKFLOW_DIR.exists():
        return []
    return list(WORKFLOW_DIR.glob("*.json"))


def test_workflow_files_exist() -> None:
    workflows = _load_workflows()
    assert len(workflows) >= 2, "At least L1 notify and escalation workflows must exist"
    names = {p.name for p in workflows}
    assert any("router" in n.lower() for n in names)
    assert any("notify" in n.lower() or "l1" in n.lower() for n in names)
    assert any("escalation" in n.lower() or "incident" in n.lower() for n in names)


def test_no_secrets_in_workflow_jsons() -> None:
    """Ensure no raw secrets, API keys, or passwords in exported workflow JSONs."""
    workflows = _load_workflows()
    for wf_path in workflows:
        content = wf_path.read_text()
        data = json.loads(content)
        dumped = json.dumps(data).lower()

        # Security: workflows should not contain full_log as forwarded data
        # They may mention full_log in a validation that rejects it (allowed)
        for node in data.get("nodes", []):
            notes = node.get("notes", "").lower()
            params_str = json.dumps(node.get("parameters", {})).lower()
            if '\\"full_log\\"' in params_str:
                # Allowed only if node is a security validation
                assert "must not contain full_log" in params_str or "security" in notes, (
                    f"full_log reference without security validation in {wf_path.name}"
                )

        # Check for hardcoded secrets (excluding credential references)
        for pattern in ["change-me", "sk-live", "super-secret"]:
            assert pattern not in dumped, f"Potential secret pattern '{pattern}' in {wf_path.name}"

        # Ensure no raw token values (like test tokens) are in workflows
        assert "test-ingest-key-not-a-real-secret" not in dumped
        assert "test-callback-token-not-a-real-secret" not in dumped


def test_workflows_use_credential_references_not_secrets() -> None:
    """Workflows must use credential references not raw credentials."""
    workflows = _load_workflows()
    for wf_path in workflows:
        data = json.loads(wf_path.read_text())
        for node in data.get("nodes", []):
            creds = node.get("credentials", {})
            for _cred_type, cred_info in creds.items():
                if isinstance(cred_info, dict):
                    cred_id = cred_info.get("id", "")
                    # id should be a reference, not a secret value
                    low_id = cred_id.lower()
                    assert "secret" not in low_id or "ref" in low_id or "credential" in low_id
                    low_info = json.dumps(cred_info).lower()
                    assert "password" not in low_info or "reference" in low_info


def test_no_destructive_actions_in_workflows() -> None:
    """Ensure no destructive actions like host isolation, user disable, etc."""
    destructive_keywords = [
        "isolate_host",
        "disable_user",
        "shutdown",
        "reboot",
        "kill_process",
        "quarantine",
        "autonomous_containment",
    ]
    workflows = _load_workflows()
    for wf_path in workflows:
        content = wf_path.read_text().lower()
        for keyword in destructive_keywords:
            if keyword in content:
                # Allowed only if explicitly forbidding or requiring approval
                assert (
                    f"no {keyword}" in content
                    or "no autonomous" in content
                    or "human approval required" in content
                ), f"Destructive keyword {keyword} without approval note in {wf_path.name}"

        # Extra check: no SSH nodes that would do containment
        data = json.loads(wf_path.read_text())
        for node in data.get("nodes", []):
            node_type = node.get("type", "").lower()
            if "ssh" in node_type:
                assert "containment" not in content or "no autonomous" in content, (
                    f"Potential destructive SSH node in {wf_path.name}"
                )


def test_no_autonomous_containment() -> None:
    """Workflows must require human approval for response actions."""
    workflows = _load_workflows()
    for wf_path in workflows:
        data = json.loads(wf_path.read_text())
        content = json.dumps(data).lower()
        if "escalation" in wf_path.name.lower() or "contain" in content:
            assert "human" in content and "approval" in content, (
                f"Workflow {wf_path.name} must require human approval for containment"
            )
        meta_desc = data.get("meta", {}).get("description", "").lower()
        if meta_desc:
            assert (
                "no autonomous" in meta_desc
                or "human approval" in meta_desc
                or "no destructive" in meta_desc
            )


def test_no_full_log_forwarding_in_workflows() -> None:
    """Ensure workflows do not forward full_log field."""
    workflows = _load_workflows()
    for wf_path in workflows:
        data = json.loads(wf_path.read_text())
        for node in data.get("nodes", []):
            params = node.get("parameters", {})
            params_str = json.dumps(params).lower()
            if node.get("type") == "n8n-nodes-base.emailSend" and "full_log" in params_str:
                # Email body should be built from safe fields, not full_log
                assert "must not" in node.get("notes", "").lower()


def test_workflow_json_valid_n8n_structure() -> None:
    """Basic validation that workflow JSONs are valid n8n format."""
    workflows = _load_workflows()
    for wf_path in workflows:
        data = json.loads(wf_path.read_text())
        assert "name" in data
        assert "nodes" in data
        assert "connections" in data
        assert isinstance(data["nodes"], list)
        assert len(data["nodes"]) >= 2, f"Workflow {wf_path.name} should have at least 2 nodes"
        for node in data["nodes"]:
            assert "id" in node
            assert "name" in node
            assert "type" in node


def test_payload_schema_no_secret_leakage() -> None:
    """Ensure notification payload builder never includes secrets."""
    from datetime import UTC, datetime
    from uuid import uuid4

    from soc_triage.models.assessment import (
        Decision,
        DecisionAction,
        RiskAssessment,
        RiskTier,
        ScoreFactor,
    )
    from soc_triage.models.canonical import (
        CanonicalAgent,
        CanonicalAlert,
        CanonicalDedupe,
        CanonicalRule,
        CanonicalSourceEvent,
    )
    from soc_triage.notifications.payload import build_n8n_payload

    now = datetime(2026, 8, 30, 10, 0, 0, tzinfo=UTC)
    risk = RiskAssessment(
        score=50,
        tier=RiskTier.MEDIUM,
        engine_version="scoring.v1",
        factors=(ScoreFactor(name="rule_severity", points=14, max=40, detail="level 5"),),
        summary="Score 50",
    )
    decision = Decision(action=DecisionAction.QUEUE_L1, decided_at=now, reasons=("test",))
    alert = CanonicalAlert(
        alert_id=uuid4(),
        source="wazuh",
        received_at=now,
        source_event=CanonicalSourceEvent(
            rule=CanonicalRule(id="5710", level=5, description="test"),
            agent=CanonicalAgent(id="001", name="test"),
            full_log="secret should not be forwarded",
        ),
        dedupe=CanonicalDedupe(group_key="test", occurrences=1, first_seen=now, last_seen=now),
        risk=risk,
        decision=decision,
    )
    payload = build_n8n_payload(alert, dedupe_status="new_generation")
    dumped = json.dumps(payload.model_dump(mode="json")).lower()
    assert "secret should not be forwarded" not in dumped
    assert "full_log" not in dumped
