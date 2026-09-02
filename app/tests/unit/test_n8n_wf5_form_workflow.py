"""Static regression coverage for the WF5 n8n Form runtime fix (Phase 2E).

Root cause being locked out: the checked-in WF5 wired a plain Webhook node
(via a Function node) into an ``n8n-nodes-base.form`` ("Form - Feedback")
page. On n8n 1.85.0 a Form page requires an actual ``n8n-nodes-base.formTrigger``
upstream — in the editor the node showed
"An n8n Form Trigger node must be set up before this node." and at runtime
``Form.node.ts`` throws ``NodeOperationError: Form Trigger node must be set
before this node`` (verified against the n8n@1.85.0 source,
``packages/nodes-base/nodes/Form/Form.node.ts``).

The fix turns WF5 into a valid n8n Form workflow:

    Form Trigger - Analyst Feedback   (/form/soc-analyst-feedback-form, page 1)
      -> Form - Feedback              (page 2: verdict allow-list + notes)
      -> Validate Form & Verdict      (merge pages, allow-list, no full_log)
    Webhook - Analyst Feedback        (machine entry, unchanged token gate)
      -> Validate Token & Verdict
    .. both merge at: HTTP - POST Feedback to API -> Switch - Contain Requested?
      -> contain: Email - Containment Approval Request -> Respond - Feedback OK
      -> else:    Respond - Feedback OK (+ formSubmittedText for the form UI)

n8n 1.85.0 runtime rules these tests enforce (all verified in the n8n source):
* Form pages must have a ``formTrigger`` ancestor and must never hang off a
  plain webhook (``Form.node.ts`` throws otherwise).
* A ``respondToWebhook`` node downstream of a formTrigger v2.2+ is rejected at
  submission time ("The 'Respond to Webhook' node is not supported in
  workflows initiated by the 'n8n Form Trigger'"); for v<=2.1 the trigger must
  set ``responseMode=responseNode`` (``Form/utils.ts ::
  validateResponseModeConfiguration``).

Docker is unavailable in this sandbox, so these tests statically pin the exact
structure the lab exercises at runtime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIR = REPO_ROOT / "n8n" / "workflows"
WF5_FILE = WORKFLOW_DIR / "WF5_soc-analyst-feedback.json"

FORM_TRIGGER_TYPE = "n8n-nodes-base.formTrigger"
FORM_NODE_TYPE = "n8n-nodes-base.form"
WEBHOOK_TYPE = "n8n-nodes-base.webhook"
FUNCTION_TYPE = "n8n-nodes-base.function"
RESPOND_TYPE = "n8n-nodes-base.respondToWebhook"
HTTP_TYPE = "n8n-nodes-base.httpRequest"
EMAIL_TYPE = "n8n-nodes-base.emailSend"
SWITCH_TYPE = "n8n-nodes-base.switch"

WF5_STABLE_ID = "wf5-soc-analyst-feedback"
FORM_TRIGGER_NAME = "Form Trigger - Analyst Feedback"
FORM_PAGE_NAME = "Form - Feedback"
VALIDATE_FORM_NAME = "Validate Form & Verdict"
WEBHOOK_NAME = "Webhook - Analyst Feedback"
VALIDATE_TOKEN_NAME = "Validate Token & Verdict"
HTTP_POST_NAME = "HTTP - POST Feedback to API"
SWITCH_NAME = "Switch - Contain Requested?"
EMAIL_NAME = "Email - Containment Approval Request"
RESPOND_NAME = "Respond - Feedback OK"

#: n8n 1.85.0 Form Trigger versions that still permit a Respond to Webhook
#: node downstream (v2.2+ hard-rejects it at submission time).
MAX_FORM_TRIGGER_VERSION_WITH_RESPOND = 2.1

VERDICT_ALLOW_LIST = [
    "true_positive",
    "false_positive",
    "benign",
    "escalate",
    "acknowledged",
    "resolved",
    "contain_requested",
]

#: Verdicts that must stay non-destructive (approval-only, human in the loop).
DESTRUCTIVE_NODE_TYPES = {
    "n8n-nodes-base.ssh",
    "n8n-nodes-base.executeCommand",
    "n8n-nodes-base.aws",
    "n8n-nodes-base.microsoftDynamics",
}


def _load_wf5() -> dict[str, Any]:
    return json.loads(WF5_FILE.read_text(encoding="utf-8"))


def _load_all_workflows() -> dict[str, dict[str, Any]]:
    return {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(WORKFLOW_DIR.glob("*.json"))
    }


def _nodes(workflow: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {node["name"]: node for node in workflow.get("nodes", [])}


def _node(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    nodes = _nodes(workflow)
    assert name in nodes, f"WF5 is missing expected node: {name!r}"
    return nodes[name]


def _adjacency(workflow: dict[str, Any]) -> dict[str, list[str]]:
    """Flat main-connection adjacency (all output branches merged)."""
    adjacency: dict[str, list[str]] = {}
    for source, connection in workflow.get("connections", {}).items():
        targets: list[str] = []
        for branch in connection.get("main", []):
            targets.extend(entry["node"] for entry in branch)
        adjacency.setdefault(source, []).extend(targets)
    return adjacency


def _ancestors(workflow: dict[str, Any], name: str) -> set[str]:
    """All node names reachable upstream of ``name`` via main connections."""
    adjacency = _adjacency(workflow)
    seen: set[str] = set()
    # Invert source->targets so we can walk upstream from `name`.
    inverted: dict[str, list[str]] = {}
    for source, targets in adjacency.items():
        for target in targets:
            inverted.setdefault(target, []).append(source)
    stack = list(inverted.get(name, []))
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(inverted.get(current, []))
    return seen


def _descendants(workflow: dict[str, Any], name: str) -> set[str]:
    adjacency = _adjacency(workflow)
    seen: set[str] = set()
    stack = list(adjacency.get(name, []))
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(adjacency.get(current, []))
    return seen


def _reaches(workflow: dict[str, Any], source: str, target: str) -> bool:
    return target in _descendants(workflow, source)


def _form_field_labels(node: dict[str, Any]) -> list[str]:
    values = node.get("parameters", {}).get("formFields", {}).get("values", [])
    return [entry.get("fieldLabel", "") for entry in values]


def _verdict_options(node: dict[str, Any]) -> list[str]:
    fields = node.get("parameters", {}).get("formFields", {}).get("values", [])
    for field in fields:
        if field.get("fieldLabel") == "Verdict":
            entries = field.get("fieldOptions", {}).get("values", [])
            return [entry.get("option", "") for entry in entries]
    return []


# ---------------------------------------------------------------------------
# 1. Valid n8n Form chain: Form Trigger + Form page
# ---------------------------------------------------------------------------


def test_wf5_contains_form_trigger() -> None:
    """WF5 must contain the n8n Form Trigger the Form page requires."""
    workflow = _load_wf5()
    triggers = [n for n in workflow["nodes"] if n["type"] == FORM_TRIGGER_TYPE]
    assert len(triggers) == 1, "WF5 must contain exactly one n8n Form Trigger node"
    trigger = triggers[0]
    assert trigger["name"] == FORM_TRIGGER_NAME
    # Production form URL comes from `path` (v2.1 top-level parameter).
    assert trigger["parameters"]["path"] == "soc-analyst-feedback-form"
    assert trigger["parameters"]["formTitle"] == "SOC Alert Feedback"
    # A form page renders 'Problem loading form' with zero fields on 1.85.0,
    # so the trigger page must collect at least one field itself.
    assert _form_field_labels(trigger), "Form Trigger page must define fields"


def test_wf5_form_page_has_form_trigger_upstream() -> None:
    """The 'Form - Feedback' page must be a valid page in a Form chain."""
    workflow = _load_wf5()
    page = _node(workflow, FORM_PAGE_NAME)
    assert page["type"] == FORM_NODE_TYPE
    assert page["parameters"].get("operation") == "page", (
        "Form - Feedback must be a 'Next Form Page' (operation=page)"
    )
    ancestors = _ancestors(workflow, FORM_PAGE_NAME)
    assert FORM_TRIGGER_NAME in ancestors, (
        "Form - Feedback must have the Form Trigger upstream "
        "(n8n 1.85.0 throws 'Form Trigger node must be set before this node' otherwise)"
    )
    # The chain order is exactly trigger -> page -> validation.
    adjacency = _adjacency(workflow)
    assert adjacency[FORM_TRIGGER_NAME] == [FORM_PAGE_NAME]
    assert adjacency[FORM_PAGE_NAME] == [VALIDATE_FORM_NAME]


def test_form_trigger_version_supports_shared_respond_node() -> None:
    """n8n 1.85.0: respondToWebhook downstream of a v2.2+ Form Trigger fails.

    ``validateResponseModeConfiguration`` throws
    'The "Respond to Webhook" node is not supported in workflows initiated by
    the "n8n Form Trigger"' for typeVersion > 2.1. For <= 2.1 it requires
    responseMode='responseNode'. WF5 shares the Respond node between the form
    and webhook entries, so the trigger must satisfy the v2.1 contract.
    """
    workflow = _load_wf5()
    trigger = _node(workflow, FORM_TRIGGER_NAME)
    respond_downstream = RESPOND_NAME in _descendants(workflow, FORM_TRIGGER_NAME)
    assert respond_downstream, "expected the shared Respond node downstream of the form"

    version = float(trigger["typeVersion"])
    if version > MAX_FORM_TRIGGER_VERSION_WITH_RESPOND:
        raise AssertionError(
            "Form Trigger typeVersion > 2.1 with a Respond to Webhook node downstream "
            "is rejected by n8n 1.85.0 at submission time"
        )
    assert trigger["parameters"].get("responseMode") == "responseNode", (
        "Form Trigger <= 2.1 with respondToWebhook downstream must set "
        "responseMode=responseNode (n8n 1.85.0 validation)"
    )


# ---------------------------------------------------------------------------
# 2. Webhook/token security behavior remains intact
# ---------------------------------------------------------------------------


def test_webhook_entry_and_token_gate_preserved() -> None:
    """The machine webhook entry keeps its path and token-validation gate."""
    workflow = _load_wf5()
    webhook = _node(workflow, WEBHOOK_NAME)
    assert webhook["type"] == WEBHOOK_TYPE
    assert webhook["parameters"]["httpMethod"] == "POST"
    assert webhook["parameters"]["path"] == "soc-analyst-feedback"
    assert webhook["parameters"]["responseMode"] == "responseNode"

    validate = _node(workflow, VALIDATE_TOKEN_NAME)
    assert validate["type"] == FUNCTION_TYPE
    code = validate["parameters"]["functionCode"]
    # Exact-match shared-token validation (Phase 2B) must remain.
    assert "$env.N8N_WEBHOOK_TOKEN || $env.N8N_CALLBACK_TOKEN" in code
    assert "Server misconfigured: shared token not set in n8n env" in code
    assert "Missing authentication token - X-N8N-Token required" in code
    assert "Invalid authentication token" in code
    assert "supplied !== expected" in code, "token comparison must stay an exact match"
    # Verdict allow-list + full_log rejection must remain.
    for verdict in VERDICT_ALLOW_LIST:
        assert verdict in code
    assert "must not contain full_log" in code

    adjacency = _adjacency(workflow)
    assert adjacency[WEBHOOK_NAME] == [VALIDATE_TOKEN_NAME]
    assert adjacency[VALIDATE_TOKEN_NAME] == [HTTP_POST_NAME], (
        "the webhook branch must go straight to the HTTP POST node"
    )


def test_form_branch_keeps_security_controls() -> None:
    """The form branch enforces the same allow-list and full_log rejection."""
    workflow = _load_wf5()
    validate_form = _node(workflow, VALIDATE_FORM_NAME)
    code = validate_form["parameters"]["functionCode"]
    for verdict in VERDICT_ALLOW_LIST:
        assert verdict in code, f"form-branch validation lost verdict {verdict}"
    assert "not in allow-list" in code
    assert "must not contain full_log" in code
    assert "alert_id" in code and "verdict" in code and "notes" in code
    assert "analyst_email" in code, "form validation must map analyst_email"
    # Reads both form pages so alert_id survives into the shared HTTP POST.
    assert f"$('{FORM_TRIGGER_NAME}')" in code
    assert "approval-required" in code, (
        "contain_requested must be documented as approval-required in the form branch"
    )


# ---------------------------------------------------------------------------
# 3. Required form fields remain present
# ---------------------------------------------------------------------------


def test_required_feedback_fields_preserved() -> None:
    """alert_id, verdict, notes and analyst_email must all stay on the form."""
    workflow = _load_wf5()
    trigger = _node(workflow, FORM_TRIGGER_NAME)
    page = _node(workflow, FORM_PAGE_NAME)
    labels = _form_field_labels(trigger) + _form_field_labels(page)
    for label in ("Alert ID", "Verdict", "Notes", "Analyst Email"):
        assert label in labels, f"feedback form lost field {label!r}"

    # Required flags preserved: Alert ID + Verdict required, others optional.
    trigger_fields = {f["fieldLabel"]: f for f in trigger["parameters"]["formFields"]["values"]}
    page_fields = {f["fieldLabel"]: f for f in page["parameters"]["formFields"]["values"]}
    assert trigger_fields["Alert ID"]["requiredField"] is True
    assert trigger_fields["Analyst Email"]["requiredField"] is False
    assert page_fields["Verdict"]["requiredField"] is True
    assert page_fields["Notes"]["requiredField"] is False
    assert page_fields["Verdict"]["fieldType"] == "dropdown"

    # Fields are split across the two pages; every field must exist exactly once.
    assert sorted(labels) == sorted(["Alert ID", "Analyst Email", "Verdict", "Notes"]), (
        "form fields must not be duplicated or dropped"
    )


def test_verdict_allow_list_preserved_on_form() -> None:
    """The dropdown must offer exactly the 7 allowed verdicts."""
    workflow = _load_wf5()
    options = _verdict_options(_node(workflow, FORM_PAGE_NAME))
    expected = [
        *VERDICT_ALLOW_LIST[:-1],
        "contain_requested (approval-required, no auto containment)",
    ]
    assert options == expected, f"verdict allow-list changed: {options}"
    # The workflow strips the approval suffix before POSTing to the API.
    http_code = json.dumps(_node(workflow, HTTP_POST_NAME)["parameters"])
    assert "(approval-required, no auto containment)" in http_code


# ---------------------------------------------------------------------------
# 4. contain_requested stays approval-only
# ---------------------------------------------------------------------------


def test_contain_requested_is_approval_only() -> None:
    """contain_requested may only create an approval request — never act."""
    workflow = _load_wf5()

    # The only containment outcome is an approval email.
    email = _node(workflow, EMAIL_NAME)
    assert email["type"] == EMAIL_TYPE
    assert "APPROVAL REQUIRED" in email["parameters"]["subject"]
    assert "no containment action is executed" in email["parameters"]["text"]
    assert "Human approval required" in email["parameters"]["text"]

    # Switch output 0 (contain_requested) routes ONLY to the email node.
    switch_branches = workflow["connections"][SWITCH_NAME]["main"]
    assert [entry["node"] for entry in switch_branches[0]] == [EMAIL_NAME]
    assert [entry["node"] for entry in switch_branches[1]] == [RESPOND_NAME]

    # The routing rule must use the Switch v3 rules format. The old JSON carried
    # IF-node-style `conditions.string` parameters which Switch ignores entirely,
    # so no branch ever fired and the Respond node was never reached (runtime
    # bug found during n8n 1.85.0 validation).
    switch = _node(workflow, SWITCH_NAME)
    assert switch["typeVersion"] >= 3, "Switch must use the v3 (rules) node version"
    rules = switch["parameters"]["rules"]["values"]
    assert len(rules) == 1, "exactly one routing rule: contain_requested -> approval"
    rule_conditions = rules[0]["conditions"]["conditions"]
    assert rule_conditions[0]["leftValue"] == "={{ $json.verdict }}"
    assert rule_conditions[0]["rightValue"] == "contain_requested"
    assert rule_conditions[0]["operator"]["operation"] == "contains"
    # Everything else falls through to the recorded/Respond branch.
    assert switch["parameters"]["options"]["fallbackOutput"] == "extra"

    # No node type in WF5 can execute an action against a host/account.
    for node in workflow["nodes"]:
        assert node["type"] not in DESTRUCTIVE_NODE_TYPES
        assert node["type"] != FORM_NODE_TYPE or node["name"] == FORM_PAGE_NAME

    # Approval-only language preserved end to end.
    dumped = json.dumps(workflow).lower()
    assert "human approval" in dumped
    assert "no autonomous" in dumped
    assert "approval-required" in dumped


# ---------------------------------------------------------------------------
# 5. API contract + flow integrity
# ---------------------------------------------------------------------------


def test_form_submission_reaches_http_post_node() -> None:
    """Requirement: the form submission reaches HTTP - POST Feedback to API."""
    workflow = _load_wf5()
    assert _reaches(workflow, FORM_TRIGGER_NAME, HTTP_POST_NAME)
    for step in (VALIDATE_FORM_NAME, HTTP_POST_NAME):
        assert _reaches(workflow, FORM_TRIGGER_NAME, step), f"form chain broken at {step}"
    assert _reaches(workflow, WEBHOOK_NAME, HTTP_POST_NAME), (
        "webhook branch must still reach the HTTP POST node"
    )


def test_http_post_api_contract_preserved() -> None:
    """POST /api/v1/alerts/{id}/feedback with the env token stays the API call."""
    workflow = _load_wf5()
    http = _node(workflow, HTTP_POST_NAME)
    assert http["type"] == HTTP_TYPE
    # n8n httpRequest v4 defaults to GET — an explicit POST is required or the
    # body is silently dropped and the persistence API is never called.
    assert http["parameters"]["method"] == "POST", (
        "HTTP node must set method=POST (n8n httpRequest v4 defaults to GET)"
    )
    assert http["parameters"]["contentType"] == "json", (
        "feedback body must be JSON (the API rejects form-encoded bodies)"
    )
    # sendHeaders must be true or n8n import silently DROPS headerParameters —
    # without it the X-N8N-Token auth header never reaches the API (latent
    # Phase 2 bug found during runtime validation).
    assert http["parameters"]["sendHeaders"] is True, (
        "HTTP node must set sendHeaders=true or n8n drops the X-N8N-Token header"
    )
    url = http["parameters"]["url"]
    assert url.startswith("={{ $env.TRIAGE_API_BASE_URL || 'http://triage-api:8000' }}")
    assert url.endswith("/api/v1/alerts/{{ $json.alert_id }}/feedback")

    headers = {p["name"]: p["value"] for p in http["parameters"]["headerParameters"]["parameters"]}
    assert headers["X-N8N-Token"] == "={{ $env.N8N_WEBHOOK_TOKEN || $env.N8N_CALLBACK_TOKEN }}"
    assert headers["Content-Type"] == "application/json"
    # Retry resilience lives at node level (options.retryOnFail is ignored).
    assert http.get("retryOnFail") is True and http.get("maxTries", 0) >= 2, (
        "HTTP node must keep retry-on-fail (node-level retryOnFail/maxTries)"
    )

    body = {p["name"]: p["value"] for p in http["parameters"]["bodyParameters"]["parameters"]}
    assert set(body) == {"verdict", "notes", "actor"}
    assert "$json.verdict" in body["verdict"]
    assert "$json.notes" in body["notes"]
    assert "$json.actor || $json.analyst_email || 'analyst'" in body["actor"]


def test_all_workflow_http_posts_declare_method_and_content_type() -> None:
    """Regression: any workflow HTTP node that sends a body must declare a method.

    n8n httpRequest v4 defaults to GET; a body-sending node without an explicit
    method silently drops its payload (the WF5 runtime bug this pins out).
    The body must also be JSON (contentType=json keypair mode or specifyBody=json),
    and nodes that carry headerParameters must enable sendHeaders or n8n drops
    them at import time.
    """
    for filename, workflow in _load_all_workflows().items():
        for node in workflow.get("nodes", []):
            if node.get("type") != HTTP_TYPE:
                continue
            params = node.get("parameters", {})
            if params.get("sendBody") is True:
                assert params.get("method") == "POST", (
                    f"{filename}: {node['name']!r} sends a body but does not set method=POST"
                )
                sends_json = (
                    params.get("contentType") == "json"
                    or params.get("specifyBody") == "json"
                    or bool(params.get("jsonBody"))
                )
                assert sends_json, f"{filename}: {node['name']!r} must send a JSON body"
            if params.get("headerParameters"):
                assert params.get("sendHeaders") is True, (
                    f"{filename}: {node['name']!r} defines headerParameters but not "
                    "sendHeaders=true — n8n drops the headers at import"
                )


def test_workflow_connections_integrity() -> None:
    """Every connection endpoint must exist; every node must be reachable."""
    workflow = _load_wf5()
    node_names = set(_nodes(workflow))
    for source, connection in workflow["connections"].items():
        assert source in node_names, f"connection from unknown node {source!r}"
        for branch in connection["main"]:
            for entry in branch:
                assert entry["node"] in node_names, f"connection to unknown node {entry['node']!r}"
                assert entry["type"] == "main"

    triggers = {
        name
        for name, node in _nodes(workflow).items()
        if node["type"] in (FORM_TRIGGER_TYPE, WEBHOOK_TYPE)
    }
    assert triggers == {FORM_TRIGGER_NAME, WEBHOOK_NAME}
    for name in node_names - triggers:
        reachable = any(_reaches(workflow, trigger, name) for trigger in triggers)
        assert reachable, f"node {name!r} is not reachable from any trigger"

    # The Respond node ends both branches and speaks both dialects: JSON for
    # webhook callers and formSubmittedText for the n8n form completion screen.
    # n8n 1.85.0 reads `responseBody` for respondWith=json — the old
    # `responseData` name silently returned the default {"myField": "value"}.
    respond = _node(workflow, RESPOND_NAME)
    assert respond["parameters"]["respondWith"] == "json"
    response_body = respond["parameters"]["responseBody"]
    assert "formSubmittedText" in response_body
    assert "feedback_received" in response_body
    assert "responseData" not in respond["parameters"], (
        "respondToWebhook v1/1.1 reads `responseBody`, not `responseData`"
    )


def test_stable_workflow_id_preserved() -> None:
    """The workflow id must stay stable so re-imports update, not duplicate."""
    workflow = _load_wf5()
    assert workflow["id"] == WF5_STABLE_ID
    assert workflow["name"] == WF5_FILE.stem


# ---------------------------------------------------------------------------
# 6. Cross-workflow regression: no webhook/Form Trigger mismatch, ever
# ---------------------------------------------------------------------------


def test_no_form_page_hangs_off_a_plain_webhook_anywhere() -> None:
    """Regression: an n8n Form page must never be downstream of a webhook.

    This is the exact class of bug that broke WF5: the 'Form - Feedback' page
    was fed by Webhook -> Function. On n8n 1.85.0 the editor shows 'An n8n Form
    Trigger node must be set up before this node.' and runtime executions
    throw. Applies to every checked-in workflow.
    """
    for filename, workflow in _load_all_workflows().items():
        nodes = _nodes(workflow)
        for name, node in nodes.items():
            if node["type"] != FORM_NODE_TYPE:
                continue
            ancestors = _ancestors(workflow, name)
            assert FORM_TRIGGER_NAME in ancestors or any(
                nodes[ancestor]["type"] == FORM_TRIGGER_TYPE for ancestor in ancestors
            ), f"{filename}: form page {name!r} has no Form Trigger upstream"
            webhook_ancestors = [
                ancestor for ancestor in ancestors if nodes[ancestor]["type"] == WEBHOOK_TYPE
            ]
            assert not webhook_ancestors, (
                f"{filename}: form page {name!r} is fed by webhook node(s) "
                f"{webhook_ancestors} — n8n Form pages require a Form Trigger"
            )


def test_every_form_trigger_compatible_with_respond_node() -> None:
    """Any formTrigger with respondToWebhook downstream must be v<=2.1+responseNode."""
    for filename, workflow in _load_all_workflows().items():
        nodes = _nodes(workflow)
        for name, node in nodes.items():
            if node["type"] != FORM_TRIGGER_TYPE:
                continue
            descendants = _descendants(workflow, name)
            has_respond = any(
                nodes[descendant]["type"] == RESPOND_TYPE for descendant in descendants
            )
            if not has_respond:
                continue
            version = float(node["typeVersion"])
            assert version <= MAX_FORM_TRIGGER_VERSION_WITH_RESPOND, (
                f"{filename}: {name!r} v{version} + downstream respondToWebhook is "
                'rejected by n8n 1.85.0 (\'The "Respond to Webhook" node is not '
                'supported in workflows initiated by the "n8n Form Trigger"\')'
            )
            assert node["parameters"].get("responseMode") == "responseNode", (
                f"{filename}: {name!r} must set responseMode=responseNode when a "
                "Respond to Webhook node is connected (n8n 1.85.0 validation)"
            )
