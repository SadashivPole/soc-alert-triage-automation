"""Static regression coverage for the n8n email notification chain (Phase 2D).

Docker/n8n runtime is unavailable in this sandbox, so these tests statically
validate the complete email delivery chain that the lab exercises at runtime:

* every ``emailSend`` node in the checked-in workflows has an SMTP credential
  bound (n8n refuses to execute a Send Email node without one — the root cause
  of the Phase 2D "notification never arrives" bug);
* the lab SMTP credential exists, points at the local Mailpit sink, and carries
  no real secret;
* the startup helper provisions the SMTP credential **before** importing the
  workflows, and renders connection details from ``$env`` (never hardcodes);
* the notification email bodies render structured payload objects as text
  (no ``[object Object]``, no raw ``JSON.stringify`` of rule/iocs, and only the
  allow-listed ``investigation_links`` fields);
* the triage-api payload supplies the ``feedback_url`` the workflows link to.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIR = REPO_ROOT / "n8n" / "workflows"
CREDENTIAL_DIR = REPO_ROOT / "n8n" / "credentials"
CREDENTIAL_FILE = CREDENTIAL_DIR / "smtp_lab_mailpit.json"
IMPORT_SCRIPT = REPO_ROOT / "scripts" / "n8n-import-workflows.sh"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"

SMTP_CREDENTIAL_NAME = "SMTP Lab Mailpit"
#: Credential id bound to every emailSend node (WF2/WF3/WF5) and used as the
#: import-time upsert key by `n8n import:credentials` (n8n 1.85.0).
SMTP_CREDENTIAL_ID = "smtp-lab-mailpit"
EMAIL_NODE_TYPE = "n8n-nodes-base.emailSend"
FUNCTION_NODE_TYPE = "n8n-nodes-base.function"

WORKFLOW_FILES = [
    "WF1_soc-triage-router.json",
    "WF2_soc-analyst-notify.json",
    "WF3_soc-incident-escalation.json",
    "WF5_soc-analyst-feedback.json",
]


def _load_workflows() -> dict[str, dict[str, Any]]:
    return {
        name: json.loads((WORKFLOW_DIR / name).read_text(encoding="utf-8"))
        for name in WORKFLOW_FILES
    }


def _email_nodes(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    return [n for n in workflow.get("nodes", []) if n.get("type") == EMAIL_NODE_TYPE]


def _function_code(workflow: dict[str, Any]) -> str:
    return "\n".join(
        n.get("parameters", {}).get("functionCode", "")
        for n in workflow.get("nodes", [])
        if n.get("type") == FUNCTION_NODE_TYPE
    )


def test_every_email_node_has_smtp_credential_bound() -> None:
    """The Phase 2D root cause: emailSend nodes without credentials never send."""
    workflows = _load_workflows()
    assert _email_nodes(workflows["WF2_soc-analyst-notify.json"])
    found = 0
    for name, workflow in workflows.items():
        for node in _email_nodes(workflow):
            found += 1
            smtp = node.get("credentials", {}).get("smtp")
            assert isinstance(smtp, dict), f"{name}: {node['name']} has no smtp credential"
            assert smtp.get("id"), f"{name}: {node['name']} credential missing id"
            assert smtp.get("name") == SMTP_CREDENTIAL_NAME, (
                f"{name}: {node['name']} credential name must be "
                f"{SMTP_CREDENTIAL_NAME!r}, got {smtp.get('name')!r}"
            )
    # WF2 (1) + WF3 (2) + WF5 (1) = 4 notification emails.
    assert found == 4, f"expected 4 emailSend nodes across lab workflows, found {found}"


def test_lab_smtp_credential_file_points_at_mailpit() -> None:
    """The provisioned credential targets the local Mailpit sink, no real auth.

    The file must be a **top-level JSON array** — `n8n import:credentials`
    (verified against n8n 1.85.0) rejects an object wrapper with "File does not
    seem to contain credentials. Make sure the credentials are contained in an
    array." The credential id must match the id every emailSend node binds.
    """
    assert CREDENTIAL_FILE.is_file(), f"missing lab credential: {CREDENTIAL_FILE}"
    data = json.loads(CREDENTIAL_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == 1, (
        "credential file must be a top-level JSON array (n8n import:credentials format)"
    )
    cred = data[0]
    assert cred.get("id") == SMTP_CREDENTIAL_ID, (
        f"credential id must be {SMTP_CREDENTIAL_ID!r} (the id bound by every emailSend node)"
    )
    assert cred["name"] == SMTP_CREDENTIAL_NAME
    assert cred["type"] == "smtp"
    conn = cred["data"]
    assert conn["host"] == "mailpit"
    assert int(conn["port"]) == 1025
    assert conn["secure"] is False
    # Lab sink accepts unauthenticated mail: no real password may be committed.
    assert conn["user"] in ("", None)
    assert conn["password"] in ("", None)


def test_import_helper_provisions_credential_before_workflows() -> None:
    """The SMTP credential must exist before workflows reference it."""
    script = IMPORT_SCRIPT.read_text(encoding="utf-8")
    cred_import = script.find("n8n import:credentials")
    wf_import = script.find("n8n import:workflow")
    activate = script.find("n8n update:workflow")
    assert cred_import != -1, "import helper must provision the SMTP credential"
    assert cred_import < wf_import < activate, (
        "order must be: import credentials -> import workflows -> activate"
    )
    # Connection details come from env (lab defaults match Mailpit); never hardcoded.
    assert "${SMTP_HOST:-mailpit}" in script
    assert "${SMTP_PORT:-1025}" in script
    # The credential name used in the JSON must match the provisioned credential.
    assert SMTP_CREDENTIAL_NAME in script


def test_import_helper_uses_busybox_compatible_mktemp() -> None:
    """n8nio/n8n:1.85.0 (BusyBox mktemp) rejects templates with a suffix after XXXXXX."""
    script = IMPORT_SCRIPT.read_text(encoding="utf-8")
    match = re.search(r'RENDERED_CRED="\$\(mktemp\s+(\S+)\)"', script)
    assert match, "import helper must create its temp credential file with mktemp"
    template = match.group(1)
    # BusyBox mktemp fails ("Invalid argument") when the template has a literal
    # suffix after the XXXXXX run, e.g. /tmp/smtp-cred.XXXXXX.json.
    assert re.fullmatch(r"\S*X{6}", template), (
        f"mktemp template {template!r} must end with exactly six X's: "
        "Alpine/BusyBox mktemp (n8n 1.85.0) rejects a suffix after XXXXXX "
        "with 'Invalid argument'"
    )
    # Cleanup must still remove the same rendered credential file.
    assert re.search(r"trap\s+'rm -f \"\$RENDERED_CRED\"'\s+EXIT", script), (
        "trap must still remove the rendered credential file"
    )


def test_import_helper_has_no_crlf_line_endings() -> None:
    """BusyBox /bin/sh in n8nio/n8n:1.85.0 cannot parse CRLF line endings.

    The script is mounted into the container from a Windows checkout, so a
    CRLF-converted file would fail before the mktemp line ever runs. The
    checked-in blob (and the worktree, per .gitattributes) must be LF-only.
    """
    assert IMPORT_SCRIPT.is_file()
    raw = IMPORT_SCRIPT.read_bytes()
    crlf_count = raw.count(b"\r\n")
    assert b"\r\n" not in raw, (
        f"{IMPORT_SCRIPT.name} contains CRLF line endings ({crlf_count} occurrences); "
        "BusyBox /bin/sh in n8nio/n8n:1.85.0 fails to parse it"
    )
    assert raw.count(b"\n") > 0, "script must use LF line endings"
    assert b"\r" not in raw, "stray carriage-return bytes must not be present"

    # .gitattributes must keep *.sh LF on Windows checkouts (core.autocrlf)
    # so the mounted script never regresses to CRLF on Windows.
    attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert re.search(r"(?m)^\*\.sh\s+text\s+eol=lf\s*$", attributes), (
        ".gitattributes must declare `*.sh text eol=lf` to keep shell scripts LF-only"
    )


def test_compose_mounts_credentials_and_supplies_smtp_env() -> None:
    """Compose must make the credential dir and SMTP env available to n8n."""
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    n8n = compose["services"]["n8n"]
    volumes = [str(v) for v in n8n["volumes"]]
    assert any("./n8n/credentials:/credentials" in v for v in volumes), (
        "compose must mount ./n8n/credentials into the n8n container"
    )
    env = n8n["environment"]
    for var in ("SMTP_HOST", "SMTP_PORT", "SOC_FROM_EMAIL", "SOC_L1_EMAIL", "SOC_L2_EMAIL"):
        assert var in env, f"n8n compose environment missing {var}"


def test_notification_email_nodes_have_from_and_to() -> None:
    """Every Send Email node must resolve sender and recipient from env."""
    for name, workflow in _load_workflows().items():
        for node in _email_nodes(workflow):
            params = node["parameters"]
            assert "fromEmail" in params, f"{name}: {node['name']} missing fromEmail"
            assert "toEmail" in params, f"{name}: {node['name']} missing toEmail"
            assert "$env.SOC_FROM_EMAIL" in params["fromEmail"]
            assert "$env.SOC_" in params["toEmail"]


def test_notification_formatters_render_objects_as_text() -> None:
    """Email bodies must not leak [object Object] / raw JSON into analyst mail."""
    workflows = _load_workflows()
    formatter_code = (
        _function_code(workflows["WF2_soc-analyst-notify.json"])
        + "\n"
        + _function_code(workflows["WF3_soc-incident-escalation.json"])
    )
    # rule and iocs are structured payload objects: direct template interpolation
    # of `alert.rule` renders "[object Object]".
    assert re.search(r"\$\{(?:\s*)alert\.rule(?:\s*)\}", formatter_code) is None, (
        "formatter must not interpolate the rule object directly"
    )
    # IOCs must be grouped per type and joined, never JSON.stringify()'d raw.
    assert "groups.ipv4" in formatter_code, "formatter must render IOCs by type"
    assert "JSON.stringify(alert.iocs" not in formatter_code, (
        "formatter must not dump the raw iocs structure into the email"
    )
    # Only allow-listed investigation_links fields may be referenced: the
    # payload carries alert_api / alert_console / runbook / feedback_url — never
    # siem_search_url or timeline_url (which were silently "n/a").
    assert "siem_search_url" not in formatter_code
    assert "timeline_url" not in formatter_code
    assert "links.alert_api" in formatter_code
    assert "links.feedback_url" in formatter_code


def test_payload_supplies_feedback_url_for_workflow_emails() -> None:
    """build_n8n_payload must populate investigation_links.feedback_url."""
    from tests.unit.test_n8n_payload import _make_scored_alert  # type: ignore[import]

    from soc_triage.notifications.payload import build_n8n_payload

    payload = build_n8n_payload(
        _make_scored_alert(),
        dedupe_status="new_generation",
        investigation_base_url="http://localhost:8000",
    )
    links = payload.investigation_links
    assert links.feedback_url is not None
    assert links.feedback_url == f"http://localhost:8000/api/v1/alerts/{payload.alert_id}/feedback"
    assert links.alert_api.endswith(f"/api/v1/alerts/{payload.alert_id}")
    # Serialized payload must surface the link for the n8n function nodes.
    dumped = payload.model_dump(mode="json")
    assert dumped["investigation_links"]["feedback_url"] == links.feedback_url
