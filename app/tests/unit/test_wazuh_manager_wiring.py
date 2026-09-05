"""Regression tests for Wazuh manager integration wiring (Phase 4).

Validates that the entrypoint installer explicitly enforces
ownership and permissions for /var/ossec/integrations so that
the wazuh user can traverse it, without loosening security.

Root cause addressed:
- install -d -m 750 alone does NOT enforce ownership when the
  directory already exists (remains root:root 0750).
- wazuh-integratord runs as wazuh user and fails to list the
  directory, reporting "File not found inside 'integrations'".

Fix required:
    install -d -m 750 "$DEST_DIR"
    chown root:wazuh "$DEST_DIR"
    chmod 0750 "$DEST_DIR"

And file installs must stay root:wazuh 0750, not writable by wazuh.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "wazuh" / "entrypoint-scripts" / "10-install-triage-integration.sh"

EXPECTED_DIR_LINES = [
    'install -d -m 750 "$DEST_DIR"',
    'chown root:wazuh "$DEST_DIR"',
    'chmod 0750 "$DEST_DIR"',
]


def _read_script() -> str:
    assert SCRIPT_PATH.exists(), f"Missing required installer: {SCRIPT_PATH}"
    return SCRIPT_PATH.read_text(encoding="utf-8")


def test_installer_script_exists_and_is_shell() -> None:
    text = _read_script()
    assert text.startswith("#!/bin/sh") or text.startswith("#!/bin/bash")
    assert "DEST_DIR" in text
    assert "/var/ossec/integrations" in text


def test_integrations_directory_ownership_explicitly_enforced() -> None:
    """Ownership must be explicitly set to root:wazuh, not just install -d."""
    text = _read_script()
    # Must contain explicit chown root:wazuh for DEST_DIR
    assert 'chown root:wazuh "$DEST_DIR"' in text, (
        "Installer must explicitly enforce ownership with "
        'chown root:wazuh "$DEST_DIR" — install -d alone does not '
        "fix existing root:root directory"
    )
    # Ensure it is not chowning to wazuh:wazuh or making writable
    assert "chown wazuh:wazuh" not in text
    assert "chown wazuh:root" not in text
    # Count occurrences — should appear at least once
    assert text.count('chown root:wazuh "$DEST_DIR"') >= 1


def test_integrations_directory_mode_enforced_0750() -> None:
    """Mode must be explicitly enforced to 0750, not loosened."""
    text = _read_script()
    # Must contain explicit chmod 0750 for DEST_DIR
    assert 'chmod 0750 "$DEST_DIR"' in text, (
        'Installer must explicitly enforce mode with chmod 0750 "$DEST_DIR" after chown'
    )
    # Verify install -d also uses 750 (or 0750)
    assert (
        re.search(r"install\s+-d\s+-m\s+0?750\s+\"\$\DEST_DIR\"", text)
        or re.search(r"install\s+-d\s+-m\s+0?750\s+\"\$\{?DEST_DIR", text)
        or ('install -d -m 750 "$DEST_DIR"' in text)
    ), "Installer should create directory with install -d -m 750"
    # Check for dangerous modes explicitly
    for bad in ("chmod 0770", "chmod 0775", "chmod 0777", 'chmod 0755 "$DEST_DIR"'):
        if bad in text:
            raise AssertionError(f"Installer must not loosen permissions with {bad}")


def test_directory_initialization_order_and_completeness() -> None:
    """All three lines must exist and in correct order: install -d, chown, chmod."""
    text = _read_script()
    # Find positions
    pos_install = text.find('install -d -m 750 "$DEST_DIR"')
    pos_chown = text.find('chown root:wazuh "$DEST_DIR"')
    pos_chmod = text.find('chmod 0750 "$DEST_DIR"')

    assert pos_install != -1, "Missing install -d line"
    assert pos_chown != -1, "Missing chown line"
    assert pos_chmod != -1, "Missing chmod line"

    # Order must be install -> chown -> chmod
    assert pos_install < pos_chown < pos_chmod, (
        "Directory initialization must be in order: install -d, chown root:wazuh, chmod 0750"
    )

    # Ensure the three lines are close together (within 10 lines)
    lines = text.splitlines()
    idx_install = next(
        (i for i, line in enumerate(lines) if 'install -d -m 750 "$DEST_DIR"' in line), -1
    )
    idx_chown = next(
        (i for i, line in enumerate(lines) if 'chown root:wazuh "$DEST_DIR"' in line), -1
    )
    idx_chmod = next((i for i, line in enumerate(lines) if 'chmod 0750 "$DEST_DIR"' in line), -1)
    assert idx_install != -1 and idx_chown != -1 and idx_chmod != -1
    assert idx_chown - idx_install <= 5, "chown should immediately follow install -d"
    assert idx_chmod - idx_chown <= 3, "chmod should immediately follow chown"


def test_custom_triage_files_installed_with_secure_ownership() -> None:
    """Both integration files must be installed as root:wazuh 0750."""
    text = _read_script()
    # Check for custom-triage file install
    assert "custom-triage" in text
    assert "custom-triage.py" in text

    # At least ensure the explicit ownership/mode flags appear near the filenames
    assert re.search(r"install.*root.*wazuh.*0?750.*custom-triage", text), (
        "custom-triage must be installed with root:wazuh 0750"
    )
    assert re.search(r"install.*root.*wazuh.*0?750.*custom-triage\.py", text), (
        "custom-triage.py must be installed with root:wazuh 0750"
    )

    # Ensure no writable-by-group or world-writable installs
    assert " -m 0770 " not in text
    assert " -m 0775 " not in text
    assert " -m 0777 " not in text
    # Ensure files are not installed with wazuh as owner
    assert " -o wazuh " not in text


def test_installer_does_not_loosen_integrations_directory() -> None:
    """Regression guard: directory must NOT be made writable by wazuh or world."""
    text = _read_script()
    # No chmod that adds group write or other write for DEST_DIR
    # The only allowed chmod for DEST_DIR is 0750
    chmod_dest_lines = [
        line.strip() for line in text.splitlines() if "$DEST_DIR" in line and "chmod" in line
    ]
    for line in chmod_dest_lines:
        # Extract mode
        match = re.search(r"chmod\s+0?(\d{3,4})", line)
        if match:
            mode = match.group(1)
            # Normalize to last 3 digits
            mode_3 = mode[-3:]
            assert mode_3 == "750", f"DEST_DIR chmod must be 0750, found {mode} in: {line}"

    # No chown that gives wazuh ownership of directory (must stay root:wazuh)
    chown_dest_lines = [
        line.strip() for line in text.splitlines() if "$DEST_DIR" in line and "chown" in line
    ]
    for line in chown_dest_lines:
        assert "root:wazuh" in line, f"DEST_DIR chown must be root:wazuh, found: {line}"


def test_installer_is_defensive_only() -> None:
    """Ensure installer does not contain autonomous response/containment."""
    text = _read_script().lower()
    forbidden = [
        "active-response",
        "ossec-control",
        "agent_control",
        "firewall-drop",
        "host-deny",
        "disable-account",
    ]
    for term in forbidden:
        assert term not in text, f"Installer must not contain autonomous response: {term}"
