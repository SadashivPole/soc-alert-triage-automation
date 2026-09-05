"""Static regression tests for the Phase 4.2 Wazuh-manager wiring.

Docker is intentionally unavailable in unit tests. These tests validate the
checked-in Wazuh entrypoint script and its surrounding contract without
invoking a container runtime. Specifically they pin the ownership fix
delivered in Phase 4.2:

* the entrypoint script exists at the documented ``entrypoint-scripts.d``
  location and is syntactically valid POSIX ``sh``;
* the script chowns installed integrations to ``root:wazuh`` (executables
  0750, non-executables 0640) so ``wazuh-integratord`` can read+execute
  but never tamper with the script body;
* the local alert-buffer directory is ``wazuh:wazuh`` 0750 (writable by
  the daemon, not world-readable);
* the script is idempotent and degrades gracefully when the source
  bind-mount is absent (the ``sim`` profile).
"""

from __future__ import annotations

import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
ENTRYPOINT_SCRIPT = (
    REPO_ROOT / "wazuh" / "entrypoint-scripts" / "10-install-triage-integration.sh"
)

#: Default paths documented in ARCHITECTURE §13 and referenced by the future
#: ``wazuh-manager`` service block in docker-compose.yml. Pinned here so an
#: accidental rename or path drift fails the gate before it lands.
EXPECTED_DEFAULTS = {
    "TRIAGE_INTEGRATOR_SOURCE_DIR": "/wazuh-src/integrator",
    "TRIAGE_INTEGRATOR_DIR": "/var/ossec/integrations",
    "TRIAGE_INTEGRATOR_BUFFER_DIR": "/var/ossec/integrations/triage-buffer",
    "TRIAGE_INTEGRATOR_USER": "wazuh",
    "TRIAGE_INTEGRATOR_GROUP": "wazuh",
}


def _script_text() -> str:
    return ENTRYPOINT_SCRIPT.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# File presence & POSIX-shell syntax
# ---------------------------------------------------------------------------


def test_entrypoint_script_exists() -> None:
    """Phase 4.2 must ship the entrypoint script at the documented path."""
    assert ENTRYPOINT_SCRIPT.is_file(), f"missing {ENTRYPOINT_SCRIPT}"


def test_entrypoint_script_has_shebang_and_is_executable() -> None:
    """The script must be a valid POSIX-sh entrypoint (shebang + +x bit)."""
    text = _script_text()
    assert text.startswith("#!/bin/sh"), "script must use #!/bin/sh (Alpine/BusyBox-safe)"
    mode = ENTRYPOINT_SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR, "script must be chmod +x so the entrypoint can exec it"
    assert mode & stat.S_IXGRP, "script must be group-executable for consistency"


def test_entrypoint_script_passes_sh_n_syntax_check() -> None:
    """``sh -n`` must report no syntax errors (same gate the CI shell job uses)."""
    result = subprocess.run(
        ["sh", "-n", str(ENTRYPOINT_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"sh -n failed: {result.stderr.strip()}"
    assert result.stderr.strip() == ""


def test_entrypoint_uses_strict_mode() -> None:
    """Fail-fast shell flags so a missing command aborts instead of silently
    continuing with partially-applied ownership."""
    text = _script_text()
    assert "set -eu" in text, "script must `set -eu` to abort on errors/undefs"


# ---------------------------------------------------------------------------
# Default paths / env-override contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("var", "expected"),
    sorted(EXPECTED_DEFAULTS.items()),
    ids=sorted(EXPECTED_DEFAULTS),
)
def test_default_paths_match_architecture_contract(var: str, expected: str) -> None:
    """Each configurable path must default to the documented location and be
    overridable from the environment (``${VAR:-default}`` form)."""
    pattern = re.compile(
        rf'^{var}="\${{{var}:-{re.escape(expected)}}}"',
        re.MULTILINE,
    )
    assert pattern.search(_script_text()), (
        f"{var} must default to {expected} and be env-overridable via ${{{var}:-default}}"
    )


# ---------------------------------------------------------------------------
# Ownership / permissions — the core Phase 4.2 fix
# ---------------------------------------------------------------------------


def test_script_chowns_integrations_to_root_wazuh() -> None:
    """Installed scripts must be owned by root:wazuh.

    The daemon runs as ``wazuh``; it needs read+execute on the script body
    but MUST NOT be able to overwrite it, otherwise a compromised integratord
    could persist changes to disk.
    """
    text = _script_text()
    # The exact chown invocation — recursive so any subdirectories we may add
    # later (e.g. lib/) inherit the same ownership.
    assert re.search(
        r"chown\s+-R\s+\"root:\$\{TRIAGE_INTEGRATOR_GROUP\}\"",
        text,
    ), "integrator dir must be chown -R root:${TRIAGE_INTEGRATOR_GROUP}"


def test_script_sets_directory_permissions_to_0750() -> None:
    """Directories under the integrations tree must be 0750 (root:wazuh)."""
    text = _script_text()
    assert re.search(
        r"find\s+\"\$\{TRIAGE_INTEGRATOR_DIR\}\"\s+-type\s+d\s+-exec\s+chmod\s+0750",
        text,
    ), "directories must be chmod 0750"


def test_script_sets_executable_files_to_0750_and_data_files_to_0640() -> None:
    """Executable scripts: 0750; non-executable files (config, README etc.):
    0640 — never world-readable, never writable by wazuh."""
    text = _script_text()
    assert re.search(
        r"find\s+\"\$\{TRIAGE_INTEGRATOR_DIR\}\"\s+-type\s+f\s+-perm\s+-u\+x\s+-exec\s+chmod\s+0750",
        text,
    ), "executable files must be chmod 0750"
    assert re.search(
        r"find\s+\"\$\{TRIAGE_INTEGRATOR_DIR\}\"\s+-type\s+f\s+!\s+-perm\s+-u\+x\s+-exec\s+chmod\s+0640",
        text,
    ), "non-executable files must be chmod 0640"


def test_buffer_directory_is_wazuh_wazuh_0750() -> None:
    """The local buffer/spool directory must be owned wazuh:wazuh mode 0750
    so the daemon can write retry payloads but the directory is not world-
    readable (alerts may contain sensitive fields)."""
    text = _script_text()
    assert re.search(
        r"chown\s+\"\$\{TRIAGE_INTEGRATOR_USER\}:\$\{TRIAGE_INTEGRATOR_GROUP\}\"\s+\"\$\{TRIAGE_INTEGRATOR_BUFFER_DIR\}\"",
        text,
    ), "buffer dir must be chown ${TRIAGE_INTEGRATOR_USER}:${TRIAGE_INTEGRATOR_GROUP}"
    assert re.search(
        r"chmod\s+0750\s+\"\$\{TRIAGE_INTEGRATOR_BUFFER_DIR\}\"",
        text,
    ), "buffer dir must be chmod 0750"


def test_chown_happens_before_chmod() -> None:
    """Ownership must be applied *before* mode bits so that a previous run
    that left a file owned by wazuh can't keep write access after chmod."""
    text = _script_text()
    chown_idx = text.find("chown -R")
    chmod_dir_idx = text.find("-type d -exec chmod")
    chmod_exec_idx = text.find("-perm -u+x -exec chmod")
    assert chown_idx >= 0
    assert chmod_dir_idx > chown_idx
    assert chmod_exec_idx > chown_idx


def test_ownership_order_chown_then_chmod_for_buffer() -> None:
    """Same ordering constraint for the buffer directory."""
    text = _script_text()
    buffer_chown = text.find("chown \"${TRIAGE_INTEGRATOR_USER}")
    buffer_chmod = text.find("chmod 0750 \"${TRIAGE_INTEGRATOR_BUFFER_DIR}\"")
    assert buffer_chown >= 0
    assert buffer_chmod > buffer_chown


# ---------------------------------------------------------------------------
# Idempotency / graceful-degrade behaviour
# ---------------------------------------------------------------------------


def test_script_skips_gracefully_when_source_missing() -> None:
    """In the ``sim`` profile the source bind-mount is absent; the script
    must log and exit 0 rather than failing the container boot."""
    text = _script_text()
    assert re.search(
        r'if\s+\[\s+!\s+-d\s+"\$\{TRIAGE_INTEGRATOR_SOURCE_DIR\}"\s+\]',
        text,
    ), "script must test for -d source dir"
    assert "exit 0" in text, "missing-source path must exit 0"
    assert "skipping integration install" in text


def test_script_skips_md_and_gitkeep_files() -> None:
    """README/.gitkeep are scaffolding artifacts in the repo; they must not
    be copied into the live integrations directory."""
    text = _script_text()
    assert r"! -name '*.md' ! -name '.gitkeep'" in text


def test_script_is_idempotent_mkdir_p() -> None:
    """Re-running the script on restart must be a no-op rather than
    erroring out; mkdir -p guarantees both destinations pre-exist safely."""
    text = _script_text()
    assert 'mkdir -p "${TRIAGE_INTEGRATOR_DIR}"' in text
    assert 'mkdir -p "${TRIAGE_INTEGRATOR_BUFFER_DIR}"' in text


def test_script_does_not_inline_any_secrets() -> None:
    """Defensive: the entrypoint must never hardcode URLs, keys, or tokens.
    It is an installer, not the integration body — the integrator script
    itself (not shipped here) reads URL/key from env."""
    text = _script_text()
    forbidden = (
        "X-API-Key",
        "TRIAGE_INGEST_API_KEY",
        "hook_url",
        "http://triage-api",
        "/api/v1/alerts/ingest",
        "change-me",
    )
    for needle in forbidden:
        assert needle not in text, f"entrypoint must not hardcode {needle!r}"


# ---------------------------------------------------------------------------
# Contract check: running sh -n directly (mirrors the pre-commit gate)
# ---------------------------------------------------------------------------


def test_script_has_no_bashisms_required_by_the_precommit_gate() -> None:
    """``sh -n`` is the documented pre-commit gate. Double-run it here so
    a failure surfaces as a test failure with the full stderr, not just a
    CI job abort."""
    proc = subprocess.run(
        [sys.executable, "-c", "import subprocess,sys;r=subprocess.run(['sh','-n',sys.argv[1]],capture_output=True,text=True);sys.stderr.write(r.stderr);sys.exit(r.returncode)", str(ENTRYPOINT_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
