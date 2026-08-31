"""Static regression coverage for the n8n workflow import mechanism.

Docker is unavailable in this sandbox, so these tests statically validate the
lab import path used by ``docker-compose.yml``:
* the checked-in WF1/WF2/WF3/WF5 files exist, parse, and have stable unique ids
* the import helper imports and activates exactly those files
* the n8n service executes the helper before ``n8n start``
* the compose environment still supplies every ``$env.*`` reference used by the
  workflow JSONs
* no secrets are hardcoded into workflow JSON
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW_DIR = REPO_ROOT / "n8n" / "workflows"
IMPORT_SCRIPT = REPO_ROOT / "scripts" / "n8n-import-workflows.sh"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

EXPECTED_WORKFLOW_FILES = {
    "WF1_soc-triage-router.json",
    "WF2_soc-analyst-notify.json",
    "WF3_soc-incident-escalation.json",
    "WF5_soc-analyst-feedback.json",
}

_SECRET_KEYS = {
    "password",
    "api_key",
    "apikey",
    "secret",
    "token",
    "access_token",
    "accesskey",
    "client_secret",
}

_ENV_REF_PATTERN = re.compile(r"\$env\.([A-Za-z0-9_]+)")


def _workflow_json_files() -> list[Path]:
    return [WORKFLOW_DIR / filename for filename in sorted(EXPECTED_WORKFLOW_FILES)]


def _load_workflows() -> dict[Path, dict[str, Any]]:
    loaded: dict[Path, dict[str, Any]] = {}
    for path in _workflow_json_files():
        loaded[path] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def _secret_key_strings(obj: Any) -> list[str]:
    """Return secret-looking string values that appear under secret field names."""
    hits: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in _SECRET_KEYS and isinstance(value, str) and value.strip():
                hits.append(value)
            hits.extend(_secret_key_strings(value))
    elif isinstance(obj, list):
        for item in obj:
            hits.extend(_secret_key_strings(item))
    return hits


def _string_values(obj: Any) -> list[str]:
    """Return all string values contained in a parsed JSON structure."""
    values: list[str] = []
    if isinstance(obj, dict):
        for item in obj.values():
            values.extend(_string_values(item))
    elif isinstance(obj, list):
        for item in obj:
            values.extend(_string_values(item))
    elif isinstance(obj, str):
        values.append(obj)
    return values


def test_expected_lab_workflow_files_exist_and_parse() -> None:
    """Every expected lab workflow must be present and be valid JSON."""
    assert WORKFLOW_DIR.is_dir(), f"missing workflow directory: {WORKFLOW_DIR}"
    actual = {path.name for path in WORKFLOW_DIR.glob("*.json")}
    assert actual == EXPECTED_WORKFLOW_FILES, f"unexpected lab workflows: {actual}"
    loaded = _load_workflows()
    assert set(loaded) == {WORKFLOW_DIR / name for name in EXPECTED_WORKFLOW_FILES}


def test_workflow_files_have_stable_unique_ids() -> None:
    """Stable ids let the importer update rather than duplicate on restart."""
    loaded = _load_workflows()
    ids: list[str] = []
    for path, workflow in loaded.items():
        assert workflow.get("name") == path.stem, f"{path.name} name mismatch"
        workflow_id = workflow.get("id")
        assert isinstance(workflow_id, str) and workflow_id.strip(), (
            f"{path.name} must define a non-empty stable id"
        )
        ids.append(workflow_id)
    assert len(ids) == len(set(ids)), "workflow ids must be unique"


def test_import_script_imports_and_activates_lab_workflows() -> None:
    """The startup helper must import the four files and activate them."""
    assert IMPORT_SCRIPT.is_file(), f"missing import helper: {IMPORT_SCRIPT}"
    script = IMPORT_SCRIPT.read_text(encoding="utf-8")
    for filename in EXPECTED_WORKFLOW_FILES:
        assert filename in script, f"import helper is missing {filename}"
    assert "n8n import:workflow --input=" in script
    assert "n8n update:workflow --all --active=true" in script
    assert "set -eu" in script


def test_import_script_has_no_hardcoded_secrets() -> None:
    """The import helper must only reference files and CLI commands."""
    script = IMPORT_SCRIPT.read_text(encoding="utf-8").lower()
    for needle in ("password=", "api_key=", "secret=", "token="):
        assert needle not in script


def test_compose_runs_import_before_n8n_start() -> None:
    """n8n must execute the import helper before the server starts."""
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    n8n = compose["services"]["n8n"]

    entrypoint = n8n.get("entrypoint")
    assert entrypoint == ["/bin/sh", "-c"], (
        "n8n image entrypoint is the n8n CLI; override with a shell wrapper"
    )
    command = (
        n8n["command"]
        if isinstance(n8n["command"], str)
        else " ".join(str(p) for p in n8n["command"])
    )
    assert "n8n-import-workflows.sh" in command
    assert "n8n start" in command
    assert not (isinstance(n8n["command"], list) and n8n["command"] and n8n["command"][0] == "sh")

    volumes = [str(volume) for volume in n8n["volumes"]]
    assert any("n8n-import-workflows.sh" in volume for volume in volumes), (
        "compose must mount the import helper"
    )
    assert any("./n8n/workflows:/workflows:ro" in volume for volume in volumes)


def test_compose_provides_every_env_reference_used_by_workflows() -> None:
    """Preserve the workflow env/credential references after import."""
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    n8n_env = compose["services"]["n8n"]["environment"]
    env_example = _env_example_keys()

    referenced: set[str] = set()
    for path in _workflow_json_files():
        source = path.read_text(encoding="utf-8")
        referenced.update(_ENV_REF_PATTERN.findall(source))

    assert referenced, "expected at least one $env.* reference in workflow JSONs"
    missing = sorted(referenced - set(n8n_env))
    assert not missing, f"n8n compose environment is missing: {missing}"

    missing_docs = sorted(referenced - env_example)
    assert not missing_docs, f".env.example is missing documented vars: {missing_docs}"


def _env_example_keys() -> set[str]:
    """Parse the assignment keys from .env.example."""
    keys: set[str] = set()
    if not ENV_EXAMPLE.is_file():
        return keys
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key:
            keys.add(key)
    return keys


def test_workflow_json_has_no_hardcoded_secret_values() -> None:
    """Workflow JSONs must keep secrets as env/credential references only."""
    loaded = _load_workflows()
    for path, workflow in loaded.items():
        hits = _secret_key_strings(workflow)
        assert not hits, f"{path.name} contains hardcoded secret values: {hits}"

        for value in _string_values(workflow):
            assert (
                not value.strip()
                .lower()
                .startswith(
                    (
                        "password=",
                        "api_key=",
                        "secret=",
                        "token=",
                        "accesskey=",
                    )
                )
            ), f"{path.name} contains a literal secret-like assignment"
