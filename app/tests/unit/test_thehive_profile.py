"""Phase 4.6 static validation: TheHive 5 CE ``thehive`` compose profile.

Docker is unavailable in this sandbox (see ``test_docker_lab_config.py`` for the
same constraint), so the optional ``thehive`` profile is validated *statically* —
plus one executable check of the profile's secret guard:

* the profile is strictly additive — every TheHive service is gated on
  ``profiles: ["thehive"]``, TheHive never starts in the default profile, and no
  default service gains a ``depends_on`` on it (ARCHITECTURE.md §13, §14);
* every image is pinned to the exact vendor tag (never ``latest``) and is the
  Community Edition image — ``strangebee/thehive`` (CE), never Premium;
* TheHive stays internal-only: no host ports, ``soc-core`` only, healthchecks,
  resource limits and container hardening;
* every credential comes from the environment with no committed default
  (SECURITY.md §2, §4). Compose interpolates the whole file before it filters
  inactive profiles, so the profile cannot use ``${VAR:?}`` without breaking the
  default stack; ``thehive-preflight`` enforces the same fail-fast contract at
  profile start, and its shell guard is executed by these tests. The
  platform-side ``THEHIVE_URL``/``THEHIVE_API_KEY`` keep their empty defaults,
  preserving disable-by-empty and the deterministic-sans-TheHive default;
* SQLite remains the triage-api default database (``TRIAGE_DB_URL`` SQLite).

Out of scope here and intentionally NOT claimed: TheHive 5.7.6 wires Cassandra
and Elasticsearch from the vendor-documented entrypoint flags; the runtime
contracts of those flags are asserted by *playing the vendor's own* convention
(the upstream ``prod1-thehive``/``testing`` stacks use the same Cassandra
healthcheck, ES healthcheck, and TheHive status path), but **no live TheHive CE
run is claimed anywhere** — live validation is operator-side only.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
THEHIVE_README = REPO_ROOT / "thehive" / "README.md"

#: The Phase 4.6 services and their exact pins from the upstream
#: StrangeBeeCorp/docker ``versions.env`` (2026-09-19 audit). No floating tags.
EXPECTED_IMAGES = {
    "thehive-cassandra": "cassandra:4.1.12",
    "thehive-elasticsearch": "docker.elastic.co/elasticsearch/elasticsearch:8.19.21",
    "thehive": "strangebee/thehive:5.7.6",
}
#: The three long-running containers (`thehive-preflight` is a one-shot guard).
THEHIVE_STACK_SERVICES = tuple(EXPECTED_IMAGES)
THEHIVE_GUARD_SERVICE = "thehive-preflight"
THEHIVE_SERVICES = (THEHIVE_GUARD_SERVICE, *THEHIVE_STACK_SERVICES)
DEFAULT_SERVICES = ("triage-api", "n8n", "mailpit")

#: Secrets the profile requires — sourced from `.env`, never committed, and
#: enforced by `thehive-preflight` (see the module docstring for why not
#: `${VAR:?}`).
REQUIRED_SECRETS = (
    "THEHIVE_SECRET",
    "THEHIVE_ORG_NAME",
    "THEHIVE_ADMIN_USERNAME",
    "THEHIVE_ADMIN_PASSWORD",
    "THEHIVE_API_KEY",
    "ELASTICSEARCH_PASSWORD",
)

#: Credential-shaped literals that must never appear in checked-in TheHive
#: profile files (mirrors scripts/check_secrets.sh; the vocabulary is assembled
#: at runtime so this test file cannot itself be misread as a credential
#: assignment).
_SECRET_KEYWORDS = ("password", "passwd", "secret", "api_key", "apikey", "access_token")
SECRET_ASSIGNMENT = re.compile(
    r"(?:{}|auth_token)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+_]{{16,}}".format(
        "|".join(_SECRET_KEYWORDS)
    )
)
TOKEN_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compose() -> dict[str, Any]:
    return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))


def _thehive_compose_text() -> str:
    """Return only the Phase 4.6 block of docker-compose.yml."""
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    start = text.index("# Phase 4.6 — optional `thehive` profile")
    end = text.index("\nnetworks:", start)
    return text[start:end]


def _parse_ports(service: dict[str, Any]) -> list[str]:
    return [str(port) for port in service.get("ports", [])]


def _run_preflight(values: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Execute the checked-in TheHive secret guard with host-portable behavior.

    Production uses BusyBox ``/bin/sh`` inside the TheHive preflight container.
    POSIX hosts execute the exact checked-in shell guard. Windows does not
    require a host POSIX shell for this static test, so it evaluates the same
    fail-fast contract directly in Python (same pattern as the MISP guard).
    """
    guard = _compose()["services"][THEHIVE_GUARD_SERVICE]
    script = guard["command"][0].replace("$$", "$")

    env = {"PATH": "/usr/bin:/bin"}
    for name in guard["environment"]:
        env[name] = values.get(name, "")

    if os.name == "nt":
        missing = [name for name in REQUIRED_SECRETS if not env.get(name, "")]
        if missing:
            stderr = (
                "ERROR: the 'thehive' profile is missing required .env values:"
                + "".join(f" {name}" for name in missing)
                + "\n"
                + "Generate each value locally (see thehive/README.md) - no "
                + "defaults are shipped on purpose.\n"
            )
            return subprocess.CompletedProcess(
                args=["thehive-preflight", "python-fallback"],
                returncode=1,
                stdout="",
                stderr=stderr,
            )
        return subprocess.CompletedProcess(
            args=["thehive-preflight", "python-fallback"],
            returncode=0,
            stdout="thehive profile: required secrets are present\n",
            stderr="",
        )

    shell = shutil.which("sh") or shutil.which("bash")
    if shell is None:
        raise RuntimeError(
            "A POSIX shell (sh or bash) is required to execute the TheHive "
            "preflight guard on non-Windows hosts."
        )
    return subprocess.run(
        [shell, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# Compose: profile gating (strictly additive)
# ---------------------------------------------------------------------------


def test_thehive_profile_defines_exactly_the_ce_stack() -> None:
    """The profile adds only the TheHive CE stack and its guard, gated on `thehive`."""
    services = _compose()["services"]
    assert set(services) >= set(THEHIVE_SERVICES)
    for name in THEHIVE_SERVICES:
        assert services[name]["profiles"] == ["thehive"], name


def test_thehive_never_starts_in_the_default_profile() -> None:
    """Default services carry no profile, so `docker compose up` never starts TheHive."""
    services = _compose()["services"]
    for name in DEFAULT_SERVICES:
        assert "profiles" not in services[name], name
    # A TheHive service without a profile would silently join the default stack.
    for name in THEHIVE_SERVICES:
        assert services[name].get("profiles"), name


def test_no_default_service_depends_on_thehive() -> None:
    """The zero-external fallback must not require TheHive to start."""
    services = _compose()["services"]
    for name, service in services.items():
        if name in THEHIVE_SERVICES:
            continue
        depends_on = set(service.get("depends_on", {}))
        assert not depends_on & set(THEHIVE_SERVICES), (name, depends_on)


def test_thehive_services_only_belong_to_the_internal_network() -> None:
    """TheHive lives on `soc-core` only; it is never attached to `soc-edge`."""
    services = _compose()["services"]
    for name in THEHIVE_STACK_SERVICES:
        assert services[name].get("networks") == ["soc-core"], name
    assert services[THEHIVE_GUARD_SERVICE].get("network_mode") == "none"
    assert "networks" not in services[THEHIVE_GUARD_SERVICE]


# ---------------------------------------------------------------------------
# Compose: pinned CE images, internal-only ports, hardening
# ---------------------------------------------------------------------------


def test_thehive_images_are_pinned_to_exact_versions() -> None:
    services = _compose()["services"]
    for name, expected in EXPECTED_IMAGES.items():
        image = services[name]["image"]
        assert image == expected, (name, image)
        assert ":latest" not in image, (name, image)
        assert re.match(r"^[a-z0-9./_-]+:[0-9v][0-9A-Za-z._-]+$", image), (name, image)
    guard_image = services[THEHIVE_GUARD_SERVICE]["image"]
    assert guard_image == "busybox:1.37.0"
    assert ":latest" not in guard_image


def test_thehive_image_is_community_edition_never_premium() -> None:
    """`strangebee/thehive` is TheHive 5 Community Edition; no Premium image reference."""
    services = _compose()["services"]
    image = services["thehive"]["image"]
    assert image.startswith("strangebee/thehive:"), image
    # The legacy Premium/partner image name must not reappear as an image ref.
    assert not image.startswith("thehiveproject/"), image
    block = _thehive_compose_text().lower()
    assert "community edition" in block
    assert "thehiveproject/" not in block
    # The block may *mention* Premium only to state it is never used; it must
    # never be an image reference or service.
    for name in THEHIVE_SERVICES:
        assert "premium" not in str(services[name].get("image", "")).lower(), name
    # Elasticsearch must be the official Elastic registry image (never Docker Hub).
    assert services["thehive-elasticsearch"]["image"].startswith(
        "docker.elastic.co/elasticsearch/elasticsearch:"
    )


def test_thehive_publishes_no_host_ports() -> None:
    """Internal-only: the profile publishes nothing (ARCHITECTURE.md §13)."""
    services = _compose()["services"]
    for name in THEHIVE_SERVICES:
        assert _parse_ports(services[name]) == [], name
        assert "expose" not in services[name], name
    text = _thehive_compose_text()
    for published in ("9000:9000", "9200:9200", "9042:9042", "7000:7000", "443:443"):
        assert published not in text, published


def test_thehive_stack_services_have_healthchecks_and_resource_limits() -> None:
    services = _compose()["services"]
    for name in THEHIVE_STACK_SERVICES:
        service = services[name]
        assert service["restart"] == "unless-stopped", name
        limits = service["deploy"]["resources"]["limits"]
        assert limits["cpus"], name
        assert limits["memory"], name
        healthcheck = service["healthcheck"]
        assert healthcheck["retries"] >= 3, name
        assert healthcheck.get("start_period") is not None, name
    guard = services[THEHIVE_GUARD_SERVICE]
    assert guard["restart"] == "no"
    assert "healthcheck" not in guard


def test_thehive_services_are_hardened() -> None:
    services = _compose()["services"]
    for name in THEHIVE_SERVICES:
        assert services[name]["security_opt"] == ["no-new-privileges:true"], name
        assert services[name]["cap_drop"] == ["ALL"], name
    guard = services[THEHIVE_GUARD_SERVICE]
    assert guard["read_only"] is True
    assert guard["deploy"]["resources"]["limits"]["memory"]


def test_thehive_healthchecks_probe_real_internal_listeners() -> None:
    """Cassandra cqlsh, ES `_cat/health`, TheHive `/thehive/api/status` (vendor paths)."""
    services = _compose()["services"]

    cassandra_check = " ".join(str(p) for p in services["thehive-cassandra"]["healthcheck"]["test"])
    assert "cqlsh" in cassandra_check
    assert "describe keyspaces" in cassandra_check

    es_check = " ".join(str(p) for p in services["thehive-elasticsearch"]["healthcheck"]["test"])
    assert "_cat/health" in es_check
    assert "elastic" in es_check

    thehive_check = " ".join(str(p) for p in services["thehive"]["healthcheck"]["test"])
    assert "/thehive/api/status" in thehive_check
    assert "9000" in thehive_check


def test_thehive_wires_cassandra_and_elasticsearch_internally() -> None:
    """TheHive connects to the in-profile Cassandra and Elasticsearch services only."""
    services = _compose()["services"]
    command = " ".join(str(part) for part in services["thehive"]["command"])
    assert "--cql-hostnames" in command
    assert "thehive-cassandra" in command
    assert "--es-hostnames" in command
    assert "thehive-elasticsearch" in command
    assert "--secret" in command
    assert "--storage-directory" in command
    depends_on = services["thehive"]["depends_on"]
    assert set(depends_on) == {THEHIVE_GUARD_SERVICE, "thehive-cassandra", "thehive-elasticsearch"}
    assert depends_on["thehive-cassandra"]["condition"] == "service_healthy"
    assert depends_on["thehive-elasticsearch"]["condition"] == "service_healthy"


def test_every_thehive_service_waits_for_the_secret_guard() -> None:
    """No container can start before the guard has validated the .env values."""
    services = _compose()["services"]
    for name in THEHIVE_STACK_SERVICES:
        depends_on = services[name]["depends_on"]
        assert depends_on[THEHIVE_GUARD_SERVICE]["condition"] == "service_completed_successfully", (
            name
        )


def test_thehive_state_is_confined_to_additive_named_volumes() -> None:
    compose = _compose()
    assert set(compose["volumes"]) >= {
        "thehive-cassandra-data",
        "thehive-elasticsearch-data",
        "thehive-data",
    }
    services = compose["services"]
    for name in THEHIVE_STACK_SERVICES:
        mounts = services[name].get("volumes", [])
        assert mounts, name
        for mount in mounts:
            assert not mount.startswith("./"), (name, mount)
            assert mount.startswith("thehive-"), (name, mount)
    # The guard only inspects env: no mounts either.
    assert "volumes" not in services[THEHIVE_GUARD_SERVICE]


# ---------------------------------------------------------------------------
# Secrets: environment only, no committed defaults
# ---------------------------------------------------------------------------


def test_thehive_secrets_are_environment_only_and_interpolation_safe() -> None:
    """Secrets come from `.env` only, and only with interpolation-safe defaults.

    Compose interpolates the entire file — profile-gated services included —
    before filtering inactive profiles, so a required-variable reference inside
    this block would make the default `docker compose up -d` fail until TheHive
    was configured. The guard container owns the fail-fast contract instead.
    """
    text = _thehive_compose_text()
    # Comments are allowed to *mention* the syntax they explain; YAML must not use it.
    yaml_lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    yaml_only = "\n".join(yaml_lines)
    assert ":?" not in yaml_only
    required_set = {"THEHIVE_SECRET", "THEHIVE_API_KEY", "ELASTICSEARCH_PASSWORD"}
    for reference in re.findall(r"\$\{([A-Z0-9_]+)(:[^}]*)?\}", yaml_only):
        if reference[0] in required_set:
            assert reference[1].startswith(":-"), reference
    guard_env = _compose()["services"][THEHIVE_GUARD_SERVICE]["environment"]
    assert set(guard_env) == set(REQUIRED_SECRETS)
    for name in REQUIRED_SECRETS:
        assert guard_env[name] == f"${{{name}:-}}", name


def test_preflight_guard_blocks_the_profile_without_secrets() -> None:
    """Executed guard: an unconfigured `.env` aborts the profile, listing names."""
    result = _run_preflight({})
    assert result.returncode == 1
    assert result.stdout == ""
    assert "ERROR" in result.stderr
    for name in REQUIRED_SECRETS:
        assert name in result.stderr, name


def test_preflight_guard_passes_when_every_secret_is_set() -> None:
    values = {name: f"synthetic-{name.lower()}" for name in REQUIRED_SECRETS}
    result = _run_preflight(values)
    assert result.returncode == 0, result.stderr
    assert "present" in result.stdout


def test_thehive_compose_contains_no_credential_literals() -> None:
    text = _thehive_compose_text()
    assert SECRET_ASSIGNMENT.search(text) is None
    for pattern in TOKEN_PATTERNS:
        assert pattern.search(text) is None, pattern.pattern


# ---------------------------------------------------------------------------
# Platform-side wiring: disable-by-empty + SQLite default
# ---------------------------------------------------------------------------


def test_triage_api_keeps_thehive_disabled_by_empty() -> None:
    """Platform-side defaults stay empty: no TheHive URL/key ⇒ export disabled."""
    env = _compose()["services"]["triage-api"]["environment"]
    assert env["THEHIVE_URL"] == "${THEHIVE_URL:-}"
    assert env["THEHIVE_API_KEY"] == "${THEHIVE_API_KEY:-}"
    assert env["THEHIVE_ORGANISATION"] == "${THEHIVE_ORGANISATION:-}"
    assert env["THEHIVE_VERIFY_TLS"] == "${THEHIVE_VERIFY_TLS:-1}"
    assert env["THEHIVE_TIMEOUT_SECONDS"] == "${THEHIVE_TIMEOUT_SECONDS:-10}"
    # No default service may require a TheHive credential to start.
    for name in DEFAULT_SERVICES:
        for key, value in _compose()["services"][name].get("environment", {}).items():
            assert not ("THEHIVE" in str(key) and ":?" in str(value)), (name, key, value)


def test_triage_api_default_database_remains_sqlite() -> None:
    """SQLite stays the default; TheHive never shifts the triage-api database."""
    env = _compose()["services"]["triage-api"]["environment"]
    db_url = str(env.get("TRIAGE_DB_URL", ""))
    assert "sqlite" in db_url
    assert "${TRIAGE_DB_URL:-sqlite" in db_url
    depends_on = _compose()["services"]["triage-api"].get("depends_on", {})
    assert not set(depends_on) & set(THEHIVE_SERVICES)


def test_thehive_profile_renders_safely_with_empty_defaults() -> None:
    """Empty-safe interpolation keeps the profile valid for the default stack.

    Docker is unavailable in CI, so the test exercises the static contract that
    makes full-file interpolation safe: (a) no ``${VAR:?…}`` reference appears
    anywhere in the profile block; (b) every ``${VAR…}`` reference inside the
    block carries an interpolation-safe ``:-`` default or is a plain ``${VAR}``
    (a plain reference interpolates to an empty string — never an error); and
    (c) the block itself survives a YAML re-load after ``:-`` defaults are
    normalized. The preflight guard — not interpolation — is what fails fast for
    missing secrets at runtime.
    """
    text = _thehive_compose_text()
    # Comments may *mention* `:?` while explaining why it is not used; only the
    # YAML (non-comment) lines must be free of it. Runtime-escaped `$${VAR}`
    # refs (which Compose collapses to `$$` before filtering) are not Compose
    # interpolation and are collapsed first.
    yaml_lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    yaml_only = "\n".join(yaml_lines).replace("$${", "$$RUNTIME{")
    assert not re.search(r"\$\{[A-Z0-9_]+:[?]", yaml_only)
    for reference in re.findall(r"\$\{([A-Z0-9_]+)(:[^}]*)?\}", yaml_only):
        assert reference[1] is None or reference[1].startswith(":-"), reference
    # `:-` references already resolve to empty strings; pin that form explicitly.
    assert "${THEHIVE_SECRET:-}" in yaml_only
    assert "${ELASTICSEARCH_PASSWORD:-}" in yaml_only
    # The dedented services must still parse as a mapping after subst-normalization.
    normalized = re.sub(r"\$\{[A-Z0-9_]+:[^}]*\}", r"$$EMPTY$$", yaml_only)
    yaml.safe_load(normalized)  # raises on malformed YAML


# ---------------------------------------------------------------------------
# Documentation: thehive/README.md reflects unimplemented-runtime truth
# ---------------------------------------------------------------------------


def test_thehive_readme_documents_status_and_runtime_truth() -> None:
    """The README must document CE-only, optional, env-backed, operator-validated."""
    assert THEHIVE_README.exists(), "thehive/README.md is missing"
    readme = THEHIVE_README.read_text(encoding="utf-8")
    lowered = readme.lower()
    for required in (
        "--profile thehive",
        "community edition",
        "not claimed",
        "operator",
        "host ports",
        "thehive_url",
        "thehive_api_key",
        "premium",
        "disable-by-empty",
    ):
        assert required in lowered, required
    # TheHive CE requirement stated; Premium never required.
    assert "never premium" in lowered or "no premium" in lowered
    # No production claim.
    assert "production" not in lowered or "no production" in lowered
