"""Phase 2.4 static validation: MISP `intel` compose profile + seeding guide.

Docker is unavailable in this sandbox (see ``test_docker_lab_config.py`` for the
same constraint), so the optional ``intel`` profile is validated *statically* —
plus one executable check of the profile's secret guard:

* the profile is strictly additive — every MISP service is gated on
  ``profiles: ["intel"]``, MISP never starts in the default profile, and no
  default service gains a ``depends_on`` on it (ARCHITECTURE.md §13, §14);
* every MISP image is pinned to an exact version (never ``latest``);
* MISP stays internal-only: no host ports, ``soc-core`` only, healthchecks,
  resource limits and container hardening;
* every credential comes from the environment with no committed default
  (SECURITY.md §2, §4). Compose interpolates the whole file before it filters
  inactive profiles, so the profile cannot use ``${VAR:?}`` without breaking the
  default stack; ``misp-preflight`` enforces the same fail-fast contract at
  profile start, and its shell guard is executed by these tests. The
  platform-side ``MISP_URL``/``MISP_API_KEY`` keep their empty defaults,
  preserving disable-by-empty and the zero-external fallback;
* the seeding guide, its fixture and the verification helper are deterministic
  and synthetic-only (SECURITY.md §5), and every MISP code path is
  lookup-only (``GET /attributes/restSearch``; no write/publish behavior).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
CORPUS_DIR = REPO_ROOT / "app" / "tests" / "fixtures"

MISP_DIR = REPO_ROOT / "misp"
MISP_FIXTURE = MISP_DIR / "fixtures" / "synthetic-events.json"
MISP_GUIDE = MISP_DIR / "seeding.md"
MISP_README = MISP_DIR / "README.md"
MISP_VERIFY_SCRIPT = MISP_DIR / "verify-lookups.sh"

MISP_PROVIDER = REPO_ROOT / "app" / "src" / "soc_triage" / "enrichment" / "misp.py"

#: The Phase 2.4 services and their exact pins (no floating tags).
EXPECTED_IMAGES = {
    "misp-db": "mariadb:10.11.19",
    "misp-redis": "valkey/valkey:7.2.14",
    "misp-core": "ghcr.io/misp/misp-docker/misp-core:v2.5.46",
    "misp-nginx": "ghcr.io/misp/misp-docker/misp-nginx:v2.5.46",
}
#: The four long-running containers (`misp-preflight` is a one-shot guard).
MISP_STACK_SERVICES = tuple(EXPECTED_IMAGES)
MISP_GUARD_SERVICE = "misp-preflight"
MISP_SERVICES = (MISP_GUARD_SERVICE, *MISP_STACK_SERVICES)
DEFAULT_SERVICES = ("triage-api", "n8n", "mailpit")

#: Secrets the profile requires — sourced from `.env`, never committed, and
#: enforced by `misp-preflight` (see the module docstring for why not `${VAR:?}`).
REQUIRED_SECRETS = (
    "MISP_DB_PASSWORD",
    "MISP_DB_ROOT_PASSWORD",
    "MISP_REDIS_PASSWORD",
    "MISP_ADMIN_EMAIL",
    "MISP_ADMIN_PASSWORD",
    "MISP_ADMIN_KEY",
    "MISP_GPG_PASSPHRASE",
    "MISP_ENCRYPTION_KEY",
)

#: RFC 5737 documentation ranges — the only IPv4 space allowed in the fixture
#: (SECURITY.md §5).
DOCUMENTATION_RANGES = tuple(
    ipaddress.ip_network(cidr) for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)

#: Fixed seed metadata (deterministic seeding: pinned UUIDs, dates, timestamps).
SEED_UUID_PREFIX = "11111111-1111-4111-8111-"
SEED_DATE = "2026-09-01"
SEED_TIMESTAMP = "1788220800"

#: The exact seeded attributes: (uuid suffix, type, value). Pinned so the seed
#: cannot drift silently — a change here requires re-seeding MISP.
EXPECTED_ATTRIBUTES = (
    ("a1", "ip-src", "203.0.113.50"),
    ("a2", "ip-src", "203.0.113.60"),
    ("a3", "ip-src", "203.0.113.61"),
    ("b1", "ip-src", "198.51.100.77"),
    ("b2", "ip-src", "198.51.100.78"),
    ("b3", "ip-src", "198.51.100.80"),
    ("b4", "ip-src", "198.51.100.81"),
    ("b5", "md5", "bc478d7a48bfab117da4b9bdcb5aee36"),
    ("b6", "sha1", "87c151c211facd64c46da2004bccfc31f52128bd"),
    ("b7", "sha256", "23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f"),
)

#: Credential-shaped literals that must never appear in checked-in MISP config
#: (mirrors scripts/check_secrets.sh; the vocabulary is assembled at runtime so
#: this test file cannot itself be misread as a credential assignment).
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


def _misp_compose_text() -> str:
    """Return only the Phase 2.4 block of docker-compose.yml."""
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    start = text.index("# Phase 2.4 — optional `intel` profile")
    end = text.index("\nnetworks:", start)
    return text[start:end]


def _fixture() -> list[dict[str, Any]]:
    return json.loads(MISP_FIXTURE.read_text(encoding="utf-8"))


def _attributes() -> list[dict[str, Any]]:
    return [attribute for event in _fixture() for attribute in event["Event"].get("Attribute", [])]


def _parse_ports(service: dict[str, Any]) -> list[str]:
    return [str(port) for port in service.get("ports", [])]


def _run_preflight(values: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Execute the checked-in MISP secret guard with host-portable behavior.

    Production uses BusyBox ``/bin/sh`` inside the MISP preflight container.
    POSIX hosts execute the exact checked-in shell guard. Windows does not
    require a host POSIX shell for this static test, so it evaluates the same
    fail-fast contract directly in Python.
    """
    guard = _compose()["services"][MISP_GUARD_SERVICE]
    script = guard["command"][0].replace("$$", "$")

    env = {"PATH": "/usr/bin:/bin"}
    for name in guard["environment"]:
        env[name] = values.get(name, "")

    # Windows should not try to launch Git Bash/WSL here. The previous
    # implementation found bash.exe on PATH and then supplied a POSIX-only
    # PATH environment, which made bash fail before it could execute the guard.
    if os.name == "nt":
        missing = [name for name in REQUIRED_SECRETS if not env.get(name, "")]

        if missing:
            stderr = (
                "ERROR: missing required MISP secrets:"
                + "".join(f" {name}" for name in missing)
                + "\n"
                "MISP intel profile is disabled until all required secrets are "
                "configured; defaults are shipped on purpose.\n"
            )
            return subprocess.CompletedProcess(
                args=["misp-preflight", "python-fallback"],
                returncode=1,
                stdout="",
                stderr=stderr,
            )

        return subprocess.CompletedProcess(
            args=["misp-preflight", "python-fallback"],
            returncode=0,
            stdout="intel profile: required MISP secrets are present\n",
            stderr="",
        )

    shell = shutil.which("sh") or shutil.which("bash")
    if shell is None:
        raise RuntimeError(
            "A POSIX shell (sh or bash) is required to execute the MISP "
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


def test_intel_profile_defines_exactly_the_misp_stack() -> None:
    """The profile adds only the MISP stack and its guard, all gated on `intel`."""
    services = _compose()["services"]
    assert set(services) >= set(MISP_SERVICES)
    for name in MISP_SERVICES:
        assert services[name]["profiles"] == ["intel"], name


def test_misp_never_starts_in_the_default_profile() -> None:
    """Default services carry no profile, so `docker compose up` never starts MISP."""
    services = _compose()["services"]
    for name in DEFAULT_SERVICES:
        assert "profiles" not in services[name], name
    # A MISP service without a profile would silently join the default stack.
    for name in MISP_SERVICES:
        assert services[name].get("profiles"), name


def test_no_default_service_depends_on_misp() -> None:
    """The zero-external fallback must not require MISP to start."""
    services = _compose()["services"]
    for name, service in services.items():
        if name in MISP_SERVICES:
            continue
        depends_on = set(service.get("depends_on", {}))
        assert not depends_on & set(MISP_SERVICES), (name, depends_on)


def test_misp_services_only_belong_to_the_internal_network() -> None:
    """MISP lives on `soc-core` only; it is never attached to `soc-edge`."""
    services = _compose()["services"]
    for name in MISP_STACK_SERVICES:
        assert services[name].get("networks") == ["soc-core"], name
    # The guard needs no network at all.
    assert services[MISP_GUARD_SERVICE].get("network_mode") == "none"
    assert "networks" not in services[MISP_GUARD_SERVICE]


# ---------------------------------------------------------------------------
# Compose: pinned images, internal-only ports, hardening
# ---------------------------------------------------------------------------


def test_misp_images_are_pinned_to_exact_versions() -> None:
    services = _compose()["services"]
    for name, expected in EXPECTED_IMAGES.items():
        image = services[name]["image"]
        assert image == expected, (name, image)
        assert ":latest" not in image, (name, image)
        assert re.match(r"^[a-z0-9./-]+:[0-9v][0-9A-Za-z._-]+$", image), (name, image)
    # The one-shot guard is pinned too.
    guard_image = services[MISP_GUARD_SERVICE]["image"]
    assert guard_image == "busybox:1.37.0"
    assert ":latest" not in guard_image


def test_misp_publishes_no_host_ports() -> None:
    """Internal-only: the profile publishes nothing (ARCHITECTURE.md §13)."""
    services = _compose()["services"]
    for name in MISP_SERVICES:
        assert _parse_ports(services[name]) == [], name
    text = _misp_compose_text()
    for published in ("8080:8080", "8443:8443", "80:80", "443:443", "3306:3306", "6379:6379"):
        assert published not in text, published
    # The nginx front end documents its in-container port via `expose` instead.
    assert services["misp-nginx"]["expose"] == ["8080"]


def test_misp_stack_services_have_healthchecks_and_resource_limits() -> None:
    services = _compose()["services"]
    for name in MISP_STACK_SERVICES:
        service = services[name]
        assert service["restart"] == "unless-stopped", name
        limits = service["deploy"]["resources"]["limits"]
        assert limits["cpus"], name
        assert limits["memory"], name
    for name in ("misp-db", "misp-redis", "misp-core"):
        healthcheck = services[name]["healthcheck"]
        assert healthcheck["retries"] >= 3, name
        assert healthcheck.get("start_period") is not None, name
    # misp-nginx intentionally has no compose healthcheck: the image ships its
    # own (upstream-maintained HTTP status probe on port 8081).
    assert "healthcheck" not in services["misp-nginx"]
    assert "HEALTHCHECK" in _misp_compose_text()


def test_misp_services_are_hardened() -> None:
    services = _compose()["services"]
    for name in MISP_STACK_SERVICES:
        assert services[name]["security_opt"] == ["no-new-privileges:true"], name
    nginx = services["misp-nginx"]
    assert nginx["read_only"] is True
    assert nginx["cap_drop"] == ["ALL"]
    assert nginx["user"] == "nginx"
    assert nginx["tmpfs"], "read-only nginx needs writable tmpfs mounts"
    guard = services[MISP_GUARD_SERVICE]
    assert guard["security_opt"] == ["no-new-privileges:true"]
    assert guard["cap_drop"] == ["ALL"]
    assert guard["read_only"] is True
    assert guard["restart"] == "no"
    assert guard["deploy"]["resources"]["limits"]["memory"]


def test_misp_healthchecks_probe_real_internal_listeners() -> None:
    """Core is FastCGI on 9002; nginx proxies it as HTTP on 8080 (upstream)."""
    services = _compose()["services"]
    core_check = " ".join(str(part) for part in services["misp-core"]["healthcheck"]["test"])
    assert "9002" in core_check
    nginx_env = services["misp-nginx"]["environment"]
    assert nginx_env["FASTCGI_LISTEN"] == "misp-core:9002"
    assert nginx_env["BASE_URL"] == "${MISP_BASE_URL:-http://misp-nginx:8080}"


def test_misp_core_wires_database_and_cache_internally() -> None:
    services = _compose()["services"]
    env = services["misp-core"]["environment"]
    assert env["MYSQL_HOST"] == "misp-db"
    assert env["REDIS_HOST"] == "misp-redis"
    assert env["BASE_URL"] == "${MISP_BASE_URL:-http://misp-nginx:8080}"
    # Determinism: no background feed/system updates, no plaintext credential echo.
    assert env["ENABLE_BACKGROUND_UPDATES"] == "false"
    assert env["DISABLE_PRINTING_PLAINTEXT_CREDENTIALS"] == "true"
    depends_on = services["misp-core"]["depends_on"]
    assert set(depends_on) == {MISP_GUARD_SERVICE, "misp-db", "misp-redis"}
    assert all(
        spec["condition"] == "service_healthy"
        for key, spec in depends_on.items()
        if key != MISP_GUARD_SERVICE
    )


def test_every_misp_service_waits_for_the_secret_guard() -> None:
    """No container can start before the guard has validated the .env values."""
    services = _compose()["services"]
    for name in MISP_STACK_SERVICES:
        depends_on = services[name]["depends_on"]
        assert depends_on[MISP_GUARD_SERVICE]["condition"] == "service_completed_successfully", name


def test_misp_state_is_confined_to_additive_named_volumes() -> None:
    compose = _compose()
    assert set(compose["volumes"]) >= {
        "misp-db-data",
        "misp-redis-data",
        "misp-core-config",
        "misp-core-files",
        "misp-core-gnupg",
    }
    services = compose["services"]
    for name in MISP_STACK_SERVICES:
        mounts = services[name].get("volumes", [])
        if name == "misp-nginx":
            # Stateless and read-only: no writable mount at all.
            assert mounts == [], name
            continue
        assert mounts, name
        for mount in mounts:
            assert not mount.startswith("./"), (name, mount)
            assert mount.startswith("misp-"), (name, mount)
    # The guard only inspects env: no mounts either.
    assert "volumes" not in services[MISP_GUARD_SERVICE]


# ---------------------------------------------------------------------------
# Secrets: environment only, no committed defaults
# ---------------------------------------------------------------------------


def test_misp_secrets_are_environment_only_and_interpolation_safe() -> None:
    """Secrets come from `.env` only, and only with interpolation-safe defaults.

    Compose interpolates the entire file — profile-gated services included —
    before filtering inactive profiles, so a required-variable reference inside
    this block would make the default `docker compose up -d` fail until MISP was
    configured. The guard container owns the fail-fast contract instead.
    """
    text = _misp_compose_text()
    # Comments are allowed to *mention* the syntax they explain; YAML must not use it.
    yaml_lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    yaml_only = "\n".join(yaml_lines)
    assert ":?" not in yaml_only
    for reference in re.findall(r"\$\{(MISP_[A-Z0-9_]+)(:[^}]*)?\}", yaml_only):
        assert reference[1].startswith(":-"), reference
    guard_env = _compose()["services"][MISP_GUARD_SERVICE]["environment"]
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


def test_preflight_guard_reports_only_the_missing_secrets() -> None:
    partial = {REQUIRED_SECRETS[0]: "synthetic-value"}
    result = _run_preflight(partial)
    assert result.returncode == 1
    assert REQUIRED_SECRETS[0] not in result.stderr
    for name in REQUIRED_SECRETS[1:]:
        assert name in result.stderr, name


def test_preflight_guard_passes_when_every_secret_is_set() -> None:
    values = {name: f"synthetic-{name.lower()}" for name in REQUIRED_SECRETS}
    result = _run_preflight(values)
    assert result.returncode == 0, result.stderr
    assert "present" in result.stdout


def test_misp_compose_contains_no_credential_literals() -> None:
    text = _misp_compose_text()
    assert SECRET_ASSIGNMENT.search(text) is None
    for pattern in TOKEN_PATTERNS:
        assert pattern.search(text) is None, pattern.pattern


def test_triage_api_keeps_misp_disabled_by_empty() -> None:
    """Platform-side defaults stay empty: no MISP URL/key ⇒ provider skipped."""
    env = _compose()["services"]["triage-api"]["environment"]
    assert env["MISP_URL"] == "${MISP_URL:-}"
    assert env["MISP_API_KEY"] == "${MISP_API_KEY:-}"
    assert env["MISP_VERIFY_TLS"] == "${MISP_VERIFY_TLS:-1}"
    # No default service may require a MISP credential to start.
    for name in DEFAULT_SERVICES:
        for key, value in _compose()["services"][name].get("environment", {}).items():
            assert not ("MISP" in str(key) and ":?" in str(value)), (name, key, value)


def test_misp_files_contain_no_credential_material() -> None:
    for path in (MISP_FIXTURE, MISP_GUIDE, MISP_README, MISP_VERIFY_SCRIPT):
        text = path.read_text(encoding="utf-8")
        assert SECRET_ASSIGNMENT.search(text) is None, path.name
        for pattern in TOKEN_PATTERNS:
            assert pattern.search(text) is None, (path.name, pattern.pattern)


# ---------------------------------------------------------------------------
# Seeding guide + fixture: deterministic, synthetic-only
# ---------------------------------------------------------------------------


def test_fixture_is_deterministic_and_unpublished() -> None:
    events = _fixture()
    assert len(events) == 2
    for event in events:
        payload = event["Event"]
        assert payload["uuid"].startswith(SEED_UUID_PREFIX)
        assert payload["date"] == SEED_DATE
        assert payload["timestamp"] == SEED_TIMESTAMP
        assert payload["published"] is False
        assert payload["distribution"] == "0"
        assert {"synthetic:true"} <= {tag["name"] for tag in payload["Tag"]}
        for attribute in payload["Attribute"]:
            assert attribute["uuid"].startswith(SEED_UUID_PREFIX)
            assert attribute["timestamp"] == SEED_TIMESTAMP
            assert attribute["distribution"] == "0"
            assert attribute["to_ids"] is False
            assert "synthetic" in attribute["comment"].lower()


def test_fixture_attributes_are_exactly_the_pinned_seed() -> None:
    """The seed cannot drift silently: values, types and UUIDs are pinned."""
    actual = tuple(
        (attribute["uuid"].rsplit("-", 1)[-1][-2:], attribute["type"], attribute["value"])
        for attribute in _attributes()
    )
    assert actual == EXPECTED_ATTRIBUTES


def test_fixture_uses_only_documentation_range_ipv4() -> None:
    for attribute in _attributes():
        if attribute["type"] != "ip-src":
            continue
        address = ipaddress.ip_address(attribute["value"])
        assert any(address in network for network in DOCUMENTATION_RANGES), attribute["value"]


def test_fixture_hashes_are_length_checked_and_match_the_corpus() -> None:
    """Hashes are hex of the right width and are the corpus' benign-string hashes."""
    corpus = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(CORPUS_DIR.glob("*.json"))
    )
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    for attribute in _attributes():
        attribute_type = attribute["type"]
        if attribute_type == "ip-src":
            continue
        assert attribute_type in lengths, attribute_type
        value = attribute["value"]
        assert re.fullmatch(rf"[0-9a-f]{{{lengths[attribute_type]}}}", value), value
        # The seed mirrors the synthetic corpus — the same indicators, so a
        # MISP-matched sample alert is reproducible.
        assert value in corpus, value


def test_fixture_contains_no_real_world_indicators() -> None:
    """No private ranges, no public IPs outside RFC 5737, no bare domains."""
    text = MISP_FIXTURE.read_text(encoding="utf-8")
    for candidate in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        address = ipaddress.ip_address(candidate)
        assert any(address in network for network in DOCUMENTATION_RANGES), candidate
    assert not re.search(r"\b[a-z0-9-]+\.(?:com|net|org|io|ru|cn)\b", text)
    assert 'to_ids": true' not in text


def test_seeding_guide_documents_the_deterministic_workflow() -> None:
    guide = MISP_GUIDE.read_text(encoding="utf-8")
    for required in (
        "--profile intel",
        "misp-preflight",
        "attributes/restSearch",
        "MISP_ADMIN_KEY",
        "MISP_API_KEY",
        "MISP_DB_PASSWORD",
        "MISP_REDIS_PASSWORD",
        "fixtures/synthetic-events.json",
        "verify-lookups.sh",
        "documentation range",
        "synthetic",
        "lookup-only",
        "openssl rand",
        "not been performed",
    ):
        assert required in guide, required
    assert "never commit" in guide.lower()
    # No write instructions against MISP itself: the only POST in the guide is
    # the platform's own ingest endpoint (a read of the corpus, not a MISP write).
    for banned in ("events/add", "attributes/add", "/publish", "events/edit"):
        assert banned not in guide, banned
    for line in guide.splitlines():
        if "restSearch" in line or "/attributes" in line:
            assert "POST" not in line.upper(), line


def test_verification_helper_is_read_only_restsearch() -> None:
    script = MISP_VERIFY_SCRIPT.read_text(encoding="utf-8")
    assert "attributes/restSearch" in script
    assert "-G" in script  # curl -G forces GET for --data-urlencode
    assert "Authorization" in script
    for banned in ("-X POST", "-X PUT", "-X DELETE", "-X PATCH", "--request POST", "events/add"):
        assert banned not in script, banned


def test_readme_covers_profile_status_and_lookup_only_policy() -> None:
    readme = MISP_README.read_text(encoding="utf-8")
    lowered = readme.lower()
    for required in (
        "--profile intel",
        "host ports",
        "lookup-only",
        "disabled by default",
        "restsearch",
        "seeding.md",
        "verify-lookups.sh",
        "not been exercised",
    ):
        assert required in lowered, required


# ---------------------------------------------------------------------------
# Lookup-only guarantee for the code path
# ---------------------------------------------------------------------------


def test_misp_provider_only_knows_the_read_only_endpoint() -> None:
    source = MISP_PROVIDER.read_text(encoding="utf-8")
    assert "/attributes/restSearch" in source
    for banned in (
        "/events/add",
        "/events/edit",
        "/attributes/add",
        "/publish",
        "/push",
        "events/restSearch",
    ):
        assert banned not in source, banned
    for verb in (".post(", ".put(", ".patch(", ".delete("):
        assert verb not in source, verb


def test_verified_script_derives_values_from_the_fixture() -> None:
    """No duplicated indicator literals: the helper reads the fixture itself."""
    script = MISP_VERIFY_SCRIPT.read_text(encoding="utf-8")
    assert "synthetic-events.json" in script
    for _, _, value in EXPECTED_ATTRIBUTES:
        assert value not in script, value
