"""Static Docker lab configuration regression tests.

Docker is intentionally unavailable in this sandbox. These tests validate the
checked-in Docker/compose configuration without invoking a daemon:

* the container healthchecks point at the real FastAPI liveness route (/health)
* the triage-api service does not hard-depend on n8n or Mailpit at startup
"""

from __future__ import annotations

from pathlib import Path

import yaml

from soc_triage.core.config import Settings
from soc_triage.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = REPO_ROOT / "Dockerfile"
DEPLOY_DOCKERFILE = REPO_ROOT / "deploy" / "triage-api.Dockerfile"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
HEALTH_SOURCE = REPO_ROOT / "app" / "src" / "soc_triage" / "api" / "health.py"

OLD_HEALTHCHECK_URL = "http://localhost:8000/api/v1/health"
HEALTHCHECK_URL = "http://localhost:8000/health"


def _app_health_paths() -> set[str]:
    """Return the health-style paths exposed by the FastAPI application."""
    settings = Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="soc-test",
        triage_db_url="sqlite:///:memory:",
        triage_ingest_api_key="test-ingest-key-not-a-real-secret",
        n8n_callback_token="test-callback-token-not-a-real-secret",
    )
    app = create_app(settings=settings)
    return set(app.openapi()["paths"])


def test_triage_healthcheck_uses_real_fastapi_health_path() -> None:
    """Container healthchecks must target the actual application route.

    The health router is mounted without the ``/api/v1`` prefix, so the real
    liveness URL is ``/health``. This test also confirms the application opens
    that route.
    """
    paths = _app_health_paths()
    assert "/health" in paths
    assert "/api/v1/health" not in paths

    dockerfile_text = DOCKERFILE.read_text(encoding="utf-8")
    deploy_dockerfile_text = DEPLOY_DOCKERFILE.read_text(encoding="utf-8")
    compose_text = COMPOSE_FILE.read_text(encoding="utf-8")

    for label, text in (
        ("root Dockerfile", dockerfile_text),
        ("deploy Dockerfile", deploy_dockerfile_text),
        ("docker-compose.yml", compose_text),
    ):
        assert HEALTHCHECK_URL in text, f"{label} is missing {HEALTHCHECK_URL}"
        assert OLD_HEALTHCHECK_URL not in text, f"{label} still uses {OLD_HEALTHCHECK_URL}"

    compose = yaml.safe_load(compose_text)
    triage_healthcheck = compose["services"]["triage-api"]["healthcheck"]["test"]
    assert HEALTHCHECK_URL in " ".join(str(part) for part in triage_healthcheck)


def test_compose_is_valid_yaml() -> None:
    """The compose file must stay syntactically valid YAML."""
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert compose["services"]["triage-api"]["build"]["dockerfile"] == "Dockerfile"
    assert "n8n" in compose["services"]
    assert "mailpit" in compose["services"]


def test_triage_api_has_no_hard_dependency_on_n8n_or_mailpit() -> None:
    """Triage API startup must not depend on optional SOAR/notification services.

    Notification delivery is fail-open (ARCHITECTURE.md §16), so ``depends_on``
    for n8n or Mailpit would incorrectly make those optional services part of
    the API's startup contract.
    """
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    triage_api = compose["services"]["triage-api"]

    depends_on = triage_api.get("depends_on", {})
    blocking = set(depends_on)
    assert not blocking.intersection({"n8n", "mailpit"}), (
        f"triage-api must not hard-depend on optional services: {sorted(blocking)}"
    )


def test_compose_has_no_obsolete_version_field() -> None:
    """Compose v2 ignores top-level version; keep the file warning-free."""
    compose_text = COMPOSE_FILE.read_text(encoding="utf-8")
    compose = yaml.safe_load(compose_text)
    assert "version" not in compose
    assert not compose_text.lstrip().startswith("version:")


def test_mailpit_healthcheck_uses_documented_readyz() -> None:
    """Mailpit /api/v1/status is 404; /readyz is the documented readiness probe."""
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    healthcheck = compose["services"]["mailpit"]["healthcheck"]["test"]
    joined = " ".join(str(part) for part in healthcheck)
    assert "/readyz" in joined
    assert "/api/v1/status" not in joined
    assert "localhost" in joined or "127.0.0.1" in joined


def test_n8n_encryption_key_is_not_hardcoded() -> None:
    """Encryption key must come from .env; changing it on an existing volume mismatches."""
    compose_text = COMPOSE_FILE.read_text(encoding="utf-8")
    compose = yaml.safe_load(compose_text)
    key = compose["services"]["n8n"]["environment"]["N8N_ENCRYPTION_KEY"]
    assert "N8N_ENCRYPTION_KEY" in str(key)
    assert "lab-encryption-key-do-not-use-in-prod" not in compose_text
    assert "${N8N_ENCRYPTION_KEY:-" not in compose_text


def test_n8n_startup_does_not_pass_sh_as_cli_command() -> None:
    """n8nio/n8n:1.85.0 treats command args as n8n CLI verbs; do not pass sh there."""
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    n8n = compose["services"]["n8n"]
    command = n8n["command"]
    entrypoint = n8n.get("entrypoint")
    assert entrypoint == ["/bin/sh", "-c"]
    if isinstance(command, list):
        assert command[0] != "sh"
        joined = " ".join(str(part) for part in command)
    else:
        joined = str(command)
    assert "n8n-import-workflows.sh" in joined
    assert "n8n start" in joined


def test_health_source_does_not_hide_route_with_api_v1_prefix() -> None:
    """Guard against the route itself drifting under /api/v1.

    The container healthcheck is validated against the registered application
    route, but this keeps the source-level contract explicit as well.
    """
    source = HEALTH_SOURCE.read_text(encoding="utf-8")
    assert '@router.get("/health"' in source
    assert 'prefix="/api/v1' not in source
