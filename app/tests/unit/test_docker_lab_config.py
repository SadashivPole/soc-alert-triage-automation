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


def test_health_source_does_not_hide_route_with_api_v1_prefix() -> None:
    """Guard against the route itself drifting under /api/v1.

    The container healthcheck is validated against the registered application
    route, but this keeps the source-level contract explicit as well.
    """
    source = HEALTH_SOURCE.read_text(encoding="utf-8")
    assert '@router.get("/health"' in source
    assert 'prefix="/api/v1' not in source
