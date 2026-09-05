"""Static Docker lab configuration regression tests.

Docker is intentionally unavailable in this sandbox. These tests validate the
checked-in Docker/compose configuration without invoking a daemon:

* the container healthchecks point at the real FastAPI liveness route (/health)
* the triage-api service does not hard-depend on n8n or Mailpit at startup
* the Phase 3.7 (D11) optional ``observability`` profile is strictly additive:
  profile gating, pinned images, internal-only Prometheus scrape at
  ``triage-api:8000`` (9090 never published), Grafana lab port 3000, correct
  networks, healthchecks, resource limits, secret-free Prometheus/Grafana
  configuration and dashboards restricted to the approved metric catalog.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from soc_triage.core.config import Settings
from soc_triage.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = REPO_ROOT / "Dockerfile"
DEPLOY_DOCKERFILE = REPO_ROOT / "deploy" / "triage-api.Dockerfile"
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
HEALTH_SOURCE = REPO_ROOT / "app" / "src" / "soc_triage" / "api" / "health.py"
PROMETHEUS_CONFIG = REPO_ROOT / "deploy" / "prometheus" / "prometheus.yml"
PROMETHEUS_ENTRYPOINT = REPO_ROOT / "deploy" / "prometheus" / "entrypoint.sh"
GRAFANA_DATASOURCE = (
    REPO_ROOT / "deploy" / "grafana" / "provisioning" / "datasources" / "prometheus.yml"
)
GRAFANA_DASHBOARD_PROVIDER = (
    REPO_ROOT / "deploy" / "grafana" / "provisioning" / "dashboards" / "dashboards.yml"
)
GRAFANA_DASHBOARD = (
    REPO_ROOT / "deploy" / "grafana" / "dashboards" / "soc-triage-observability.json"
)

OLD_HEALTHCHECK_URL = "http://localhost:8000/api/v1/health"
HEALTHCHECK_URL = "http://localhost:8000/health"

#: The approved Phase 3.7 catalog (docs/specs/phase-3.7-prometheus-observability.md §5).
APPROVED_METRIC_FAMILIES = frozenset(
    {
        "soc_triage_http_requests",
        "soc_triage_http_request_duration_seconds",
        "soc_triage_ingest_rejections",
        "soc_triage_alerts_processed",
        "soc_triage_alert_processing_duration_seconds",
        "soc_triage_alerts_scored",
        "soc_triage_enrichment_status",
        "soc_triage_enrichment_provider_outcomes",
        "soc_triage_n8n_notifications",
        "soc_triage_n8n_notification_duration_seconds",
        "soc_triage_feedback",
        "soc_triage_incident_transitions",
        "soc_triage_incident_auto_close",
        "soc_triage_sweeper_passes",
        "soc_triage_up",
        "soc_triage_database_up",
        "soc_triage_migrations_applied",
    }
)

#: Label names approved for dashboard queries (spec §5 + prometheus bookkeeping).
APPROVED_DASHBOARD_LABELS = frozenset(
    {
        "method",
        "route",
        "status",
        "reason",
        "outcome",
        "tier",
        "decision",
        "degraded",
        "provider",
        "verdict",
        "from_status",
        "to_status",
        "result",
        "le",
        "job",
        "instance",
    }
)

#: Label names that must never appear in dashboard queries (high cardinality).
PROHIBITED_DASHBOARD_LABELS = frozenset(
    {
        "id",
        "alert_id",
        "incident_id",
        "rule_id",
        "agent_id",
        "ip",
        "domain",
        "url",
        "hash",
        "email",
        "username",
        "hostname",
        "path",
        "error",
        "exception",
        "message",
    }
)

#: Minimal credential-pattern set mirroring scripts/check_secrets.sh (D11-gated
#: files must stay clean of these in addition to the repo-wide scan). The key
#: vocabulary is assembled at runtime so this test file itself cannot be
#: misread as a credential assignment by the repo scanner.
_SECRET_KEYWORDS = (
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
)
SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?:{})\s*[:=]\s*[\"']?[A-Za-z0-9/+_]{{16,}}[\"']?".format("|".join(_SECRET_KEYWORDS))
    ),
)

DEFAULT_SERVICE_FACTS = {
    "triage-api": {"ports": ["8000:8000"], "networks": ["soc-core"]},
    "n8n": {"ports": ["5678:5678"], "networks": ["soc-core", "soc-edge"]},
    "mailpit": {"ports": ["1025:1025", "8025:8025"], "networks": ["soc-core"]},
}


def _compose() -> dict:
    """Load the root docker-compose.yml."""
    return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))


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


# ---------------------------------------------------------------------------
# Phase 3.7 (D11) — optional observability profile (compose + provisioning)
# ---------------------------------------------------------------------------


def _observability_files() -> dict[str, str]:
    """Map every observability artifact to its checked-in text."""
    return {
        "docker-compose.yml": COMPOSE_FILE.read_text(encoding="utf-8"),
        "deploy/prometheus/prometheus.yml": PROMETHEUS_CONFIG.read_text(encoding="utf-8"),
        "deploy/prometheus/entrypoint.sh": PROMETHEUS_ENTRYPOINT.read_text(encoding="utf-8"),
        "deploy/grafana/provisioning/datasources/prometheus.yml": GRAFANA_DATASOURCE.read_text(
            encoding="utf-8"
        ),
        "deploy/grafana/provisioning/dashboards/dashboards.yml": GRAFANA_DASHBOARD_PROVIDER.read_text(
            encoding="utf-8"
        ),
        "deploy/grafana/dashboards/soc-triage-observability.json": GRAFANA_DASHBOARD.read_text(
            encoding="utf-8"
        ),
    }


def test_observability_profile_gates_only_the_two_new_services() -> None:
    """prometheus/grafana are profile-gated; default services are not."""
    compose = _compose()
    assert set(compose["services"]) == {
        "triage-api",
        "n8n",
        "mailpit",
        "prometheus",
        "grafana",
        # Phase 4.1: the `full` profile is separately gated and asserted below.
        "wazuh-manager",
    }
    for name in ("prometheus", "grafana"):
        assert compose["services"][name].get("profiles") == ["observability"], name
    assert compose["services"]["wazuh-manager"].get("profiles") == ["full"]
    for name in ("triage-api", "n8n", "mailpit"):
        assert "profiles" not in compose["services"][name], name


def test_observability_images_are_pinned_not_floating() -> None:
    """Both observability images use pinned version tags (never ``latest``)."""
    compose = _compose()
    for name in ("prometheus", "grafana"):
        image = compose["services"][name]["image"]
        assert not image.endswith(":latest"), (name, image)
        assert ":latest" not in image, (name, image)
        assert re.match(r"^[a-z0-9]+/[a-z0-9-]+:[0-9v][0-9A-Za-z._-]+$", image), (name, image)


def test_prometheus_port_9090_is_never_published() -> None:
    """Prometheus stays internal-only; the profile never publishes 9090."""
    compose = _compose()
    service = compose["services"]["prometheus"]
    assert service.get("ports", []) == []
    compose_text = COMPOSE_FILE.read_text(encoding="utf-8")
    assert "9090:9090" not in compose_text
    assert "'9090'" not in compose_text


def test_grafana_publishes_only_the_approved_lab_port() -> None:
    """Grafana may publish 3000 (lab) and nothing else."""
    compose = _compose()
    assert compose["services"]["grafana"].get("ports") == ["3000:3000"]


def test_prometheus_scrape_config_matches_approved_contract() -> None:
    """One internal target (triage-api:8000), 15s interval, /metrics path."""
    config = yaml.safe_load(PROMETHEUS_CONFIG.read_text(encoding="utf-8"))
    assert config["global"]["scrape_interval"] == "15s"
    assert config["global"]["scrape_timeout"] == "10s"
    jobs = config["scrape_configs"]
    assert len(jobs) == 1
    job = jobs[0]
    assert job["job_name"] == "triage-api"
    assert job["metrics_path"] == "/metrics"
    assert job["scheme"] == "http"
    assert job["static_configs"] == [
        {"targets": ["triage-api:8000"], "labels": {"job": "triage-api"}}
    ]
    # Default config is auth-free and secret-free (auth is runtime-only,
    # injected by the entrypoint only when the env token is set).
    assert "authorization" not in job
    assert "bearer_token" not in job
    assert "credentials" not in job


def test_observability_services_use_only_internal_soc_core_network() -> None:
    """Both services join soc-core only; neither reaches soc-edge."""
    compose = _compose()
    for name in ("prometheus", "grafana"):
        networks = compose["services"][name].get("networks", [])
        assert networks == ["soc-core"], (name, networks)


def test_observability_services_are_not_required_dependencies() -> None:
    """No existing service depends on prometheus/grafana; defaults unchanged."""
    compose = _compose()
    for name, facts in DEFAULT_SERVICE_FACTS.items():
        service = compose["services"][name]
        depends_on = service.get("depends_on", {})
        assert not set(depends_on) & {"prometheus", "grafana", "wazuh-manager"}, (name, depends_on)
        assert service.get("ports") == facts["ports"], name
        assert service.get("networks") == facts["networks"], name
        assert "profiles" not in service, name
    # Topology: only the two existing networks; new volumes are additive.
    assert set(compose["networks"]) == {"soc-core", "soc-edge"}
    for network in compose["networks"].values():
        assert network == {"driver": "bridge"}
    assert set(compose["volumes"]) == {
        "n8n-data",
        "prometheus-data",
        "grafana-data",
        "wazuh-manager-etc",
        "wazuh-manager-logs",
        "wazuh-manager-queue",
    }


def test_observability_healthchecks_and_resource_limits_exist() -> None:
    """Both observability services have healthchecks and resource limits."""
    compose = _compose()
    expected = {
        "prometheus": ("http://127.0.0.1:9090/-/healthy", "1.0", "512M"),
        "grafana": ("http://127.0.0.1:3000/api/health", "1.0", "512M"),
    }
    for name, (url, cpus, memory) in expected.items():
        service = compose["services"][name]
        healthcheck = service["healthcheck"]
        joined = " ".join(str(part) for part in healthcheck["test"])
        assert url in joined, (name, joined)
        assert healthcheck["interval"] == "15s"
        assert healthcheck["retries"] >= 3
        assert healthcheck.get("start_period") is not None
        limits = service["deploy"]["resources"]["limits"]
        assert limits["cpus"] == cpus, name
        assert limits["memory"] == memory, name
        assert service["restart"] == "unless-stopped", name


def test_observability_configuration_contains_no_secrets() -> None:
    """No credential patterns, inline tokens, or credential keys in the profile."""
    for name, text in _observability_files().items():
        for pattern in SECRET_PATTERNS:
            assert pattern.search(text) is None, (name, pattern.pattern)
    datasource = yaml.safe_load(GRAFANA_DATASOURCE.read_text(encoding="utf-8"))
    assert datasource["datasources"][0]["type"] == "prometheus"
    assert "secureJsonData" not in datasource["datasources"][0]
    assert "basicAuth" not in datasource["datasources"][0]
    assert "user" not in datasource["datasources"][0]
    assert "password" not in datasource["datasources"][0]
    # Compose forwards the existing env token; the value is never inlined.
    compose_text = COMPOSE_FILE.read_text(encoding="utf-8")
    assert "${METRICS_SCRAPE_TOKEN:-}" in compose_text


def test_prometheus_auth_anchor_is_a_single_exact_marker() -> None:
    """The auth anchor is one standalone marker line (never a header match)."""
    config_text = PROMETHEUS_CONFIG.read_text(encoding="utf-8")
    anchors = [
        line.strip() for line in config_text.splitlines() if line.strip() == "# __SCRAPE_AUTH__"
    ]
    assert anchors == ["# __SCRAPE_AUTH__"]


def test_prometheus_entrypoint_uses_runtime_credentials_file_only() -> None:
    """The entrypoint forwards the env token via a runtime file, never inline."""
    script = PROMETHEUS_ENTRYPOINT.read_text(encoding="utf-8")
    assert "METRICS_SCRAPE_TOKEN" in script
    assert "credentials_file: $token_file" in script
    assert "umask 077" in script
    assert 'exec /bin/prometheus --config.file="$config_file" "$@"' in script
    assert "authorization" in script


def test_observability_defines_no_external_endpoints() -> None:
    """The profile only reaches in-stack services on the internal network."""
    for name, text in _observability_files().items():
        assert "host.docker.internal" not in text, name
        assert "http://172." not in text, name
        assert "http://10." not in text, name
    prometheus = yaml.safe_load(PROMETHEUS_CONFIG.read_text(encoding="utf-8"))
    assert prometheus["scrape_configs"][0]["static_configs"][0]["targets"] == ["triage-api:8000"]
    datasource = yaml.safe_load(GRAFANA_DATASOURCE.read_text(encoding="utf-8"))
    assert datasource["datasources"][0]["url"] == "http://prometheus:9090"
    provider = yaml.safe_load(GRAFANA_DASHBOARD_PROVIDER.read_text(encoding="utf-8"))
    assert provider["providers"][0]["options"]["path"] == "/var/lib/grafana/dashboards"


def _dashboard_exprs() -> list[str]:
    """Return every PromQL expression in the checked-in dashboard."""
    dashboard = json.loads(GRAFANA_DASHBOARD.read_text(encoding="utf-8"))
    return [
        target["expr"]
        for panel in dashboard["panels"]
        for target in panel["targets"]
        if target.get("expr")
    ]


def test_dashboard_references_only_approved_metric_families() -> None:
    """Dashboard queries use only the approved soc_triage_* catalog."""
    exprs = _dashboard_exprs()
    assert len(exprs) >= 11  # compact but covers the required panels
    referenced: set[str] = set()
    for expr in exprs:
        for name in re.findall(r"soc_triage_[a-z0-9_]+", expr):
            referenced.add(re.sub(r"_(total|count|sum|bucket|created)$", "", name))
    assert referenced <= APPROVED_METRIC_FAMILIES, referenced - APPROVED_METRIC_FAMILIES
    required = {
        "soc_triage_alerts_processed",
        "soc_triage_http_requests",
        "soc_triage_http_request_duration_seconds",
        "soc_triage_alerts_scored",
        "soc_triage_enrichment_status",
        "soc_triage_enrichment_provider_outcomes",
        "soc_triage_n8n_notifications",
        "soc_triage_feedback",
        "soc_triage_incident_transitions",
        "soc_triage_sweeper_passes",
    }
    assert required <= referenced, required - referenced


def test_dashboard_queries_introduce_no_high_cardinality_labels() -> None:
    """Label selectors in dashboard queries stay inside the approved set."""
    for expr in _dashboard_exprs():
        for selector in re.findall(r"\{([^}]*)\}", expr):
            names = {match[0] for match in re.findall(r"([a-z_]+)\s*(=~?|!~)", selector)}
            assert names <= APPROVED_DASHBOARD_LABELS, (expr, names - APPROVED_DASHBOARD_LABELS)
            assert not names & PROHIBITED_DASHBOARD_LABELS, (expr, names)
        for prohibited in PROHIBITED_DASHBOARD_LABELS - {"id"}:
            assert not re.search(rf"\b{prohibited}\b", expr), (expr, prohibited)


# ---------------------------------------------------------------------------
# Phase 4.1 — optional `full` profile (real Wazuh manager)
# ---------------------------------------------------------------------------

WAZUH_INTEGRATOR_DIR = REPO_ROOT / "wazuh" / "integrator"
WAZUH_OSSEC_CONF = REPO_ROOT / "wazuh" / "config" / "ossec.conf"
WAZUH_INSTALL_HOOK = REPO_ROOT / "wazuh" / "entrypoint-scripts" / "10-install-triage-integration.sh"


def _wazuh_service() -> dict:
    return _compose()["services"]["wazuh-manager"]


def test_wazuh_manager_is_profile_gated_and_pinned() -> None:
    """The manager only runs under `--profile full`, on a pinned 4.x tag."""
    service = _wazuh_service()
    assert service["profiles"] == ["full"]
    image = service["image"]
    assert image.startswith("wazuh/wazuh-manager:4.")
    assert ":latest" not in image
    assert re.match(r"^wazuh/wazuh-manager:4\.[0-9]+\.[0-9]+$", image), image


def test_wazuh_manager_is_never_a_dependency_of_the_default_stack() -> None:
    """Zero-external fallback: `sim` mode must still work with no Wazuh."""
    compose = _compose()
    for name in DEFAULT_SERVICE_FACTS:
        depends_on = compose["services"][name].get("depends_on", {})
        assert "wazuh-manager" not in set(depends_on), name


def test_wazuh_manager_publishes_only_agent_enrollment_ports() -> None:
    """1514/1515 for agents; the Wazuh API (55000) is never host-visible."""
    ports = _wazuh_service().get("ports", [])
    assert ports == ["1514:1514/tcp", "1515:1515/tcp"]
    assert all("55000" not in str(port) for port in ports)


def test_wazuh_manager_stays_on_the_internal_network() -> None:
    assert _wazuh_service().get("networks") == ["soc-core"]


def test_wazuh_manager_has_healthcheck_and_resource_limits() -> None:
    service = _wazuh_service()
    assert service["restart"] == "unless-stopped"
    assert service["healthcheck"]["retries"] >= 3
    assert service["healthcheck"].get("start_period") is not None
    limits = service["deploy"]["resources"]["limits"]
    assert limits["cpus"] == "2.0"
    assert limits["memory"] == "2G"
    assert service["security_opt"] == ["no-new-privileges:true"]


def test_wazuh_manager_takes_all_credentials_from_the_environment() -> None:
    """No credential literal is committed; required secrets fail fast."""
    env = _wazuh_service()["environment"]
    for name in ("API_USERNAME", "API_PASSWORD", "TRIAGE_INGEST_API_KEY"):
        value = str(env[name])
        assert value.startswith("${") and ":?" in value, (name, value)
        assert ":-" not in value, f"{name} must not carry a default credential"
    assert env["TRIAGE_API_BASE_URL"] == "${TRIAGE_API_BASE_URL:-http://triage-api:8000}"


def test_full_profile_mounts_are_read_only_and_repo_sourced() -> None:
    """Config/scripts come from this repo, read-only; only state is writable."""
    volumes = _wazuh_service()["volumes"]
    read_only = [v for v in volumes if v.startswith("./")]
    assert read_only, "integrator/config must be mounted from the repository"
    for mount in read_only:
        assert mount.endswith(":ro"), mount
    named = [v for v in volumes if not v.startswith("./")]
    assert {v.split(":")[0] for v in named} == {
        "wazuh-manager-etc",
        "wazuh-manager-logs",
        "wazuh-manager-queue",
    }


def test_ossec_conf_is_mounted_where_the_image_actually_copies_it() -> None:
    """The image copies /wazuh-config-mount/<path> -> /var/ossec/<path>.

    Wazuh has no ossec.conf.d include mechanism, so the whole ossec.conf must
    be mounted at /wazuh-config-mount/etc/ossec.conf or it silently never
    applies. Regression guard for the original (broken) fragment mount.
    """
    volumes = _wazuh_service()["volumes"]
    targets = [v.split(":")[1] for v in volumes if v.startswith("./")]
    assert "/wazuh-config-mount/etc/ossec.conf" in targets
    assert not any("ossec.conf.d" in target for target in targets), (
        "ossec.conf.d is not a Wazuh feature; the fragment would never load"
    )
    assert not any(target.startswith("/var/ossec/integrations") for target in volumes), (
        "integrations/ must be installed by the entrypoint hook with root:wazuh 750, "
        "not bind-mounted with host ownership"
    )


def test_full_profile_installs_the_integrator_via_the_entrypoint_hook() -> None:
    """The image runs /entrypoint-scripts/*.sh before starting Wazuh."""
    volumes = _wazuh_service()["volumes"]
    targets = [v.split(":")[1] for v in volumes if v.startswith("./")]
    assert "/entrypoint-scripts" in targets
    assert "/triage-integration" in targets


def test_full_profile_configuration_contains_no_secrets() -> None:
    files = {
        "docker-compose.yml (wazuh)": COMPOSE_FILE.read_text(encoding="utf-8"),
        "wazuh/config/ossec.conf": WAZUH_OSSEC_CONF.read_text(encoding="utf-8"),
        "wazuh/entrypoint-scripts/install": WAZUH_INSTALL_HOOK.read_text(encoding="utf-8"),
        "wazuh/integrator/custom-triage": (WAZUH_INTEGRATOR_DIR / "custom-triage").read_text(
            encoding="utf-8"
        ),
        "wazuh/integrator/custom-triage.py": (WAZUH_INTEGRATOR_DIR / "custom-triage.py").read_text(
            encoding="utf-8"
        ),
    }
    for name, text in files.items():
        for pattern in SECRET_PATTERNS:
            assert pattern.search(text) is None, (name, pattern.pattern)


def test_full_profile_declares_no_active_response() -> None:
    """Defensive-only charter (SECURITY.md §1): no containment anywhere."""
    text = COMPOSE_FILE.read_text(encoding="utf-8").lower()
    for banned in ("active-response", "active_response", "firewall-drop", "host-deny"):
        assert banned not in text, banned


def test_wazuh_healthcheck_targets_a_real_daemon_name() -> None:
    """`wazuh-control status` prints '<daemon> is running...' per daemon.

    wazuh-analysisd is a non-optional daemon (src/init/wazuh-server.sh
    DAEMONS), so it is a valid readiness signal.
    """
    joined = " ".join(str(p) for p in _wazuh_service()["healthcheck"]["test"])
    assert "/var/ossec/bin/wazuh-control status" in joined
    assert "wazuh-analysisd is running" in joined
