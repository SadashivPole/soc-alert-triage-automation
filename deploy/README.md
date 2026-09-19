# deploy/ — Docker Build & Compose Fragments

Dockerfiles and compose configuration for the stack. The root `docker-compose.yml`
(Phase 1, assembled in `deploy/`) defines the default services; topology, networks,
profiles, ports, and hardening rules are fixed by design in
[ARCHITECTURE.md §13](../ARCHITECTURE.md#13-docker--deployment-architecture).

**Status:** the default stack (`triage-api`, `n8n`, `mailpit`) and the optional Phase 3.7
`observability` (`prometheus`, `grafana`), Phase 4.1 `full` (`wazuh-manager`) and Phase 2.4
`intel` (MISP) profiles are **implemented** in the root `docker-compose.yml`; every profile
is optional and additive (the default stack is unchanged). The Phase 3.8 `postgres`
profile is **implemented and contract-tested** (SQLite default preserved); live
PostgreSQL validation remains operator-side.
See [docs/specs/phase-3.7-prometheus-observability.md](../docs/specs/phase-3.7-prometheus-observability.md).

Files:

- **`triage-api.Dockerfile`** — deploy-side copy of the API image build (the compose
  stack builds the root `Dockerfile`; keep both in sync). Non-root `app` user, minimal
  `slim` base, tagged dependencies, `/health` healthcheck.
- **`prometheus/`** (Phase 3.7) — `prometheus.yml` scrape config: one static job,
  target `http://triage-api:8000/metrics` on `soc-core`, **15 s scrape interval / 10 s
  timeout**, no external targets, no secrets; `entrypoint.sh` keeps the checked-in
  config secret-free and, only when `METRICS_SCRAPE_TOKEN` is set at runtime, writes the
  token to a tmpfs credentials file (0600) and injects an `authorization.credentials_file`
  block into a generated config — the token value is never committed or inlined.
- **`grafana/`** (Phase 3.7) — provisioning (`datasources/prometheus.yml` → Prometheus
  at `http://prometheus:9090`; `dashboards/dashboards.yml` file provider) plus
  `dashboards/soc-triage-observability.json`, a 13-panel lab dashboard built only from
  the approved `soc_triage_*` metric catalog; no secrets.

Compose profiles (dockered, free, self-hosted only):

| Profile | Services | Ports published |
| --- | --- | --- |
| default | `triage-api`, `n8n`, `mailpit` | 8000, 5678, 8025/1025 |
| `observability` (Phase 3.7) | `prometheus`, `grafana` | Grafana 3000 (lab) only; Prometheus 9090 never published (internal `soc-core` scrape) |
| `full` (Phase 4.1) | `wazuh-manager` | 1514/1515 for agent enrollment only (Wazuh API 55000 never published) |
| `intel` (Phase 2.4) | `misp-db`, `misp-redis`, `misp-core`, `misp-nginx` | **none** — internal `soc-core` only (`triage-api` reaches MISP at `http://misp-nginx:8080`) |

Profile usage (optional, additive — the default stack is unchanged by the profile):

```bash
docker compose up -d                                   # default lab
docker compose --profile observability up -d           # + Prometheus + Grafana
docker compose --profile full up -d                    # + real Wazuh manager
docker compose --profile intel up -d                   # + self-hosted MISP (internal only)
```

Observability notes (Phase 3.7):

- Prometheus (`prom/prometheus:v3.5.0`) scrapes `triage-api` on `soc-core` every 15 s;
  port 9090 is **never** published (no `ports` entry). Grafana
  (`grafana/grafana:12.1.0`) publishes **3000 for lab access only**. Both run on
  `soc-core`, non-root, `cap_drop: ALL`, read-only root + tmpfs, healthchecks, 1 CPU /
  512 MB limits, named state volumes (`prometheus-data`, `grafana-data`).
- Token behavior: empty `METRICS_SCRAPE_TOKEN` = no `Authorization` header sent (matches
  the API's empty = auth disabled); when set, `entrypoint.sh` injects the runtime
  credentials file described above. Never hardcode a token in checked-in config.
- No secrets in any observability file; dashboards/provisioning are non-secret and
  labeled lab/portfolio.

MISP `intel` profile notes (Phase 2.4):

- Five pinned containers — a one-shot `misp-preflight` guard (`busybox:1.37.0`) plus
  `misp-db` (`mariadb:10.11.19`), `misp-redis` (`valkey/valkey:7.2.14`), `misp-core` and
  `misp-nginx` (`ghcr.io/misp/misp-docker/*:v2.5.46`) — profile-gated on `intel`,
  `soc-core` only (`misp-preflight` has no network), **no host ports**. MISP is never
  host-visible.
- Every credential comes from `.env` with no committed defaults. Because Compose
  interpolates the whole file before profile filtering, the profile deliberately avoids
  `${VAR:?…}`: the guard validates `MISP_DB_PASSWORD`, `MISP_DB_ROOT_PASSWORD`,
  `MISP_REDIS_PASSWORD`, `MISP_ADMIN_EMAIL`, `MISP_ADMIN_PASSWORD`, `MISP_ADMIN_KEY`,
  `MISP_GPG_PASSPHRASE` and `MISP_ENCRYPTION_KEY` before any container starts and aborts
  the profile naming every missing value (upstream defaults are unreachable). The admin
  key is pinned (deterministic first boot) and the API uses the same value through
  `MISP_API_KEY`; the platform-side `MISP_URL`/`MISP_API_KEY` defaults stay empty, so MISP
  lookups remain disabled until an operator opts in.
- **Lookup-only:** the platform issues `GET /attributes/restSearch` and nothing else.
  Seeding is a documented human action using only synthetic documentation-range
  indicators — [misp/seeding.md](../misp/seeding.md) and the read-only
  `misp/verify-lookups.sh`.
- **Validated statically only:** the profile/config/fixture are covered by tests; no
  Docker/MISP instance was started in CI, so no live lookup is claimed.

Hardening baseline (from [SECURITY.md §4](../SECURITY.md#4-network--container-security)):
non-root users, dropped capabilities, read-only filesystems where possible, resource
limits, no Docker socket, no `--privileged`, tag-pinned images, no secrets in any
checked-in configuration.
