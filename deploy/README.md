# deploy/ — Docker Build & Compose Fragments

Dockerfiles and compose configuration for the stack. The root `docker-compose.yml`
(Phase 1, assembled in `deploy/`) defines the default services; topology, networks,
profiles, ports, and hardening rules are fixed by design in
[ARCHITECTURE.md §13](../ARCHITECTURE.md#13-docker--deployment-architecture).

**Status:** the default stack (`triage-api`, `n8n`, `mailpit`) and the Phase 3.7
`observability` profile (`prometheus`, `grafana`) are **implemented** in the root
`docker-compose.yml`; the profile is optional and additive (the default stack is
unchanged). Other profiles (`full`, `intel`, `postgres`) remain planned per the roadmap.
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

Profile usage (optional, additive — the default stack is unchanged by the profile):

```bash
docker compose up -d                                   # default lab
docker compose --profile observability up -d           # + Prometheus + Grafana
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

Hardening baseline (from [SECURITY.md §4](../SECURITY.md#4-network--container-security)):
non-root users, dropped capabilities, read-only filesystems where possible, resource
limits, no Docker socket, no `--privileged`, tag-pinned images, no secrets in any
checked-in configuration.
