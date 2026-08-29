# deploy/ — Docker Build & Compose Fragments

Dockerfiles and compose fragments for the stack. The root `docker-compose.yml`
(Phase 1) assembles these. Topology, networks, profiles, ports, and hardening rules are
fixed by design in [ARCHITECTURE.md §13](../ARCHITECTURE.md#13-docker--deployment-architecture).

**Status: scaffolded — Dockerfiles land in Phase 1.**

Planned contents:

- `triage-api.Dockerfile` — multi-stage, non-root `app` user, minimal `slim` base,
  pinned dependencies, healthcheck.
- Compose fragments per profile: default (`triage-api`, `n8n`, `mailpit`),
  `full` (wazuh-manager), `intel` (MISP), `postgres`, `observability` (Grafana).

Hardening baseline (from SECURITY.md §4): non-root users, dropped capabilities,
read-only filesystems where possible, resource limits, no Docker socket, no
`--privileged`, tag-pinned images.
