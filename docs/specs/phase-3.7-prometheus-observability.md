# Phase 3.7 — Prometheus `/metrics` + optional Grafana profile

**Status:** Implemented (2026-09-04) — decision docs-first (D1), then implementation
D2–D11: metrics core/settings/endpoint/middleware, ingest–sweeper counters (D6–D9),
security & cardinality guards (D10), and the optional Docker `observability` profile
(D11). D12 (this task) finalizes the project documentation; D13 (full gate run + PR)
remains.
**Phase:** 3.7 — Prometheus `/metrics` + optional Grafana profile
([DEVELOPMENT_PLAN.md](../../DEVELOPMENT_PLAN.md), Phase 3).
**Document class:** Phase specification (Spec Kit: *Specify* → *Plan* → *Tasks* →
*Implement*). This document is the work item; it never overrides governance:

- [ARCHITECTURE.md](../../ARCHITECTURE.md) — source of truth for system architecture
  (this spec's metric catalog is mirrored in §15).
- [DEVELOPMENT_PLAN.md](../../DEVELOPMENT_PLAN.md) — phase roadmap and acceptance gates.
- [SECURITY.md](../../SECURITY.md) / [CONTRIBUTING.md](../../CONTRIBUTING.md) — security
  and contribution rules (defensive-only charter, no secrets, no fake production claims,
  TheHive Premium never required, deterministic core, AI/LLM optional and non-load-bearing).

---

## 1. WHY

SOC operators need measurable visibility into pipeline health and behavior: ingest volume
vs. duplicates, enrichment coverage and fail-open behavior, scoring/decision distribution,
incident lifecycle, sweeper effectiveness, n8n delivery reliability, and request latency.
Today these are only inferable from structured logs and the append-only audit log — not
scrapeable, not alertable, and not dashboard-friendly. Phase 3.7 adds a **read-only,
self-hosted, free** observability surface without touching deterministic core behavior.

## 2. Scope & Non-Goals

**In scope**

- `GET /metrics` — Prometheus text exposition from the Triage API service.
- Optional, profile-gated `observability` compose profile (`prometheus` + `grafana`).
- Bounded counters/histograms/gauges over existing pipeline events.
- Docs, tests, and gates per the project Definition of Done.

**Out of scope (unchanged charter)**

- Any change to scoring, deduplication, normalization, decision, audit, or API semantics.
- Any autonomous response or offensive capability.
- Any mandatory Grafana/Prometheus dependency, SaaS, or paid service.
- DB-derived aggregate gauges (e.g. `incidents{status}` current counts) — **deferred to
  Phase 3.8** (PostgreSQL profile + migration parity tests) per approved decision D3.
- TheHive (CE or Premium) — unrelated to this phase.
- LLM/AI assistance — unrelated to this phase.

## 3. Requirements — MUST HAVE

1. `/metrics` endpoint on the existing service (same origin as `/health`), Prometheus text
   exposition format (`text/plain; version=0.0.4; charset=utf-8`), hidden from OpenAPI.
2. Request/processing counters and latency metrics (HTTP request levels + ingest pipeline
   duration).
3. Alert-processing metrics (dedupe outcome, scoring/decision distribution, ingest
   rejections).
4. Enrichment-status metrics (alert-level status + per-provider outcomes; never indicator
   values).
5. Useful application health metrics (`soc_triage_up`, `soc_triage_database_up`,
   `soc_triage_migrations_applied`; the default `process_*` / `python_info` collectors are
   deliberately **not** exposed — see §14).
6. Metrics must **not** expose secrets (no tokens, API keys, DB URLs, webhook URLs or
   hosts, alert/incident ids, IOC values, exception messages, free text).
7. Metrics must avoid unsafe/high-cardinality labels (enum-sourced, fixed vocabulary only;
   route templates, never raw paths).
8. Deterministic core behavior (scoring, dedupe, normalization, decisions, audit) must
   remain unchanged; metrics are non-load-bearing and never raise into the pipeline.
9. Optional `METRICS_SCRAPE_TOKEN` bearer authentication for `/metrics` (decision D1).
10. Optional compose `observability` profile with Prometheus (internal scrape, no host
    port) + Grafana (host port 3000 for the lab) (decision D2).

## 4. Requirements — MUST NOT HAVE

- No mandatory Grafana dependency; no mandatory external SaaS.
- No change to scoring semantics, deduplication semantics, or existing API contracts.
- No autonomous response; no new offensive capability.
- No breaking changes to existing APIs (no changes to `/health`, `/ready`, ingest, read
  APIs, feedback, or incident lifecycle contracts).
- No new database schema or Alembic migration.
- No DB aggregation queries in `/metrics` in Phase 3.7 (decision D3).
- No new background infrastructure (no Celery/Redis/queue/worker).
- No reuse of existing N8N/API tokens for metrics scraping (decision D1).
- No hardcoded secrets in code, tests, compose, dashboards, or provisioning files.
- No fake production claims; Grafana dashboards remain "lab/portfolio" labeled.
- No TheHive Premium requirement.

## 5. Metric Catalog & Cardinality Contract

All application metrics are prefixed `soc_triage_`. Prometheus counter names are declared
without the `_total` suffix (the client appends it at exposition). All labels derive from
fixed enums or registration-order names — **never** from alert content.

| Metric family | Type | Labels (bounded) | Increment site |
| --- | --- | --- | --- |
| `soc_triage_http_requests` | Counter | `method`, `route` (route template, e.g. `/api/v1/alerts/{alert_id}`, else `unmatched`), `status` (HTTP code) | HTTP middleware |
| `soc_triage_http_request_duration_seconds` | Histogram | `method`, `route` | HTTP middleware (monotonic clock) |
| `soc_triage_ingest_rejections` | Counter | `reason` ∈ {`malformed_json`, `schema_invalid`, `identity_invalid`, `payload_too_large`, `auth_failed`, `storage_unavailable`} | ingest handler / auth guard |
| `soc_triage_alerts_processed` | Counter | `outcome` ∈ {`new_generation`, `repeated`, `exact_duplicate`} | ingest after dedupe |
| `soc_triage_alert_processing_duration_seconds` | Histogram | (none) | ingest pipeline (normalize → enrich → dedupe → score → persist; n8n excluded) |
| `soc_triage_alerts_scored` | Counter | `tier` (5 values), `decision` (4 values), `degraded` (0/1) | after score + decide persist |
| `soc_triage_enrichment_status` | Counter | `status` ∈ {`complete`, `partial`, `failed`, `skipped`} | `EnrichmentChain` outcome |
| `soc_triage_enrichment_provider_outcomes` | Counter | `provider` (registered names), `status` (4 values) | per `ProviderOutcome` |
| `soc_triage_n8n_notifications` | Counter | `outcome` ∈ {`delivered`, `failed`, `skipped`, `duplicate_suppressed`} | notification path |
| `soc_triage_n8n_notification_duration_seconds` | Histogram | (none) | webhook send |
| `soc_triage_feedback` | Counter | `verdict` (7 values) | feedback endpoint |
| `soc_triage_incident_transitions` | Counter | `from_status`, `to_status` (≤7×7) | lifecycle PATCH + feedback sync |
| `soc_triage_incident_auto_close` | Counter | `outcome` ∈ {`closed`, `skipped`, `error`} | sweeper |
| `soc_triage_sweeper_passes` | Counter | `result` ∈ {`completed`, `failed`} | sweeper loop |
| `soc_triage_up` | Gauge | (none) | process serving `/metrics` |
| `soc_triage_database_up` | Gauge | (none) | one `SELECT 1` per scrape (try/except → 0) |
| `soc_triage_migrations_applied` | Gauge | (none) | one `alembic_version` read per scrape |
| default `process_*` / `python_info` collectors | various | (none) | **not emitted** — see [§14 Final Implementation Notes](#14-final-implementation-notes--deviations) |

**Derived, not emitted:** dedupe ratio (`exact_duplicate / alerts_processed`), 4xx/5xx
rates, enrichment fail rate. **Deferred to Phase 3.8:** DB aggregate gauges (e.g. incident
counts by status).

**Cardinality rules (enforced by tests)**

- Every label value is drawn from a documented, finite vocabulary.
- No alarm-level identifier (alert id, incident id, dedupe group key), no rule/agent id,
  no IOC type+value, no host/URL, no username/email, no raw path, no exception message,
  no `SOC_INSTANCE_NAME` may ever appear as a label value.
- A CI cardinality-guard test scrapes `/metrics` after a representative pipeline run and
  asserts every observed `(metric, label-value)` pair is inside the per-metric allowlist.

## 6. Security Requirements

1. **Secrets:** metrics come only from enum/registry values; a canary test injects
   synthetic secret values + synthetic IOC values and asserts they never appear in the
   `/metrics` exposition. `scripts/check_secrets.sh` remains the repo gate.
2. **Auth (decision D1):** `/metrics` accepts an optional
   `Authorization: Bearer <METRICS_SCRAPE_TOKEN>`. Empty token = no auth required
   (development-compatible). A non-empty placeholder (`change-me-*`) is rejected outside
   `SOC_ENV=development` via the existing fail-fast settings rule; an empty value remains
   the documented "disabled" default in every environment. The N8N/API tokens are never
   used for scraping. The optional `observability` profile forwards
   `METRICS_SCRAPE_TOKEN` to the Prometheus container through the existing environment
   mechanism only: `deploy/prometheus/entrypoint.sh` writes it to a runtime-only
   credentials file (tmpfs, 0600) and generates the scrape config with
   `authorization.credentials_file` — the token value is never committed and never
   inlined into any configuration file. `METRICS_ENABLED=false` removes the route
   entirely (requests return 404) and no metrics are recorded.
3. **Network:** Prometheus runs on `soc-core`, scrapes
   `http://triage-api:8000/metrics` internally; port 9090 is **not** published to the
   host. Grafana may publish 3000 for lab access only, and only when the optional profile
   is enabled. Default `docker compose up` behavior is unchanged (decision D2).
4. **Least privilege:** no metric ever triggers a write, an external call, or a state
   transition; `/metrics` is read-only and side-effect-free.

## 7. Non-Functional Requirements

- **Determinism:** identical alert inputs produce byte-identical scores, decisions,
  dedupe outcomes, and API responses with or without metrics enabled; tests assert this.
- **Performance:** per-request overhead is counter/histogram increments only; `/metrics`
  performs at most one `SELECT 1` and one `alembic_version` read per scrape; no DB
  aggregation queries; no per-request allocations beyond reused route templates.
- **SQLite/PostgreSQL parity:** metrics are in-process (no DB reads for counters), so
  parity is trivial by construction; the two health checks are dialect-agnostic SQL
  already used by `/health` and `/ready`.
- **Test determinism:** one `CollectorRegistry` per app instance (never the process-global
  default registry) so counters never leak between tests; histograms asserted via counts
  and bucket ranges, never exact wall-clock values.
- **Free/self-hosted:** `prometheus-client` (Apache-2.0), Prometheus (Apache-2.0), Grafana
  (AGPLv3, self-hosted) — all optional, all free; no SaaS and no paid tier anywhere.

## 8. Architectural Impact

**Affected (additive only)**

- `app/src/soc_triage/core/metrics.py` (new) — app-scoped registry, metric definitions,
  cardinality allowlists, non-raising record helpers (no FastAPI import).
- `app/src/soc_triage/core/config.py` — `METRICS_ENABLED`, `METRICS_SCRAPE_TOKEN`.
- `app/src/soc_triage/api/metrics.py` (new) — `GET /metrics`, hidden from OpenAPI,
  optional bearer auth.
- `app/src/soc_triage/main.py` — lifespan wiring only (registry on `app.state`,
  middleware, route, recorder passed to sweeper).
- `app/src/soc_triage/api/alerts.py`, `feedback.py`, `incidents.py` — counters at existing
  decision points (no logic changes, no contract changes).
- `app/src/soc_triage/enrichment/chain.py`, `sweeper.py` — optional recorder injection
  (default no-op), semantics unchanged.
- `app/tests/integration/test_metrics_contract_guards.py`,
  `app/tests/integration/test_metrics_no_secret_exposition.py`,
  `app/tests/integration/test_metrics_failure_isolation.py` — D10 guard suites
  (catalog/cardinality, no-secret canaries, failure isolation);
  `app/tests/unit/test_docker_lab_config.py` extended with the observability-profile
  static config tests.
- `docker-compose.yml` + `deploy/prometheus/` (`prometheus.yml`, `entrypoint.sh`) +
  `deploy/grafana/` (`provisioning/datasources/`, `provisioning/dashboards/`,
  `dashboards/soc-triage-observability.json`) — optional `observability` profile only.
- `app/pyproject.toml` — one runtime dependency (`prometheus-client`, upper-bounded
  range — see §14).
- Docs: ARCHITECTURE §12/§13/§15/§20, README, app/README, deploy/README, `.env.example`,
  CHANGELOG, this spec.

**Unchanged (contract):** scoring engine, decision engine, normalizer, deduplication
(in-memory + persistent), IOC extractor/policy, canonical models, ORM/repositories, audit,
existing API routes + auth + rate limits, default compose services, n8n workflows, CI job
structure, sample-alert corpus, DB schema.

**No new architecture:** metrics are a passive, in-process subsystem under ARCHITECTURE
§15 ("Logging, Audit & Observability"). No new system-context component, no new data flow,
no new table, no new worker.

## 9. Implementation Plan & Status

Ordered, independently testable steps (one PR/commit each, trunk-based). All implemented
stages passed their required gates (unit/integration tests, ruff check, ruff format
--check, mypy, secret scan, existing suite green) and delivered a stop-report before the
next stage:

| # | Task | Status (2026-09-04) |
| --- | --- | --- |
| D1 | Docs-first: this spec; ARCHITECTURE §12/§13/§15 + ADR-9; deploy/README; CHANGELOG entry | ✅ landed |
| D2 | Dependency + metrics core: `prometheus-client`; `core/metrics.py` | ✅ landed |
| D3 | Settings: `METRICS_ENABLED`, `METRICS_SCRAPE_TOKEN` (+ `.env.example`) | ✅ landed |
| D4 | Endpoint: `GET /metrics`, exposition content type, optional bearer auth, disabled → route absent (404) | ✅ landed |
| D5 | HTTP middleware: request counter + latency histogram (route templates, non-recursive `/metrics`) | ✅ landed |
| D6 | Ingest instrumentation: rejections, dedupe outcome, processing duration | ✅ landed |
| D7 | Scoring/decision counters | ✅ landed |
| D8 | Enrichment counters (alert status + per-provider outcomes) | ✅ landed |
| D9 | Notification/feedback/incident/sweeper counters | ✅ landed |
| D10 | Security hardening tests: no-secret canary + cardinality guard + registry isolation + scrape safety + failure isolation | ✅ landed |
| D11 | Docker observability profile: compose + Prometheus/Grafana provisioning | ✅ landed |
| D12 | Docs: README, app/README, deploy/README, `.env.example`, CHANGELOG, this spec | ✅ landed |
| D13 | Full gate run & PR | ⬜ pending |

Stage gates were run after each stage; the final D13 gate run is a summary of the same
gates and is the only remaining release step.

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Metric cardinality | Prometheus memory growth | Enum-sourced labels; route templates; per-metric allowlist test |
| Secret leakage | Tokens/IOCs surface in exposition | No free-text labels; dedicated scrape token; canary exposition test; `check_secrets.sh` |
| Unauthorized exposure | Operational totals readable on published 8000 | Optional bearer auth; Prometheus internal-only; documented lab exposure guidance (SECURITY §4) |
| Performance | Request latency / scrape cost | Counter increments only; at most one `SELECT 1` + one `alembic_version` read per scrape; no aggregates |
| Docker drift | Default stack breakage | `observability` profile strictly additive; existing static compose tests extended |
| SQLite/PostgreSQL parity | Dialect-specific metric queries | No DB queries in counters; deferred aggregate gauges to 3.8; health pings are dialect-agnostic |
| Test determinism | Global registry leakage / clock flakiness | Per-app `CollectorRegistry`; no global `REGISTRY`; histograms asserted structurally |
| Instrumentation coupling | Metrics change pipeline behavior | Non-raising record helpers; metrics never read back; determinism tests assert unchanged scores/responses |
| Supply chain | New dependency surface | Bounded range, conscious addition, scanned; pip-audit policy discrepancy flagged to maintainers |

## 11. Acceptance Criteria (Definition of Done)

- Unit tests (registry, boundedness, names/types, auth) and integration tests
  (`/metrics` after representative pipeline activity) pass.
- Existing test suite remains green; no scoring/dedupe golden drift.
- `ruff check` passes; `ruff format --check` passes; `mypy` passes.
- `scripts/check_secrets.sh` passes.
- Documentation updated (ARCHITECTURE, README, app/README, deploy/README, `.env.example`);
  CHANGELOG updated per project conventions.
- CI green on Python 3.11 + 3.12, Node tests, secret scan.
- Existing Phase 3 behavior remains intact (identical scores, decisions, dedupe outcomes,
  responses, audit rows).

## 12. Approved Decisions

| # | Decision | Resolution | Date |
| --- | --- | --- | --- |
| D1 | `/metrics` auth | Optional `METRICS_SCRAPE_TOKEN` bearer auth; empty token keeps development compatibility but does not weaken test/production (placeholder fail-fast applies); existing N8N/API tokens never reused | 2026-09-04 |
| D2 | Observability profile | Optional compose `observability` profile includes Prometheus (internal scrape of `triage-api`, port 9090 NOT published) and Grafana (port 3000 published for the lab); default compose unchanged | 2026-09-04 |
| D3 | DB-derived gauges | Deferred `incidents{status}`-style aggregate gauges to Phase 3.8; Phase 3.7 keeps only cheap DB health/migration checks | 2026-09-04 |

## 13. Observations / Pre-existing Drift

- `ARCHITECTURE.md` (and historically `DEVELOPMENT_PLAN.md`) mentioned `/healthz`; the
  service exposes `/health` + `/ready` (the compose healthcheck targets `/health`). The
  documentation in this phase's scope was normalized to `/health` + `/ready`; the
  DEVELOPMENT_PLAN.md Phase 1 acceptance-criteria line still says `/healthz` — left
  untouched here (out of Phase 3.7 scope), behavior was never changed.
- The `observability` profile was specified in this document and implemented in D11
  (statuses in §9).
- `SECURITY.md §4` mentions `pip-audit` in CI from Phase 1, but `.github/workflows/ci.yml`
  does not run it today. Flagged to maintainers; not part of 3.7 scope.
- Root `Dockerfile` is the image built by compose; `deploy/triage-api.Dockerfile` is a
  parallel copy. Unchanged by this phase.

## 14. Final Implementation Notes & Deviations

**Final dependency decision (D2):** `prometheus-client` is declared in `app/pyproject.toml`
as an upper-bounded range (`>=0.20,<1`), not a single exact version; the implementation was
verified against 0.26.0. It has no additional runtime dependencies.

**Final implementation decisions**

- One `MetricsRegistry` per running application; each owns a private
  `prometheus_client.CollectorRegistry` — the process-global `REGISTRY` is never touched
  (D10 registry-isolation test).
- Non-load-bearing by design (ADR-9): record/render helpers never raise into the pipeline;
  recorder failures are logged by type only; a failing render returns an empty 200
  exposition instead of an error.
- `/metrics` is mounted only when `METRICS_ENABLED=true` (otherwise the route is absent,
  so requests return 404); it is hidden from OpenAPI and served with
  `text/plain; version=0.0.4; charset=utf-8`.
- `METRICS_SCRAPE_TOKEN`: empty = authentication disabled; non-empty = `Authorization:
  Bearer <token>` required, verified with a constant-time compare; a dedicated token —
  ingest API key and N8N tokens are never accepted.
- D5 middleware records static route paths and route templates only (raw paths collapse
  to `unmatched`); `/metrics` scrapes are recorded with the static `/metrics` route label,
  one increment per scrape (never recursive).
- D6–D9 counters record exactly once per actual semantic outcome (new/repeated/duplicate,
  one outcome per notification attempt/skip/suppression, one transition per actual state
  change, one auto-close result per candidate, one pass record per sweep pass) — enforced
  by the D9 lifecycle suite and the D10 guards.
- D10 guard suites: `test_metrics_contract_guards.py` (static catalog + cardinality
  allowlists + registry isolation + repeated-scrape stability),
  `test_metrics_no_secret_exposition.py` (synthetic secrets/IOC canaries through the whole
  pipeline), `test_metrics_failure_isolation.py` (forced recorder/render failures at
  D2–D9 paths).
- D11 profile as implemented: `prometheus` (`prom/prometheus:v3.5.0`, `soc-core` only,
  port 9090 never published, internal scrape of `http://triage-api:8000/metrics` every
  15 s with a 10 s timeout) and `grafana` (`grafana/grafana:12.1.0`, `soc-core`, host
  port 3000 for the lab only); both read-only-root + dropped capabilities +
  no-new-privileges, healthchecks, and 1 CPU / 512 MB resource limits; named volumes
  `prometheus-data` / `grafana-data`. A single `soc-triage-observability` dashboard
  (13 panels) is provisioned from `deploy/grafana/provisioning/` and uses only the
  approved catalog (rates and a `histogram_quantile` p95 — no invented metrics).

**Deviations from the original spec (all conservative)**

1. The spec's §5 table listed default `process_*` / `python_info` collectors; the
   implementation does **not** register them — the app-scoped registry contains exactly
   the 17 application families. Deliberate: keeps the exposition fixed and testable, and
   matches the "app-scoped, never global" isolation contract.
2. Supporting the optional Bearer token without breaking the empty-token default required
   the small runtime-only `deploy/prometheus/entrypoint.sh` wrapper (a token file that is
   always mounted would send an empty `Authorization` header and be rejected). The
   checked-in `prometheus.yml` is auth-free by default; the wrapper injects a
   `credentials_file` block only when the env token is set.
3. The dependency is version-ranged rather than exact-pinned (see above).
4. **Validation caveat (resolved at D13):** Docker was unavailable in the Arena sandbox,
   so `docker compose config` and runtime smoke validation (container health, actual
   scrape, port checks) were **not** executed during D1–D12. That gap was closed at D13:
   the stack was runtime-validated on Windows Docker Desktop — triage-api `/health`,
   `/ready`, and `/metrics` healthy; Prometheus healthy with `triage-api:8000/metrics` UP
   on a 15 s scrape and port 9090 not host-published; Grafana healthy on localhost:3000
   with the Phase 3.7 dashboard loading and metrics populated from a real synthetic alert.
   No production deployment or readiness claims are made.
