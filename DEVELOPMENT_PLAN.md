# Development Plan

**Project:** Defensive SOC Alert Triage & Incident Response Automation
**Working model:** phase-gated development — each phase has scope, deliverables,
acceptance criteria, and a validation gate. Nothing merges without its gate.
**Charter constraints (apply to every phase):** free services only · no hardcoded
secrets · defensive-only capabilities · **no production claims** · deterministic scoring
and decision routing stay the authoritative core path · no AI/LLM component in any
decision path · TheHive Premium must never be required.

**Status vocabulary** (identical in [README.md](README.md)):

| Label | Meaning |
| --- | --- |
| ✅ **Implemented** | Present in the repository and exercised by the default runtime or by automated tests. |
| ✅ **Locally validated** | Actually executed and observed (test run, or documented runtime validation with recorded evidence). |
| 🔍 **Source-audited** | Verified by reading pinned upstream sources/image contents, not by a live run. |
| 🟡 **Partially validated** | Implemented and partly exercised; specific sub-checks are listed as outstanding. |
| ⬜ **Outstanding** | Scoped work with no implementation, or implementation without validation. |
| 🔮 **Future / planned** | Not started; outside current scope. No code exists. |

**Source-of-truth rule:** this file and [README.md](README.md) are the only documents that
state project *status*. [ARCHITECTURE.md](ARCHITECTURE.md) owns design intent,
[SECURITY.md](SECURITY.md) owns security policy, [CHANGELOG.md](CHANGELOG.md) owns change
history. Status claims elsewhere are descriptive, not authoritative.

---

## Roadmap at a Glance

| Phase | Status | One-line evidence |
| --- | --- | --- |
| **Phase 0 — Foundation** | ✅ Implemented · locally validated | Docs, scaffolding, secret scanner, CI |
| **Phase 1 — MVP triage pipeline** | ✅ Implemented · locally validated | Ingest → normalize → dedupe → score → decide → notify, tests green (simulator script ✅ implemented) |
| **Phase 2 — Enrichment & threat intelligence** | ✅ Implemented · locally validated | 2.2 static allowlist + asset inventory ✅ (47 tests); 2.3 enrichment response TTL cache ✅ (61 tests); 2.4 MISP client + `intel` profile + seeding guide ✅ statically validated (57 tests — no live MISP run); 2.5 scoring v2 `threat_intel` factor ✅ (56 tests); 2.6 late-enrichment re-score ✅ (12 unit +3 integration); 2.7A automatic sweep ✅ (7+9 tests, disabled by default, idempotent); 2.7B provider-specific IOC verdict visibility in WF2 ✅; VT/MISP fake-transport, disabled by default; §8.2 weight rescaling explicit open item |
| **Phase 3 — Incidents, analyst workflow & observability** | 🟡 Partially validated | Incidents, lifecycle, read APIs, timeline, sweeper, console, runbooks, `/metrics` + Grafana profile, PostgreSQL profile, and Phase 3.9 stats/WF6 are implemented; Docker/n8n runtime validation and other named gaps remain |
| **Phase 4 — Real Wazuh integration & approved response** | 🟡 Partially validated | 4.1/4.2 source-audited + live-validated end-to-end; 4.4 validated; V7/V9 partially live-validated with specific remaining runtime checks; V8 secret/log hygiene verified but post-Phase-4 `/metrics` hygiene re-check remains; 4.3 authored but not live-validated; 4.6 TheHive CE export + `thehive` profile implemented and test-validated only (no live CE run claimed); 4.7 soak harness authored with CI integrity tests, but live 10k/day execution not performed; 4.5 containment runbook remains outstanding |
| **Phase 5 — Deterministic detection evaluation** | ✅ Implemented · locally validated | Labeled corpus, ground truth, confusion matrix, precision/recall/F1/FPR, runtime evaluation tests |
| **Phase 6 — Detection quality & correlation** | ✅ Implemented · locally validated | Detection coverage framework ✅ (6.1); ATT&CK mapping ✅ (6.2 — registry + rendered view + validation tests); expanded regression corpus ✅ (6.3, 24 scenarios); cross-alert correlation ✅ (6.4); analyst explainability ✅ (6.5); detection-quality CI gates ✅ (6.6 — precision/recall/F1/FPR and confusion-matrix bounds asserted by the existing pytest CI job) |

No release tags have been cut. The package version is `0.1.0a1` and `CHANGELOG.md` is
still under `[Unreleased]`.

---

## Guiding Principles

1. **Docs-first:** ARCHITECTURE.md is the design source of truth; design changes land as
   doc PRs (or ADR additions) before code.
2. **Walking skeleton, then muscle:** every phase ends with a demoable vertical slice,
   not a pile of half-wired components.
3. **Explainable by construction:** no score, decision, or notification may exist without
   a stored justification.
4. **Deterministic core, authoritative path:** the risk score and the routing decision are
   pure, reproducible functions of a versioned policy file. Nothing else — enrichment,
   n8n, a future optional assistant, or an operator preference — may alter them.
5. **Test-first for core logic:** the scoring engine and normalizer are built
   golden-test-first; enrichment/decision code follows with unit + fake-external tests.
6. **Zero-external fallback:** the full pipeline must run with no VirusTotal, no MISP, no
   chat webhook, and no LLM — degraded but functional and honest about it.
7. **No status inflation:** a feature is "implemented" only when it is in the tree and
   covered by a gate; "validated" only when it was actually run, with the evidence named.

---

## Phase 0 — Foundation ✅

**Status: implemented and locally validated.**

- [x] `README.md` — purpose, architecture overview, tech, use cases, roadmap
- [x] `ARCHITECTURE.md` — full design: components, data flow, schemas, scoring spec,
      decision matrix, n8n workflows, Docker/network design, ADRs
- [x] `DEVELOPMENT_PLAN.md` (this file), `SECURITY.md`, `CONTRIBUTING.md`
- [x] `.gitignore` (secrets, runtime data, caches) and `.env.example` (placeholders only)
- [x] Directory scaffolding with per-directory READMEs (`app/`, `n8n/`, `wazuh/`,
      `misp/`, `deploy/`, `docs/`, `scripts/`, `data/`)
- [x] Synthetic Wazuh sample alerts (`docs/sample-alerts/`) — safe test data for dev + CI
- [x] `scripts/check_secrets.sh` — repo hygiene scanner for credential patterns

**Exit criteria met:** docs validate, no secrets in tree, structure reviewable.

---

## Phase 1 — MVP triage pipeline ✅

**Goal:** a walking skeleton — alert in → normalize → dedupe → score (v1) → decide →
n8n callback → notification visible in Mailpit. Fully offline (no VT/MISP).

**Status: implemented and locally validated** (all deliverables implemented, including 1.9).

| # | Deliverable | Status | Notes |
| --- | --- | --- | --- |
| 1.1 | Python project scaffold (`pyproject.toml`, ruff + pytest + mypy config, `soc_triage` package) | ✅ | per ARCHITECTURE §12 |
| 1.2 | `core/`: settings, structlog logging, error envelope, API-key auth | ✅ | fails fast on `change-me*` secrets |
| 1.3 | DB layer + Alembic | ✅ | `alerts`, `audit_log`, `dead_letters`, incidents, feedback |
| 1.4 | Ingest router + Wazuh normalizer + dedupe | ✅ | contract tests over all sample alerts |
| 1.5 | Scoring engine v1 + `app/config/scoring.yaml` | ✅ | golden tests pin sample-alert scores |
| 1.6 | Decision engine v1 + `app/config/decisions.yaml` | ✅ | matrix per ARCHITECTURE §9 |
| 1.7 | n8n webhook client (outbound) + `pending_notifications` retry loop | ✅ | timeout + park-and-retry |
| 1.8 | Docker compose: `triage-api`, `n8n`, `mailpit`; networks `soc-edge`/`soc-core` | ✅ | non-root images, healthchecks, limits |
| 1.9 | Simulator `scripts/send_test_alert` | ✅ | **implemented** — `scripts/send_test_alert.py` replays `docs/sample-alerts/` fixtures over HTTP (stdlib-only; `--repeat`, `--base-url`, `--help`), covered by `app/tests/unit/test_send_test_alert.py` |
| 1.10 | n8n WF1 (`soc-triage-router`) + WF2 (`soc-analyst-notify`) exports | ✅ | imported via `n8n/README.md` |
| 1.11 | CI workflow (GitHub Actions) | ✅ | ruff, mypy, pytest, `check_secrets.sh`, console JS |
| 1.12 | API reference (OpenAPI auto-docs) + quickstart in README | ✅ | honest "lab" wording |
| 1.13 | IOC extraction & enrichment provider interface (Phase 1E) | ✅ | pure extractor, injectable provider protocol, disabled no-op provider, `enrichment_status: skipped` without external calls |

**Acceptance:** compose stack healthy · repeated sample alert deduplicates to one row with
recurrence · auth/limit/validation error paths correct · pipeline completes with
`enrichment_status: skipped` when no intel keys are set · core-package tests green in CI.

---

## Phase 2 — Enrichment & threat intelligence ✅

**Goal:** real intel enrichment with quota safety and graceful degradation.

**Status: ✅ Implemented · locally validated — 2.2 (static allowlist `allowlist.v1` + asset inventory `asset_inventory.v1`), 2.3 (enrichment response TTL cache, SQLite-backed, disabled by default), 2.4 (MISP client contract + optional `intel` compose profile + deterministic synthetic seeding guide) are ✅ implemented · locally/statically validated; 2.5 (scoring v2 `threat_intel` factor) ✅ implemented · locally validated at payload level; 2.6 (late-enrichment re-score) ✅ implemented · locally validated (deterministic re-assessment via `LateEnrichmentService` + atomic `persist_assessment`); 2.7A (automatic late-enrichment sweep) ✅ implemented · locally validated (disabled by default, idempotent fingerprint guard, fail-open, bounded batch, restart-safe); 2.7B (provider-specific IOC verdict visibility in WF2) ✅ implemented · locally validated (payload preserves sanitized provider verdicts, WF2 renders per-provider verdict table); VirusTotal/MISP providers remain fake-transport tested, disabled by default; §8.2 weight rescaling remains explicit open item.**

| # | Deliverable | Status | Evidence / gap |
| --- | --- | --- | --- |
| 2.1 | IOC extractor | ✅ implemented (delivered early as Phase 1E/1.13) | pure, deterministic, no network I/O |
| 2.2 | Allowlist + asset-inventory YAML loaders | ✅ Implemented · locally validated | deterministic, versioned, non-secret static policies — `app/config/allowlists.yaml` (`allowlist.v1`) and `app/config/asset_inventory.yaml` (`asset_inventory.v1`) — **validated fail-loud at load**, and loaded only when `TRIAGE_ALLOWLIST_PATH` / `TRIAGE_ASSET_INVENTORY_PATH` are set (empty path ⇒ disabled; the shipped files contain no entries). The `allowlist` provider registers in the chain **only when configured**; matching is on exact normalized indicators plus IPv4 CIDR; the provider's `enrichment_status` is always `skipped`, so local policy adds no intel points; the existing scoring `allowlist` (−20) factor and `suppress` decision route are consumed **unchanged** — no scoring- or decision-policy change. The asset inventory is a pure fill-only normalization seam (precedence `agent_id` → IP → name; source-provided fields always win) and does **not** alter the `asset_criticality` model or weights. No network I/O, no AI/LLM. Evidence: 47 targeted tests (26 allowlist unit · 16 asset-inventory unit · 5 integration wiring) + ruff check/format + mypy + CI on Python 3.11 & 3.12 + secret scan. **Still not validated:** an operator-side run with a populated policy (no Docker-lab validation) and a corpus-level `suppress` pin (see 6.3 / coverage gap G10) |
| 2.3 | VirusTotal v3 client: token bucket (4/min, 500/day), quota accounting, fake-server tests; response TTL cache | ✅ implemented · locally validated (no live run) | client: `httpx.MockTransport` fakes only; **TTL cache**: `enrichment_cache` table (migration `c7d8e9f0a1b2`) + `PersistentEnrichmentCache` — per-type TTLs per ARCHITECTURE §7.2 (6 h hashes / 1 h IPs / 1 h other), provider-scoped keys, definitive verdicts only (failures stay retryable), byte-identical replay, bounded (`max_entries`, soonest-expiring eviction), fail-open, **disabled by default** (`TRIAGE_ENRICHMENT_CACHE_ENABLED`), 61 targeted tests (24 cache unit · 19 provider-cache unit · 12 wiring/migration integration · 6 config); no live-provider run yet |
| 2.4 | MISP client + `intel` compose profile + seeding guide | ✅ Implemented · statically validated (no live MISP run) | `enrichment/misp.py` (lookup-only `GET /attributes/restSearch`, sanitized provenance, disabled by default, Phase 2.3 cache preserved) + an optional `intel` compose profile — `misp-db` (`mariadb:10.11.19`), `misp-redis` (`valkey/valkey:7.2.14`), `misp-core`/`misp-nginx` (`ghcr.io/misp/misp-docker/*:v2.5.46`) plus a one-shot `misp-preflight` guard (`busybox:1.37.0`) — pinned, profile-gated, `soc-core`-only with **no host ports** (guard: no network), every credential from `.env` with no committed default, enforced by the guard via `service_completed_successfully` (no `${VAR:?}`: Compose interpolates the whole file before profile filtering, which would break the default stack), `triage-api` MISP vars still default-empty (disable-by-empty preserved). Deterministic seeding guide `misp/seeding.md` + pinned synthetic fixture `misp/fixtures/synthetic-events.json` (documentation ranges only, fixed UUIDs/timestamps, `to_ids: false`, unpublished) + read-only verification helper `misp/verify-lookups.sh`. Evidence: 57 targeted tests (29 profile/guide/fixture/guard static — including the executed `misp-preflight` guard in missing/partial/complete states · 27 MISP lookup contract: request shape, sanitization allow-list/caps, failure modes, cache wiring, secret safety, zero-external fallback · 1 integration MISP-outage fail-open) + the updated compose service/volume contract assertions + full suite + ruff + mypy + secret scan. **Still not validated:** MISP was never started (no Docker daemon in the sandbox) — no live lookup, seeding or UI import has been exercised |
| 2.5 | Scoring v2 (`threat_intel` factor) + updated goldens | ✅ Implemented · locally validated | The policy is now `scoring.v2` and carries a **config-driven `threat_intel` factor** (`app/config/scoring.yaml`, max 25) implementing ARCHITECTURE.md §8.2's intel row exactly: per-indicator VirusTotal awards read from the *sanitized* `last_analysis_stats` payload (malicious ≥10 → 15 · positive-below-10 → 8 · suspicious-only → 4) plus MISP awards (matched attribute/event → 10, threat-actor tag → +5; `apt`/`threat-actor`/`intrusion-set`, prefix-matched so `apt:38` counts and `capture` does not), summed across indicators and capped at 25. **Pure and offline** — the engine reads only `IOC.enrichment[provider]` and never a live service, so ingest gains no I/O; unavailable intel (provider disabled, `error`/`timeout`/`rate_limited`), absent or malformed payloads and unhandled indicator types contribute 0, and no payload shape can raise. The factor is **optional in the schema**: a policy without the block keeps the 7-factor `scoring.v1` set byte-identically (asserted at unit *and* pipeline level). Determinism: indicators are folded in sorted-key order, one award per provider per indicator, so points, tier and explanation text are independent of enrichment order. Explanation safety: the detail quotes aggregate counts, at most `detail_max_iocs` (3) indicator keys, and only tag values matching a conservative shape — upstream free text (e.g. a log line smuggled into a MISP tag) can never reach a stored justification (SECURITY.md §7). Validation is fail-loud: bands must be monotonic and must fit under the factor cap. Goldens updated deliberately: `evaluation/ground_truth.json` scores are **unchanged** (no fixture carries an enrichment payload), while the response-contract goldens (`scoring.v1` → `scoring.v2`, 7 → 8 ordered factors) were re-pinned in the ingest, explanation, evaluation and scoring-config suites. **Explicitly not applied:** the §8.2 *rescaling* of the pre-existing weights (40→30 · 15→10 · 25→20 · 20→15 · −20→−25) — a separate golden change, still open. Evidence: 56 new targeted tests (52 factor unit · 3 policy-schema/back-compat unit · 1 offline pipeline golden) + the re-pinned contract goldens + the full 1376-test suite + ruff check/format + mypy + secret scan + console JS tests. **Still not validated:** no live VT/MISP run — intel verdicts are exercised only as the sanitized payloads the fake-transport providers emit, and no Docker-lab operator run with populated intel |
| 2.6 | Late-enrichment background re-score | ✅ Implemented · locally validated | `LateEnrichmentService.reassess` / `reassess_persisted` / `reassess_persisted_if_changed` + `persist_assessment` atomic incident create/attach, timestamp-insensitive enrichment fingerprint for idempotency, fail-open; evidence: 12 unit (`test_late_enrichment.py`) + 3 integration (`test_late_enrichment_integration.py`) + ruff/mypy/secret scan; no live VT/MISP run, no additional n8n notification |
| 2.7A | Automatic late-enrichment sweep | ✅ Implemented · locally validated | `late_enrichment_sweep.py` (`sweep_once` + `run_late_enrichment_loop` started from lifespan, ADR-4 no Celery/Redis, blocking work in `asyncio.to_thread`), disabled by default (`LATE_ENRICHMENT_SWEEP_ENABLED=false`), bounded (`_BATCH_LIMIT=200`, lookback `LATE_ENRICHMENT_LOOKBACK_SECONDS=604800` default, interval 300 s), idempotent via fingerprint guard (same enrichment never re-scores twice), fail-open per-alert error isolation, restart-safe; evidence: 7 sweep unit + 9 trigger integration (`test_late_enrichment_sweep.py`, `test_late_enrichment_trigger.py`) + CI; no live provider run |
| 2.7B | WF2 provider-specific IOC verdict visibility | ✅ Implemented · locally validated | `notifications/payload.py` preserves sanitized `lookup_status`/`result` (malicious/suspicious/tags) per indicator per provider, `WF2_soc-analyst-notify.json` renders per-provider verdict table (`verdictFor` + `verdictRows`); evidence: `test_n8n_payload.py` provider verdict preservation + `test_n8n_email_chain.py` WF2 credential/binding checks, no secrets, no `full_log` |

**Acceptance (met):** VT outage/quota simulations never delay ingest beyond the budget and always mark `enrichment_status`; an intel-matched alert now scores per a new golden (2.5); quota usage is observable; late-enrichment re-score re-assesses persisted alerts deterministically with atomic persistence and incident linkage; automatic sweep is disabled by default, bounded, idempotent, fail-open and restart-safe; WF2 renders per-provider IOC verdicts. 2.2's own gate — **is met** by its 47 targeted tests + CI. 2.3's own gate — **is met** by its 61 targeted tests + CI (no live-provider run yet). 2.4's own gate — **is met** by its 57 targeted tests + CI, with explicit caveat no Docker/MISP instance was started. 2.5's own gate — **is met** by its 56 targeted tests + CI, with §8.2 weight rescaling left as documented open item. 2.6's own gate — deterministic re-enrich + re-score + re-decide + atomic persist with before/after audit snapshots, fingerprint idempotency — **is met** by its 12 unit +3 integration tests + CI (no live run, no extra n8n notification). 2.7A's own gate — disabled-by-default sweep, bounded batch, lookback window, idempotent fingerprint guard, fail-open per-alert isolation, restart-safe, no ingest path change — **is met** by its 7 sweep unit +9 trigger integration tests + CI. 2.7B's own gate — sanitized provider verdicts preserved in payload, WF2 renders per-provider verdict table, no secrets, no `full_log` — **is met** by its payload + email chain tests + CI. The **phase** gate is now **met**; §8.2 weight rescaling remains explicit open item, not blocking.

---

## Phase 3 — Incidents, analyst workflow & observability 🟡

**Goal:** the full analyst loop with human-in-the-loop response.

| # | Deliverable | Status | Evidence / gap |
| --- | --- | --- | --- |
| 3.1 | `incidents` table + API + WF3 | ✅ | incident persistence + escalation workflow exported |
| 3.2 | Incident lifecycle + feedback synchronization | ✅ | state machine, `PATCH /api/v1/incidents/{id}/status`, `POST /api/v1/alerts/{id}/feedback` (+ read-only status endpoint) |
| 3.3 | Alert/incident read APIs + incident timeline | ✅ | list/detail + append-only timeline |
| 3.4 | Auto-close TTL sweeper | ✅ | non-terminal incidents only; terminal states never touched |
| 3.5 | Static SOC console at `/console/` | ✅ | alert queue, score drill-down, incident board/detail; same-origin, token held in memory; 15 JS tests |
| 3.6 | Runbooks for the six sample scenarios | ✅ | `docs/runbooks/` (5 runbooks covering 6 fixtures), investigation-only, containment as approval-gated proposals |
| 3.7 | Prometheus `/metrics` + optional Grafana profile | ✅ | bounded `soc_triage_*` catalog, optional bearer token, non-load-bearing; runtime-validated in the lab |
| 3.8 | PostgreSQL profile + migration parity tests | ✅ Implemented · locally validated | Optional `postgres` compose profile (`postgres:16-alpine`, `soc-core` only, no host ports, `postgres-data` volume, `pg_isready` healthcheck, `postgres-preflight` guard) + `psycopg[binary]` driver (`postgresql+psycopg://` accepted), dialect-aware `_JsonExtractCompat` (`json_extract` on SQLite / `->`/`->>` on PostgreSQL), `.env.example` commented PG block with SQLite default preserved; parity suite `app/tests/integration/test_postgres_migration_parity.py` (3 passed no-live-DB + 9 skipped without live PG: fresh upgrade head to `c7d8e9f0a1b2`, downgrade base→head, schema existence, column parity, round-trip alert/incident/audit, API ingest, UTC, JSON payload, idempotency) + `test_repository_json_extract_portability.py` (11 passed, no live PG) + docker contract `test_docker_lab_config.py` extended (43 passed, 8 new postgres gates: profile exists `postgres`, no ports, soc-core only, volume additive, pg_isready, preflight guard pattern, env-only credentials, default TRIAGE_DB_URL remains SQLite); migration recovery 27 passed, ruff/mypy/secret-scan clean; live PG tests skip cleanly when unavailable, no mandatory PG dependency, no scoring/policy/API changes |
| 3.9 | `stats` endpoints + WF6 daily digest | ✅ Implemented · locally validated | `GET /api/v1/stats/daily` (explicit UTC date or previous UTC day), aggregate-only SQLite queries, shared-token auth, deterministic top rules/tuning suggestions, and WF6 static/security contract tests |

**Acceptance:** end-to-end demo — sample alert → incident → (no ack) → escalation email →
verdict via form → audit rows. The Phase 3.9 stats contract and WF6 export are covered by
focused tests; Docker/n8n live execution is not claimed here. Stats reads are read-only
aggregates, while mutating paths remain audit-logged.

---

## Phase 4 — Real Wazuh integration & approved response 🟡

**Goal:** ingestion from an actual Wazuh manager; safe, approval-gated response actions.

| # | Deliverable | Status | Evidence / gap |
| --- | --- | --- | --- |
| 4.1 | `full` compose profile with `wazuh-manager` (4.9.2 pinned) | 🟡 implemented · 🔍 source-audited · ✅ live-validated | agents enroll/report on 1514/1515 only; API 55000 never host-published; no active-response config exists |
| 4.2 | `custom-triage` integrator (env-only URL/key, retry, disk spool) | 🟡 implemented · 🔍 source-audited · ✅ live-validated | forwards unmodified alert JSON to `POST /api/v1/alerts/ingest`; transient failures retried then spooled oldest-first; always exits 0 |
| 4.3 | Custom rules/decoders showcase (SSH, FIM, web) | 🟡 authored, **not live-validated** | `wazuh/ruleset/rules/soc-triage-rules.xml` (rules 100100–100121 with ATT&CK tags) + decoders, mounted read-only in the `full` profile; no live rule match recorded |
| 4.4 | Agent enrollment docs (lab agents) | ✅ documented + live-validated | `wazuh/README.md`; a real Windows agent (007) enrolled and active during live validation |
| 4.5 | Human-approved containment runbook (active-response *proposal* + audit) | ⬜ outstanding | the API records `contain_requested` as an **approval-required request** and writes `incident.containment_requested` audit entries; there is no response-execution runbook or approval workflow |
| 4.6 | Optional TheHive CE case export (CE only) | ✅ implemented · locally validated (fake-transport/tests; **no live TheHive CE run**) | `app/src/soc_triage/thehive/{client,export}.py` + `api/incident_thehive.py` + settings (`THEHIVE_*`, disable-by-empty) + optional additive `thehive` compose profile (pinned CE image `strangebee/thehive:5.7.6` + Cassandra/Elasticsearch, internal `soc-core` only, no host ports, preflight guard, `no-new-privileges`) + contract tests + `thehive/README.md`. Premium never required. Live validation is operator-side only. |
| 4.7 | Performance soak: 10k synthetic alerts/day with SLA-safe timings | ✅ implemented · locally validated as authored/tested artifact; **soak execution not performed here** | `scripts/phase47_soak.py` (subprocess `curl.exe`, single identity => acute recurrence/burst shape, reports throughput/latency percentiles + the 10k/day arrival rate) plus the CI-runnable integrity tests `app/tests/integration/test_phase47_soak_integrity.py` (5 tests through the real ingest path with distinct `rule.id`/`agent.id` identities, temp SQLite, dedup/idempotency proven from DB counters). Runbook: `docs/specs/phase-4.7-soak-runbook.md`. Live 10k/day execution is operator-side and not executed in this validation run. |

**Acceptance:** real Wazuh alert (agent → manager → integrator → API) visible with
enrichment and scoring (✅ met in the live validation below) · containment proposal
requires explicit approval and writes audit rows (🟡 request capture exists, execution
path intentionally absent) · **no autonomous destructive action exists anywhere** (✅ by
design and by test).

### Phase 4 validation record

**A. Source audit (completed 2026-09-05, commit `4262ce1`) — 🔍 source-audited**

Audited against the `wazuh/wazuh-manager:4.9.2` image source and the Wazuh 4.9.2 sources.
Three defects that would have made the integration silently non-functional were found and
fixed:

- `ossec.conf.d` fragment was never loaded (Wazuh has no include mechanism; the image
  copies `/wazuh-config-mount/<path>` over `/var/ossec/<path>`) → now ships a complete
  `ossec.conf` derived from the official v4.9.2 single-node template, with
  indexer/vulnerability-detection disabled.
- The integrator was installed at an unusable path with wrong ownership →
  `wazuh/entrypoint-scripts/10-install-triage-integration.sh` installs it under
  `/var/ossec/integrations/` as `root:wazuh` `0750` (Wazuh's documented requirement).
- All integrator output was discarded (`integratord` appends `> /dev/null 2>&1` unless the
  manager runs at debug level) → the integrator now appends structured, secret-free JSON to
  `/var/ossec/logs/integrations.log` (still mirrored to stderr).

Supporting hygiene fix: `.gitattributes` pins LF line endings for `wazuh/integrator/*`,
`wazuh/entrypoint-scripts/*`, and `*.py`, with a regression test asserting LF-only bytes.

**B. Live runtime validation (performed by the maintainer on 2026-09-06, Windows/Docker
Desktop, real Windows Wazuh agent 007) — ✅ locally validated**

- Compose (checklist V2–V3): `--profile full up -d` succeeded; `wazuh-manager` healthy;
  `triage-api`, `n8n`, `mailpit` unaffected; `55000` not host-bound; `1514`/`1515`
  reachable; default stack still works with the profile off.
- Wiring (checklist V4): install hook ran; `/var/ossec/integrations/custom-triage` and
  `custom-triage.py` present as `root:wazuh`; shebangs LF-only; the `custom-triage` block
  present in the **running** `ossec.conf`; `wazuh-integratord` running as `wazuh`; the
  ingest key absent from `/var/ossec/etc/`.
- Log sink (checklist V5): `/var/ossec/logs/integrations.log` exists (`660`, `root:wazuh`)
  and contains structured `wazuh_integrator` lines.
- End-to-end with a disposable agent — **Phase 4.4 acceptance**
  (checklist V6, verified): real Windows Application ERROR event (Source=Phase4Test, Event ID=200)
  → rule 60602 level 9 → `alert_forwarded` with `status=202` → triage
  `POST /api/v1/alerts/ingest 202` → `alert_scored score=38 tier=low decision=monitor
  degraded=false` → IOC extraction `ioc_count=0 enrichment_status=skipped` → n8n
  notification HTTP 200 → alert present in `alerts.json` and the dated alert log.
- Secret/log hygiene (checklist V8, verified): API key absent from `integrations.log`,
  `ossec.log`, and compose logs; no `full_log`/alert-body content in logs; no `user:pass@`
  URLs in logs.

**C. Additional live runtime validation (performed by the maintainer on 2026-09-19, Windows/Docker
Desktop, active Windows Wazuh agent 009) — 🟡 partially validated**

- Fresh `Phase4Test` / rule `60602` detections (`V7-SPOOL-01`, `V7-SPOOL-02`, `V7-SPOOL-03`) were
  generated while `triage-api` was unavailable. The events were confirmed in `alerts.json`, but
  `wazuh-integratord` was processing an older rule `19007` backlog and did not reach the fresh
  `60602` events during the outage window. The fresh-agent → integratord → spool path therefore
  remains unverified.
- Controlled replay used the exact real Wazuh alert bodies extracted from `alerts.json` and the
  **real installed** `/var/ossec/integrations/custom-triage` integrator, with a dedicated
  `WAZUH_INTEGRATOR_SPOOL_DIR` at `/tmp/v7-controlled-spool`. The controlled spool was owned by
  `wazuh:wazuh` with mode `0700`; the API was stopped for buffering and restarted for replay/drain.
- Retry handling was live-verified at `attempts=3` with `alert_buffered`; spool entries were
  `0600`, the spool directory was `0700`, and no `.tmp` files remained.
- Three real Wazuh alert bodies were replayed oldest-first through the installed integrator;
  `spool_flush` reported `delivered=3`, the controlled spool drained, and marker order was
  `V7-SPOOL-01 → V7-SPOOL-02 → V7-SPOOL-03`.
- Repeated distinct alerts in one group aggregated as occurrences `1 → 2 → 3`.
- An exact re-delivery was absorbed without creating a second alert row;
  `delivery_count` changed `1 → 2`, `duplicate_deliveries` changed `0 → 1`, and
  `alert.duplicate_absorbed` was audited.
- On the previously validated live incident path, repeated Wazuh alerts attached to one incident
  (`INC-2026-09-19-0001`) rather than opening a second incident.

**Checklist item status
([docs/specs/phase-4-live-validation-checklist.md](docs/specs/phase-4-live-validation-checklist.md)):**

| Check | Status |
| --- | --- |
| V7 failure/spool recovery | 🟡 partially validated — retry budget → `alert_buffered`; spool `0700`/`0600`, no `.tmp`; controlled three-entry oldest-first replay through the installed integrator; occurrence aggregation; exact-duplicate absorption. Remaining: fresh agent → `wazuh-integratord` → spool while API is down, because the `19007` backlog delayed the fresh `60602` events. |
| V8 post-Phase-4 `/metrics` hygiene (no new families, no Wazuh data) | 🟡 partially validated — secret/log hygiene verified; post-Phase-4 `/metrics` hygiene re-check remains outstanding. |
| V9 idempotent duplicate delivery at runtime | 🟡 partially validated — repeated distinct alerts aggregated as occurrences `1 → 2 → 3`; exact duplicate absorbed with no second alert row; repeated alerts on the previously validated incident path remained attached to `INC-2026-09-19-0001`. Remaining: exact duplicate of an `open_incident`-producing live event. |
| 4.3 custom rules/decoder live match | ⬜ outstanding |
| 4.5 containment approval runbook / response proposal flow | ⬜ outstanding |
| 4.6 TheHive CE export **live** run against a started CE instance | ⬜ outstanding (client/export/API + `thehive` profile implemented · test-validated only; **no live CE run claimed**, operator-side) |
| 4.7 10k alerts/day soak execution | ⬜ outstanding (harness `scripts/phase47_soak.py` authored; CI integrity tests implemented; **the full 10k/day run not executed here**) |

---

## Phase 5 — Deterministic detection evaluation ✅

**Goal:** measure the deterministic detection path against labeled expectations, instead
of asserting only that individual units behave.

**Status: implemented and locally validated.** No production, benchmark, or accuracy
claims are attached to these numbers.

| # | Deliverable | Status | Evidence |
| --- | --- | --- | --- |
| 5.1 | Labeled evaluation corpus | ✅ | `evaluation/corpus.json` (version `1.0`): 6 fixtures, each labeled `positive` (5) or `negative` (1) with a reason; fixtures are the synthetic Wazuh scenarios also used as test fixtures |
| 5.2 | Ground truth | ✅ | `evaluation/ground_truth.json` (version `1.0`): expected `score`, `tier`, decision `action` per fixture, `severity` additionally pinned for the malware fixture, plus notes on why each expectation is what it is |
| 5.3 | Confusion matrix | ✅ | `evaluation/metrics.py`: frozen `ConfusionMatrix` (TP/FP/FN/TN) + `total`; the harness classifies each fixture by comparing the corpus label with the measured decision action (positive actions: `queue_l1`, `open_incident`; negative actions: `monitor`, `suppress`) |
| 5.4 | Precision | ✅ | `tp / (tp + fp)`, zero-division safe |
| 5.5 | Recall | ✅ | `tp / (tp + fn)`, zero-division safe |
| 5.6 | F1 | ✅ | `2PR / (P + R)`, zero-division safe |
| 5.7 | False-positive rate | ✅ | `fp / (fp + tn)`, zero-division safe |
| 5.8 | Runtime evaluation tests | ✅ | `app/tests/evaluation/test_evaluation.py` (2 tests, run in CI with the full `pytest` suite): replays every corpus fixture through the real ingest route (FastAPI `TestClient` + temp SQLite → normalizer → dedupe → scoring → decision), compares the measured `risk.score` / `risk.tier` / `decision.action` / `decision.severity` to ground truth, fails on any ground-truth contract violation, and asserts corpus ↔ ground-truth fixture parity |
| 5.9 | Offline evaluation helper | ✅ | `evaluation/evaluator.py`: ground-truth loading, `compare_expected`, `evaluate_fixture` (supports an `unverified` score contract → `partial`), `summarize`, and a CLI status report (`python evaluation/evaluator.py`). Not invoked by CI; the runtime comparison lives in the test harness |

**Measured baseline (printed by the harness; verified locally on Python 3.11,
2026-09-10).** Command: `cd app && pytest tests/evaluation -q -s`.

| Fixture | Label | Measured action | Classification | Score / tier |
| --- | --- | --- | --- | --- |
| `01_wazuh_ssh_brute_force.json` | positive | `monitor` | FN | 43 / low |
| `02_wazuh_ssh_brute_force_success.json` | negative | `monitor` | TN | 27 / low |
| `03_wazuh_fim_etc_passwd_change.json` | positive | `queue_l1` | TP | 63 / medium |
| `04_wazuh_malware_hash_virustotal.json` | positive | `open_incident` | TP | 73 / high |
| `05_wazuh_web_sql_injection.json` | positive | `queue_l1` | TP | 59 / medium |
| `06_wazuh_windows_user_created.json` | positive | `queue_l1` | TP | 47 / medium |

Confusion matrix: **TP 4 · FP 0 · FN 1 · TN 1** → **precision 1.0000**, **recall 0.8000**,
**F1 0.8889**, **false-positive rate 0.0000**.

**Interpretation (stated plainly):**

- The single FN is a **corpus-label/action-mapping observation**. The first-occurrence SSH
  brute-force fixture is labeled `positive`, but the deterministic engine scores it
  `43 / low → monitor` because recurrence (handled by the dedupe/recurrence factor) is what
  escalates it; that fixture's own ground-truth contract (score/tier/action) passes. The
  harness treats `monitor` as a negative action, so it is counted as FN. **No scoring
  change is implied or made** — the metric is a property of the label semantics of a
  6-fixture corpus.
- Every other fixture matches its ground-truth contract exactly, which is what pinning
  deterministic scoring buys: reproducible, reviewable expectations.

**Known limitations (deliberate, carried into Phase 6):**

- Metric values are **printed but not asserted**, so there is **no detection-quality CI
  gate** yet.
- The corpus is 6 fixtures (1 negative) — far too small to be called a benchmark.
- All fixtures run with enrichment **disabled/skipped**, so enrichment quality is not
  measured at all.
- Wazuh rule-level detection coverage (which rules fire, which are blind spots) is not
  measured.

---

## Phase 6 — Detection quality & correlation ✅

**Goal:** move from "the deterministic path behaves as pinned" to "detection quality is
continuously measured and regressions are blocked".

**Status: ✅ implemented · locally validated — 6 of 6 items implemented** (detection coverage framework; ATT&CK
mapping; expanded regression corpus of 24 scenarios; cross-alert correlation as an
investigation context; analyst explainability; detection-quality CI gates). Item 6.6 asserts precision/recall/F1 thresholds and confusion-matrix bounds over the
24-scenario corpus through the existing pytest CI job. Live Wazuh rule coverage remains
out of scope for this gate.

| # | Item | Scope | Status |
| --- | --- | --- | --- |
| 6.1 | Detection coverage framework | A machine-readable inventory of the scenarios, Wazuh rules/decoders, and pipeline outcomes the platform covers, plus explicit blind spots | ✅ **implemented** (delivered as the Phase 6.2 implementation task) — see below |
| 6.2 | MITRE ATT&CK mapping | Maintained mapping from scenarios/rules to ATT&CK techniques for reporting and analyst context (today ATT&CK ids only pass through from Wazuh rule metadata as `rule.mitre`, and their presence contributes to the `rule_groups_mitre` score factor) | ✅ **implemented** (registry + rendered view + validation tests; runtime untouched) — see below |
| 6.3 | Expanded regression corpus | Grow the labeled corpus well beyond 6 fixtures; add negatives per scenario; define and document the positive/negative ↔ decision-action semantics (including the UC-1 first-occurrence case) | ✅ **implemented** — corpus grown to 24 scenarios (12 positive / 12 negative), including per-scenario negatives, custom-rule near-misses, and a just-below-trigger recurrence boundary (`SCN-17`–`SCN-24`); label semantics defined and enforced (SCN-01 remains the documented UC-1 first-occurrence FN) |
| 6.4 | Cross-alert correlation | Correlate related alerts (same host, user, or indicator over time) into one investigation context (today only rule+agent recurrence is grouped) | ✅ **implemented** (investigation-context scope; user correlation unsupported by design — no stable canonical user field) — see below |
| 6.5 | Analyst explainability | Extend per-alert explanations beyond today's factor-by-factor score justification, decision reasons, and incident timeline — e.g. "what changed since the last occurrence" | ✅ **implemented** (merged via PR #31) — deterministic, read-only per-alert explanations (`explanation.v1`): `GET /api/v1/alerts/{alert_id}/explanation` assembles the stored alert/detection/score/decision/dedupe/correlation/incident/audit facts with explicit nulls, never re-scoring or inferring |
| 6.6 | Detection-quality CI gates | Fail CI when precision/recall/F1 degrade beyond an agreed threshold, on a corpus large enough to make the thresholds meaningful | ✅ **implemented · locally validated** — `DetectionQualityThresholds` defines precision ≥ 1.0, recall ≥ 11/12, F1 ≥ 22/23, FPR ≤ 0.0, TP ≥ 11, FP ≤ 0, FN ≤ 1, TN ≥ 12; `assert_detection_quality_gate()` enforces all 8 conditions from `test_evaluation.py`, and `test_detection_quality_gates.py` proves a degraded metric is rejected. The gate runs through the existing `python-checks` pytest job; it is a corpus/detection-quality gate, not live Wazuh coverage measurement. |

### 6.1 Detection coverage framework — what is now implemented (Phase 6.2 task)

**Status: ✅ implemented and locally validated. No scoring or decision-routing behavior
changed; the framework is read-only data + documentation + validation tests.**

| Artifact | Purpose | Status |
| --- | --- | --- |
| [`evaluation/detection_catalog.yaml`](evaluation/detection_catalog.yaml) | Machine-readable coverage catalog (version `1.0`): 4 custom detections (`DET-100100`–`DET-100121`, traced to `wazuh/ruleset/rules/soc-triage-rules.xml`) and 6 evaluation scenarios (`SCN-01`–`SCN-06`, traced to fixtures + ground truth) | ✅ implemented |
| [`docs/detection-coverage.md`](docs/detection-coverage.md) | Human-readable framework: the coverage tables (detection → ATT&CK → scenario → expected outcome → runbook → regression test → validation status), the documented catalog schema, and 9 explicitly flagged gaps | ✅ implemented |
| [`app/tests/evaluation/test_detection_coverage.py`](app/tests/evaluation/test_detection_coverage.py) | 39 read-only validation tests asserting every mapping against repository evidence (ruleset, decoders, fixtures, ground truth, corpus, runbooks, test references, document ↔ catalog sync) | ✅ implemented · locally validated |

**Traced today:** 4 custom rules → ATT&CK (`T1110`, `T1565`, `T1190`) → related scenarios
(`SCN-01`, `SCN-03`, `SCN-05`) → expected outcomes → analyst runbooks → validation status ·
6 scenarios → fixtures → ground truth outcomes (`43/low/monitor`, `27/low/monitor`,
`63/medium/queue_l1`, `73/high/open_incident+SEV2`, `59/medium/queue_l1`,
`47/medium/queue_l1`) → runbooks → regression tests.

**Explicitly NOT claimed** (these are gaps in the framework, not pending guesses):

- No custom rule yet covers `SCN-02`, `SCN-04`, or `SCN-06` (gaps G1, G2).
- No fixture exercises any custom rule, so no custom rule has a pinned score/tier/action —
  those detection-table cells stay `—` by design (gap G3), and Phase 4.3 remains
  "authored, not live-validated".
- The `soc-web` decoder path is unexercised (G4).
- Runbook linkage is documentation-only: `decisions.yaml` wires no runbook (G6).
- Cross-alert correlation is absent (G7); coverage is documented, not measured (G8);
  rule `frequency`/`timeframe` thresholds are unvalidated (G9).

**Still outstanding in this item:** nothing mandatory — future work is to close the gaps
above and to re-run the validation when rules, fixtures, or ground truth change (it fails
on drift by design; verified locally by mutation checks during implementation).

*(Phase 6.3 update: the corpus and validation suite below have since grown — the catalog
now traces 10 scenarios `SCN-01`–`SCN-10`; the outcome list above records what 6.1/6.2
delivered and is kept as written.)*

### 6.2 MITRE ATT&CK mapping — what is now implemented

**Status: ✅ implemented and locally validated. No scoring, decision, dedupe, recurrence,
correlation, incident, explainability, or canonical-model behavior changed; the framework
is read-only registry data + a rendered document + static validation tests. No runtime
Python under `app/src/soc_triage/` was touched.**

| Artifact | Purpose | Status |
| --- | --- | --- |
| `evaluation/attack_mappings.yaml` | Machine-readable technique-first registry (version `1.0`): 6 techniques (`T1110`, `T1136`, `T1190`, `T1204`, `T1565`, `T1566` — exactly the ids the repository declares), 11 rule mappings (4 custom rules + 7 fixture-declared rule ids, including two that declare none), 10 scenario mappings, and the G5 conflict pinned as `known_discrepancies` (`recorded-unresolved`) | ✅ implemented |
| `docs/attack-coverage.md` | Rendered technique-first view of the full chain: Wazuh detection → rule → ATT&CK technique → scenario → expected outcome → regression test → analyst/runbook context, plus the documented registry schema | ✅ implemented |
| `app/tests/evaluation/test_attack_mappings.py` | 39 read-only validation tests: schema/version (incl. the permanent `attack_reference.matrix_verification: unverified` flag), unique ids, provenance-file existence, no invented ids (registry set == repository-declared set, both directions), rule/scenario mappings vs the ruleset, the fixtures, and the Phase 6.1 catalog, verbatim names/tactics with complete metadata provenance, byte-identical fixture copies, G5 liveness, runbook ↔ fixture agreement, and full document sync (ids and table cells vs registry, catalog, and ground truth) | ✅ implemented · locally validated |

**Design (documented combination, no runtime coupling):** runtime keeps consuming
source-declared `rule.mitre` verbatim (scoring counts *presence* only; correlation matches
ids; explainability echoes the stored block) — a side-catalog is never consulted at
runtime, so the registry can never silently diverge from what an alert actually carried.
The registry records *what the repository's detection content declares*, every entry
carrying provenance to its source file/path; declared names/tactics are recorded verbatim
with `matrix_verification: unverified`, because the repository carries no ATT&CK reference
data — nothing is corrected, completed, or validated against an external matrix, and no
external/STIX/API data or runtime enrichment was added.

**Explicitly NOT claimed:** no ATT&CK matrix version is pinned; the fixture-declared
name/tactic triples are unverified; the G5 conflict (`SCN-03`/fixture rule `550` declares
`T1566` with name "Modify Authentication Process", custom rule `DET-100110` declares
`T1565`) is recorded, not resolved; the alert read API still omits `rule.mitre` from
`RuleSummary` (an additive, separately-reviewed change if ever wanted); coverage is still
documented, not measured (gap G8 → 6.6).

**Still outstanding in this item:** nothing mandatory — the registry fails on drift by
design (verified by mutation checks during implementation: an altered fixture id, a
removed G5 record, an altered provenance path, and a doc/registry desync each fail the
suite); re-run the validation when rules, fixtures, ground truth, or runbooks change.

### 6.3 Expanded regression corpus — what is now implemented

**Status: ✅ implemented. No scoring or decision-routing behavior changed; the
expansion adds fixtures, ground-truth pins, catalog/registry rows, coverage docs,
and regression tests only.**

| Scenario | What it pins | Why it exists |
| --- | --- | --- |
| `SCN-07` (`07_wazuh_ssh_brute_force_recurrence.json`, corpus case `deliveries: 3`) | First delivery 43/low/`monitor`; third occurrence 55/medium/`queue_l1`, `occurrences: 3`, escalation attributable to the recurrence factor alone (+12 rapid burst) | First multi-delivery corpus case: pins recurrence/velocity score change and the resulting tier/action transition at corpus level, with ground truth as the single source (`recurrence` block) |
| `SCN-08` (`08_wazuh_ssh_session_opened.json`, negative) | 14/informational/`monitor`: no suspicious groups, no MITRE, no indicators, no asset-tier label | Second corpus negative; pins the informational band, the benign zero-contribution path, and the unknown-asset fallback end-to-end |
| `SCN-09` (`09_wazuh_malware_hash_critical_server.json`) | 88/critical/`open_incident` + `SEV1` | Only critical-tier scenario; pins the critical band and SEV1 incident severity through the real pipeline (previously unit/integration-only) |
| `SCN-10` (`10_wazuh_web_sql_injection_staging.json`) | 46/medium/`queue_l1` with the `low` asset-criticality band | Last unexercised asset band (`low`); shows rule severity holding a tier-3 asset in medium |

Plus: corpus label semantics defined and enforced (`positive` scenarios must never be
suppressed; `negative` scenarios must never be actioned — `SCN-01` remains the documented
UC-1 first-occurrence FN), harness assertions for the stable scoring.v2/decisions.v1
contract (engine version, non-degraded factor set and order, decision reasons shape,
severity consistency, offline `enrichment_status`), a replay-determinism test over the
whole corpus, and recurrence boundary tests (2 occurrences and window ±1 s at unit level;
second-delivery non-escalation at pipeline level).

Plus `SCN-17`–`SCN-24` (all negative, all `monitor`): authorized FIM, expected account
creation, non-malicious hash, custom-rule SSH/FIM/web near-misses, a non-triggering web
request, and a two-delivery recurrence boundary that stays below rapid-burst. The labeled
corpus is now 24 scenarios (12 positive / 12 negative). Quality thresholds are now asserted
in 6.6 via `DetectionQualityThresholds` and the existing evaluation gate (TP 11, FP 0,
FN 1, TN 12; precision 1.0, recall 11/12, F1 22/23, FPR 0.0). An allowlist provider now exists
(Phase 2.2 — static `allowlist.v1`, registered
only when `TRIAGE_ALLOWLIST_PATH` points at a policy; it performs no matching until that
policy has entries), so the `suppress` route is reachable in the runtime path once an
operator configures a populated policy (loader → chain merge → decision router wiring is
present, and the −20 factor and `suppress` route are unit-tested) — but that composition is
not pinned by an end-to-end test, and the corpus still does not pin a `suppress` outcome.
`docs/detection-coverage.md` gap G10 additionally still describes the loader as outstanding
(a follow-up docs update is needed there — that file is outside this plan's edit scope).

**Phase 6 exit criteria (to be refined as items land):** a documented coverage map exists
(✅ 6.1) · ATT&CK mapping is generated from a maintained source and covered by tests
(✅ 6.2 — the registry is generated from the declaring sources, every value verbatim with
provenance, matrix-verification explicitly `unverified`) ·
the corpus has scenario-level negatives, and its label semantics are documented ·
correlation produces a single investigation context for a multi-stage scenario
(✅ 6.4 — e.g. `SCN-01`+`SCN-02` group through `shared_source_ip`+`same_agent` evidence;
the corpus-level *pin* of that outcome is still outstanding) ·
quality gates run in CI with thresholds justified by the corpus size · all existing
deterministic goldens and Phase 5 contracts still pass unchanged (✅ re-verified for 6.4
and 6.2).

### 6.4 Cross-alert correlation — what is now implemented

**Status: ✅ implemented and locally validated. No deduplication, recurrence, scoring,
decision, or incident behavior changed; correlation is an additive, read-side investigation
context.**

| Artifact | Purpose | Status |
| --- | --- | --- |
| `app/src/soc_triage/correlation/evidence.py` | Pure evidence engine: pairwise evidence derivation between two canonical alerts plus the sufficiency policy `correlation.v1` | ✅ implemented |
| `app/src/soc_triage/correlation/service.py` | Orchestrator: candidate loading (window-bounded, distinct alerts only), context create/extend/deterministic merge, audit, fail-open semantics | ✅ implemented |
| `correlation_contexts` / `correlation_members` tables (migration `f9a0b1c2d3e4`) | Persistence: one context = many distinct alert ids, each membership carrying its pairwise evidence (`evidence_type`, `value`, `peer_alert_id`) | ✅ implemented |
| `GET /api/v1/correlations`, `GET /api/v1/correlations/{context_id}`, `GET /api/v1/alerts/{alert_id}/correlation` | Read-only API (shared N8N token): context summaries, member alerts, aggregated explainable evidence, deterministic ordering | ✅ implemented |
| `app/tests/unit/test_correlation_evidence.py` + `app/tests/integration/test_correlation.py` | 45 focused tests (21 unit · 24 integration) covering the A–M scenario matrix, regression protection, and mutation-checked drift detection | ✅ implemented · locally validated |

**Concept separation (the core design constraint):**

- **Deduplication** — "is this the same event / recurrence family?" — *unchanged* (`compute_group_key`,
  `decide_delivery`, window semantics untouched; candidates from the alert's own dedupe group are
  excluded from correlation, so recurrence can never surface as correlation).
- **Recurrence** — distinct events of one `rule.id + agent.id` group within the dedupe window —
  *unchanged* (occurrences/generation/duplicate counters verified byte-identical by tests).
- **Correlation** — "are these distinct alerts related enough to present as one investigation
  context?" — *new*: deterministic evidence (`same_agent`, `same_rule`, `shared_technique`,
  `shared_source_ip`, `shared_destination_ip`, `shared_ioc`), sufficiency policy (any shared
  indicator, or same-agent **plus** shared ATT&CK technique — agent-only is deliberately
  insufficient to avoid noisy host dumping-grounds), bounded by `TRIAGE_CORRELATION_WINDOW_SECONDS`
  (default 900 s, inclusive boundary, independent knob).
- **Incident** — the response object opened by `open_incident` decisions — *unchanged and
  independent*: correlation never reads or writes `alerts.incident_id`, never creates/merges/
  escalates incidents; each member row surfaces its own `dedupe_group_key` and `incident_id`.

**Explicitly unsupported dimensions (no stable canonical field — nothing inferred):**
usernames (`data.srcuser`/`dstuser` only surface as *email indicators* when they validate as
one — a `shared_user` evidence type would be built on data the model does not guarantee);
free-text/`full_log` similarity; any ML/LLM similarity score. Allowlisted indicators are
excluded from evidence.

**Deliberate scope limits (blind spots, not gaps in implementation):** correlation does not
feed `scoring.v2`/`decisions.v1`; contexts have no lifecycle (no TTL sweeper — bounded growth
is a deployment concern); a context may span longer than one window when evidence chains
transitively (each pairwise link stays window-bounded and carries its own evidence); contexts
merge only when a *newly ingested alert* presents qualifying evidence bridging them
(deterministically into the earlier-created context), never spontaneously — incidents are
never merged at all.

---

## Testing Strategy

**Verified locally on the checkout as of 2026-09-11, after Phase 6.4:**
`pytest` → **998 passed** (595 unit · 346 integration · 57 evaluation, of which 52 are the
Phase 6.1 detection-coverage validation; the 45 Phase 6.4 correlation tests are included);
ruff check + format check, mypy `src`, and
`check_secrets.sh` clean; `node --test app/tests/js/console_core.test.cjs` → **15 passed**.

That 998 figure predates the Phase 2.2 merge. Phase 2.2 is evidenced by its own
**47 targeted tests** (26 allowlist unit · 16 asset-inventory unit · 5 integration wiring)
plus the same CI gate (ruff check, ruff format check, mypy, pytest on Python 3.11 & 3.12,
secret scan). Phase 2.3 is evidenced by its own **61 targeted tests** (24 cache unit ·
19 provider-cache unit · 12 wiring/migration integration · 6 config) plus the same CI
gate. No full-suite re-count was taken for Phase 2.2, so **no updated suite total is
claimed anywhere in this plan or the README** (for reference, the local full-suite run
accompanying Phase 2.3 measured 1258 passed on Python 3.11).

| Layer | Runs on | Tooling | Gate |
| --- | --- | --- | --- |
| Unit (scoring, normalizer, dedupe, decisions, config, integrator, metrics) | every PR | pytest, golden files | zero golden drift without an explicit golden update in the same PR |
| Contract (sample alerts ↔ normalizer/scorer) | every PR | pytest fixtures (`app/tests/fixtures/`) | all samples parse + score |
| Integration (API + temp SQLite + auth + audit + lifecycle) | every PR | FastAPI `TestClient` | all acceptance-path tests green |
| External fakes (VirusTotal/MISP behavior) | every PR | injected `httpx.MockTransport` clients (no `respx`, no network) | outage/quota/timeout paths covered |
| Evaluation (Phase 5 + 6.6) | every PR | pytest + `evaluation/` corpus/ground truth/metrics + detection-quality gate | ground-truth contracts and corpus parity hold; TP/FP/FN/TN, precision/recall/F1/FPR are asserted over the 24-scenario corpus via `assert_detection_quality_gate()` |
| Console JS | every PR | Node 22 `--test` | 15 tests green |
| Security | every PR | `check_secrets.sh`, secret-canary metrics test, authz matrix | all green |
| E2E smoke (compose) | — | compose + curl assertions | ⬜ **not implemented** (no nightly compose job) |
| Coverage threshold | — | `pytest-cov` available | ⬜ **not enforced in CI** (no `--cov` invocation); treated as a local expectation, not a gate |

**CI jobs** (`.github/workflows/ci.yml`, on push to `main`, every PR, and manual dispatch):
`python-checks` (ruff lint, ruff format check, mypy `src`, pytest on Python 3.11 and 3.12),
`secret-scan` (`scripts/check_secrets.sh`), `console-js-tests` (Node 22).

**Conventions:** tests live in `app/tests/{unit,integration,evaluation,js}`; fixtures in
`app/tests/fixtures`; no network access in unit/integration tests (fakes only);
deterministic seeds for any randomized behavior (jitter tests use seeded RNG).

---

## Definition of Done (every PR)

- Docs updated if behavior changed; **status claims updated in README/DEVELOPMENT_PLAN** if
  a phase item moved between implemented / validated / outstanding.
- Tests + gate green (ruff, format, mypy, pytest, secret scan, console JS).
- No new secrets or runtime data committed.
- Logging follows the structured format with correlation IDs; no `full_log`, credentials,
  or IOC payloads in logs.
- Error paths handled per ARCHITECTURE §16.
- `CHANGELOG.md` entry added (the project's one known gap: the Phase 5 entry is still
  missing).
- Deterministic goldens changed **only** with an explicit, reviewed golden update in the
  same PR.

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| VirusTotal public quota exhausted mid-demo | enrichment gaps | non-blocking token bucket ✅ (an exhausted quota marks lookups `rate_limited` instead of stalling the pipeline) + `soc_triage_enrichment_provider_outcomes` counters; response TTL cache ✅ (repeat indicators served from `enrichment_cache` without consuming tokens; disabled by default); zero-intel fallback mode is a *feature* demo |
| MISP docker stack is heavy (RAM/time) | lab friction | optional `intel` profile by design and internal-only; VT-only mode still works; `misp/seeding.md` documents the workstation-sized limits, the 180 s first-boot health period, and the no-feeds/no-modules determinism choices |
| External providers only ever tested with fake transports | live-API surprises | explicit status labelling (no live VT/MISP call is claimed anywhere) and a planned live smoke check |
| n8n breaking API changes between versions | workflow imports fail | pin the n8n image tag; workflows exported per version; static/security tests in CI |
| Wazuh integrator behaviour differs across 4.x minors | lost alerts | version pinned in compose; source-audited against the pinned image; live-validated once; ⬜ soak + failure-recovery runtime checks |
| Evaluation corpus too small / label semantics ambiguous | misleading quality numbers | Phase 5 numbers are labelled as a 6-fixture smoke baseline; Phase 6 expands the corpus and defines label semantics before adding CI thresholds |
| Detection-quality metrics regress | silent regressions | ✅ mitigated — `DetectionQualityThresholds` and `assert_detection_quality_gate()` enforce 8 corpus-quality conditions through the existing pytest CI job |
| Coverage threshold documented but not enforced | untested paths slip through | stated honestly; enforcement tracked as ⬜ in the testing table |
| Documentation drift (status restated in several files) | reviewers lose trust | single status vocabulary; README + this file are the only status sources; out-of-date statements are listed as known drift rather than silently ignored |
| Scope creep toward offensive tooling | charter violation | CONTRIBUTING explicitly rejects offensive capabilities; review checklist item |

---

## Milestones & Versioning

- Semantic versioning intent from `v0.1.0`; **no tags have been cut yet** — `CHANGELOG.md`
  remains under `[Unreleased]` and the package version is `0.1.0a1`.
- `CHANGELOG.md` documents changes per phase (Phases 1A–4.7 recorded today; the Phase 5
  entry is ⬜ outstanding).
- Branching: trunk-based — short-lived feature branches → PR → CI gates → merge to `main`
  (see CONTRIBUTING.md).

---

## Known Documentation Drift (outside this plan's edit scope)

Recorded rather than hidden; each is a small docs-only follow-up.

| File | Drift |
| --- | --- |
| `CHANGELOG.md` | No Phase 5 entry yet (the evaluation framework is merged but undocumented there). |
| `docs/detection-coverage.md` (gap G10) | Previously stated that the allowlist provider/loader was missing. Reconciled: Phase 2.2 provides the allowlist provider/loader; the remaining G10 gap is that the evaluation corpus does not pin a `suppress` outcome. |
| `CHANGELOG.md` | No Phase 5 entry yet; Phase 2.2/2.6/2.7A/2.7B entries added in this reconciliation — Phase 5 still missing. |
