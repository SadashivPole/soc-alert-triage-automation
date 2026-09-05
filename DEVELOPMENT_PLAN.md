# Development Plan

**Project:** AI-Assisted SOC Alert Triage & Incident Response Automation
**Working model:** phase-gated development — each phase has scope, deliverables,
acceptance criteria, and a test gate. Nothing merges without its gate.
**Charter constraints (apply to every phase):** free services only · no hardcoded
secrets · defensive-only capabilities · no fake production claims · TheHive Premium
must never be required.

---

## Guiding Principles

1. **Docs-first:** ARCHITECTURE.md is the source of truth; design changes land as doc
   PRs (or ADR additions) before code.
2. **Walking skeleton, then muscle:** every phase ends with a demoable vertical slice,
   not a pile of half-wired components.
3. **Explainable by construction:** no score, decision, or notification may exist
   without a stored justification.
4. **Test-first for core logic:** the scoring engine and normalizer are built
   golden-test-first; enrichment/decision code follows with unit + fake-external tests.
5. **Zero-external fallback:** the full pipeline must run with no VirusTotal, no MISP,
   no chat webhook, no LLM — degraded but functional and honest about it.

---

## Phase 0 — Foundation ✅ (this milestone)

Delivered:

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

## Phase 1 — MVP triage pipeline (target tag `v0.1.0`)

**Goal:** a walking skeleton — alert in → normalize → dedupe → score (v1) → decide →
n8n callback → notification visible in Mailpit. Fully offline (no VT/MISP).

**Scope & deliverables**

| # | Deliverable | Notes |
| --- | --- | --- |
| 1.1 | Python project scaffold | `pyproject.toml`, ruff + pytest config, `soc_triage` package per ARCHITECTURE §12 |
| 1.2 | `core/`: settings, structlog logging, error envelope, API-key auth | fails fast on `change-me*` secrets |
| 1.3 | DB layer | SQLAlchemy models: `alerts`, `audit_log`, `dead_letters` (+ Alembic init) |
| 1.4 | Ingest router + Wazuh normalizer + dedupe | tolerant Pydantic schema; contract tests over all sample alerts |
| 1.5 | Scoring engine v1 + `app/config/scoring.yaml` | golden tests pin sample-alert scores |
| 1.6 | Decision engine v1 + `app/config/decisions.yaml` | matrix from ARCHITECTURE §9 |
| 1.7 | n8n webhook client (outbound) + `pending_notifications` retry loop | 2 s timeout, park-and-retry |
| 1.8 | Docker compose: `triage-api`, `n8n`, `mailpit`; networks `soc-edge`/`soc-core` | per ARCHITECTURE §13; non-root images |
| 1.9 | Simulator `scripts/send_test_alert` | sends samples with `X-API-Key` |
| 1.10 | n8n WF1 (`soc-triage-router`) + WF2 (`soc-analyst-notify`) exports | imported via `n8n/README.md` |
| 1.11 | CI workflow (GitHub Actions) | lint (ruff), unit + integration tests, `check_secrets.sh` |
| 1.12 | API reference (OpenAPI auto-docs) + quickstart in README | honest "lab" wording |
| 1.13 | IOC extraction & enrichment provider interface (Phase 1E) | pure extractor (ipv4/domain/url/md5/sha1/sha256/email) with provenance + FP policy; injectable `EnrichmentProvider` protocol; disabled no-op provider; **no external calls**; `enrichment_status: skipped` |

**Acceptance criteria**

- `docker compose up` → all three services healthy (`/health`, `/healthz`).
- Sending `01_wazuh_ssh_brute_force.json` (×10) creates **one** alert row with
  `occurrences=10`, score per golden file, decision logged, notification email in Mailpit.
- Wrong/missing `X-API-Key` → 401; oversized body → 413; malformed JSON → 422 + dead letter.
- With `VIRUSTOTAL_API_KEY` empty, pipeline completes with `enrichment_status: skipped`.
- Phase 1E: every sample alert extracts the documented indicators, repeated extraction is
  byte-identical, and no extraction path performs network I/O.
- Coverage ≥ 85 % on `scoring/`, `ingest/`, `decisions/`, `core/`; CI green.

**Out of scope (deferred):** VT/MISP calls, incidents, escalation timers, console UI.

---

## Phase 2 — Enrichment & threat intel (target tag `v0.2.0`)

**Goal:** real intel enrichment with quota safety and graceful degradation; scoring v2.

- 2.1 IOC extractor — **delivered early as Phase 1E** (deliverable 1.13); Phase 2
  resumes at 2.2 · 2.2 allowlist + asset inventory
  YAML loaders · 2.3 VirusTotal v3 client: token bucket (4/min, 500/day), TTL cache,
  quota accounting, fake-server tests (`respx`) · 2.4 MISP client + `intel` compose
  profile + seeding guide (public feeds, clearly-labeled synthetic events) ·
  2.5 scoring v2 (`threat_intel` factor) + updated goldens · 2.6 late-enrichment
  background re-score · 2.7 WF2 message now includes IOC verdict table.

**Acceptance:** VT outage/quota simulations never delay ingest > 5 s and always mark
`enrichment_status`; a MISP-matched sample alert scores per new golden; quota usage
observable via logs + stats endpoint.

---

## Phase 3 — Incidents, SLA escalation, feedback, console (target tag `v0.3.0`)

**Goal:** the full analyst loop with human-in-the-loop response.

- 3.1 `incidents` table + API + WF3 · 3.2 incident lifecycle + feedback sync ·
  3.3 alert/incident read APIs + incident timeline · 3.4 auto-close TTL sweeper
  (this milestone) · 3.5 SOC console (static HTML) ✅ — alert queue, score
  drill-down, incident board, served same-origin at `/console` (this milestone) ·
  3.6 runbooks for the six sample scenarios · 3.7 Prometheus
  `/metrics` + optional Grafana profile · 3.8 PostgreSQL profile + migration
  parity tests · 3.9 `stats` endpoints + WF6 daily digest. (WF4 SLA / WF5 form
  landed with Phase 2B/2C.)

**Acceptance:** end-to-end demo — sample alert → incident → (no ack) → escalation email →
FP verdict via form → tuning suggestion in next digest. All actions audit-logged.

---

## Phase 4 — Real Wazuh integration & approved response (target tag `v0.4.0`)

**Goal:** production-shaped ingestion from an actual Wazuh manager; safe response actions.

- 4.1 `full` compose profile with `wazuh-manager` ✅ (this milestone) · 4.2 custom
  `integrator` script (`wazuh/integrator/`) reading env for URL/key, with local
  buffering ✅ (this milestone) · 4.3 custom
  rules/decoders showcase (SSH, FIM, web) · 4.4 agent enrollment docs (lab agents) ·
  4.5 human-approved containment runbook (Wazuh active-response *proposal* requiring
  explicit analyst approval; audited) · 4.6 optional TheHive CE case export (CE only) ·
  4.7 performance soak: 10k synthetic alerts/day replay with SLA-safe timings.

**Acceptance:** real Wazuh alert (agent → manager → integrator → API) visible as incident
with enrichment; containment proposal requires explicit approval and writes audit rows;
no autonomous destructive action exists anywhere.

---

## Phase 5 — Optional AI assistance & tuning (target tag `v0.5.0`, experimental)

**Goal:** clearly-labeled LLM assistance, never load-bearing.

- 5.1 LLM module (OpenAI-compatible, free-tier friendly) drafting **summaries only** —
  appended after deterministic scoring, flagged `ai_assisted: true`, disabled by default ·
  5.2 MITRE ATT&CK mapping enrichment from rule metadata · 5.3 feedback-driven tuning
  assistant: proposes weight diffs from FP/TP history; humans apply via reviewed PR ·
  5.4 evaluation harness: replay historical sample corpus, compare engine versions.

**Acceptance:** with LLM disabled, system behaves exactly as v0.4; with LLM enabled,
numeric scores/decisions are byte-identical (tests assert this).

---

## Testing Strategy

**Pyramid & gates**

| Layer | Runs on | Tooling | Gate |
| --- | --- | --- | --- |
| Unit (scoring, normalizer, dedupe, decisions, config) | every PR | pytest, golden files | ≥ 85 % coverage on core packages; zero golden drift without an explicit golden update in the same PR |
| Contract (sample alerts ↔ normalizer/scorer) | every PR | pytest fixtures from `docs/sample-alerts/` | all samples parse + score |
| Integration (API + temp SQLite + auth + audit) | every PR | FastAPI TestClient | all acceptance-path tests green |
| External fakes (VT/MISP behavior) | every PR | `respx` fake transports | outage/quota/timeout paths covered |
| E2E smoke (compose `sim`) | nightly + on release | compose + curl assertions | alert→notification within 60 s |
| Security | every PR | `check_secrets.sh`, secret-canary log test, authz matrix | all green |

**Conventions:** tests live in `app/tests/{unit,integration}`; fixtures in
`app/tests/fixtures`; no network access in unit/integration tests (fakes only);
deterministic seeds for any randomized behavior (jitter tests use seeded RNG).

**Definition of Done (every PR):** docs updated if behavior changed · tests + gate green ·
no new secrets or runtime data committed · logging follows structured format with
correlation IDs · error paths handled per ARCHITECTURE §16 · CHANGELOG entry.

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| VirusTotal public quota exhausted mid-demo | enrichment gaps | token bucket + cache + quota metrics; zero-intel fallback mode is a *feature* demo |
| MISP docker stack is heavy (RAM/time) | lab friction | optional profile; VT-only mode; documented sizing |
| n8n breaking API changes between versions | workflow imports fail | pin n8n image tag; workflows exported per version; import test in CI (Phase 3+) |
| Wazuh integrator script env handling differs across 4.x minors | lost alerts | version pinned in compose; integration test in `full` profile (Phase 4) |
| Alert-flood sample replays skew dedupe/scoring state | confusing demos | simulator resets DB or uses distinct agents per scenario (`--fresh` flag) |
| Scope creep toward offensive tooling | policy violation | CONTRIBUTING explicitly rejects offensive capabilities; review checklist item |

---

## Milestones & Versioning

- Semantic versioning from `v0.1.0`; tags cut only at phase completion with all gates green.
- `CHANGELOG.md` starts in Phase 1.
- Branching: trunk-based — short-lived feature branches → PR → CI gates → merge to
  `main` (see CONTRIBUTING.md).
