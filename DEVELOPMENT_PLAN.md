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
| **Phase 1 — MVP triage pipeline** | ✅ Implemented · locally validated | Ingest → normalize → dedupe → score → decide → notify, tests green (⬜ simulator script) |
| **Phase 2 — Enrichment & threat intelligence** | 🟡 Partially validated | VirusTotal + MISP providers implemented (fake-transport tested, disabled by default); MISP profile, static allowlist loader, scoring v2 intel factor, TTL cache ⬜ |
| **Phase 3 — Incidents, analyst workflow & observability** | 🟡 Partially validated | Incidents, lifecycle, read APIs, timeline, sweeper, console, runbooks, `/metrics` + Grafana profile all implemented; PostgreSQL profile + stats/digest ⬜ |
| **Phase 4 — Real Wazuh integration & approved response** | 🟡 Partially validated | 4.1/4.2 source-audited + live-validated end-to-end; 4.4 validated; 4.3 authored but not live-validated; 4.5/4.6/4.7 and runtime failure/duplicate checks ⬜ |
| **Phase 5 — Deterministic detection evaluation** | ✅ Implemented · locally validated | Labeled corpus, ground truth, confusion matrix, precision/recall/F1/FPR, runtime evaluation tests |
| **Phase 6 — Detection quality & correlation** | 🟡 In progress (1 of 6 items implemented) | Detection coverage framework ✅ (catalog + doc + validation tests); ATT&CK mapping, expanded regression corpus, cross-alert correlation, analyst explainability, detection-quality CI gates 🔮 |

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

**Status: implemented and locally validated** (deliverable 1.9 outstanding).

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
| 1.9 | Simulator `scripts/send_test_alert` | ⬜ | **not implemented**; sample alerts are replayed manually or by the Phase 5 harness |
| 1.10 | n8n WF1 (`soc-triage-router`) + WF2 (`soc-analyst-notify`) exports | ✅ | imported via `n8n/README.md` |
| 1.11 | CI workflow (GitHub Actions) | ✅ | ruff, mypy, pytest, `check_secrets.sh`, console JS |
| 1.12 | API reference (OpenAPI auto-docs) + quickstart in README | ✅ | honest "lab" wording |
| 1.13 | IOC extraction & enrichment provider interface (Phase 1E) | ✅ | pure extractor, injectable provider protocol, disabled no-op provider, `enrichment_status: skipped` without external calls |

**Acceptance:** compose stack healthy · repeated sample alert deduplicates to one row with
recurrence · auth/limit/validation error paths correct · pipeline completes with
`enrichment_status: skipped` when no intel keys are set · core-package tests green in CI.

---

## Phase 2 — Enrichment & threat intelligence 🟡

**Goal:** real intel enrichment with quota safety and graceful degradation.

**Status: partially validated — provider clients implemented, container profile and
scoring integration still outstanding.**

| # | Deliverable | Status | Evidence / gap |
| --- | --- | --- | --- |
| 2.1 | IOC extractor | ✅ implemented (delivered early as Phase 1E/1.13) | pure, deterministic, no network I/O |
| 2.2 | Allowlist + asset-inventory YAML loaders | ⬜ outstanding | the scoring engine (`allowlist` −20) and the decision engine (`suppress`) already honor an allowlist *match*, but no provider/loader produces one today; asset criticality comes from `agent.labels.asset_tier` in the alert |
| 2.3 | VirusTotal v3 client: token bucket (4/min, 500/day), quota accounting, fake-server tests | 🟡 implemented, no live run | `httpx.MockTransport` fakes only; **no response TTL cache** (⬜) |
| 2.4 | MISP client + `intel` compose profile + seeding guide | 🟡 client ✅ / profile ⬜ | `enrichment/misp.py` implemented and disabled by default; `misp/` is scaffolded only — no compose service, no seeding guide |
| 2.5 | Scoring v2 (`threat_intel` factor) + updated goldens | ⬜ outstanding | policy is still `scoring.v1` (7 factors); IOC verdicts do not yet add intel-specific points |
| 2.6 | Late-enrichment background re-score | ⬜ outstanding | no re-score loop exists |
| 2.7 | WF2 message includes IOC verdict table | 🟡 partial | WF2 renders IOC/enrichment summaries grouped by type; no separate per-provider verdict table |

**Acceptance (not yet met):** VT outage/quota simulations never delay ingest beyond the
budget and always mark `enrichment_status`; a MISP-matched sample alert scores per a new
golden; quota usage observable. Fail-open behavior, token-bucket non-blocking behavior,
and status marking are covered by tests today.

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
| 3.8 | PostgreSQL profile + migration parity tests | ⬜ outstanding | SQLite is the only wired database; URLs are PostgreSQL-shaped and migrations are portable |
| 3.9 | `stats` endpoints + WF6 daily digest | ⬜ outstanding | UC-7 is not implemented |

**Acceptance:** end-to-end demo — sample alert → incident → (no ack) → escalation email →
verdict via form → audit rows. All implemented paths are audit-logged; the digest step of
the demo remains ⬜.

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
| 4.6 | Optional TheHive CE case export (CE only) | ⬜ outstanding | no TheHive code, profile, or docs beyond design |
| 4.7 | Performance soak: 10k synthetic alerts/day with SLA-safe timings | ⬜ outstanding | no soak harness exists |

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
- Secret/log hygiene (checklist V8, partially verified): API key absent from `integrations.log`,
  `ossec.log`, and compose logs; no `full_log`/alert-body content in logs; no `user:pass@`
  URLs in logs.

**Still outstanding from the checklist
([docs/specs/phase-4-live-validation-checklist.md](docs/specs/phase-4-live-validation-checklist.md)):**

| Check | Status |
| --- | --- |
| V7 failure/spool recovery (stop `triage-api` → retries → `alert_buffered`; spool `0700`/`0600`, no stale `.tmp`; restart → oldest-first replay, spool drains, no duplicate incident) | ⬜ outstanding |
| V8 post-Phase-4 `/metrics` hygiene (no new families, no Wazuh data) | ⬜ outstanding |
| V9 idempotent duplicate delivery at runtime (occurrences increment, no duplicate row/incident) | ⬜ outstanding (covered by automated tests, not by a live run) |
| 4.3 custom rules/decoder live match | ⬜ outstanding |
| 4.5 containment approval runbook / response proposal flow | ⬜ outstanding |
| 4.6 TheHive CE export | ⬜ outstanding |
| 4.7 10k alerts/day soak with SLA-safe timings | ⬜ outstanding |

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

## Phase 6 — Detection quality & correlation 🟡

**Goal:** move from "the deterministic path behaves as pinned" to "detection quality is
continuously measured and regressions are blocked".

**Status: in progress — 1 of 6 items implemented (detection coverage framework).**
Everything else below is still a scope, not an achievement.

| # | Item | Scope | Status |
| --- | --- | --- | --- |
| 6.1 | Detection coverage framework | A machine-readable inventory of the scenarios, Wazuh rules/decoders, and pipeline outcomes the platform covers, plus explicit blind spots | ✅ **implemented** (delivered as the Phase 6.2 implementation task) — see below |
| 6.2 | MITRE ATT&CK mapping | Maintained mapping from scenarios/rules to ATT&CK techniques for reporting and analyst context (today ATT&CK ids only pass through from Wazuh rule metadata as `rule.mitre`, and their presence contributes to the `rule_groups_mitre` score factor) | 🔮 not started as a framework — the coverage catalog now *records* the ATT&CK ids each rule/fixture declares, and surfaces one fixture-level metadata discrepancy (gap G5) |
| 6.3 | Expanded regression corpus | Grow the labeled corpus well beyond 6 fixtures; add negatives per scenario; define and document the positive/negative ↔ decision-action semantics (including the UC-1 first-occurrence case) | 🔮 not started |
| 6.4 | Cross-alert correlation | Correlate related alerts (same host, user, or indicator over time) into one investigation context (today only rule+agent recurrence is grouped) | 🔮 not started — now named as gap G7 in the coverage framework |
| 6.5 | Analyst explainability | Extend per-alert explanations beyond today's factor-by-factor score justification, decision reasons, and incident timeline — e.g. "what changed since the last occurrence" | 🔮 not started |
| 6.6 | Detection-quality CI gates | Fail CI when precision/recall/F1 degrade beyond an agreed threshold, on a corpus large enough to make the thresholds meaningful | 🔮 not started — coverage framework validates traceability, not quality (gap G8) |

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

**Phase 6 exit criteria (to be refined as items land):** a documented coverage map exists
(✅ 6.1) · ATT&CK mapping is generated from a maintained source and covered by tests ·
the corpus has scenario-level negatives, and its label semantics are documented ·
correlation produces a single investigation context for a multi-stage scenario ·
quality gates run in CI with thresholds justified by the corpus size · all existing
deterministic goldens and Phase 5 contracts still pass unchanged.

---

## Testing Strategy

**Verified locally on the current checkout (Python 3.11, 2026-09-10):**
`pytest` → **930 passed** (571 unit · 318 integration · 41 evaluation, of which 39 are the
Phase 6.1 detection-coverage validation); ruff check + format check, mypy `src`, and
`check_secrets.sh` clean; `node --test app/tests/js/console_core.test.cjs` → **15 passed**.

| Layer | Runs on | Tooling | Gate |
| --- | --- | --- | --- |
| Unit (scoring, normalizer, dedupe, decisions, config, integrator, metrics) | every PR | pytest, golden files | zero golden drift without an explicit golden update in the same PR |
| Contract (sample alerts ↔ normalizer/scorer) | every PR | pytest fixtures (`app/tests/fixtures/`) | all samples parse + score |
| Integration (API + temp SQLite + auth + audit + lifecycle) | every PR | FastAPI `TestClient` | all acceptance-path tests green |
| External fakes (VirusTotal/MISP behavior) | every PR | injected `httpx.MockTransport` clients (no `respx`, no network) | outage/quota/timeout paths covered |
| Evaluation (Phase 5) | every PR | pytest + `evaluation/` corpus/ground truth/metrics | ground-truth contracts and corpus parity hold; metric **values** are printed, not asserted |
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
| VirusTotal public quota exhausted mid-demo | enrichment gaps | non-blocking token bucket ✅ (an exhausted quota marks lookups `rate_limited` instead of stalling the pipeline) + `soc_triage_enrichment_provider_outcomes` counters; response TTL cache ⬜; zero-intel fallback mode is a *feature* demo |
| MISP docker stack is heavy and not yet containerized (RAM/time) | lab friction | optional profile by design, VT-only mode; document sizing when the profile lands |
| External providers only ever tested with fake transports | live-API surprises | explicit status labelling (no live VT/MISP call is claimed anywhere) and a planned live smoke check |
| n8n breaking API changes between versions | workflow imports fail | pin the n8n image tag; workflows exported per version; static/security tests in CI |
| Wazuh integrator behaviour differs across 4.x minors | lost alerts | version pinned in compose; source-audited against the pinned image; live-validated once; ⬜ soak + failure-recovery runtime checks |
| Evaluation corpus too small / label semantics ambiguous | misleading quality numbers | Phase 5 numbers are labelled as a 6-fixture smoke baseline; Phase 6 expands the corpus and defines label semantics before adding CI thresholds |
| Quality metrics printed but not asserted | silent regressions | explicitly tracked as ⬜ Phase 6 (detection-quality CI gates) |
| Coverage threshold documented but not enforced | untested paths slip through | stated honestly; enforcement tracked as ⬜ in the testing table |
| Documentation drift (status restated in several files) | reviewers lose trust | single status vocabulary; README + this file are the only status sources; out-of-date statements are listed as known drift rather than silently ignored |
| Scope creep toward offensive tooling | charter violation | CONTRIBUTING explicitly rejects offensive capabilities; review checklist item |

---

## Milestones & Versioning

- Semantic versioning intent from `v0.1.0`; **no tags have been cut yet** — `CHANGELOG.md`
  remains under `[Unreleased]` and the package version is `0.1.0a1`.
- `CHANGELOG.md` documents changes per phase (Phases 1A–4.2 today; the Phase 5 entry is
  ⬜ outstanding).
- Branching: trunk-based — short-lived feature branches → PR → CI gates → merge to `main`
  (see CONTRIBUTING.md).

---

## Known Documentation Drift (outside this plan's edit scope)

Recorded rather than hidden; each is a small docs-only follow-up.

| File | Drift |
| --- | --- |
| `ARCHITECTURE.md` §8.3 | Refers to "optional LLM polish in Phase 5". Phase 5 is now the **deterministic detection evaluation** phase, and no LLM exists in the codebase. |
| `app/README.md` | Declares "Status: Phase 1E", which predates Phases 2–5. |
| `docs/sample-alerts/README.md` | Documents `./scripts/send_test_alert`, which is not implemented. |
| `CHANGELOG.md` | No Phase 5 entry yet (the evaluation framework is merged but undocumented there). |
| `misp/README.md` | Describes the `intel` compose profile as landing "in Phase 2"; it is still ⬜ outstanding. |
