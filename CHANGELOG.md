# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
semantic (`v0.1.0` targeted at the end of Phase 1).

## [Unreleased]

### Added — Phase 3.4: Incident auto-close TTL sweeper

- **Configurable auto-close TTL.** New settings (env-driven, validated):
  `INCIDENT_AUTO_CLOSE_TTL_SECONDS` (default **604800 s = 7 days** — conservative
  lab default) and `INCIDENT_SWEEPER_INTERVAL_SECONDS` (default **300 s = 5
  minutes**). Both are `ge=1` and documented in `.env.example`. No hardcoded
  secrets; no overlapping TTL settings introduced.
- **Eligibility rule.** A background sweeper periodically scans for
  non-terminal incidents (`open`, `investigating`, `acknowledged`,
  `escalated`) whose `updated_at ≤ now − TTL`. Terminal states (`resolved`,
  `false_positive`) and any incident touched (PATCH / feedback / escalation)
  within the TTL window are excluded. The activity timestamp is the existing
  `incidents.updated_at` — no new column is introduced.
- **Auto-close transition.** Eligible incidents are moved to `resolved` with
  `updated_at` refreshed to the sweep time, `resolved_at` set exactly once,
  and `acknowledged_at` preserved. The transition is performed by a narrow
  system-only path (actor `system:sweeper`); manual analyst transitions
  continue to enforce the strict Phase 3.2 state machine unchanged (so
  `open → resolved` via the public API remains `409`).
- **Audit.** Exactly one append-only `audit_log` row per auto-close:
  `actor = "system:sweeper"`, `action = "incident.auto_closed"`, with a small
  structured `after` snapshot (`incident_id`, `previous_status`, `status`,
  `acknowledged_at`, `resolved_at`, `ttl_seconds`, `idle_seconds`,
  `reason = "ttl_expired"`, `actor`). Secrets and raw payloads are never
  logged. Repeat sweeps are idempotent: terminal rows never match the
  eligibility predicate, so no second `incident.auto_closed` row is ever
  appended.
- **Sweeper implementation.** A lightweight `asyncio` periodic loop
  (`soc_triage/sweeper.py`) is started from the FastAPI lifespan and
  cancelled cleanly on shutdown — no Celery, Redis, APScheduler, or new
  infrastructure dependency (ADR-4). The first pass runs immediately at
  startup so stale rows left by a crashed process are closed without
  waiting a full interval. Each candidate runs in its own short
  transaction; a failure on one incident is logged (by `error_type` only)
  and processing continues. Structured logs (`sweeper_started`,
  `sweeper_pass_completed` with `candidates/closed/skipped/errors/
  duration_ms`, `incident_auto_closed`, `sweeper_incident_failed`,
  `sweeper_stopped`) make the sweeper observable without Prometheus
  metrics (deferred to Phase 3.7).
- **Race safety.** Each close uses a single conditional `UPDATE ... WHERE
  incident_id = :id AND status = :expected_status AND updated_at =
  :expected_updated_at AND updated_at <= :cutoff`. If an analyst PATCH or
  feedback synchronisation bumps `updated_at` between the sweeper's SELECT
  and UPDATE, the UPDATE matches zero rows, no audit row is written, and
  the manual action wins — no stale overwrite. SQLite's single-writer lock
  serialises the UPDATE; the same predicate is atomic on PostgreSQL. No
  distributed-lock claims are made (single-instance lab target).
- **Repository layer.** `IncidentRepository` gains
  `list_incidents_eligible_for_auto_close(ttl_seconds, as_of, limit)` and
  `auto_close_if_stale(...)` — minimal additions that follow the existing
    repository pattern and do not bypass the state machine for manual paths.
- **API impact.** No new public endpoint; GET endpoints never trigger the
  sweeper. The sweeper is background-only behavior.
- **No schema migration.** Auto-close uses columns that already exist
  (`status`, `updated_at`, `acknowledged_at`, `resolved_at`) from
  Phase 3.1/3.2 — no Alembic revision is required.
- **Documentation.** `ARCHITECTURE.md §10.4` defines TTL semantics,
  eligibility, the automatic transition, audit schema, race-safety
  strategy, restart behavior, and single-instance SQLite limitations.
  `.env.example` documents the two new settings.
- **Tests:** `tests/integration/test_sweeper.py` (27 new tests) covers
  config defaults + overrides + validation (1–3), eligibility for each
  non-terminal state and exclusion for terminal/recently-updated
  incidents plus exact boundary behavior (4–10), auto-close correctness
  (resolved status, `resolved_at` once, `acknowledged_at` preserved,
  `updated_at` bump, `system:sweeper` actor, single audit row, idempotency
  across reruns, unrelated incidents untouched) (11–18), race safety
  against manual updates and double-pass idempotency (19–20), restart
  persistence and lifespan start/stop (21–22), terminal-state regression
  (24), and per-incident error isolation. All **640** tests pass; ruff,
  mypy (pre-existing PyYAML stub warnings only), and `check_secrets.sh`
  are clean. Phase 3.1/3.2/3.3 tests remain green.

### Added — Phase 3.5: Static SOC console

- **What it is.** A lightweight, static analyst console served by the same
  FastAPI service that exposes the API. No frontend framework, no build step,
  no new container — `app/console/` (plain `index.html` + `styles.css` +
  `console.js` + `console-core.js`) is mounted at `/console` via
  `StaticFiles(html=True)` in `main.py`. Sharing the origin means the browser
  calls the API with no CORS and the analyst token is sent as the `X-N8N-Token`
  header, exactly like the existing n8n callback channel.
- **Three views.** (1) **Alert Queue** — `GET /api/v1/alerts` with
  pagination + tier/severity/source/duplicate filters, dense table, risk tier
  + decision + incident linkage per row. (2) **Alert Detail / score
  drill-down** — `GET /api/v1/alerts/{alert_id}` showing metadata, source/rule/
  agent/asset/location, the server-provided risk **score + factor breakdown**
  (the UI never recomputes a score), decision + reasons, dedupe, IOC summary,
  and enrichment status. (3) **Incident Board / Incident Detail** —
  `GET /api/v1/incidents` grouped into Open / Investigating / Acknowledged /
  Escalated / Resolved / False-positive columns, drill-down to
  `GET /api/v1/incidents/{id}` (lifecycle timestamps, primary + linked alerts)
  and `GET /api/v1/incidents/{id}/timeline` (chronological events with
  before/after/metadata — rendered read-only, never mutated).
- **Lifecycle actions.** The console reuses the existing
  `PATCH /api/v1/incidents/{id}/status` endpoint. It offers **only** the
  transitions the backend state machine allows for the current status
  (a read-only mirror of `VALID_TRANSITIONS` in `console-core.js`); it never
  invents a transition. On success it re-fetches the incident + timeline to
  reflect server truth; backend `409` (illegal transition) and `422`/`5xx`
  errors are surfaced to the analyst with the allowed transitions. The
  auto-close sweeper is **never** triggered from the UI (the console only
  displays its result).
- **Authentication (no new auth system).** The analyst pastes the shared N8N
  callback token into the top bar; it is held **in memory only** (a module
  variable), never in `localStorage`/`sessionStorage`, never hardcoded, never
  in the served files. Every API call attaches it as `X-N8N-Token`. A
  dedicated analyst/read token remains deferred (ARCHITECTURE.md §19); the
  console documents this limitation rather than weakening backend authz.
- **Security / XSS / redaction.** All alert/incident/timeline text is rendered
  via DOM `textContent` (or `escapeHtml` in `console-core.js`) — no untrusted
  string is ever injected with `innerHTML`. The console consumes only the
  redacted read models (no `full_log`, no secrets); server-side redaction
  (`schemas.redact_mapping`) still applies. Treats all API data as untrusted.
- **API error handling.** `401/404/409/422/5xx`/network errors show concise,
  analyst-friendly messages (no raw server internals). Loading / empty / error
  states are present for every view.
- **Tests.** `tests/integration/test_console.py` (17 tests) verifies the
  console is served, references the correct endpoints, keeps the token
  in-memory-only, embeds no secrets, and that every endpoint it depends on
  behaves (read-only lists/detail/timeline, legal PATCH → 200, illegal
  transition → 409, filters/pagination preserved, no GET mutation, safe
  rendering of alert-controlled strings). `app/tests/js/console_core.test.cjs`
  (Node, no browser stack) unit-tests the shared helpers (escaping, state
  machine, score-factor projection, query-string/pagination). All **657** tests
  pass; ruff, ruff format, mypy, and `check_secrets.sh` are clean.
- **Docker.** `Dockerfile` copies `app/console/` into the image; the existing
  `triage-api` service serves it at `http://localhost:8000/console/`. No new
  compose service is required.

### Added — Phase 3.3: Incident/alert read APIs + incident timeline

- **Alert read APIs.** `GET /api/v1/alerts` (paginated list) and
  `GET /api/v1/alerts/{alert_id}` (detail) return analyst-safe projections of
  persisted alerts: identity, source, timestamps, rule/agent, risk score/tier,
  decision, incident linkage, dedupe summary, IOC summaries. `full_log`,
  credentials, tokens, and API keys are never included. Filters are simple
  equality matches on fields already stored (`source`, `incident_id`,
  `rule_id`, `agent_id`, risk `tier`, decision `severity`, `dedupe_group_key`,
  `duplicate`). Unknown alerts return a structured `404`.
- **Incident read APIs.** `GET /api/v1/incidents` and
  `GET /api/v1/incidents/{incident_id}` return status, severity,
  `primary_alert_id`, `dedupe_group_key`, lifecycle timestamps, and (on
  detail) linked-alert summaries/count. Filters: `status`, `severity`,
  `dedupe_group_key`, `created_from`/`created_to`. Unknown incidents return a
  structured `404`.
- **Incident timeline.** `GET /api/v1/incidents/{incident_id}/timeline` is a
  **read-only** assembly of existing `audit_log` rows for the incident and its
  linked alerts (`incident.created`, `incident.status_updated`,
  `incident.escalated`, alert created/scored/decided, `feedback.received`).
  Events are sorted by timestamp with a deterministic audit-id tie-breaker.
  GET never writes audit rows, never transitions state, and never calls
  n8n/Wazuh/intel/LLM.
- **Pagination.** Shared `limit` (default 50, max 200) / `offset` (≥0) with
  `{items, pagination: {limit, offset, total, has_more}}`. Alerts order by
  `received_at DESC, alert_id DESC`; incidents by `created_at DESC,
  incident_id DESC`.
- **Auth.** Shared N8N token (same convention as feedback / incident status
  PATCH). A dedicated analyst/read token is not introduced in this milestone.
- **Tests:** `tests/integration/test_read_apis.py`, `tests/unit/test_timeline.py`,
  `tests/unit/test_read_redaction.py`. All **613** tests pass; ruff, mypy and
  `check_secrets.sh` are clean. Phase 3.1/3.2 tests remain green.

### Added — Phase 3.2: Incident lifecycle + feedback synchronization

- **Strict incident status model.** `IncidentStatus` is now
  `open | investigating | acknowledged | resolved | false_positive |
  escalated`, with an explicit transition table
  (`VALID_TRANSITIONS` in `soc_triage/models/incident.py`):
  `open → investigating/acknowledged/false_positive/escalated`;
  `investigating → acknowledged/resolved/escalated/false_positive`;
  `acknowledged → investigating/resolved/escalated`;
  `escalated → investigating/acknowledged/resolved/false_positive`;
  `resolved` and `false_positive` are terminal. No other transitions exist;
  self-transitions are never allowed (what makes repeated identical feedback
  idempotent).
- **Incident update API.** `PATCH /api/v1/incidents/{incident_id}/status`
  (shared N8N-token auth, same convention as the analyst feedback endpoint)
  accepts `{status, notes?, actor?}`. Unknown incidents return a structured
  `404`; illegal transitions return a structured `409` with the current
  status and the allowed targets. Lifecycle timestamps are maintained in
  UTC: `acknowledged_at` is set exactly when the incident reaches
  `acknowledged`; `resolved_at` exactly when it reaches a terminal state;
  neither is fabricated for any other state.
- **Feedback → incident synchronization.** `POST /api/v1/alerts/{id}/feedback`
  keeps its request/response contract exactly, but after persistence it now
  synchronizes the linked incident **in the same transaction** (all-or-
  nothing) via the documented conservative mapping — a verdict is *not*
  proof that remediation is complete:
  `true_positive → acknowledged` (only when the current state explicitly
  allows it — never resolved); `acknowledged → acknowledged`;
  `resolved → resolved` (state machine still requires investigation/
  acknowledgement first, so `open` incidents are untouched);
  `false_positive → false_positive`; `escalate → escalated`;
  `benign → false_positive` (safest valid terminal meaning, never
  `resolved`); `contain_requested` → **no transition** (human approval
  required — WF5 approval email unchanged; only an
  `incident.containment_requested` audit entry is recorded, with
  `containment_executed: false`). When the current incident state does not
  allow the mapped transition, the verdict is still recorded and the
  incident is left exactly as-is.
- **Audit vocabulary (append-only).** `incident.status_updated` (actor,
  incident id, before/after status + lifecycle timestamps, optional notes)
  and `incident.escalated` (emitted alongside `incident.status_updated` on
  escalation) are added to `incident.created`;
  `incident.containment_requested` records approval-required containment
  requests. Snapshots stay small and secret-free (SECURITY.md §5, §7).
- **Migration `e7f8a9b0c1d2`.** Adds nullable `incidents.acknowledged_at` /
  `incidents.resolved_at` — restart-safe and idempotent (introspects before
  adding, so an interrupted run is finished on restart, never replayed),
  preserves all incident/alert/audit data, and downgrades cleanly on
  SQLite (FK-safe batch recreate with pragma restore). No data is deleted
  or reset.
- **Tests:** `tests/unit/test_incident_state_machine.py` (15 tests: exact
  transition table, terminal states, error contract, documented mapping),
  `tests/integration/test_incident_lifecycle.py` (30 tests: valid/illegal
  transitions, structured 404/409, timestamp semantics, audit rows, all
  seven feedback-verdict synchronizations, TP-never-resolves,
  contain-requested non-destruction, restart persistence, idempotency) and
  `tests/integration/test_incident_lifecycle_migration.py` (3 tests:
  data-preserving upgrade, restart-safe interruption recovery,
  data-preserving downgrade). All **584** tests pass; ruff, mypy and
  `check_secrets.sh` are clean.

### Fixed — Phase 2D: n8n email notification chain

- **Send Email nodes were missing their SMTP credential binding.** All four
  `n8n-nodes-base.emailSend` nodes (WF2 L1 alert, WF3 L2 escalation, WF3 SLA
  breach, WF5 containment approval) now bind an SMTP credential named
  `SMTP Lab Mailpit`. n8n refuses to execute a Send Email node that has no
  credential selected, so the notification chain failed silently before this
  fix even though the webhook/format path succeeded.
- **Lab SMTP credential is provisioned automatically.** `n8n/credentials/
  smtp_lab_mailpit.json` defines a single `smtp` credential targeting the local
  Mailpit sink (`mailpit:1025`, no TLS, no auth). `scripts/
  n8n-import-workflows.sh` now runs `n8n import:credentials` **before**
  importing workflows, rendering connection details from the `SMTP_HOST` /
  `SMTP_PORT` / `SMTP_SECURE` / `SMTP_USER` / `SMTP_PASS` environment
  variables. No connection detail or password is hardcoded in the checked-in
  files (n8n encrypts the imported credential at rest). The
  `n8n/credentials/` directory is mounted read-only into the compose service.
- **Notification emails render the structured payload as readable text.** The
  WF2/WF3 formatter Function nodes previously interpolated objects directly
  (`${alert.rule}` → `[object Object]`), dumped the raw IOC list via
  `JSON.stringify(alert.iocs)`, and referenced investigation links
  (`siem_search_url`, `timeline_url`) that the triage-api payload never sends
  (those lines always rendered `n/a`). The formatters now read
  `rule.description`/`rule.id`/`rule.level`, group IOCs by type
  (ipv4/domain/url/md5/sha1/sha256/email), show enrichment status, and link the
  allow-listed `alert_api`, `runbook`, and `feedback_url` fields.
- **Payload supplies `feedback_url`.** `InvestigationLinks` gains an optional
  `feedback_url` (the `POST /api/v1/alerts/{id}/feedback` endpoint) populated by
  `build_n8n_payload`, so workflow emails link to a stable, allow-listed
  address instead of reconstructing the URL in JavaScript.
- **Tests:** new `tests/unit/test_n8n_email_chain.py` (7 tests) statically
  verifies that every email node binds the expected SMTP credential, the lab
  credential points at Mailpit with no real secret, the import helper
  provisions credentials before workflows, compose mounts the credential
  directory and supplies SMTP env, every email node resolves from/to from env,
  the formatters contain no `[object Object]`/`JSON.stringify(iocs)` patterns,
  and the payload exposes `feedback_url`. All **488** tests pass; ruff, mypy
  and `check_secrets.sh` are clean.

### Added — Phase 2A: Threat Intelligence Provider Integration

- **Shared provider machinery** (`enrichment/threat_intel.py`): a
  `LookupStatus` vocabulary (`found` / `not_found` / `error` / `rate_limited` /
  `timeout`) and a sanitized `LookupRecord` provenance model (provider,
  indicator type, lookup status, ISO-8601 timestamp, allow-listed result
  metadata); a **non-blocking** `TokenBucket` (an exhausted quota marks
  lookups `rate_limited` instead of stalling the alert pipeline); a
  `RetryConfig` with capped exponential backoff + jitter applied **only** to
  safe, idempotent GETs and only to transient failures (network errors,
  timeouts, HTTP 429 — honouring `Retry-After` — and 500/502/503/504).
- **VirusTotal provider** (`enrichment/virustotal.py`): v3 lookups for
  hashes (`/files`), IPv4 (`/ip_addresses`), domains (`/domains`) and URLs
  (`/urls`, base64url id). Rate-limited to the free public tier (4 req/min,
  burst of 4). Stores only `malicious` / `suspicious` / `harmless` /
  `undetected` / `reputation` — never the raw upstream body.
- **MISP provider** (`enrichment/misp.py`): self-hosted
  `/attributes/restSearch` lookups by exact value for every IOC type. Stores
  only the match count, capped sorted event ids and capped sorted tag names.
- **Configuration** (`core/config.py` + `.env.example`): `VIRUSTOTAL_API_KEY`,
  `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_TLS`. Both providers are **disabled
  by default** (disable-by-empty, ARCHITECTURE §14); keys come only from the
  environment/secret store and are held as `SecretStr`.
- **Wiring** (`main.py`): the chain now registers `noop` → `virustotal` →
  `misp` (all disabled by default). A provider failure never blocks scoring or
  decisioning — the deterministic score/decision behaviour is unchanged
  (`enrichment_status: failed` contributes 0, as before).

### Fixed — Phase 2A hardening: IOC provenance credential leak

- Credential-bearing URLs (`https://user:pass@host/…`) are now stripped of
  their userinfo **everywhere** they would otherwise be persisted
  (SECURITY.md §2):
  - `IOCProvenance.raw_value` stores the sanitized URL (not the raw match) for
    both typed URL fields (`data.url`, `data.virustotal.permalink`) and
    text-scanned URLs;
  - a URL's userinfo is never re-extracted as an email or domain indicator
    (`pass@host` inside `user:pass@host` is not an email);
  - the typed URL fields in the canonical alert's `data` block are
    userinfo-stripped (`strip_url_userinfo`) so the credential never reaches
    `normalized_payload`, the API response, audit records, or logs.
- Documented the VirusTotal Public API as lab/non-commercial use only
  (`.env.example`, `app/README.md`) and removed the stale MISP API-key
  placeholder (empty value = disabled).

### Added — Phase 1F: Deterministic Risk Scoring & Decision Engine

- **Result models** (`models/assessment.py`): dependency-free `RiskAssessment`
  (score 0–100, `RiskTier`, per-factor `ScoreFactor`s, generated summary, and
  a `degraded` flag), `Decision` (`DecisionAction`: `suppress` / `monitor` /
  `queue_l1` / `open_incident`, optional `DecisionSeverity` SEV1/SEV2,
  reasons, `decided_at`), plus the `RiskTier` / enums.
- **Deterministic, explainable scoring engine** (`scoring/engine.py`): the pure
  `score_alert(CanonicalAlert, ScoringPolicy) → RiskAssessment` computes seven
  config-driven factors — `rule_severity` (Wazuh level band map),
  `rule_groups_mitre` (suspicious groups + MITRE technique/tactic presence),
  `asset_criticality` (tier→band mapping with an *unknown* fallback),
  `recurrence_velocity` (occurrences-in-window thresholds), `ioc_evidence`
  (distinct indicator count), `enrichment_status` (corroboration credit) and a
  subtractive `allowlist_modifier` — clipped to 0–100 and mapped to a tier.
  Every factor carries a human-readable `detail`; output is byte-identical for
  identical input. `RiskScorer` adds the rule-severity-only degraded fallback
  (fail-open, never crashes ingest).
- **Configuration-driven policy** (`scoring/policy.py` + `app/config/scoring.yaml`,
  `decisions/policy.py` + `app/config/decisions.yaml`): versioned, non-secret,
  schema-validated YAML (fail-loud on invalid/missing config); weights and
  thresholds are tunable without code changes.
- **Decision & routing engine** (`decisions/router.py`): pure `decide(...)`
  maps the risk tier onto an action (critical→SEV1 / high→SEV2 incident,
  medium→L1 queue, low/informational→monitor) and overrides to `suppress`
  for allowlisted sources regardless of score. No autonomous response action
  is taken (SECURITY.md §1, ADR-8).
- **Persistence & audit**: the assessment is written back onto the alert of
  record (`AlertRepository.update_normalized_payload`) and append-only
  `alert.scored` / `alert.decided` audit entries record the score/decision
  (with before/after snapshots for future re-scoring). The canonical model
  gains `asset`, `enrichment_status`, `risk`, and `decision` fields; asset
  tier/owner are derived from agent `labels`.
- **Fully offline**: scoring/decisioning perform zero I/O and no external
  calls (no VirusTotal/MISP); enrichment unavailability degrades to a valid
  score (enrichment `failed`/`skipped` contribute 0).

### Added — Phase 1E: IOC Extraction & Enrichment Interface

- **IOC domain model** (`models/ioc.py`): `IOCType` (`ipv4`, `domain`, `url`,
  `md5`, `sha1`, `sha256`, `email`), a frozen `IOC` carrying the *normalized*
  value plus `IOCProvenance` records (canonical field path, alert location,
  character offset, raw substring, extraction strategy) and a provider-keyed
  `enrichment` mapping. Indicators are deduplicated by `(type, value)` and
  always ordered by `(type, value)` — extraction output is byte-stable.
- **Pure extractor** (`enrichment/extractor.py`): `(CanonicalAlert, policy) →
  [IOC]` with no I/O, clock, logging or randomness. Two strategies, both
  recorded in provenance: **typed fields** (`data.srcip`, `data.dstip`,
  `agent.ip`, `data.url`, `data.hostname`, `data.srcuser`/`dstuser`,
  `data.virustotal.{md5,sha1,sha256,permalink}`, `syscheck.{md5,sha1,sha256}_{
  before,after}` — the whole value must validate) and **opt-in text scans**
  (`full_log`, `location`, unrecognized `data`/`syscheck` leaves).
- **Validation & normalization** (`enrichment/normalize.py`): IPv4 parsed via
  `ipaddress` (rejects `999.1.1.1`, `010.1.1.1`, `1.2.3`, `1.2.3.4.5`);
  domains lowercased with LDH label + alphabetic-TLD rules; URLs canonicalized
  (host lowercased/IDNA, default port and fragment dropped, **userinfo removed**
  so credentials never become a stored indicator); hashes validated by hex
  length (32/40/64); emails validated with case-preserving local part. Common
  defang markers (`hxxp://`, `evil[.]example[.]com`) are normalized back.
- **False-positive policy** (`enrichment/policy.py`, frozen and injectable):
  RFC 1918 / loopback / link-local / CGNAT / multicast / reserved addresses are
  dropped by default (`include_private_ipv4=False`); RFC 5737 + RFC 2544
  documentation ranges are **kept** by default because the synthetic corpus is
  built from them (SECURITY.md §5) and can be excluded per deployment;
  `full_log` and `location` are not extraction sources by default
  (ARCHITECTURE §7.1); file paths (`/etc/passwd`, `C:\…\invoice_tracker.exe`)
  and version-like strings never become domains or IPs; `max_iocs` bounds the
  indicator set.
- **Enrichment provider interface** (`enrichment/providers.py`): a
  runtime-checkable `EnrichmentProvider` protocol (`name`, `enabled`,
  `enrich(iocs, *, context)`), an immutable `EnrichmentContext` (alert id,
  source, received_at, dedupe group) and a `ProviderEnrichment` result keyed by
  `ioc_key`. **No provider performs any network call in this phase.**
- **Offline no-op provider**: `NoOpEnrichmentProvider` is **disabled by
  default** (an unconfigured integration is never called — ARCHITECTURE §14)
  and returns `skipped` with no payloads even when enabled, so local
  development and CI run with zero external services.
- **Fail-open orchestration** (`enrichment/chain.py`): `EnrichmentChain` runs
  providers in registration order, merges payloads onto indicator copies,
  records a per-provider `ProviderOutcome` (status, enriched count, error
  *type*), and aggregates `enrichment_status: complete|partial|failed|skipped`
  (ARCHITECTURE §16). A provider that raises is logged by exception type only
  and skipped — ingestion never breaks on enrichment.
- **Pipeline wiring**: `POST /api/v1/alerts/ingest` now extracts indicators and
  runs the chain before the deduplication write, so the alert **of record**
  carries its indicators. The response adds `iocs` (type, value, provenance,
  enrichment) and `enrichment_status`; a duplicate delivery echoes the
  original's indicators (idempotency). Structured log event `iocs_extracted`
  carries counts and types only — never raw log text (SECURITY.md §7).
- **No database redesign**: indicators ride along in the existing
  `alerts.normalized_payload` JSON via `CanonicalAlert.iocs`; the
  `ioc_observations` table remains Phase 2/3 work. Canonical source events now
  preserve the structured `data` and `syscheck` blocks that typed extraction
  reads (backwards-compatible optional fields, no migration).
- Tests: 117 new tests (`tests/unit/test_ioc_extraction.py`,
  `tests/unit/test_enrichment_chain.py`,
  `tests/integration/test_ingest_iocs.py`) covering every indicator type,
  mixed input, duplicate normalization, invalid IPs/hashes/domains/emails,
  false-positive handling, provenance, deterministic repeated extraction,
  policy switches, provider-protocol conformance, offline no-op enrichment,
  fail-open partial/failed aggregation, persistence and raw-log hygiene. All
  118 pre-existing Phase 1A–1D tests pass unchanged. Coverage: 100 % on every
  `enrichment/` module and `models/ioc.py`, 98 % overall.

### Added — Phase 1D: Persistent Storage & Audit

- **SQLAlchemy ORM models** (`models/orm.py`): `alerts` (one row per distinct
  source event, full canonical payload + denormalized query fields),
  `alert_dedupe_groups` (recurrence/generation state: `occurrences`,
  `generation`, `first_seen`/`last_seen`, `duplicate_deliveries`),
  `alert_events` (per-event-identity idempotency records, window-bounded),
  and the append-only `audit_log` (actor, action, entity, before/after JSON).
- **SQLite support for the MVP** (`db/engine.py`): engine + session factory
  from `TRIAGE_DB_URL` (env-configurable), defensive pragmas (foreign keys,
  WAL, busy timeout), parent-directory auto-creation; the same SQLAlchemy
  URL shape runs on the later PostgreSQL profile with identical migrations.
- **Alembic** (`app/alembic/`, `alembic.ini`): initial migration
  `9ec2a1b4b3bf` (verified reproducible: `upgrade head` → `downgrade base` →
  `upgrade head`, and `alembic check` reports no ORM drift). The application
  applies migrations automatically at startup; manual `alembic upgrade head`
  works via `TRIAGE_DB_URL`.
- **Persistence-backed deduplication** (`ingest/persistent_deduplication.py`):
  implements the same `Deduplicator` contract over the database. The pure
  `decide_delivery` state machine is now shared by both backends, so the
  Phase 1C contract holds exactly in the database: exact duplicates return
  the original `alert_id` and the preserved original canonical alert;
  duplicate flooding never extends the deduplication window; occurrence
  counts and generation information are persisted per group; state is
  **restored correctly after a restart** (idempotency and recurrence
  continue across process death).
- **Audit persistence** (`audit.py` + `AuditRepository`): meaningful state
  changes are audited in the same transaction as the state change itself —
  `dedupe.generation_started`, `alert.created`, `alert.duplicate_absorbed`,
  `alert.content_divergence` — with small before/after JSON snapshots
  (counts, ids, timestamps; never raw payloads or secrets). The audit table
  is append-only by construction (no update/delete path exists).
- **Transactional correctness** (`db/session.py`): one unit of work per
  delivery (alert + event + group state + audit rows commit or roll back
  together); a simulated mid-transaction failure is covered by a test
  asserting no partial state survives.
- **Safe error handling**: storage failures log the exception *type* only
  and surface as `StorageError` → retryable `503` via the shared error
  envelope — no database paths, driver text, or internals ever reach the
  client. `/health` now pings the database (503 when unavailable) and
  `/ready` verifies config + database + applied migrations.
- **Layering preserved**: DB/session mechanics live in `db/`; only
  `models/repositories.py` touches ORM objects; domain packages still never
  import FastAPI.
- Tests: `tests/integration/test_persistence.py` (16 new tests: new/exact
  duplicate/repeated persistence, occurrence counts, generation changes,
  window pruning, restart recovery, audit records + no-raw-data/no-secret
  assertions, rollback atomicity, safe 503 on DB loss, health/ready, and a
  64-delivery concurrency test on the persistent path). All 102 pre-existing
  Phase 1A/1B/1C tests pass unchanged against the persistent backend.

### Added — Phase 1C: Alert Deduplication & Idempotency

- Deterministic **event identity**: `wazuh:{event_id}:{rule_id}:{agent_id}` when a Wazuh
  event id is present, else a versioned SHA-256 content hash over the validated payload
  (volatile `rule.firedtimes` excluded). Blank rule/agent ids and naive timestamps are
  rejected (`InvalidDedupeInputError`) instead of guessed.
- **Idempotent duplicate handling**: an exact re-delivery returns the preserved original
  canonical alert with its original `alert_id` (`200`, `duplicate: true`) — ARCHITECTURE
  §16. Recurrence state is never modified by duplicate deliveries.
- **Configurable deduplication window** via `TRIAGE_DEDUPE_WINDOW_SECONDS` (default 900 s,
  documented in `.env.example`), implemented as a sliding window over group `last_seen`.
- Three distinguishable outcomes surfaced as `dedupe_status`: `new_generation`,
  `exact_duplicate`, `repeated` — plus recurrence tracking (`occurrences`, `first_seen`,
  `last_seen`, `generation`, `duplicate_deliveries`, `event_identity`) on
  `CanonicalDedupe` for later risk scoring.
- **Evidence preservation**: duplicate deliveries are counted and logged (including a
  warned `content_variants` counter when a known identity arrives with divergent
  content); nothing is silently discarded, and no destructive actions exist.
- `Deduplicator` protocol keeps dedup logic separate from FastAPI routing;
  `InMemoryDeduplicator` is thread-safe (lock-serialized transitions) and covered by
  concurrency tests (exactly-once per identity under parallel delivery).
- Integration + unit test suites for the full dedup contract (first alert, exact
  duplicate, repeats, window expiry/boundary, agent/rule isolation, invalid identity
  inputs, concurrent/repeated delivery).
- `CHANGELOG.md` (this file).

### Changed — Phase 1C (breaking within Phase 1 pre-release)

- `POST /api/v1/alerts/ingest` now responds **`200` with `duplicate: true` and the
  original `alert_id`** for exact duplicate deliveries (previously every delivery
  created a fresh `alert_id` with `202`). New/recurring alerts still return `202`.
  The Phase 1B test asserting unique ids for identical deliveries was superseded by the
  idempotency contract.

## Phase 1B — Wazuh Alert Ingestion & Validation (merged 2026-08-30)

- Tolerant Wazuh 4.x Pydantic schemas (`ingest/schemas.py`) — unknown fields preserved.
- Pure normalizer `(WazuhAlert, received_at) → CanonicalAlert` (`ingest/normalizer.py`).
- Canonical alert model (`models/canonical.py`) with frozen `CanonicalAlert`.
- `POST /api/v1/alerts/ingest` wiring: API-key auth, 256 KiB body cap, JSON/schema
  validation errors via the shared error envelope; contract tests over all six sample
  fixtures.

## Phase 1A — FastAPI SOC Triage Foundation (merged 2026-08-30)

- Project scaffold (`pyproject.toml`, ruff + pytest + mypy config), `soc_triage` package.
- `core/`: pydantic-settings `Settings` (fails fast on placeholder secrets), structlog
  JSON logging, error envelope, health/ready endpoints, app factory.
- `ingest/auth.py`: constant-time `X-API-Key` verification.
