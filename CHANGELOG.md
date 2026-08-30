# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
semantic (`v0.1.0` targeted at the end of Phase 1).

## [Unreleased]

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
