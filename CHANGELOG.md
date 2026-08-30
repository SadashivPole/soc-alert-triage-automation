# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
semantic (`v0.1.0` targeted at the end of Phase 1).

## [Unreleased]

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
