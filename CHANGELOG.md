# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
semantic (`v0.1.0` targeted at the end of Phase 1).

## [Unreleased]

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
