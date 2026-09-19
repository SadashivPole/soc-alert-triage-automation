# scripts/ — Repo & Dev Utilities

Small helper scripts for repository hygiene, development, and optional lab
validation. Everything here must be safe to run and defensive-only (see
[SECURITY.md](../SECURITY.md)).

| Script | Purpose | Status |
| --- | --- | --- |
| `check_secrets.sh` | Scan git-tracked files for common credential patterns (API keys, tokens, private keys) and verify `.env` hygiene. Runs in CI from Phase 1. | ✅ available |
| `n8n-import-workflows.sh` | Import the exported n8n workflows (`n8n/workflows/*.json`) via the n8n API. | ✅ available |
| `phase47_soak.py` | Phase 4.7 performance-soak harness: replays synthetic alerts at the ingest endpoint (single identity ⇒ acute recurrence/burst shape) and reports throughput/latency. | ✅ authored · **not executed in this repository's validation run** |
| `app/tests/integration/test_phase47_soak_integrity.py` | Phase 4.7 CI-runnable integrity tests: distinct synthetic identities through the real ingest path prove dedup/idempotency. | ✅ implemented · locally validated (5 tests) |
| `send_test_alert` | Replay synthetic alerts from `docs/sample-alerts/` into the ingest endpoint (with `--repeat` for dedupe demos). | ⬜ not implemented (Phase 1 backlog item only) |

Run the hygiene check any time:

```bash
bash scripts/check_secrets.sh
```

---

## `phase47_soak.py` — Phase 4.7 performance soak harness (authored, not executed)

**Purpose.** A deterministic, self-contained soak harness that generates synthetic
alerts (each derived from the `app/tests/fixtures/01_wazuh_ssh_brute_force.json`
fixture, with a per-run unique `phase47-<run_id>-<sequence>` id) and POSTs them,
one at a time, to `POST /api/v1/alerts/ingest`. It expects **HTTP 202** per
request and reports:

- total requests, successful 202s, and a status-count breakdown;
- total wall-clock time and throughput (alerts/s);
- mean, median (p50), p95, p99, and max latency (ms);
- the 10k-alerts/day **average arrival-rate reference**: `10000 / 86400 ≈ 0.116
  alerts/s` (printed as information only — it is not an SLA assertion).

**Workload shape (accurate labeling).** The harness mutates only `payload["id"]`
(rule/agent stay on the fixture's single identity `5710`/`001`). Because the
dedupe group is `rule.id + agent.id`, every request is a *distinct event inside
one group* — so a `--count N` run exercises an **acute recurrence/burst** around
one rule→agent identity, **not** N independent alerts. Throughput/latency are
real wall-clock numbers, but they describe a burst workload until an operator
uses a distinct-identity driver (not yet authored). See
[`docs/specs/phase-4.7-soak-runbook.md`](../docs/specs/phase-4.7-soak-runbook.md)
for the full interpretation rules, the integrity-vs-live distinction, and the
evidence template.

**Usage.**

```bash
# From the repository root; requires a platform .env/secret with a real ingest key.
python scripts/phase47_soak.py --api-key <TRIAGE_INGEST_API_KEY>
```

**Arguments and defaults (verbatim from the harness).**

| Argument | Default | Meaning |
| --- | --- | --- |
| `--base-url` | `http://127.0.0.1:8000` | Triage API base URL; the harness posts to `<base-url>/api/v1/alerts/ingest` |
| `--api-key` | *(required)* | `X-API-Key` header value for ingest auth |
| `--count` | `100` | Number of unique synthetic alerts to send |
| `--timeout` | `30.0` | Per-request `--max-time`/`--connect-timeout` seconds (plus a hard subprocess deadline of `timeout + 2.0s`) |
| `--progress` | `25` | Print a progress line every N requests (and always the first and last) |

Validation: `--count` must be ≥ 1, `--timeout` > 0, `--progress` ≥ 1.

**Transport dependency — Windows `curl.exe`.** The harness shells out to
`curl.exe` (not an in-process HTTP client) with `--max-time`, `--connect-timeout`,
`--max-time`, `--data-binary`, and `--write-out "…%{http_code}"` to enforce a hard
wall-clock deadline per request. On Windows, `curl.exe` is the OS-supplied binary and
resolves from `PATH`. On non-Windows hosts, no `curl.exe` exists by default — the
harness is a Windows-lab utility, so **run it on Windows (Docker Desktop host), or
otherwise provide a `curl.exe` on `PATH` before running**. A subprocess-level hard
timeout is used so an unresponsive API cannot stall the harness past
`timeout + 2.0` seconds.

**Exit behavior.** Exits `0` when every replay returns HTTP 202; exits `1` when any
request returned a non-202 status or a transport error (first ten failures are
printed).

**Status (truthful).** The harness is **authored and preserved byte-for-byte**, and
its invocation surface is documented here, but **the soak was not executed in this
repository's validation run** — no throughput, latency, or 10k/day figure is claimed
anywhere. Running it against a live `triage-api` (and reading the results per the
runbook) is operator-side work.

## Phase 4.7 integrity tests (`app/tests/integration/test_phase47_soak_integrity.py`)

The CI-runnable complement to the harness: it drives the **real**
`POST /api/v1/alerts/ingest` path in-process with a temporary SQLite database and
proves the contracts the soak depends on — a distinct identity spread (varied
`rule.id`/`agent.id`) stays distinct and accepted; an exact re-delivery returns
HTTP 200 with `duplicate: true` and the original `alert_id`; database dedupe
counters (`occurrences`/`duplicate_deliveries`/`delivery_count`) demonstrate the
absorption; an `id`-only repeat (the harness shape) increments occurrences rather
than collapsing. Throughput is printed as `[diagnostic, NOT a benchmark]` and is
never asserted. Run with the suite:

```bash
cd app && pytest tests/integration/test_phase47_soak_integrity.py -v
```

The difference between this (integrity) and the harness (live wall-clock 10k/day)
is spelled out in [`docs/specs/phase-4.7-soak-runbook.md`](../docs/specs/phase-4.7-soak-runbook.md).
