# Phase 4.7 — soak runbook (performance integrity vs. live 10k/day execution)

This document is the source of truth for how Phase 4.7 soak evidence is produced,
read, and **not** misrepresented. It supersedes any casual reading of the harness
output and is referenced from `scripts/README.md`, `README.md`, and
`DEVELOPMENT_PLAN.md`.

## 1. What exists

| Artifact | Kind | Where it runs | Status |
| --- | --- | --- | --- |
| `scripts/phase47_soak.py` | Wall-clock soak harness (subprocess `curl.exe`) | Windows/Docker **operator** machine | ✅ authored; **not executed in this repository's validation run** |
| `app/tests/integration/test_phase47_soak_integrity.py` | CI-runnable integrity tests (in-process `TestClient`, temp SQLite) | Linux CI (`pytest`) | ✅ implemented · locally validated (5 tests) |

The two are **complementary**, not interchangeable:

- The **harness** measures *wall-clock* throughput and latency of a real HTTP
  service from a real client — the eventual 10k/day figure can only come from it.
- The **integrity tests** demonstrate, deterministically and repeatably in CI,
  that the ingest + dedup + persistence contracts the harness *depends on* are
  actually correct (distinct identities stay distinct; exact re-delivery is
  idempotent; counters prove dedup). They must keep passing for any operator
  soak result to be believable.

## 2. The existing `scripts/phase47_soak.py` — exact semantics

Read `scripts/README.md` for the CLI surface. The contract points that matter for
interpreting its output:

- **It mutates only `payload["id"]`** (`make_payload` sets
  `payload["id"] = f"phase47-{run_id}-{sequence:08d}"`), leaving `rule.id`,
  `agent.id`, and everything else byte-identical to the fixture
  (`01_wazuh_ssh_brute_force.json`).
- The dedupe group is `rule.id + agent.id`
  (`app/src/soc_triage/ingest/deduplication.py`), and event identity for a
  Wazuh-`id` payload is `wazuh:{id}:{rule_id}:{agent_id}`. Because only `id`
  changes, **every request is a *distinct event inside one dedupe group***
  (`wazuh:5710:001`).
- Consequence: a `--count N` run does **not** model "N independent alerts/day".
  It models an **acute recurrence/burst** — N distinct events of one rule firing
  on one agent within the dedupe window. The scoring recurrence factors
  (`rapid_burst`, `rising_burst`, `sustained_volume` in `app/config/scoring.yaml`)
  are what escalate, exactly as they would for a real burst.
- Wall-clock latency includes the full `curl.exe` HTTP round-trip plus the
  server's normalize → extract → enrich → dedupe → score → decide → persist path.
- The printed `10k alerts/day average arrival rate: 0.116 alerts/s` is the
  arithmetic `10_000 / 86_400` — **information only, not a target and not an
  SLA**.

This burst-oriented behavior is **not a bug**: the harness was authored (and
protected) that way. Do not "fix" it by editing the harness — instead, the
integrity tests provide the distinct-identity spread, and any future operator
soak that must model independent identities should be a *separate, new* tool
(subject to the same protected-file rules: `scripts/phase47_soak.py` stays
byte-for-byte).

## 3. The CI-runnable integrity test — what it proves

`app/tests/integration/test_phase47_soak_integrity.py` drives the **real**
`POST /api/v1/alerts/ingest` application path (the same pipeline the service
runs: normalize → IOC extraction → enrichment chain → dedupe → score → decide →
persist) through FastAPI `TestClient` with a temporary SQLite database. Five
tests demonstrate the integrity contract:

1. **Distinct-identity spread** — 16 payloads spread across different
   `rule.id`/`agent.id` are accepted (202), each yields its own `alert_id`, its
   own alert row, and its own event identity. No collapse into one group.
2. **Idempotent re-delivery** — an exact re-delivery returns HTTP 200 with
   `duplicate: true`, `dedupe_status: exact_duplicate`, and the original
   `alert_id`; alert-row count is unchanged.
3. **Counters prove dedup** — after one delivery + one re-delivery per identity,
   each group shows `occurrences == 1` and `duplicate_deliveries == 1`, and each
   `alert_events` row has `delivery_count == 2`. Dedup is demonstrated from the
   database, not inferred from response codes.
4. **Recurrence, not rows** — three *distinct event ids* inside one group (the
   harness-style `id`-only pattern) create three alert rows but a single group
   whose `occurrences` reaches 3.
5. **Bounded wall-clock guard** — a coarse CI stability assertion (spread ingest
   under 30 s; expected in the hundreds of milliseconds) that catches
   pathological stalls. Throughput is printed as
   `[diagnostic, NOT a benchmark]` and is **never asserted as an SLA**.

## 4. Integrity vs. live 10k/day execution — the difference

| Dimension | Integrity tests (this repo, CI) | Operator 10k/day run |
| --- | --- | --- |
| What it measures | Correctness of ingest/dedup/persistence under an identity spread + re-deliveries | Sustained wall-clock throughput/latency of a real stack |
| Environment | Linux CI, in-process TestClient, temp SQLite | Windows/Docker Desktop, real `triage-api` (+ n8n/Mailpit as configured) |
| Input shape | Fixed 16-identity spread (deterministic) | `--count 10000` burst around one identity (or a future spread tool) |
| Output | Pass/fail assertions; diagnostic throughput line labeled "NOT a benchmark" | `=== Results ===` throughput, p50/p95/p99 latency, status counts |
| Claims allowed | "ingest integrity verified in CI" | "measured 10k/day …" — **only after an actual successful run**, and never as an SLA/benchmark unless an SLA was separately defined and met |

## 5. Operator execution environment (the harness)

- **Host:** a Windows machine with **Docker Desktop** and the repository's
  `triage-api` reachable (default target `http://127.0.0.1:8000`).
- **`curl.exe`:** the harness shells out to `curl.exe` explicitly (Windows
  ships it; a POSIX `curl` is not a substitute unless provided *as* `curl.exe`
  on `PATH`). No other runtime dependencies beyond a Python ≥ 3.11.
- **Credentials:** `--api-key <TRIAGE_INGEST_API_KEY>` must match the running
  instance's `TRIAGE_INGEST_API_KEY` (`.env`); the key is never committed.
- **Preconditions:** `triage-api` healthy (`/health`); decide up front whether
  n8n/Mailpit are running (they add notification latency per alert), and record
  which was the case in the evidence fields below.
- **Compose:** the soak targets the existing `triage-api` service; no TheHive /
  MISP / PostgreSQL profile is required, and none is claimed by a soak run.

### Suggested operator command (10k/day shape)

```powershell
# Burst-oriented (harness semantics): 10k requests, one identity, wall-clock measured.
python scripts/phase47_soak.py --api-key <TRIAGE_INGEST_API_KEY> --count 10000 --timeout 30
```

Record the printed `=== Results ===` block verbatim into the evidence template.

## 6. Acceptance / evidence fields

An operator soak result is **not** automatically "SLA-passing". An acceptance
record must contain at least:

- **Operator / date (UTC) / host class** — who ran it, when, on what
  (Windows/Docker Desktop, resources available).
- **Stack under test** — `triage-api` image/version, `TRIAGE_DB_URL` backend
  (SQLite or the optional `postgres` profile), n8n/Mailpit on/off, enrichment
  providers on/off.
- **Harness invocation** — exact `--count`, `--timeout`, `--base-url`.
- **Raw results block** — the harness's `=== Results ===` output (request/status
  counts, total time, throughput, mean/p50/p95/p99/max).
- **Integrity gate** — confirmation `app/tests/integration/test_phase47_soak_integrity.py`
  passes before accepting the run (see §3).
- **Whether the run is read as** *(a)* burst/recurrence evidence (it is, by
  harness semantics) or *(b)* independent-identity throughput (only if a
  distinct-identity spread tool was used — not yet authored).
- **Failures** — any non-202 statuses or transport errors, with the harness's
  first-ten failure lines.

## 7. Results template

```text
Phase 4.7 soak — evidence record
run_id:                 <run_id printed by the harness>
operator:               <name/role>
date_utc:               <YYYY-MM-DD HH:MM UTC>
host:                   <Windows/Docker Desktop, CPU/RAM note>

stack:
  triage_api:           <image/tag or local build; TRIAGE_DB_URL backend>
  notifications:        <n8n/Mailpit on|off>
  enrichment:           <providers on|off>
  profiles:             <none | postgres | ...>

invocation:
  command:              python scripts/phase47_soak.py --api-key *** --count 10000 --timeout 30
  base_url:             <http://127.0.0.1:8000 or override>

integrity_gate:         <pytest tests/integration/test_phase47_soak_integrity.py => N passed>

<PASTE THE HARNESS "=== Results ===" BLOCK VERBATIM HERE>

interpretation:
  workload:             <burst/recurrence (harness default) | independent-identity spread (only if a spread tool was used)>
  sla_claim:            <none | only if an SLA was defined and this run demonstrably met it>
  notes:                <...>
```

## 8. Truth rules (binding)

1. **The 10k live soak has NOT been executed unless an actual operator run was
   completed and recorded.** No evidence record ⇒ no claim anywhere.
2. **Printed throughput is never an SLA and never a benchmark.** The harness and
   the integrity tests both label throughput "not a benchmark"; any report that
   quotes a number must carry that label and the workload caveat (§2).
3. **The burst caveat is mandatory** in any description of harness output: the
   harness exercises an acute recurrence/burst pattern around one identity, not
   a spread of independent identities.
4. **No Docker/live TheHive/MISP/PostgreSQL validation may be claimed** from any
   Phase 4.7 artifact. Those remain operator-side and separately documented.
5. **`scripts/phase47_soak.py` is protected** — byte-for-byte. New soak
   capability (e.g. an identity-spread driver) must go in a new file, never in
   the harness.
