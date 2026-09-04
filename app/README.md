# app/ — Triage API (Python / FastAPI)

The core service: ingest → normalize → dedupe → enrich → score → decide → persist →
notify n8n. Full design: [ARCHITECTURE.md §12](../ARCHITECTURE.md#12-python-service-triage-api-architecture).

**Status: Phase 1E — ingestion, deduplication, persistent storage, audit, IOC
extraction & the enrichment interface implemented**
([DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md)). This includes
the application factory, `GET /health` and `GET /ready` (with database
liveness/migration checks), typed environment configuration, structured JSON
logging, the shared error envelope, Wazuh alert ingest/normalize
(`POST /api/v1/alerts/ingest`), deterministic deduplication & idempotency
(configurable window, preserved canonical alerts, recurrence tracking) with
**SQLite persistence** (normalized alerts, dedupe recurrence/generation
state, per-event idempotency records, append-only audit log), Alembic
migrations applied automatically at startup, and **IOC extraction with a
provider-based enrichment interface** (offline only — no external calls yet).
Scoring/decisioning/notifications are later Phase 1 work.

```
app/
├── src/soc_triage/
│   ├── main.py          # app factory + lifespan (DB bootstrap + migrations)
│   ├── api/             # HTTP routers — no business logic
│   ├── core/            # settings, structlog logging, auth, errors
│   ├── db/              # engine/session bootstrap, transactions, storage errors
│   ├── models/          # SQLAlchemy ORM + repositories + Pydantic schemas
│   ├── ingest/          # Wazuh normalizer, dedupe (in-memory + persistent), guards
│   ├── enrichment/      # IOC extraction, FP policy, provider interface, chain
│   ├── scoring/         # deterministic scoring engine (pure, zero I/O)
│   ├── decisions/       # decision matrix + routing
│   ├── audit.py         # append-only audit policy + entries
│   └── notifications/   # n8n webhook client (outbound only)
├── alembic/             # migrations (initial: 9ec2a1b4b3bf)
├── config/              # scoring.yaml, decisions.yaml, allowlists.yaml (Phase 1+)
└── tests/
    ├── unit/            # golden-file scoring tests, normalizer tests
    ├── integration/     # FastAPI TestClient + temp SQLite
    └── fixtures/        # links/copies of docs/sample-alerts payloads
```

## Database (Phase 1D)

The database URL comes from `TRIAGE_DB_URL` (default
`sqlite:////data/soc_triage.db`; PostgreSQL works with the same URL shape and
identical migrations). The service creates the parent directory and applies
Alembic migrations automatically at startup — a fresh checkout just runs.
Manual migration management (run from this directory, with the app installed
and `TRIAGE_DB_URL` exported):

```bash
alembic upgrade head
alembic downgrade base   # reproducible; safe on a scratch database
alembic check            # no drift between ORM models and schema
```

## IOC extraction & enrichment (Phase 1E)

Extraction is a **pure function** — `(CanonicalAlert, policy) → [IOC]` — with no
I/O, clock, logging or randomness, so the same alert always yields the same
ordered indicator list. Supported types: `ipv4`, `domain`, `url`, `md5`,
`sha1`, `sha256`, `email`.

```python
from soc_triage.enrichment import extract_iocs, EnrichmentChain, NoOpEnrichmentProvider

iocs = extract_iocs(canonical_alert)
# IOC(type=<IOCType.IPV4: 'ipv4'>, value='203.0.113.50',
#     provenance=(IOCProvenance(field='source_event.data.srcip',
#                               extractor='typed_field', raw_value='203.0.113.50',
#                               offset=None, location='/var/log/auth.log'),),
#     enrichment={})

outcome = EnrichmentChain([NoOpEnrichmentProvider()]).enrich(iocs)
outcome.status  # 'skipped' — the offline provider is disabled by default
```

Every indicator keeps its **provenance**: the canonical field path it came
from, the alert's source location, the character offset and raw substring for
text scans, and which strategy found it. Identical `(type, value)` pairs
collapse into one indicator with merged provenance.

False positives are policy-driven (`soc_triage.enrichment.policy`):

| Control | Default | Why |
| --- | --- | --- |
| `include_private_ipv4` | `False` | RFC 1918 / loopback / link-local / CGNAT describe the lab's own estate |
| `include_documentation_ipv4` | `True` | the synthetic corpus uses RFC 5737 ranges (SECURITY.md §5) |
| `include_full_log` | `False` | ARCHITECTURE §7.1 — extract from fields, not arbitrary log text |
| `include_location` | `False` | `location` is a source descriptor, not evidence |
| `max_iocs` | `200` | bounded responses and bounded future quota usage |

**Adding a provider (Phase 2)** — implement the `EnrichmentProvider` protocol;
no other change is needed, and the chain stays fail-open:

```python
class MyProvider:
    name = "my-intel"  # key under which payloads are stored
    enabled = bool(API_KEY)  # disable-by-empty (ARCHITECTURE §14)

    def enrich(self, iocs, *, context):
        return ProviderEnrichment(provider=self.name, status=..., results={...})
```

Phase 2A adds two real, optional threat-intel providers behind the same
contract — `VirusTotalProvider` and `MISPProvider` (both **disabled by
default**; an empty `VIRUSTOTAL_API_KEY` / `MISP_URL`+`MISP_API_KEY` means the
chain skips them). With no key configured the chain registers only the offline
`NoOpEnrichmentProvider` (disabled), so every ingest reports
`enrichment_status: skipped` and performs zero external calls. Configured
providers attach sanitized per-indicator provenance
(`provider`, `indicator_type`, `lookup_status`, `timestamp`, `result`) and
never leak API keys or block the pipeline on failure.

> **VirusTotal licensing.** The free VirusTotal **Public API** is licensed for
> lab / non-commercial use only — see the VirusTotal support site's Public API
> terms. Do not point it at production or commercial workloads; use a
> licensed/premium key for those. This is documented in `.env.example` as well.

### Credential-bearing URL sanitization (Phase 2A hardening)

A URL such as `https://analyst:SuperSecret123@example.com/login` carries
credentials in its userinfo. Extraction **never persists them**:

- the canonical `value` is normalized (`normalize_url` drops userinfo);
- `IOCProvenance.raw_value` stores the *sanitized* URL (not the raw match) for
  both typed URL fields (`data.url`, `data.virustotal.permalink`) and
  text-scanned URLs;
- the URL's userinfo is never re-extracted as an email or domain indicator
  (`pass@host` inside `user:pass@host` is not an email);
- the typed URL fields in the persisted canonical payload are userinfo-stripped
  (`strip_url_userinfo`), so the credential never reaches `normalized_payload`,
  the API response, audit records, or logs.

Free-text fields and `full_log` remain raw by design (SECURITY.md §5 — the
platform keeps what Wazuh already logged).

## Metrics & observability (Phase 3.7)

The API exposes an optional Prometheus read-only surface:

- **`GET /metrics`** — Prometheus text exposition
  (`text/plain; version=0.0.4; charset=utf-8`), same origin as `/health`, hidden from
  OpenAPI. Mounted **only** when `METRICS_ENABLED=true` (default `1`); with
  `METRICS_ENABLED=false` the route does not exist (404) and nothing is recorded.
- **Optional bearer auth** — `METRICS_SCRAPE_TOKEN`. Empty (default) = authentication
  disabled; when set, the scraper must send `Authorization: Bearer <token>` (constant-time
  compare, token never logged). Dedicated token only: the ingest API key and N8N tokens
  are never accepted.
- **App-scoped registry** — `core/metrics.py` owns one
  `prometheus_client.CollectorRegistry` per application instance; the process-global
  `REGISTRY` is never used, so instances and tests cannot leak metrics into each other.
- **Bounded catalog** — 17 `soc_triage_*` families (HTTP requests/duration, ingest
  rejections/outcomes/duration, scoring/decision, enrichment status + provider outcomes,
  n8n notifications/duration, feedback, incident transitions/auto-close, sweeper passes,
  `up`/`database_up`/`migrations_applied`). All labels come from fixed enums or route
  templates — never alert content, ids, IOCs, hosts, or free text; no DB aggregate
  gauges in Phase 3.7. See
  [docs/specs/phase-3.7-prometheus-observability.md](../docs/specs/phase-3.7-prometheus-observability.md)
  and [ARCHITECTURE.md §15](../ARCHITECTURE.md#15-logging-audit--observability).
- **Non-load-bearing** (ADR-9) — recording/render failures are swallowed (logged by type
  only) and can never raise into the pipeline, write to the database, call external
  services, or change a score, decision, response, or audit row. A failing render
  returns an empty 200 exposition, never an error.
- The `observability` Docker profile (Prometheus + Grafana) is optional and additive —
  see [deploy/README.md](../deploy/README.md).

## Run & test (Phase 1A)

```bash
cd app
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# run the API (reads .env.example / real env vars; defaults are development-safe)
uvicorn soc_triage.main:app --host 0.0.0.0 --port 8000

# check endpoints
curl http://localhost:8000/health
curl http://localhost:8000/ready
curl http://localhost:8000/metrics   # Phase 3.7 (404 route if METRICS_ENABLED=false)

# test + lint + type hints
pytest
ruff check .
ruff format --check .
mypy src
```

Production/test environments must replace `change-me-*` secrets (see
[.env.example](../.env.example)); the app fails fast on placeholders outside
`SOC_ENV=development`.

Layering rules and dependency direction are enforced in review — see ARCHITECTURE.md §12.
