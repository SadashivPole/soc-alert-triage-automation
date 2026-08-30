# app/ — Triage API (Python / FastAPI)

The core service: ingest → normalize → dedupe → enrich → score → decide → persist →
notify n8n. Full design: [ARCHITECTURE.md §12](../ARCHITECTURE.md#12-python-service-triage-api-architecture).

**Status: Phase 1D — ingestion, deduplication, persistent storage & audit
implemented** ([DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md)). This includes
the application factory, `GET /health` and `GET /ready` (with database
liveness/migration checks), typed environment configuration, structured JSON
logging, the shared error envelope, Wazuh alert ingest/normalize
(`POST /api/v1/alerts/ingest`), deterministic deduplication & idempotency
(configurable window, preserved canonical alerts, recurrence tracking) with
**SQLite persistence** (normalized alerts, dedupe recurrence/generation
state, per-event idempotency records, append-only audit log), and Alembic
migrations applied automatically at startup. Scoring/enrichment/notifications
are later Phase 1 work.

```
app/
├── src/soc_triage/
│   ├── main.py          # app factory + lifespan (DB bootstrap + migrations)
│   ├── api/             # HTTP routers — no business logic
│   ├── core/            # settings, structlog logging, auth, errors
│   ├── db/              # engine/session bootstrap, transactions, storage errors
│   ├── models/          # SQLAlchemy ORM + repositories + Pydantic schemas
│   ├── ingest/          # Wazuh normalizer, dedupe (in-memory + persistent), guards
│   ├── enrichment/      # IOC extractor, VT/MISP clients, allowlist, cache
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
