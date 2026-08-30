# app/ — Triage API (Python / FastAPI)

The core service: ingest → normalize → dedupe → enrich → score → decide → persist →
notify n8n. Full design: [ARCHITECTURE.md §12](../ARCHITECTURE.md#12-python-service-triage-api-architecture).

**Status: Phase 1C — ingestion, validation & deduplication implemented**
([DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md)). This includes the application
factory, `GET /health` and `GET /ready`, typed environment configuration,
structured JSON logging, the shared error envelope, Wazuh alert
ingest/normalize (`POST /api/v1/alerts/ingest`), and deterministic
deduplication & idempotency (configurable window, preserved canonical alerts,
recurrence tracking). Scoring/enrichment/notifications are later Phase 1 work.

```
app/
├── src/soc_triage/
│   ├── main.py          # app factory + lifespan (Phase 1)
│   ├── api/             # HTTP routers — no business logic
│   ├── core/            # settings, structlog logging, auth, errors
│   ├── models/          # SQLAlchemy ORM + Pydantic schemas
│   ├── ingest/          # Wazuh normalizer, dedupe, request guards
│   ├── enrichment/      # IOC extractor, VT/MISP clients, allowlist, cache
│   ├── scoring/         # deterministic scoring engine (pure, zero I/O)
│   ├── decisions/       # decision matrix + routing
│   └── notifications/   # n8n webhook client (outbound only)
├── config/              # scoring.yaml, decisions.yaml, allowlists.yaml (Phase 1+)
└── tests/
    ├── unit/            # golden-file scoring tests, normalizer tests
    ├── integration/     # FastAPI TestClient + temp SQLite
    └── fixtures/        # links/copies of docs/sample-alerts payloads
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
