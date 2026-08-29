# app/ — Triage API (Python / FastAPI)

The core service: ingest → normalize → dedupe → enrich → score → decide → persist →
notify n8n. Full design: [ARCHITECTURE.md §12](../ARCHITECTURE.md#12-python-service-triage-api-architecture).

**Status: scaffolded — implementation begins in Phase 1** ([DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md)).

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

Layering rules and dependency direction are enforced in review — see ARCHITECTURE.md §12.
