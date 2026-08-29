# n8n/ — Workflow Orchestration

n8n owns everything that happens *after* the Triage API decides: notification fan-out,
SLA escalation timers, incident creation, the analyst feedback form, and the daily
digest. Design: [ARCHITECTURE.md §11](../ARCHITECTURE.md#11-n8n-workflow-architecture).

**Status: scaffolded — workflow JSONs land with Phases 1–3.**

```
n8n/
└── workflows/           # exported workflow JSON (WF1–WF6), one file per workflow
```

## Conventions

- One concern per workflow; sub-workflows invoked by the router (WF1).
- **No secrets in exported JSON** — only credential references. Real credentials live in
  n8n's encrypted credential store (`N8N_ENCRYPTION_KEY`). See [SECURITY.md §2](../SECURITY.md#2-secrets-management).
- Exported files are named `WF<number>_<name>.json` and must be re-exported on change
  (the n8n UI is not the source of truth — this directory is).
- An import guide + screenshots land here in Phase 1 alongside WF1/WF2.
