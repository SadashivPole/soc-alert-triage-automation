# n8n/ — Workflow Orchestration

n8n owns everything that happens *after* the Triage API decides: notification fan-out,
SLA escalation timers, incident creation, the analyst feedback form, and the daily
digest. Design: [ARCHITECTURE.md §11](../ARCHITECTURE.md#11-n8n-workflow-architecture).

**Phase 2B — Implemented (FIXED):**
- WF1_soc-triage-router: webhook `/webhook/soc-alert-scored`, **real shared-secret validation** against `$env.N8N_CALLBACK_TOKEN` / `$env.N8N_WEBHOOK_TOKEN` (exact match, reject missing/wrong, accept exact, never log token, never place secret in JSON), payload schema validation (no full_log), severity-based routing. No secrets, no destructive, no autonomous, fail-open.
- WF2_soc-analyst-notify: L1 notification (email via SMTP credential ref + optional chat webhook), structured payload with alert_id, severity, score, decision, rule info, recurrence, IOC summary, enrichment summary, investigation links. Real token validation, summary-only (no full_log). **contain_requested creates an approval-required request; no containment action is executed.**
- WF3_soc-incident-escalation: high-severity escalation (urgent email+chat, SLA timer 15m, **ack check via GET /api/v1/alerts/{id}/feedback/status read-only** returning acknowledged bool, has_feedback, latest_verdict, feedback_count, acknowledged_at, NOT POST misuse), L2 escalation if not acknowledged, **endpoint failure → fail-safe L2 escalation (safe documented behavior)**. Real token validation, no secrets, no autonomous containment. **contain_requested creates an approval-required request; no containment action is executed.**
- WF5_soc-analyst-feedback: **valid n8n Form workflow (Phase 2E fix)** — `n8n Form Trigger` at `/form/soc-analyst-feedback-form` (page 1: Alert ID + Analyst Email) → `Form - Feedback` next-form-page (page 2: verdict allow-list dropdown + notes) → form validation (allow-list, no full_log) → POST `/api/v1/alerts/{id}/feedback` with shared token; the machine entry `POST /webhook/soc-analyst-feedback` keeps the Phase 2B token gate and feeds the same POST node. Verdict allow-list validation, **contain_requested creates an approval-required request; no containment action is executed (no host isolation, no user disable, no autonomous).** Real token validation (exact match, reject missing/wrong, never log).

```
n8n/
└── workflows/           # exported workflow JSON (WF1–WF6), one file per workflow
    ├── WF1_soc-triage-router.json
    ├── WF2_soc-analyst-notify.json
    ├── WF3_soc-incident-escalation.json
    └── WF5_soc-analyst-feedback.json
```

## Conventions

- One concern per workflow; sub-workflows invoked by the router (WF1).
- **No secrets in exported JSON** — only credential references. Real credentials live in
  n8n's encrypted credential store (`N8N_ENCRYPTION_KEY`). See [SECURITY.md §2](../SECURITY.md#2-secrets-management).
- Exported files are named `WF<number>_<name>.json` and must be re-exported on change
  (the n8n UI is not the source of truth — this directory is).
- **Security:** no full_log forwarding, no destructive actions, no autonomous containment, human approval required for response actions.
- **Resilience:** timeout, retry, fail-open — n8n failure never corrupts alert (triaged-api audits attempt/result).

## Phase 2B Integration Details

### Triage API → n8n (outbound)

- Env: `N8N_WEBHOOK_URL` (empty = disabled, fail-open), `N8N_WEBHOOK_TOKEN` (shared token, fallback to `N8N_CALLBACK_TOKEN`)
- Payload: structured, validated via Pydantic, contains alert_id, severity/risk tier, score, decision, rule info, recurrence, IOC summary, enrichment summary, investigation links
- Security: no full_log, no secrets, payload hash for dedup, host-only logging
- Resilience: timeout 3s default, max retries 3 with exponential backoff + jitter, retry on 429/5xx only, fail-open (alert always accepted)
- Duplicate prevention: exact duplicates never notify; repo check prevents re-notify same alert_id; audit entries `notification.attempt/delivered/failed/skipped/duplicate_suppressed`

### n8n → Triage API (inbound feedback + status)

- Endpoint: `POST /api/v1/alerts/{id}/feedback` requires shared token via `X-N8N-Token` / `X-Callback-Token` / `Authorization: Bearer` — real validation (exact match, constant-time compare in Python, reject missing/wrong, accept exact, fail-closed when not configured, never log token)
- Endpoint (FIXED): `GET /api/v1/alerts/{id}/feedback/status` read-only, returns `acknowledged` bool, `has_feedback`, `latest_verdict`, `feedback_count`, `acknowledged_at`, `checked_at` — used by WF3 after SLA wait (NOT POST misuse). If endpoint fails, WF3 fail-safe escalates to L2 (safe documented behavior).
- Validates verdict allow-list: true_positive, false_positive, benign, escalate, acknowledged, resolved, contain_requested — **contain_requested creates an approval-required request; no containment action is executed (no host isolation, no user disable, no autonomous containment)**
- Persists to `analyst_feedback` table + audit `feedback.received`
- Security regression tests: missing token→rejected, wrong token→rejected, correct token→accepted (Python + workflow JSON), acknowledged→no L2 escalation, not acknowledged→L2 escalation, endpoint failure→safe escalation

### Import Guide

#### Docker Compose (Phase 2C lab)

The Phase 2C sandbox did **not** execute the Docker/n8n/Mailpit runtime. This
section describes the configured startup behavior and is statically validated.

The compose service overrides the `n8nio/n8n:1.85.0` entrypoint with `/bin/sh -c`
so the import helper can run **before** `n8n start`. Do **not** pass `sh` as an
n8n CLI `command` argument — that image treats command tokens as n8n verbs and
fails with `command sh not found`.

`N8N_ENCRYPTION_KEY` must be set in `.env` and kept stable. It is **not**
hardcoded in compose. Changing the key while reusing the `n8n-data` volume
causes `Mismatching encryption keys`. This lab never deletes persistent n8n
data automatically; operators must create a fresh volume only if they
intentionally rotate the key.

The helper deterministically provisions the lab SMTP credential, then imports
and activates WF1, WF2, WF3 and WF5 from `n8n/workflows/`.

- **SMTP credential (Phase 2D):** every Send Email (`emailSend`) node in
  WF2/WF3/WF5 is bound to an n8n SMTP credential named **`SMTP Lab Mailpit`**
  (`n8n/credentials/smtp_lab_mailpit.json`). The file is a **top-level JSON
  array** — the format `n8n import:credentials` requires on n8n 1.85.0 — and
  carries the credential `id` `smtp-lab-mailpit`, which matches the id bound
  to every emailSend node. n8n refuses to execute an email node with no
  credential bound, so the helper imports the credential first
  (`n8n import:credentials`), rendering the connection details from the
  `SMTP_HOST`/`SMTP_PORT`/`SMTP_SECURE`/`SMTP_USER`/`SMTP_PASS` environment
  variables (lab defaults target Mailpit on `mailpit:1025` with no auth). No
  connection detail or password is hardcoded in the checked-in files; n8n
  encrypts the imported credential at rest.
- Workflow JSONs are mounted read-only at `/workflows`.
- The JSONs contain stable ids, so re-running startup updates the existing
  records rather than creating duplicates.
- The helper targets only the four canonical lab files; unrelated JSON files in
  the mount are not imported.
- Workflows are activated automatically before the n8n server starts (n8n's CLI
  currently deactivates imported workflows by default).

#### Manual import (when not using Docker Compose)

1. In n8n UI, go to Workflows → Import from File → select JSON from `n8n/workflows/`
2. Configure credentials:
   - SMTP: create an SMTP credential (lab: Mailpit host `mailpit`, port `1025`,
     no TLS, no auth) and name it exactly **`SMTP Lab Mailpit`** — that is the
     name bound to every Send Email node. Under Docker Compose this credential is
     provisioned automatically by the import helper (see above).
   - No secrets in JSON — only credential references
3. Set env vars in n8n container:
   - `N8N_CALLBACK_TOKEN`, `N8N_WEBHOOK_TOKEN` (shared token)
   - `N8N_WEBHOOK_BASE_URL` (e.g. http://n8n:5678)
   - `TRIAGE_API_BASE_URL` (e.g. http://triage-api:8000)
   - `SOC_FROM_EMAIL`, `SOC_L1_EMAIL`, `SOC_L2_EMAIL`, `SLACK_CHANNEL_L1`
4. Activate workflows: WF1, WF2, WF3, WF5 (order matters: router calls others via webhook)
5. Test: `./scripts/send_test_alert.py docs/sample-alerts/01_wazuh_ssh_brute_force.json` → check Mailpit UI at :8025 and audit_log

## Testing

- Unit: `pytest app/tests/unit/test_n8n_*.py`
- Integration: `pytest app/tests/integration/test_n8n_integration.py`
- Coverage: payload schema validation, successful delivery, timeout, HTTP error, retry, invalid token, n8n unavailable, duplicate prevention, secret leakage
