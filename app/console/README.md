# SOC Triage Console (Phase 3.5)

A lightweight, **static** analyst console for the lab. No frontend framework, no
build step, no new container. It is served by the same FastAPI service that
exposes the API.

## Location

```
app/console/
  index.html        # app shell (token bar, nav, content host, toasts)
  styles.css        # dense, dark SOC theme
  console-core.js    # pure helpers (UMD): escaping, state machine, score-factor
                     #   projection, query-string/pagination — no DOM, no secrets
  console.js         # app logic: API client, hash router, safe DOM rendering
```

Served at `http://localhost:8000/console/` (mounted in `soc_triage/main.py`
via `StaticFiles`). The repo root `/` redirects to `/console/`.

## How to run it

With the existing Docker lab:

```bash
docker compose up -d --build
# open http://localhost:8000/console/
```

Or locally against a running `triage-api` (any origin sharing `triage-api`'s
host:port):

```bash
uvicorn soc_triage.main:create_app --host 0.0.0.0 --port 8000
# open http://localhost:8000/console/
```

## API dependency

The console only calls existing, already-authenticated endpoints (no new
backend code beyond the static mount):

| View | Endpoint |
| --- | --- |
| Alert Queue | `GET /api/v1/alerts` (pagination + `tier`/`severity`/`source`/`duplicate` filters) |
| Alert Detail | `GET /api/v1/alerts/{alert_id}` |
| Incident Board | `GET /api/v1/incidents` (`status`/`severity` filters) |
| Incident Detail | `GET /api/v1/incidents/{incident_id}` |
| Incident Timeline | `GET /api/v1/incidents/{incident_id}/timeline` |
| Lifecycle action | `PATCH /api/v1/incidents/{incident_id}/status` |

It **never recomputes a risk score** — the score + factor breakdown come
straight from the server's `risk.factors`.

## Authentication expectation

Enter the **shared N8N callback token** (`N8N_CALLBACK_TOKEN`, the same token
the n8n workflows use) into the top bar. It is kept **in browser memory only**
for the session — it is *not* persisted to `localStorage`/`sessionStorage`, never
hardcoded, and never embedded in these files. Every API call sends it as the
`X-N8N-Token` header.

If you reload the page, the token is cleared from memory and you are asked to
re-enter it (this is intentional — it keeps credentials out of browser storage).

> **Limitation (documented, not weakened):** a dedicated analyst/read token is
> deferred (ARCHITECTURE.md §19/§21). The console reuses the shared n8n token
> rather than introducing a new authentication system or relaxing backend
> authorization. If the token is unset or invalid, every view shows an
> "auth required" state instead of data.

## Current limitations

* Same-origin only by default. Serving the console from a different origin than
  `triage-api` requires server-side CORS (`TRIAGE_CORS_ORIGINS`); the lab
  default keeps it same-origin so no CORS is needed.
* The incident status machine in `console-core.js` is a *read-only mirror* of
  the backend's `VALID_TRANSITIONS`. The UI shows only legal transitions for the
  current status; if the backend ever adds a status the UI does not know, the UI
  shows no transition buttons (it never invents one) and the backend remains the
  authority.
* The console is read + lifecycle only. It does **not** expose the auto-close
  sweeper; it only displays the result of sweeper runs.
* No server-side full-log or secret fields are rendered — the API already
  redacts them, and the UI only requests the analyst-safe read models.

## Security / XSS

All alert/incident/timeline text is rendered via DOM `textContent` (or the
`escapeHtml` helper), so attacker/analyst-controlled strings (e.g. a malicious
`rule.description` or `agent.name`) cannot execute as HTML/JS. No untrusted
string is ever injected with `innerHTML`.

## Testing

* Python: `tests/integration/test_console.py` (static serving, endpoints
  referenced, in-memory token, no embedded secrets, API contract the console
  depends on).
* Node (no browser stack): `app/tests/js/console_core.test.cjs` — run with
  `node --test app/tests/js/console_core.test.cjs`.
