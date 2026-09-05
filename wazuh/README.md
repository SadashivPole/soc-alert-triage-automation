# wazuh/ — Wazuh Manager Integration

Configuration for the real Wazuh 4.x manager (compose profile `full`, Phase 4):
the `integrator` script that forwards manager alerts to the Triage API, plus the
custom rules/decoders that generate them. Design:
[ARCHITECTURE.md](../ARCHITECTURE.md#13-docker--deployment-architecture), ADR-6.

**Status: Phase 4.1 + 4.2 delivered** — the `full` profile and the
`custom-triage` integrator are implemented. Custom rules/decoders (4.3) and the
human-approved containment runbook (4.5) are still pending. The default `sim`
mode is unchanged: with the profile disabled the pipeline runs entirely on the
synthetic payloads in [docs/sample-alerts](../docs/sample-alerts/README.md), so
the zero-external fallback still holds.

```
wazuh/
├── config/
│   └── ossec.conf.integrator.xml   # <integration> fragment (no secrets)
├── integrator/
│   ├── custom-triage               # shell wrapper executed by integratord
│   └── custom-triage.py            # forwarder: filter → POST → buffer/retry
└── ruleset/                        # custom rules, decoders, syscheck policies (4.3)
```

## How the integration works

```
agent → wazuh-manager → integratord → custom-triage → POST /api/v1/alerts/ingest
                                            │
                                            └─ on transient failure → local spool → retried next invocation
```

1. `integratord` writes each matching alert to a temp JSON file and executes
   `custom-triage <alert_file> <api_key> <hook_url>`.
2. The wrapper execs `custom-triage.py` with the manager's Python.
3. The script **ignores the positional key/URL arguments** and reads all
   configuration from the environment (`ossec.conf` is world-readable inside the
   container, so a key there would be an at-rest secret).
4. It applies the forwarding filter (level + rule-id/group exclusions), POSTs the
   **unmodified** Wazuh alert JSON with the existing `X-API-Key` header, retries
   transient failures with jittered backoff, and buffers to a bounded local spool
   if the API is still unreachable. It always exits `0` — the manager is never
   blocked or crashed by triage-side problems.

## Configuration (environment only — never hardcoded)

All variables are documented in [`.env.example`](../.env.example) and injected by
the `full` compose profile.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRIAGE_API_BASE_URL` (or `TRIAGE_API_URL`) | `http://triage-api:8000` | API base; `/api/v1/alerts/ingest` is appended |
| `TRIAGE_INGEST_API_KEY` | *(required)* | Sent as `X-API-Key`; `change-me*` placeholders are rejected at startup |
| `WAZUH_INTEGRATOR_MIN_LEVEL` | `5` | Minimum Wazuh rule level forwarded |
| `WAZUH_INTEGRATOR_EXCLUDED_RULE_IDS` | *(empty)* | Comma-separated noise filter |
| `WAZUH_INTEGRATOR_EXCLUDED_GROUPS` | *(empty)* | Comma-separated rule-group filter |
| `WAZUH_INTEGRATOR_TIMEOUT_SECONDS` | `5` | Per-attempt HTTP timeout |
| `WAZUH_INTEGRATOR_MAX_ATTEMPTS` | `3` | Attempts before buffering |
| `WAZUH_INTEGRATOR_BACKOFF_SECONDS` | `0.5` | Base backoff (exponential + jitter) |
| `WAZUH_INTEGRATOR_SPOOL_DIR` | `/var/ossec/logs/triage-spool` | Local buffer directory (0700) |
| `WAZUH_INTEGRATOR_SPOOL_MAX_ENTRIES` | `1000` | Bound; overflow drops the **oldest** entries |
| `WAZUH_INTEGRATOR_SPOOL_MAX_AGE_SECONDS` | `604800` | Stale entries are pruned |
| `WAZUH_INTEGRATOR_SPOOL_FLUSH_BATCH` | `25` | Max backlog entries drained per invocation |
| `WAZUH_INTEGRATOR_VERIFY_TLS` | `1` | TLS verification for https ingest URLs |

### Buffering & retry semantics

* **Transient** (connection errors, timeouts, `408/429/5xx`) → retried in-process,
  then spooled and replayed at the start of the *next* invocation, oldest first.
* **Permanent** (`400/401/403/413/422`) → logged and dropped. Replaying a request
  the API will never accept would only grow the spool forever; fix the key or the
  payload instead.
* The spool is bounded by count **and** age so a long outage cannot fill the
  manager's disk. Flushing stops at the first transient failure so a still-down
  API is not hammered with the whole backlog.

## Lab setup — running the `full` profile

Prerequisites: the default stack already works in `sim` mode, and `.env` exists.

1. **Set the required variables** in `.env` (never commit it):

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"   # TRIAGE_INGEST_API_KEY
   ```

   ```dotenv
   TRIAGE_INGEST_API_KEY=<generated value>
   WAZUH_API_USERNAME=<lab admin user>
   WAZUH_API_PASSWORD=<long random value>
   ```

   The compose file uses `${VAR:?...}` for all three: a missing value fails the
   `up` immediately rather than silently starting with a default credential.

2. **Start the stack with the profile:**

   ```bash
   docker compose --profile full up -d
   docker compose --profile full ps
   docker compose logs -f wazuh-manager
   ```

   First start takes a few minutes (`start_period` is 120 s).

3. **Enable the integration.** The fragment in `wazuh/config/` is mounted to
   `/wazuh-config-mount/etc/ossec.conf.d/triage-integration.xml`. If your image
   revision does not auto-merge `ossec.conf.d`, append the `<integration>` block
   into `/var/ossec/etc/ossec.conf` and restart:

   ```bash
   docker compose exec wazuh-manager sh -lc \
     "cat /wazuh-config-mount/etc/ossec.conf.d/triage-integration.xml"
   docker compose exec wazuh-manager /var/ossec/bin/wazuh-control restart
   ```

4. **Link the integrator** into the manager's integrations directory (the repo
   copy is mounted read-only at `/var/ossec/integrations/triage`):

   ```bash
   docker compose exec wazuh-manager sh -lc \
     "ln -sf /var/ossec/integrations/triage/custom-triage /var/ossec/integrations/custom-triage"
   ```

5. **Verify** end to end — trigger a detection (below) and watch:

   ```bash
   docker compose exec wazuh-manager tail -f /var/ossec/logs/integrations.log
   curl -s -H "X-N8N-Token: $N8N_CALLBACK_TOKEN" http://localhost:8000/api/v1/alerts | head
   ```

## Connecting a Wazuh agent (lab)

Agents enroll over **1515/tcp** and report over **1514/tcp** (the only published
ports; the Wazuh API on 55000 stays internal to `soc-core`).

1. Install the agent on the lab host/VM following the
   [official Wazuh agent install docs](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html)
   for your platform, pinned to the **same 4.x minor** as the manager image.
2. Point it at the manager and enroll:

   ```bash
   sudo sed -i "s|<address>.*</address>|<address>$MANAGER_HOST</address>|" \
     /var/ossec/etc/ossec.conf
   sudo /var/ossec/bin/agent-auth -m "$MANAGER_HOST" -p 1515
   sudo systemctl restart wazuh-agent
   ```

   `MANAGER_HOST` is the Docker host running this stack. Enrollment passwords, if
   you enable them, belong in `.env` / the agent's own config — never in this repo.
3. Confirm registration:

   ```bash
   docker compose exec wazuh-manager /var/ossec/bin/agent_control -l
   ```
4. **Generate a test detection** (safe, non-destructive):

   ```bash
   # SSH brute force (rule 5710/5712) — from another lab host
   for i in $(seq 1 10); do ssh -o StrictHostKeyChecking=no baduser@$AGENT_IP true; done

   # FIM on a watched path (rule 550/554)
   sudo touch /etc/soc-lab-fim-test && sudo rm /etc/soc-lab-fim-test
   ```

   The alert should appear in `integrations.log`, then in `GET /api/v1/alerts`,
   and — if it scores high enough — as an incident with an analyst email in
   Mailpit.

### Troubleshooting

| Symptom | Check |
| --- | --- |
| Nothing in `integrations.log` | Is `custom-triage` symlinked and executable? Is the `<integration>` block merged? |
| `config_error` log lines | A required env var is missing or still a `change-me*` placeholder |
| `alert_rejected status=401` | `TRIAGE_INGEST_API_KEY` differs between the manager and the API |
| `alert_buffered` growing | API unreachable — check `docker compose ps triage-api`; entries replay automatically |
| Agent never appears | 1514/1515 blocked, or an agent/manager version mismatch |

## Security notes

* **No secrets in this directory.** Keys are environment-only; `ossec.conf`
  carries a marker string, not a value. `scripts/check_secrets.sh` covers these
  files and `app/tests/unit/test_wazuh_integrator.py` asserts it.
* **Existing auth contract preserved.** The integrator is just a client of the
  unchanged `X-API-Key` ingest endpoint; it adds no new auth path and cannot
  bypass one.
* **Nothing sensitive is logged.** Log lines carry rule id/level, agent id, HTTP
  status and attempt counts only — never the API key, never the alert body,
  never a URL with embedded credentials. The integrator emits **no Prometheus
  metrics**, so the metrics surface is unchanged.
* **Defensive scope.** Everything here is detection/forwarding configuration.
  The integrator spawns no processes and executes no commands; there is no
  active-response content. Containment remains an *analyst-approved proposal*
  (Phase 4.5, [SECURITY.md §1](../SECURITY.md#1-scope--charter-defensive-only)).
