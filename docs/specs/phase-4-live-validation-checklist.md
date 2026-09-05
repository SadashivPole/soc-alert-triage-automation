# Phase 4.1/4.2 — live validation checklist

**Status: OUTSTANDING.** Every item below is **unverified**. The build
environment used for Phase 4.1/4.2 had no Docker daemon, no Docker CLI, and no
reachable container registry, so none of this could be executed. The wiring was
instead audited against the pinned `wazuh/wazuh-manager:4.9.2` image source and
the Wazuh 4.9.2 sources; that audit found and fixed three defects (see
CHANGELOG → *Fixed — Phase 4.1/4.2 wiring defects*), but **source review is not
a substitute for running it**.

Run this on a machine with Docker Desktop and record the result of each step.
Phase 4.4 acceptance requires §5 to pass with a real agent.

## 0. Preconditions

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # TRIAGE_INGEST_API_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"   # N8N_ENCRYPTION_KEY
```

Set in `.env`: `TRIAGE_INGEST_API_KEY`, `N8N_ENCRYPTION_KEY`,
`WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD`.

## 1. Compose validation

- [ ] `docker compose --profile full config` exits 0 and renders `wazuh-manager`
- [ ] `docker compose config` (no profile) does **not** include `wazuh-manager`
- [ ] Missing `TRIAGE_INGEST_API_KEY` makes `--profile full config` fail (`:?` guard)

## 2. Bring-up & health

- [ ] `docker compose --profile full up -d` succeeds
- [ ] `wazuh-manager` reaches `healthy` (allow ≥120 s `start_period`)
- [ ] `triage-api` still `healthy`; `n8n` / `mailpit` unaffected
- [ ] `docker compose ps` shows **no** host binding for `55000`
- [ ] `1514`/`1515` are reachable: `nc -vz localhost 1514`, `nc -vz localhost 1515`
- [ ] Default (`sim`) stack still works with the profile **off** — zero-external
      fallback intact

## 3. Integration wiring (the three audited fixes)

- [ ] `docker compose logs wazuh-manager | grep triage-integration` shows the
      install hook ran
- [ ] `ls -l /var/ossec/integrations/custom-triage` → `-rwxr-x--- root wazuh`
- [ ] `custom-triage.py` present alongside it, same ownership
- [ ] `grep -A3 custom-triage /var/ossec/etc/ossec.conf` shows the block in the
      **running** config (proves the full-file mount worked)
- [ ] `wazuh-control status | grep integratord` → running (optional daemon; only
      starts when an `<integration>` block exists)
- [ ] `printenv TRIAGE_INGEST_API_KEY` inside the container is set
- [ ] `grep -r "$TRIAGE_INGEST_API_KEY" /var/ossec/etc/` returns **nothing**
      (no credential in Wazuh config)

## 4. Log sink (regression guard for the discarded-stderr defect)

- [ ] `/var/ossec/logs/integrations.log` exists, mode `660`, `root:wazuh`
- [ ] After an alert, it contains `{"component":"wazuh_integrator",...}` lines
      — proves logging survives `integratord`'s `> /dev/null 2>&1`

## 5. End-to-end with a disposable agent — **Phase 4.4 acceptance**

- [ ] Agent enrolled: `/var/ossec/bin/agent_control -l` lists it as Active
- [ ] Safe test detection fired (SSH auth failures, or FIM touch on a watched path)
- [ ] `integrations.log` shows `alert_forwarded` with `status=202`
- [ ] Alert visible via `GET /api/v1/alerts` (`X-N8N-Token`)
- [ ] Normalization/scoring populated; incident created if the score warrants
- [ ] Re-delivering the same alert stays idempotent (`occurrences` increments,
      no second alert row, no duplicate incident)

## 6. Failure / spool behaviour

- [ ] `docker compose stop triage-api`; fire a detection
- [ ] `integrations.log` shows retries then `alert_buffered`
- [ ] Spool dir is `0700`; entries are `0600`; no `.tmp` files left behind
- [ ] `docker compose start triage-api`; fire another detection
- [ ] Buffered alert is replayed **oldest-first**, spool drains to empty
- [ ] No duplicate incident created by the replay

## 7. Secret / log hygiene

- [ ] API key absent from `integrations.log`, `ossec.log`, and `docker compose logs`
- [ ] No alert body / `full_log` content in any log line
- [ ] No `user:pass@` URL anywhere in logs
- [ ] `/metrics` unchanged — no new families, no Wazuh data

## 8. Regression gate (re-run after any fix)

```bash
cd app && pytest && ruff check . && ruff format --check . && mypy src
mypy --strict ../wazuh/integrator/custom-triage.py
cd .. && bash scripts/check_secrets.sh
```

## Known risks this checklist is expected to surface

1. **`/var/ossec/etc` volume staleness** — the image seeds the named volume only
   when empty, and copies the mounted `ossec.conf` on each start. Changing the
   config after the volume exists needs a container restart (or volume removal).
2. **Manager Python version** — the wrapper prefers
   `/var/ossec/framework/python/bin/python3` and falls back to system `python3`.
   The script targets 3.9+ syntax; confirm on the real image.
3. **`ulimits`/`memlock` on Docker Desktop** — the `-1` memlock may warn on
   macOS/Windows backends.
4. **2 GB memory limit** — a floor for a Wazuh manager; raise if analysisd is OOM-killed.
