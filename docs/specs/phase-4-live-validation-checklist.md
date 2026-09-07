# Phase 4.1/4.2 — live validation checklist

## Validation Methodology

**A. Source-audit validation performed by Arena (completed 2026-09-05, commit 4262ce1)**
Three wiring defects were identified by auditing against the `wazuh/wazuh-manager:4.9.2` image source and the Wazuh 4.9.2 sources, then fixed. Source review confirmed these defects would have made the integration silently non-functional:

- **Defect 1**: ossec.conf.d fragment never loaded — now ships a complete ossec.conf derived from the official v4.9.2 single-node template, with indexer/vulnerability-detection disabled and the hardcoded cluster key replaced by the substitution marker.
- **Defect 2**: Integrator unreachable by integratord — `10-install-triage-integration.sh` now installs the integrator at `/var/ossec/integrations/` with `root:wazuh 0750` ownership via `chown root:wazuh "$DEST_DIR"` and `chmod 0750 "$DEST_DIR"`, instead of relying on a bind mount with wrong ownership.
- **Defect 3**: All integrator logs discarded — now appends structured JSON to `/var/ossec/logs/integrations.log` (still mirrored to stderr), matching Wazuh's own shipped integrations (instead of `> /dev/null 2>&1`).

**B. Live runtime validation performed by the user on 2026-09-06**
The full Phase 4.1/4.2 pipeline was live-validated on the user's Windows/Docker Desktop environment. The following checks were verified:

## V1. Preconditions
- `docker compose --profile full up -d` succeeded
- `.env` set with `TRIAGE_INGEST_API_KEY`, `N8N_ENCRYPTION_KEY`, `WAZUH_API_USERNAME`, `WAZUH_API_PASSWORD`

## V2. Compose validation
- [x] `docker compose --profile full config` exits 0 and renders `wazuh-manager`
- [x] `docker compose config` (no profile) does **not** include `wazuh-manager`
- [x] Missing `TRIAGE_INGEST_API_KEY` makes `--profile full config` fail (`:?` guard)

## V3. Bring-up & health
- [x] `docker compose --profile full up -d` succeeds
- [x] `soc-wazuh-manager` reaches `healthy` (allow ≥120 s `start_period`)
- [x] `triage-api` still `healthy`; `n8n` / `mailpit` unaffected
- [x] `docker compose ps` shows **no** host binding for `55000`
- [x] `1514`/`1515` are reachable: `nc -vz localhost 1514`, `nc -vz localhost 1515`
- [x] Default (`sim`) stack still works with the profile **off** — zero-external fallback intact

## V4. Integration wiring
- [x] `docker compose logs wazuh-manager | grep triage-integration` shows the install hook ran
- [x] `ls -l /var/ossec/integrations/custom-triage` → `-rwxr-x--- root wazuh`
- [x] `custom-triage.py` present alongside it, same ownership
- [x] `grep -A3 custom-triage /var/ossec/etc/ossec.conf` shows the block in the **running** config (proves the full-file mount worked)
- [x] `wazuh-integratord` running as user `wazuh`
- [x] `printenv TRIAGE_INGEST_API_KEY` inside the container is set
- [x] `grep -r "$TRIAGE_INGEST_API_KEY" /var/ossec/etc/` returns **nothing** (no credential in Wazuh config)

## V5. Log sink
- [x] `/var/ossec/logs/integrations.log` exists, mode `660`, `root:wazuh`
- [x] After an alert, it contains `{"component":"wazuh_integrator",...}` lines — proves logging survives `integratord`'s `> /dev/null 2>&1`

## V6. End-to-end with a disposable agent — **Phase 4.4 acceptance** (VERIFIED)
- [x] Agent enrolled: `/var/ossec/bin/agent_control -l` lists it as Active (Windows Wazuh agent 007)
- [x] Safe test detection fired (Windows Application ERROR event, Source=Phase4Test, Event ID=200)
- [x] `integrations.log` shows `alert_forwarded` with `status=202`
- [x] Alert visible via `GET /api/v1/alerts` (`X-N8N-Token`)
- [x] Normalization/scoring populated; score=38, tier=low, decision=monitor, degraded=false
- [x] Wazuh alert present in alerts.json and the dated alert log
- [x] Incident created if the score warrants

## V7. Failure / spool behaviour
- [ ] `docker compose stop triage-api`; fire a detection — **REMAINS OUTSTANDING**
- [ ] `integrations.log` shows retries then `alert_buffered` — **REMAINS OUTSTANDING**
- [ ] Spool dir is `0700`; entries are `0600`; no `.tmp` files left behind — **REMAINS OUTSTANDING**
- [ ] `docker compose start triage-api`; fire another detection — **REMAINS OUTSTANDING**
- [ ] Buffered alert is replayed **oldest-first**, spool drains to empty — **REMAINS OUTSTANDING**
- [ ] No duplicate incident created by the replay — **REMAINS OUTSTANDING**

## V8. Secret / log hygiene (partially verified)
- [x] API key absent from `integrations.log`, `ossec.log`, and `docker compose logs` — **VERIFIED**
- [x] No alert body / `full_log` content in any log line — **VERIFIED**
- [x] No `user:pass@` URL anywhere in logs — **VERIFIED**
- [ ] `/metrics` unchanged — no new families, no Wazuh data — **REMAINS OUTSTANDING** (verify after any fix)

## V9. Idempotent duplicate delivery (REMAINS OUTSTANDING)
- [ ] Same alert/rule/agent — occurrences increments, no duplicate alert row/incident — **REMAINS OUTSTANDING**

## V10. Regression gate
```bash
cd app && pytest && ruff check . && ruff format --check . && mypy src
mypy --strict ../wazuh/integrator/custom-triage.py
cd .. && bash scripts/check_secrets.sh
```

## Known risks this checklist is expected to surface
1. **`/var/ossec/etc` volume staleness** — the image seeds the named volume only when empty, and copies the mounted `ossec.conf` on each start. Changing the config after the volume exists needs a container restart (or volume removal).
2. **Manager Python version** — the wrapper prefers `/var/ossec/framework/python/bin/python3` and falls back to system `python3`. The script targets 3.9+ syntax; confirm on the real image.
3. **`ulimits`/`memlock` on Docker Desktop** — the `-1` memlock may warn on macOS/Windows backends.
4. **2 GB memory limit** — a floor for a Wazuh manager; raise if analysisd is OOM-killed.
