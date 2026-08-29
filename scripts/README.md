# scripts/ — Repo & Dev Utilities

Small helper scripts for repository hygiene and development. Everything here must be
safe to run and defensive-only (see [SECURITY.md](../SECURITY.md)).

| Script | Purpose | Status |
| --- | --- | --- |
| `check_secrets.sh` | Scan git-tracked files for common credential patterns (API keys, tokens, private keys) and verify `.env` hygiene. Runs in CI from Phase 1. | ✅ available |
| `send_test_alert` | Replay synthetic alerts from `docs/sample-alerts/` into the ingest endpoint (with `--repeat` for dedupe demos). | ⬜ Phase 1 |

Run the hygiene check any time:

```bash
bash scripts/check_secrets.sh
```
