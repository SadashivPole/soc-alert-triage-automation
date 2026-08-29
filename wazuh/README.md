# wazuh/ — Wazuh Manager Integration

Configuration for the real Wazuh 4.x manager (compose profile `full`, Phase 4):
custom rules/decoders that generate the alerts this platform triages, and the
`integrator` script that forwards them to the Triage API. Design:
[ARCHITECTURE.md](../ARCHITECTURE.md#13-docker--deployment-architecture), ADR-6.

**Status: scaffolded — content lands in Phase 4.** Until then the pipeline runs in `sim`
mode with the synthetic payloads in [docs/sample-alerts](../docs/sample-alerts/README.md).

```
wazuh/
├── integrator/          # custom-triage integration script (reads URL/key from env)
└── ruleset/             # custom rules, decoders, and local syscheck policies
```

## Planned integrator shape (Phase 4)

Wazuh `ossec.conf` → `<integrator>` block invoking the custom script with:

- `hook_url` = `http://triage-api:8000/api/v1/alerts/ingest`
- API key injected via environment variable — **never** hardcoded in the script.
- Rule/level filters so only relevant alerts are forwarded (e.g., `level >= 5`).
- Local buffering + retry so short API outages don't lose alerts.

## Defensive scope reminder

Anything in this directory must remain detection/forwarding configuration only.
Active-response content is limited to *analyst-approved* containment proposals
(see [SECURITY.md §1](../SECURITY.md#1-scope--charter-defensive-only)).
