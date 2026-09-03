# docs/runbooks/ — Analyst Runbooks

Step-by-step defensive triage investigation guides for the synthetic alert
scenarios used by the project.

These runbooks are documentation and investigation guidance only. They do not
perform autonomous response actions. Any containment described below is a
proposal requiring explicit analyst approval and audit logging.

## Phase 3.6 Runbook Catalog

| Runbook | Scenario | Wazuh rule |
| --- | --- | --- |
| `ssh-brute-force.md` | 01 + 02 — SSH brute-force attempts and follow-on successful authentication | 5710 / 5715 |
| `fim-critical-file.md` | 03 — `/etc/passwd` change on a critical server | 550 |
| `malware-hash.md` | 04 — VirusTotal-associated malicious file hash | 87105 |
| `web-attack.md` | 05 — SQL injection pattern against a web server | 31103 |
| `account-creation.md` | 06 — Windows Event 4720 local account creation | 60180 |

## Runbook Structure

Each runbook contains:

1. Summary
2. Triage questions
3. Investigation steps
4. Containment proposals
5. Escalation criteria
6. Closure notes
7. Related sample alert(s)
8. MITRE ATT&CK context where supplied by the sample

## Safety and Operating Rules

- All sample data is synthetic.
- Investigation must remain defensive.
- Do not execute suspicious malware as part of routine triage.
- Do not perform exploitation against target systems.
- Do not make unauthorized account, host, firewall, or file changes.
- Containment actions require explicit analyst approval.
- Approved actions must be audit-logged.
- Server-provided scores and decisions are authoritative; runbooks do not
  recalculate risk.
- Threat-intelligence outages or skipped enrichment do not prove that an
  indicator is benign.

## Related Documentation

- `../sample-alerts/README.md` — synthetic scenario catalog
- `../../ARCHITECTURE.md` — system architecture and decision model
- `../../DEVELOPMENT_PLAN.md` — phase gates and acceptance criteria