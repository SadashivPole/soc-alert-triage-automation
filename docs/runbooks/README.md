# docs/runbooks/ — Analyst Runbooks

Step-by-step triage investigation guides, one per alert scenario, linked automatically
from notifications (see ARCHITECTURE.md §9–§10).

**Status: scaffolded — runbooks land in Phase 3**, one per scenario in
[sample-alerts](../sample-alerts/README.md):

| Planned runbook | Scenario |
| --- | --- |
| `ssh-brute-force.md` | 01 + 02 (attempts and success from one source) |
| `fim-critical-file.md` | 03 (`/etc/passwd` change on critical server) |
| `malware-hash.md` | 04 (VT-confirmed malicious file) |
| `web-attack.md` | 05 (SQL injection pattern) |
| `account-creation.md` | 06 (Windows 4720 on critical server) |

Runbook template (Phase 3): summary → triage questions → investigation steps (Wazuh/API
queries) → containment *proposals* (approval required) → escalation criteria → closure notes.
