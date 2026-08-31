# docs/runbooks/ — Analyst Runbooks

Step-by-step triage investigation guides, one per alert scenario, linked automatically
from notifications (see ARCHITECTURE.md §9–§10).

**Status: template + exemplar delivered (REC-PLAYBOOK-01); the full per-scenario set
lands in Phase 3.6**, one runbook per scenario in
[sample-alerts](../sample-alerts/README.md):

| Planned runbook | Scenario | Status |
| --- | --- | --- |
| `ssh-brute-force.md` | 01 + 02 (attempts and success from one source) | ✅ exemplar (delivered) |
| `fim-critical-file.md` | 03 (`/etc/passwd` change on critical server) | ⬜ Phase 3.6 |
| `malware-hash.md` | 04 (VT-confirmed malicious file) | ⬜ Phase 3.6 |
| `web-attack.md` | 05 (SQL injection pattern) | ⬜ Phase 3.6 |
| `account-creation.md` | 06 (Windows 4720 on critical server) | ⬜ Phase 3.6 |

Every runbook is written from **[`_template.md`](_template.md)** — the standardized
structure (metadata, RACI, detection & triage, investigation steps, approval-gated
containment proposals, escalation criteria, closure & feedback, communication) derived
from the *building-incident-response-playbook* reference skill (methodology only).
A contract test (`app/tests/unit/test_recommendations_catalog.py`) enforces that every
non-template runbook keeps the required sections and phrases every response step as an
**approval-gated proposal** — containment is never executed automatically (ADR-8,
REC-PLAYBOOK-03).

Runbook improvements are tracked in the
[recommendations catalogue](../recommendations/README.md) under the `analyst-runbooks`
component (REC-TRIAGE-06, REC-FATIGUE-01, REC-IOC-04, REC-PLAYBOOK-01/02/05).
