# Runbook: <scenario name>

> One scenario per runbook. This is the **template** (REC-PLAYBOOK-01) — copy it,
> fill every section, and never merge a runbook that skips a required section
> (enforced by `app/tests/unit/test_recommendations_catalog.py`).
>
> Structure follows the *building-incident-response-playbook* reference skill as
> **methodology only**, adapted to this platform: deterministic scoring drives
> routing, runbooks carry the analyst's investigation and **approval-gated
> containment proposals** — never autonomous actions (ADR-8).

## Metadata

| Field | Value |
| --- | --- |
| Name | <scenario name> |
| Version | 1.0 |
| Owner | <L2 team / platform team> |
| Last reviewed | <date> |
| Next review | <date + 3 months> |
| Trigger conditions | <rule ids + levels + canonical fields that activate this runbook> |
| Severity criteria | <which risk tiers (informational/low/medium/high/critical) route here, per `app/config/decisions.yaml`> |

## RACI

| Activity | L1 | L2 | IR lead | Platform owner |
| --- | --- | --- | --- | --- |
| Initial triage | R | C | I | — |
| Investigation | R | A | I | — |
| Containment proposal | C | R | A | I |
| Approval & execution | — | R | A | I |
| Closure & feedback | R | A | I | — |

R = responsible · A = accountable · C = consulted · I = informed

## Detection & triage

- Which detection source emits this alert (Wazuh rule id / level / groups / MITRE
  technique) and which canonical fields matter (`source_event.data.*`, `syscheck`,
  `full_log`).
- Initial triage checklist: confirm the affected asset and tier, confirm the IOCs and
  their provenance (`ioc.provenance`: field / location / offset), check
  `enrichment_status` (was intel complete, partial, or failed?).
- Expected scoring drivers: which `scoring.v1` factors usually push this alert into its
  tier (`rule_severity`, `rule_groups_mitre`, `asset_criticality`,
  `recurrence_velocity`, `ioc_evidence`, `enrichment_status`, `allowlist_modifier`).
- Context the console/payload already provides: rule fidelity (REC-TRIAGE-03),
  correlation history (REC-TRIAGE-05), detection lag (REC-TRIAGE-04), IOC age
  (REC-IOC-03), shared-infrastructure tags (REC-IOC-02).

## Investigation steps

Numbered, tool-specific steps. Use the platform's own surfaces first, then the source
SIEM/EDR:

1. Open the alert in the console (`/alerts/{id}`) and read the score justification
   factor by factor.
2. Review IOC provenance and enrichment verdicts (VT / MISP / allowlist) per indicator;
   note indicator age and any shared-infrastructure tag.
3. Run the historical-correlation check for the same host / user / source.
4. Query the source system (e.g. Wazuh) for the raw evidence: <concrete query>.
5. Determine the incident classification (NIST category) and confirm scope (assets,
   users, data at risk).

## Containment proposals

> **Every step below is a proposal: it requires explicit analyst approval and is audit-logged. No step is ever executed automatically** (ADR-8, REC-PLAYBOOK-03).

| # | Proposal | Risk if executed | Approval path |
| --- | --- | --- | --- |
| 1 | <concrete, tool-specific step> | <blast radius> | WF5 `contain` verdict → explicit analyst approval → audited action |

- If a proposal is approved, record the action, actor, and timestamp in the incident
  timeline (the audit log is the system of record).
- If declined, record the rationale — the decline itself is audit-worthy.
- Evidence preservation comes first: never approve remediation before volatile evidence
  is captured where applicable.

## Escalation criteria

- SLA-driven re-notify (existing): critical 15 min / high 30 min ack, WF4 L2 escalation.
- Analyst-initiated escalation (never automatic): <concrete triggers, e.g. confirmed
  successful authentication after a burst, confirmed malware execution, data
  exfiltration evidence> → L2 / IR lead with the triage record attached.

## Closure & feedback

- Submit the verdict via WF5 (`true_positive` / `false_positive` / `escalate` /
  `contain`) with notes; verdicts feed the tuning digest (REC-FATIGUE-01/02).
- Confirm or correct the incident classification (REC-TRIAGE-01).
- If false-positive: capture the benign pattern as evidence for a tuning suggestion —
  humans apply rule/allowlist changes via reviewed PR, never auto-edits.
- Mark the incident resolved with a one-paragraph summary (what, why, impact, actions).

## Communication

| Audience | When | Channel |
| --- | --- | --- |
| Asset owner | impact confirmed | email via n8n |
| L2 / IR lead | escalation criteria met | chat page via n8n |
| SOC manager | incident resolved | digest / incident board |
