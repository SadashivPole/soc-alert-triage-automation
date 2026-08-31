# Runbook: SSH Brute Force & Successful Authentication

> Applies to sample scenarios `01_wazuh_ssh_brute_force.json` and
> `02_wazuh_ssh_brute_force_success.json` (Wazuh rules 5710 / 5715).
> Exemplar runbook — written from the `_template.md` structure (REC-PLAYBOOK-01).
> The full runbook set lands in Phase 3.6.

## Metadata

| Field | Value |
| --- | --- |
| Name | SSH brute force & successful authentication |
| Version | 1.0 |
| Owner | L2 — platform team |
| Last reviewed | 2026-08-31 |
| Next review | 2026-11-30 |
| Trigger conditions | Wazuh rule 5710 (`sshd` authentication failure, level 5) or 5715 (authentication success, level 3) from an external source IP, on an SSH-exposed host |
| Severity criteria | `medium` → queue for L1; `high`/`critical` → SEV2/SEV1 incident (per `app/config/decisions.yaml`); a successful auth after a burst escalates the pair |

## RACI

| Activity | L1 | L2 | IR lead | Platform owner |
| --- | --- | --- | --- | --- |
| Initial triage | R | C | I | — |
| Investigation | R | A | I | — |
| Containment proposal | C | R | A | I |
| Approval & execution | — | R | A | I |
| Closure & feedback | R | A | I | — |

## Detection & triage

- **Source:** Wazuh `sshd` group; rules 5710 (`authentication_failed`, level 5,
  MITRE T1110 Credential Access) and 5715 (`authentication success`, level 3).
- **Key canonical fields:** `source_event.data.srcip`, `data.srcuser` / `data.dstuser`,
  `agent.{id,name,ip}`, `asset.tier`, `full_log`.
- **Triage checklist:**
  1. Confirm the affected asset and its tier (`asset.tier`) — a tier-1 web server
     makes `asset_criticality` a major driver.
  2. Confirm the source IOC and its provenance (`ioc.provenance`: field / location /
     offset) — the source IP should be a single indicator with typed-field provenance.
  3. Check `enrichment_status`: `complete` vs `partial`/`failed` changes how much
     weight to give intel verdicts.
  4. Check recurrence: `dedupe.occurrences` within the generation — a burst is what
     lifts this alert from `medium` toward `high`.
- **Expected scoring drivers:** `rule_severity` (level 5 → band 14/40; level 3 → 6/40),
  `rule_groups_mitre` (`authentication_failed` + T1110), `asset_criticality`,
  `recurrence_velocity` (rapid burst), `ioc_evidence`, `enrichment_status`.
- **Context provided by the platform:** rule fidelity (historical FP rate of rule 5710
  from feedback), correlation history (same src IP or user in the last 30 days),
  detection lag, IOC age, shared-infrastructure tag on the source IP (REC-IOC-02).

## Investigation steps

1. Open the alert in the console (`/alerts/{id}`) and read the score justification
   factor by factor.
2. Review the source IP's enrichment: VirusTotal reputation (if the IP is a CDN/cloud
   edge, verify the tenant before drawing conclusions), MISP event matches and tags,
   allowlist status.
3. Run the historical-correlation check for `srcip` and `dstuser` — has this source
   appeared before? Has the service account logged in from other hosts?
4. Query Wazuh for the auth log window:
   `location: /var/log/auth.log` + `rule.id: 5710 or 5715`, same `srcip`, ±15 min —
   count failures, note any **success** (scenario 02) and the account used.
5. If a success exists: confirm the account (`data.dstuser`), the exact time, and
   whether MFA/key-only auth was in place.
6. Classify the incident (NIST category: **Unauthorized Access** for success,
   **Reconnaissance** for attempts only) and confirm scope: asset(s), account(s), data
   at risk.

## Containment proposals

> **Every step below is a proposal: it requires explicit analyst approval and is audit-logged. No step is ever executed automatically** (ADR-8, REC-PLAYBOOK-03).

| # | Proposal | Risk if executed | Approval path |
| --- | --- | --- | --- |
| 1 | Add the source IP to the perimeter firewall deny list | Legitimate shared services behind the IP may break (verify shared-infrastructure tag first) | WF5 `contain` verdict → explicit analyst approval → audited action |
| 2 | Force a credential rotation / key regeneration for the authenticated service account | Service disruption for dependent automation | WF5 `contain` verdict → explicit analyst approval → audited action |
| 3 | Request host-level review of the tier-1 asset (auth logs, persistence check) | None (read-only) — still logged as an approved action | WF5 `contain` verdict → explicit analyst approval → audited action |

If a proposal is approved, record the action, actor, and timestamp in the incident
timeline. If declined, record the rationale. Capture evidence (auth logs, timestamps,
IOC provenance) **before** any approved remediation.

## Escalation criteria

- SLA re-notify (existing): `critical` 15 min / `high` 30 min ack; WF4 escalates to L2
  on breach.
- Analyst-initiated escalation (never automatic):
  - Successful authentication after a brute-force burst (**scenario 02**) → escalate to
    L2 immediately with the triage record (classification, affected account, timeline).
  - The account has privileged access or the asset is tier-0/tier-1 → escalate to IR
    lead with the correlation history attached.
  - MISP campaign tags on the source IP → treat as campaign activity and escalate per
    the playbook's criteria (REC-IOC-05).

## Closure & feedback

- Submit the verdict via WF5 (`true_positive` / `false_positive` / `escalate` /
  `contain`) with notes.
- Confirm the classification: **Unauthorized Access** (success) or **Reconnaissance**
  (attempts only).
- If false-positive (e.g. an approved scanner): capture the source IP / scanner identity
  as evidence for a tuning suggestion; the allowlist addition lands via reviewed PR —
  never auto-edited (REC-FATIGUE-02).
- If true-positive: mark the incident resolved with a one-paragraph summary (what, why,
  impact, approved actions taken).

## Communication

| Audience | When | Channel |
| --- | --- | --- |
| Asset owner | impact confirmed (successful auth) | email via n8n |
| L2 / IR lead | escalation criteria met | chat page via n8n |
| SOC manager | incident resolved | digest / incident board |
