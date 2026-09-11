# Critical File Integrity Change

## Summary

Use this runbook when Wazuh reports an integrity change to a security-sensitive
file on a critical server.

Primary sample:

- `03_wazuh_fim_etc_passwd_change.json` — Wazuh rule `550`
- File: `/etc/passwd`
- Host: `db-prod-01`
- Asset tier: `critical`

The investigation is defensive and evidence-driven. Do not make unauthorized
system changes. Any containment action is a proposal requiring explicit
analyst approval.

## Triage Questions

1. Was the file change expected?
2. Who or what initiated the change?
3. Was there an approved maintenance, deployment, or configuration change?
4. Did the file's content, size, owner, group, or permissions change?
5. Are the before/after hashes consistent with the expected change?
6. Are there related authentication, privilege, package, or process events?
7. Is the affected server currently exposed to other suspicious activity?
8. Does the critical asset classification require incident handling?
9. Is the change legitimate, suspicious, or unexplained?

## Investigation Steps

### 1. Validate the alert

Confirm:

- alert ID
- timestamp
- rule ID and rule level
- affected hostname and IP
- asset tier and owner
- file path
- event type
- FIM metadata
- risk score, tier, decision, and reasons

For the synthetic sample:

- host: `db-prod-01`
- IP: `10.0.2.20`
- file: `/etc/passwd`
- rule: `550`
- rule level: `7`

### 2. Compare file-integrity evidence

Review the server-provided FIM information:

- `md5_before`
- `md5_after`
- `sha256_after`
- inode
- file mode
- owner
- group
- reported size change

The sample reports a size change while the permissions remain `644`.

Do not infer the exact file contents from hashes alone.

### 3. Establish change legitimacy

Check available operational context:

- approved change ticket
- deployment activity
- configuration management activity
- account-management activity
- scheduled maintenance
- administrator activity

Determine whether the timing and responsible account or process match the
approved activity.

### 4. Review related security events

Where available, examine:

- authentication events
- privilege changes
- new account activity
- process execution around the timestamp
- additional FIM changes
- other alerts for the same server

Look for a coherent sequence rather than evaluating the FIM event in isolation.

### 5. Review threat-intelligence context

Review extracted indicators and enrichment status when present.

Do not treat the absence of external intelligence as evidence that the file
change is benign.

### 6. Review the server decision

Use the backend-provided:

- score
- risk tier
- decision
- severity
- decision reasons

Do not manually recompute the score.

Because the sample targets a critical asset, verify that the incident handling
decision is consistent with the current server policy.

## Containment Proposals

Containment is not automatic.

Depending on evidence and business impact, an analyst may propose:

- restricting access to the affected host
- temporarily disabling an account associated with unauthorized changes
- isolating the host through an approved incident-response procedure
- preserving the affected file and host evidence for further investigation

Any containment requires explicit analyst approval and must be audit-logged.

Avoid changing `/etc/passwd` or other security-sensitive files solely to
“undo” the alert without establishing what caused the change.

## Escalation Criteria

Escalate to L2 or incident response when:

- the change is unexplained on a critical server
- the change is linked to unauthorized account activity
- multiple sensitive files were modified
- related privilege or authentication anomalies are present
- suspicious process activity is identified
- the activity continues
- evidence suggests persistence or privilege-related abuse

Follow the existing incident lifecycle and SLA process.

## Closure Notes

Record:

- alert and incident IDs
- affected host
- affected file
- before/after integrity evidence
- business justification, if legitimate
- related telemetry reviewed
- analyst assessment
- final verdict
- incident status transition
- containment proposal and approval, if applicable
- follow-up actions

For a legitimate change, record the approved change reference or operational
reason.

For an unexplained change, preserve the evidence and document the escalation
path.

## Related Sample

`docs/sample-alerts/03_wazuh_fim_etc_passwd_change.json`

## MITRE ATT&CK

The synthetic sample identifies:

- `T1566`
- `T1565` (custom rule 100110 declaration; retained as the unresolved G5 discrepancy)
- Tactics: Persistence, Privilege Escalation
- Technique metadata: Modify Authentication Process

Validate ATT&CK mapping against the organization's actual detection content
before production use.
Phase 6.3 regression sample: `docs/sample-alerts/12_custom_fim_rule_100110.json`.
The custom rule declares `T1565`; the existing fixture 03 discrepancy remains recorded and unresolved.
