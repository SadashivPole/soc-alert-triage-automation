# SSH Brute-Force and Follow-on Authentication

## Summary

Use this runbook for repeated SSH authentication failures and for a subsequent
successful authentication from the same source IP against the same host.

This runbook covers:

- `01_wazuh_ssh_brute_force.json` — Wazuh rule `5710`
- `02_wazuh_ssh_brute_force_success.json` — Wazuh rule `5715`
- `07_wazuh_ssh_brute_force_recurrence.json` — Wazuh rule `5710` on a second
  tier-1 host (`web-prod-02`); the evaluation corpus replays it as three
  distinct deliveries to pin the recurrence escalation (Phase 6.3, SCN-07)
- `08_wazuh_ssh_session_opened.json` — Wazuh rule `5716`; a benign baseline
  session event that must stay in the informational band (Phase 6.3, SCN-08)

The investigation is defensive only. Do not perform exploitation or
unauthorized access. Any containment action is a proposal that requires
explicit analyst approval.

## Triage Questions

1. Are repeated SSH authentication failures coming from the same source?
2. Is the source IP consistent across the related events?
3. Did a successful authentication occur shortly after the failed attempts?
4. Which account was successfully authenticated?
5. Is the destination host tier-1 or otherwise critical?
6. Is the account expected to authenticate from this source?
7. Is the authentication time consistent with approved activity?
8. Does recurrence or correlation increase the incident priority?
9. Is the available evidence sufficient to classify the activity as legitimate,
   suspicious, or requiring escalation?

## Investigation Steps

### 1. Validate the alert

Confirm the server-provided:

- alert ID
- timestamp
- rule ID and rule level
- source IP
- destination host
- source/destination account where present
- protocol
- deduplication information
- risk score, tier, decision, and reasons

For the synthetic sample:

- source IP: `203.0.113.50`
- host: `web-prod-01`
- protocol: `ssh`
- location: `/var/log/auth.log`

Do not treat one failed authentication event as proof of compromise.

### 2. Review recurrence and deduplication

Review related alerts for:

- repeated failures from the same source
- occurrence count
- first-seen timestamp
- last-seen timestamp
- dedupe group
- changes in the server-provided risk tier

The sample catalog defines recurrence as an important signal for this scenario.

### 3. Correlate the successful authentication

Determine whether a successful authentication followed the failed attempts.

Compare:

- source IP
- destination host
- timestamps
- account
- authentication method

The synthetic success sample contains:

- source IP: `203.0.113.50`
- account: `svc_deploy`
- host: `web-prod-01`

A successful authentication from the same source shortly after repeated
failures should receive focused investigation until its legitimacy is
established.

### 4. Validate account legitimacy

Determine:

- whether the account is expected
- whether it is a service account
- whether the source is an approved administration path
- whether the authentication time matches planned activity
- whether a maintenance, deployment, or operational task explains the login

Do not classify an account as compromised solely because the account name is
unfamiliar.

### 5. Review related telemetry

Where available, review:

- additional authentication events
- account changes
- privilege changes
- other alerts for the same host
- other alerts from the same source
- activity immediately before and after the authentication event

Use the SOC console and existing API read paths for available context.

### 6. Review threat-intelligence context

For a public source IP, review the enrichment result when enrichment is
available.

Consider:

- provider verdict
- reputation score
- enrichment status
- whether the result is cached
- whether enrichment was skipped, failed, or unavailable

Never treat unavailable threat intelligence as evidence that the source is
benign.

### 7. Review the server decision

Use the existing server-provided risk score, tier, decision, severity, and
reasons.

The console and runbook must not recalculate the risk score.

Document why the alert remains:

- monitored
- queued for L1
- or associated with an incident

according to the backend decision.

## Containment Proposals

Containment is not automatic.

Depending on the evidence, an analyst may propose:

- restricting the suspicious source through an approved access-control process
- requiring credential reset for an affected account
- temporarily disabling a suspicious account
- isolating the affected host through an approved incident-response process

Before proposing containment, verify that the proposed action will not
interrupt legitimate service or administrative activity.

Any approved containment must be explicitly authorized and audit-logged.

## Escalation Criteria

Escalate to L2 when any of the following apply:

- successful authentication follows a significant brute-force burst
- the source is unknown or unauthorized
- the authenticated account is privileged or sensitive
- multiple hosts are targeted
- suspicious activity continues
- evidence suggests possible credential compromise
- the incident meets the existing high/critical handling requirements

Follow the existing incident lifecycle and SLA process.

## Closure Notes

Record:

- trigger and alert IDs
- source IP
- destination host
- recurrence observed
- whether authentication succeeded
- account involved
- evidence reviewed
- legitimacy assessment
- final analyst verdict
- incident status transition
- containment proposal and approval, if any
- follow-up actions

For a false positive, record the business or operational explanation.

For suspected compromise, preserve the relevant evidence and escalation
history in the incident record.

## Related Samples

- `docs/sample-alerts/01_wazuh_ssh_brute_force.json`
- `docs/sample-alerts/02_wazuh_ssh_brute_force_success.json`
- `docs/sample-alerts/20_custom_ssh_near_miss.json`
- `docs/sample-alerts/24_ssh_recurrence_below_burst.json`

## MITRE ATT&CK

The primary technique represented by scenario 01 is:

- `T1110` — Brute Force
- Tactic: Credential Access

The technique metadata is inherited from the synthetic sample and should be
validated against the organization's detection mapping before production use.
Phase 6.3 regression samples: `docs/sample-alerts/11_custom_ssh_rule_100100.json`, `docs/sample-alerts/15_ssh_failed_auth_below_threshold.json`, `docs/sample-alerts/20_custom_ssh_near_miss.json`, `docs/sample-alerts/24_ssh_recurrence_below_burst.json`.
