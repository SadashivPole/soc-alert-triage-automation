# Windows Local Account Creation

## Summary

Use this runbook when Wazuh reports creation of a new Windows account,
especially on a critical server.

Primary sample:

- `06_wazuh_windows_user_created.json`
- Wazuh rule `60180`
- Rule level `5`
- Windows Event ID `4720`
- Host: `fin-srv-02`
- Asset tier: `critical`
- New account: `svc_temp_backup`

The investigation is defensive and evidence-driven. Do not make unauthorized
account or system changes. Any containment action is a proposal requiring
explicit analyst approval.

## Triage Questions

1. Was the account creation authorized?
2. Who created the account?
3. Why was the account created?
4. Is the account a legitimate service or administrative account?
5. Is the account name consistent with organizational naming standards?
6. Was the account created during an approved change or maintenance window?
7. What groups and privileges were assigned?
8. Are there related logon, privilege, or process events?
9. Is the account being used after creation?
10. Does the activity require escalation?

## Investigation Steps

### 1. Validate the alert

Confirm:

- alert ID
- timestamp
- rule ID and rule level
- Windows Event ID
- hostname and IP
- asset tier and owner
- subject account
- target account
- source workstation
- server-provided score, tier, decision, and reasons

For the synthetic sample:

- host: `fin-srv-02`
- IP: `10.0.4.31`
- asset tier: `critical`
- Event ID: `4720`
- target account: `svc_temp_backup`
- subject account: `adm-jdoe-lab`
- domain: `CORP-LAB`
- workstation: `FIN-WS-07`

### 2. Establish why the account was created

Determine whether the account creation corresponds to:

- an approved administrative task
- a deployment or maintenance activity
- a backup or service requirement
- a documented change request
- another legitimate operational requirement

Verify the timing and responsible administrator where possible.

Do not classify an account as malicious solely because it is new or uses a
service-style name.

### 3. Review account attributes

Where the necessary telemetry is available, inspect:

- account enabled/disabled state
- group memberships
- administrative privileges
- password or credential-management policy
- account expiration configuration
- service configuration using the account

Pay particular attention to unexpected privileged group membership.

### 4. Investigate the account creator

Review the subject account:

- `adm-jdoe-lab`

Determine:

- whether the account is authorized for account administration
- whether the source workstation is expected
- whether related administrative activity occurred
- whether the account creator recently showed other suspicious behavior

Correlate the event with other authentication and administrative activity.

### 5. Review related Windows telemetry

Where available, examine:

- subsequent logon events
- privilege assignment events
- group membership changes
- service installation or modification
- scheduled task activity
- process execution
- additional account-management alerts

Look for a consistent sequence following account creation.

### 6. Review server decision

Use the backend-provided:

- risk score
- risk tier
- decision
- severity
- decision reasons

Do not manually recalculate the score.

Because the sample targets a critical finance server, verify that the analyst
review is consistent with the current server decision and incident policy.

### 7. Review threat-intelligence context

Review extracted indicators and enrichment when present.

Do not treat the absence of threat-intelligence findings as proof that the
account creation is legitimate.

## Containment Proposals

Containment is not automatic.

Depending on the evidence, an analyst may propose:

- disabling the newly created account
- removing unexpected privileged group membership
- restricting the affected host through an approved control
- isolating the host if broader compromise is supported by evidence

Before proposing a change, establish that the account or access is
unauthorized and consider the impact on legitimate business services.

Any approved containment must be explicitly authorized and audit-logged.

## Escalation Criteria

Escalate to L2 or incident response when:

- the account creation is unauthorized or unexplained
- the new account receives unexpected administrative privileges
- the creating account is itself suspicious or compromised
- the account is immediately used for suspicious authentication
- related persistence or privilege activity is observed
- multiple unauthorized accounts are created
- the affected critical server shows additional suspicious activity
- the server decision requires higher-priority incident handling

Follow the existing incident lifecycle and SLA process.

## Closure Notes

Record:

- alert and incident IDs
- Event ID
- affected server
- newly created account
- creating account
- source workstation
- authorization/change reference
- account privileges reviewed
- related telemetry
- enrichment status
- final analyst verdict
- incident status transition
- containment proposal and approval, if applicable
- follow-up actions

For an authorized change, record the operational or change-management
justification.

For an unauthorized or unexplained account, preserve evidence and document
the escalation path.

## Related Sample

`docs/sample-alerts/06_wazuh_windows_user_created.json`

## MITRE ATT&CK

The synthetic sample identifies:

- `T1136` — Create Account
- Tactic: Persistence
- Technique: Create Account: Local Account

Validate the mapping against the organization's actual detection content
before production use.