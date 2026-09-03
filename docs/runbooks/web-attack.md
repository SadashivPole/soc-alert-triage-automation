# Web Attack / SQL Injection

## Summary

Use this runbook when Wazuh reports a suspected SQL injection pattern against
a web application or other public-facing service.

Primary sample:

- `05_wazuh_web_sql_injection.json`
- Wazuh rule `31103`
- Rule level `10`
- Host: `web-prod-01`
- Source IP: `198.51.100.77`
- HTTP status: `500`

The investigation is defensive and evidence-driven. Do not attempt to exploit
the application. Any containment action is a proposal requiring explicit
analyst approval.

## Triage Questions

1. What source IP generated the request?
2. Which application, host, and URL were targeted?
3. Was the request blocked, rejected, or processed by the application?
4. Was there a corresponding HTTP error or other application-side impact?
5. Were similar requests observed before or after the alert?
6. Did the request reach a sensitive endpoint or parameter?
7. Is there evidence of successful exploitation?
8. Are additional hosts or applications being targeted by the same source?
9. Does the evidence support incident escalation?

## Investigation Steps

### 1. Validate the alert

Confirm:

- alert ID
- timestamp
- rule ID and rule level
- source IP
- destination host
- request URL or parameter
- HTTP protocol
- HTTP response status
- decoder
- log location
- recurrence information
- server-provided score, tier, decision, and reasons

For the synthetic sample:

- source IP: `198.51.100.77`
- host: `web-prod-01`
- URL: `/products.php?id=1%27%20OR%20%271%27%3D%271`
- protocol: `HTTP/1.1`
- status: `500`
- location: `/var/log/nginx/error.log`

### 2. Validate the request context

Determine:

- which application endpoint received the request
- whether the request reached the application
- whether it was rejected by a control before processing
- whether the HTTP 500 was caused by the request or an unrelated condition

Do not reproduce the attack against a production system as part of routine
triage.

### 3. Review recurrence

Look for:

- repeated requests from the same source
- additional SQL injection patterns
- targeting of multiple URLs
- changes in request rate
- related alerts from the same source
- related alerts against the same application

Use the backend deduplication and recurrence information rather than manually
reconstructing counts when the server already provides them.

### 4. Review application and server telemetry

Where available, examine:

- web access logs
- application logs
- reverse-proxy/WAF logs
- authentication events
- error logs
- database/application monitoring
- alerts immediately before and after the event

Determine whether there is evidence of:

- unauthorized data access
- authentication bypass
- abnormal application behavior
- repeated server-side errors
- suspicious follow-on requests

### 5. Review threat-intelligence context

For the external source IP, review available enrichment.

Consider:

- provider verdict
- reputation score
- enrichment status
- cache status
- whether the lookup was skipped or unavailable

Treat threat intelligence as supporting evidence rather than proof of
successful exploitation.

### 6. Review the deterministic decision

Use the backend-provided:

- risk score
- risk tier
- decision
- severity
- decision reasons

Do not recalculate the score in the runbook.

For high or critical outcomes, follow the existing incident lifecycle and SLA
process.

## Containment Proposals

Containment is not automatic.

Depending on the evidence, an analyst may propose:

- temporary blocking of the confirmed malicious source through an approved
  network/WAF control
- tightening an existing WAF rule after validation
- restricting the affected endpoint where business impact permits
- temporarily isolating the affected application host if compromise is
  supported by evidence

Any proposed action must consider legitimate traffic and business impact.

Explicit analyst authorization is required, and approved containment must be
audit-logged.

## Escalation Criteria

Escalate to L2 or incident response when:

- evidence suggests the request was successfully processed in a harmful way
- unauthorized data access is suspected
- authentication or authorization controls may have been bypassed
- suspicious follow-on activity is observed
- multiple applications or hosts are targeted
- the source continues malicious activity
- server-side compromise is suspected
- the alert reaches high/critical incident handling requirements

Do not classify a SQL injection alert as successful exploitation based only on
the presence of an injection pattern.

## Closure Notes

Record:

- alert and incident IDs
- source IP
- targeted host and URL
- HTTP status
- recurrence observed
- application/server telemetry reviewed
- enrichment result and status
- whether successful exploitation was established
- final analyst verdict
- incident status transition
- containment proposal and approval, if applicable
- follow-up requirements

For a false positive or blocked attempt, document the evidence showing why
there was no successful compromise.

For suspected exploitation, preserve the relevant evidence and escalation
history.

## Related Sample

`docs/sample-alerts/05_wazuh_web_sql_injection.json`

## MITRE ATT&CK

The synthetic sample identifies:

- `T1190` — Exploit Public-Facing Application
- Tactic: Initial Access
- Technique: Exploit Public-Facing Application

Validate the mapping against the organization's actual detection content
before production use.