# Skill-Derived Improvement Recommendations

**Methodological references only — nothing here is copied verbatim, and no policy
threshold is adopted blindly.**

This catalogue distills improvement recommendations from four reference
cybersecurity skills and maps **each** one into the platform's existing components:

| Reference skill (methodology only) | Focus |
| --- | --- |
| [`triaging-security-incident`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/triaging-security-incident) | NIST SP 800-61r3 classification, impact-based severity, enrichment before escalation, structured triage records |
| [`implementing-alert-fatigue-reduction`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/implementing-alert-fatigue-reduction) | Measure alert quality, risk-based alerting, analyst-approved tuning, consolidation, tiered routing, trend metrics |
| [`analyzing-indicators-of-compromise`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-indicators-of-compromise) | IOC normalization, multi-source enrichment, campaign attribution, disposition frameworks, defanging, TTLs |
| [`building-incident-response-playbook`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/building-incident-response-playbook) | Playbook structure, decision trees, escalation criteria, RACI, SOAR boundaries, testing cadence |

The machine-readable source of truth is
[`recommendations.yaml`](recommendations.yaml); this document is its human-readable
rendering. A unit test (`app/tests/unit/test_recommendations_catalog.py`) schema-validates
the catalogue and mechanically enforces the guardrails below.

---

## Guardrails (non-negotiable)

These constraints are enforced by review **and** by the catalogue contract test:

1. **No copied scoring thresholds.** The reference skills' numeric bands (VT detection
   counts, AbuseIPDB scores, risk-score cutoffs, SLA minutes, TTL days, alert-per-analyst
   ratios) are *illustrative of a methodology*, never inputs to this platform's policy.
   Where a recommendation needs a threshold, it specifies **deriving it from our own
   corpus** (see [REC-IOC-06](#rec-ioc-06)).
2. **The existing `scoring.v1` policy is never replaced.** `app/config/scoring.yaml`
   keeps `engine_version: scoring.v1`; all golden-file scores stay byte-identical. No
   recommendation invents a scoring factor; the test rejects unknown `scoring.*` factor
   names. Future factors are explicitly deferred to a **new** policy version (v2+),
   additive, migration-tested, and human-approved.
3. **No offensive actions.** The catalogue contains only defensive, detection,
   enrichment, reporting, and analysis improvements. `offensive: false` is asserted for
   every entry.
4. **No autonomous containment.** Every recommendation that touches response-like
   wording is marked `requires_approval: true` and its analyst action names an explicit
   human gate. Containment exists only as a *proposal* that executes after explicit
   analyst approval, with audit rows (ADR-8, Phase 4.5). The test rejects any entry with
   response wording that lacks an approval gate.
5. **Deterministic, explainable scoring is preserved.** Every scoring-touching
   recommendation either changes *detail text only* or is a **view/context** addition.
   Anything that would move a number is pinned to golden tests and a migration plan.

---

## How to read a recommendation

Every recommendation identifies the five required elements:

| Field | Meaning |
| --- | --- |
| **Evidence** | The concrete, existing signal in this platform the recommendation builds on (fields, tables, payloads, files). |
| **Factor affected** | Which existing factor/field/policy key it touches — `scoring.*` names must be existing v1 factors; `decision.*` keys must exist; anything else is an explicitly labeled addition. |
| **Reason** | Why the reference methodology justifies it, mapped to our architecture. |
| **Expected analyst action** | What a human does with it — never an autonomous action. |
| **Test required** | The test that must land with the implementation (deterministic, no live services). |

Plus catalogue metadata: `component` (the primary existing component it maps into),
`also` (secondary surfaces), `priority`, `phase`, `status`, and guardrail flags.

## Component mapping

| Existing component | Recommendations mapped into it |
| --- | --- |
| **Scoring engine** (`scoring/`, `app/config/scoring.yaml`) | [REC-TRIAGE-02](#rec-triage-02), [REC-FATIGUE-03](#rec-fatigue-03), [REC-IOC-06](#rec-ioc-06) |
| **Decision engine** (`decisions/`, `app/config/decisions.yaml`) | [REC-TRIAGE-01](#rec-triage-01), [REC-TRIAGE-03](#rec-triage-03), [REC-TRIAGE-04](#rec-triage-04), [REC-TRIAGE-05](#rec-triage-05), [REC-FATIGUE-04](#rec-fatigue-04) |
| **IOC provenance** (`models/ioc.py`, `enrichment/`) | [REC-IOC-01](#rec-ioc-01), [REC-IOC-02](#rec-ioc-02), [REC-IOC-03](#rec-ioc-03), [REC-IOC-05](#rec-ioc-05) |
| **Analyst runbooks** (`docs/runbooks/`) | [REC-TRIAGE-06](#rec-triage-06), [REC-FATIGUE-01](#rec-fatigue-01), [REC-IOC-04](#rec-ioc-04), [REC-PLAYBOOK-01](#rec-playbook-01), [REC-PLAYBOOK-02](#rec-playbook-02), [REC-PLAYBOOK-05](#rec-playbook-05) |
| **Human approval model** (feedback, WF5, ADR-8) | [REC-FATIGUE-02](#rec-fatigue-02), [REC-PLAYBOOK-03](#rec-playbook-03), [REC-PLAYBOOK-04](#rec-playbook-04) |

---

## Catalogue

### Skill 1 — Triaging security incidents

#### REC-TRIAGE-01 — NIST SP 800-61r3 incident classification on every alert
- **Component:** decision-engine · **Priority:** medium · **Phase:** 3 · **Status:** proposed
- **Evidence:** `rule.groups` (e.g. `authentication_failed`), `rule.mitre.tactic`, and the assigned risk tier on the canonical alert.
- **Factor affected:** `alert.classification` (proposed canonical field, consumed by `decision.runbook` selection and digests; carries no score weight).
- **Reason:** The reference skill classifies the incident type before prioritizing. A stable NIST-aligned taxonomy (unauthorized access / denial of service / malicious code / improper usage / reconnaissance / web application attack) lets the decision engine pick the right runbook and lets digest statistics group incidents consistently instead of by rule id alone.
- **Expected analyst action:** On the triage verdict (WF5 form), confirm or correct the suggested classification; the correction is stored and audited like any verdict.
- **Test required:** Unit — classification derived deterministically from sample-alert groups/tactics is pinned by a golden table. Integration — a verdict correction updates `alert.classification` and writes an audit row.

#### REC-TRIAGE-02 — Impact-matrix context inside the `asset_criticality` justification
- **Component:** scoring-engine · **Priority:** medium · **Phase:** 3 · **Status:** proposed
- **Evidence:** `asset.tier` plus `rule.mitre.tactic` on the canonical alert (e.g. Credential Access against a tier-1 asset).
- **Factor affected:** `scoring.asset_criticality` — **detail text only**; points, bands, and scoring.v1 weights untouched.
- **Reason:** The reference skill computes severity as a function of asset criticality, threat type, and data sensitivity. Our factor already awards points by tier, but the justification only prints the tier label; adding the threat-type context makes the score explanation match the analyst's mental impact matrix without changing any number.
- **Expected analyst action:** Read the enriched detail; if the asset tier is wrong, correct it in the asset inventory (Phase 4) so future alerts score against the right band.
- **Test required:** Unit — factor detail includes tactic/group context when present and is byte-identical to today's golden text when absent. Golden-file scores for all six sample alerts must be unchanged.

#### REC-TRIAGE-03 — Rule fidelity (historical TP rate) surfaced as analyst context, never a weight
- **Component:** decision-engine · **Priority:** high · **Phase:** 3 · **Status:** proposed
- **Evidence:** `feedback.verdict` counts per `rule.id` (+ `agent.id`) from the existing feedback table.
- **Factor affected:** `decision.reasons` and the n8n notification payload (new read-only fidelity-context field); deliberately **not** a scoring.v1 factor.
- **Reason:** The reference skill treats alert fidelity as a first-class triage input. Adding it as a score weight would change every golden score, violating the scoring.v1 contract; surfacing it as context lets the analyst weight it subjectively and feeds the tuning digest (REC-FATIGUE-02).
- **Expected analyst action:** Treat high-score alerts from historically false-positive rules with appropriate skepticism; check the fidelity line before escalating.
- **Test required:** Integration — a rule with 3+ false-positive verdicts shows fidelity context in the API response and notification payload. Golden scores remain byte-identical.

#### REC-TRIAGE-04 — Detection-lag (dwell-time gap) annotation on the canonical alert
- **Component:** decision-engine · **Priority:** low · **Phase:** 4 · **Status:** proposed
- **Evidence:** `received_at` minus the source event's own timestamp (Wazuh top-level `timestamp`, preserved by the tolerant schema).
- **Factor affected:** canonical annotation `detection_lag_seconds`, surfaced in `decision.reasons` and the digest; no score weight.
- **Reason:** The reference skill highlights the gap between event time and detection time. A large lag signals log-source health problems or silent suppression and matters for MTTA/MTTR reporting; it should never silently inflate a score.
- **Expected analyst action:** When lag exceeds the locally defined threshold, check the log source / integrator path health before triaging the alert.
- **Test required:** Unit — lag computed deterministically from fixed timestamps (zero when the event timestamp is absent). Integration — payload includes lag only when the source timestamp exists.

#### REC-TRIAGE-05 — Historical correlation context (same host / user / source, rolling window)
- **Component:** decision-engine · **Priority:** medium · **Phase:** 3 · **Status:** proposed
- **Evidence:** prior alerts in the alert store matching `agent.id`, `data.srcuser`, or a shared IOC value within the last 30 days.
- **Factor affected:** `decision.reasons` and the console alert detail (correlation list); no scoring.v1 weight.
- **Reason:** The reference skill correlates history before escalating: an incident rarely arrives alone, and a repeat host/user changes the story. The correlation is advisory so analysts keep judgment, not an automatic escalation trigger.
- **Expected analyst action:** Check the correlation panel before submitting a verdict; escalate as one incident when related activity is confirmed.
- **Test required:** Integration — seeding related alerts yields the expected correlation list; determinism test on a fixed dataset. Golden scores unchanged.

#### REC-TRIAGE-06 — Structured triage record rendered in notifications
- **Component:** analyst-runbooks · **Priority:** low · **Phase:** 3 · **Status:** proposed
- **Evidence:** the existing `N8NAlertPayload` fields (alert_id, rule, agent, score, decision, IOCs, enrichment) already cover most of the reference skill's triage-record shape.
- **Factor affected:** notifications payload — display-only addition of classification, affected scope, and recommended-action lines.
- **Reason:** The reference skill documents a structured triage record so the ticket body is complete and consistent. Our WF2/WF3 formatters already render most fields; adding classification and recommended actions (from the runbook) closes the gap without any engine change.
- **Expected analyst action:** Use the rendered record as the ticket body; append or correct affected assets/users.
- **Test required:** Unit — payload builder emits the new display fields. Static n8n test (pattern of `test_n8n_email_chain.py`) — formatters render classification and recommended-action lines.

### Skill 2 — Implementing alert-fatigue reduction

#### REC-FATIGUE-01 — Per-rule disposition metrics (TP / FP / SNR) in the daily digest
- **Component:** analyst-runbooks · **Priority:** high · **Phase:** 3 · **Status:** proposed
- **Evidence:** `feedback.verdict` counts grouped by `rule.id` (true positive / false positive / escalate) over a rolling window.
- **Factor affected:** WF6 daily digest and the Phase 3.9 stats endpoints — reporting only, no scoring factor.
- **Reason:** The reference skill's first step is measuring before changing: per-rule volume, FP rate, and signal-to-noise make tuning decisions reviewable. The digest already plans volumes and FP rate; adding TP rate and SNR per rule is a pure reporting extension.
- **Expected analyst action:** Review the top-noisiest-rules table monthly; nominate rules for tuning review (REC-FATIGUE-02) based on evidence, never on volume alone.
- **Test required:** Integration — seeded verdicts produce the expected per-rule TP/FP/SNR numbers via the stats endpoint; unit tests for the aggregation function.

#### REC-FATIGUE-02 — Evidence-backed tuning suggestions — humans apply every change
- **Component:** human-approval-model · **Priority:** high · **Phase:** 3 · **Status:** proposed · **Approval gate required**
- **Evidence:** 3+ false-positive verdicts on a rule+agent pair (existing mechanism), extended with per-rule evidence: sample alert ids, FP rate, and the common benign pattern.
- **Factor affected:** digest `tuning_suggestions` and the allowlist config (`app/config/allowlists.yaml` is the only place exclusions land — human-edited via PR).
- **Reason:** The reference skill tunes high-volume false-positive rules with documented exclusions and approval. The platform already refuses to auto-edit Wazuh rules; this recommendation makes the suggestion record complete enough for a human to approve with confidence, and keeps the allowlist as the sole machine-consumed exclusion surface.
- **Expected analyst action:** L2 / detection owner reviews the suggestion, verifies the sample evidence, and applies an allowlist or rule change via **reviewed PR** with an expected-FP-reduction note.
- **Test required:** Unit — the suggestion record always includes evidence ids, FP rate, and expected impact. Integration — a suggestion appears in the digest only after the 3-FP threshold is met, and nothing auto-edits any rule file.

#### REC-FATIGUE-03 — Entity-based consolidation as a read-only correlation view
- **Component:** scoring-engine · **Priority:** low · **Phase:** 4 · **Status:** proposed
- **Evidence:** existing dedupe groups (`rule.id` + `agent.id`) plus a shared src IP / user across different rules within a window.
- **Factor affected:** `scoring.recurrence_velocity` — **view only**; the dedupe group key and all scoring.v1 inputs stay byte-identical.
- **Reason:** The reference skill consolidates related alerts into one investigation unit so a campaign does not produce parallel queues. Changing the dedupe group key would alter recurrence inputs and therefore scores, so the consolidation is delivered as a read-only correlation view in the console/API; the analyst decides whether it is one incident.
- **Expected analyst action:** Open the correlation view; escalate the related alerts as a single incident when they belong to one campaign.
- **Test required:** Unit — correlation grouping is pure and deterministic. Integration — enabling the view changes zero scores and zero dedupe groups (explicit assertion against golden files).

#### REC-FATIGUE-04 — Feedback-verified suppression patterns via the existing allowlist path
- **Component:** decision-engine · **Priority:** medium · **Phase:** 3 · **Status:** proposed · **Approval gate required**
- **Evidence:** repeated false-positive verdicts tied to a concrete allowlistable source (scanner IP, backup job, CDN range) already represented in IOC enrichment.
- **Factor affected:** `decision.allowlisted_action` (suppress) — the existing allowlisted path, extended only by adding verified patterns to `app/config/allowlists.yaml`.
- **Reason:** The reference skill tier-1 routes known-FP patterns to automatic suppression. The platform already suppresses allowlisted sources regardless of score; this recommendation only widens the allowlist input with feedback-verified patterns, always human-approved, with the existing audit entry retained.
- **Expected analyst action:** Approve or decline each proposed suppression pattern in the quarterly allowlist review; verify the audit trail of suppressed alerts shows no true positives lost.
- **Test required:** Integration — an allowlisted alert is suppressed regardless of score (existing test) and writes the audit row; new test that a pattern only suppresses after human approval lands it in the allowlist file.

### Skill 3 — Analyzing indicators of compromise

#### REC-IOC-01 — Optional multi-source enrichment (AbuseIPDB / MalwareBazaar) behind the provider contract
- **Component:** ioc-provenance · **Priority:** medium · **Phase:** 2 · **Status:** proposed
- **Evidence:** `IOC.enrichment` today holds `vt` and `misp` payloads only; the provider protocol (`name` / `enabled` / `enrich`) and `LookupRecord` provenance already support more sources.
- **Factor affected:** `ioc.enrichment` — new provider payloads keyed by provider name; `enrichment_status` aggregation and scoring.v1 semantics unchanged.
- **Reason:** The reference skill warns against over-relying on a single source for high-stakes decisions. Free-tier AbuseIPDB (IP reputation) and MalwareBazaar (hash family/tags) slot into the existing fail-open, rate-limited, sanitized-provenance machinery with zero scoring changes; an exhausted quota or outage still only marks the alert enrichment `partial`.
- **Expected analyst action:** Compare verdicts across sources; conflicting signals (e.g. VT malicious vs AbuseIPDB clean) warrant manual review before escalation.
- **Test required:** Unit — sanitization, token-bucket rate limiting, and lookup-status mapping for each new provider (mirror the existing VT/MISP tests). Integration — provider outage marks enrichment `partial` and the alert still scores.

#### REC-IOC-02 — Shared-infrastructure awareness (CDN / cloud ranges) as analyst context
- **Component:** ioc-provenance · **Priority:** medium · **Phase:** 4 · **Status:** proposed · **Approval gate required**
- **Evidence:** a VT/AbuseIPDB verdict on an IPv4 belonging to a known CDN or cloud provider range (Cloudflare, CloudFront, major clouds) colliding with the allowlist policy.
- **Factor affected:** `ioc.enrichment` (informational shared-infrastructure tag on the indicator) and `decision.reasons`; no score change.
- **Reason:** The reference skill's key pitfall is blocking shared infrastructure and disrupting legitimate tenants. Tagging CDN/cloud ranges as context means a reputation hit on a shared IP is seen with its caveats, and any deny-list or allowlist decision stays a human, approved, audited action.
- **Expected analyst action:** When a shared-infrastructure-tagged IP drives a high score, verify the actual tenant/service before escalating; any allowlist addition requires approval via reviewed PR.
- **Test required:** Unit — CDN/cloud range detection is a pure function with pinned fixtures. Integration — the tagged indicator surfaces the tag in the payload and scoring is unchanged.

#### REC-IOC-03 — IOC age / expiry surfaced from stored lookup timestamps
- **Component:** ioc-provenance · **Priority:** low · **Phase:** 3 · **Status:** proposed
- **Evidence:** `LookupRecord.timestamp` already stored per provider on every `IOC.enrichment` payload.
- **Factor affected:** `ioc.enrichment` provenance — analyst-facing age field computed from the stored timestamp; cache TTLs unchanged; no score weight.
- **Reason:** The reference skill warns that indicators without expiry policies accumulate and generate stale verdicts as infrastructure is repurposed. Our cache already expires entries; making the age visible lets analysts discount stale verdicts by judgment instead of by a blindly copied TTL number.
- **Expected analyst action:** Treat verdicts older than the locally defined window as lower-confidence context; request a re-enrichment when recency matters.
- **Test required:** Unit — age computed deterministically from fixed timestamps. Integration — payload shows enrichment age per indicator; existing cache TTL tests unchanged.

#### REC-IOC-04 — Defanged rendering everywhere analysts copy indicators
- **Component:** analyst-runbooks · **Priority:** low · **Phase:** 3 · **Status:** proposed
- **Evidence:** the extractor already normalizes defanged input (`hxxp://`, `evil[.]example[.]com`) and strips URL userinfo; WF2 formatters already group IOCs by type.
- **Factor affected:** notifications payload rendering and runbook documents — display only; stored IOC values unchanged.
- **Reason:** The reference skill requires defanging in documentation so pasting an indicator never triggers scanners or accidental clicks. Rendering-level defanging extends the extractor's existing normalization to every analyst-facing surface.
- **Expected analyst action:** Copy indicators directly from notifications/runbooks/console (already safe); never hand-paste raw log lines.
- **Test required:** Unit/static — renderer output contains no live scheme or un-defanged domain patterns outside allow-listed link fields (pattern of the existing n8n static tests).

#### REC-IOC-05 — Campaign attribution surfaced from MISP event tags
- **Component:** ioc-provenance · **Priority:** medium · **Phase:** 3 · **Status:** proposed
- **Evidence:** `misp.matched_event_ids` and `tags` (e.g. `tlp:amber`, `apt`, threat-actor) already stored in `IOC.enrichment`.
- **Factor affected:** `ioc.enrichment` detail and `decision.reasons` — the scoring detail already mentions MISP tags; make them analyst-visible in payload and console.
- **Reason:** The reference skill contextualizes IOCs with campaign attribution before disposition. MISP tags are context, not a v1 weight: surfacing them in the notification and console lets the analyst apply the campaign section of the runbook without any score change.
- **Expected analyst action:** When campaign tags are present, follow the runbook's campaign-attribution section and escalate per the playbook's criteria.
- **Test required:** Unit — tag sanitization keeps only allow-listed tags (existing test). Integration — payload IOC summary surfaces tags; golden scores unchanged.

#### REC-IOC-06 — Confidence/disposition framework — thresholds derived from our own corpus, never copied
- **Component:** scoring-engine · **Priority:** medium · **Phase:** 5 · **Status:** proposed · **Approval gate required**
- **Evidence:** VT detection counts, MISP matches, and (future) multi-source verdicts in `IOC.enrichment`, correlated with analyst verdicts from the feedback table.
- **Factor affected:** `scoring.threat_intel` — a future factor in a **new** policy version (scoring.v2+); scoring.v1 and its goldens stay the default until humans approve the migration.
- **Reason:** The reference skill offers a block/monitor/whitelist confidence framework, but its numeric bands are not ours to copy. The methodology — tiered disposition informed by multiple sources — is worth adopting as a future factor in a new policy version (scoring.v2+), leaving scoring.v1 untouched, with thresholds derived from our own labelled corpus via the Phase 5.4 evaluation harness and approved by analysts.
- **Expected analyst action:** Participate in the threshold review: approve derived bands only with evidence of false-positive/true-negative impact on the sample corpus.
- **Test required:** Golden-file and evaluation-harness tests — candidate thresholds are scored against the labelled corpus before any migration; a migration test asserts v1 behavior stays byte-identical until v2 ships.

### Skill 4 — Building incident-response playbooks

#### REC-PLAYBOOK-01 — Standardized runbook template (metadata, RACI, procedures, communication)
- **Component:** analyst-runbooks · **Priority:** high · **Phase:** now · **Status:** delivered
- **Evidence:** `docs/runbooks/` was scaffolded with a planned template; notifications already link `decision.runbook` to `docs/runbooks/<scenario>.md`.
- **Factor affected:** analyst runbooks — new `docs/runbooks/_template.md` plus per-scenario runbooks (Phase 3.6), consistent with the reference skill's playbook structure.
- **Reason:** The reference skill shows that a consistent playbook structure (metadata, RACI, detection, procedures, escalation, communication) keeps procedures maintainable and auditable. Delivering the template now (with one exemplar runbook) anchors every later runbook and makes the runbook contract testable.
- **Expected analyst action:** L2 maintains runbooks from the template; analysts follow the linked runbook during triage and submit corrections via PR.
- **Test required:** Doc contract test — every non-template runbook parses the required sections and phrases any response step as an approval-gated proposal.

#### REC-PLAYBOOK-02 — Per-runbook decision trees and escalation criteria
- **Component:** analyst-runbooks · **Priority:** medium · **Phase:** 3 · **Status:** proposed
- **Evidence:** the decision engine already maps tiers to actions (`monitor` / `queue_l1` / `open_incident`) with 15/30-minute ack SLAs; runbooks will embed the matching binary decision points.
- **Factor affected:** analyst runbooks (decision-tree section) and `decision.reasons` (runbook already linked per tier).
- **Reason:** The reference skill uses binary decision points to reduce hesitation and documents escalation triggers beyond SLAs (e.g. confirmed exfiltration → L2/IR lead). Encoding the existing tier decisions as runbook trees keeps analysts and automation consistent.
- **Expected analyst action:** Follow the tree; escalate per the documented criteria — escalation is always analyst-initiated, never automatic beyond the existing SLA re-notify.
- **Test required:** Doc contract test — runbook decision trees reference only existing actions/tiers; integration — escalation-criteria list surfaced in the payload for the analyst.

#### REC-PLAYBOOK-03 — Containment = proposal only, human-approved, audited (no autonomous actions)
- **Component:** human-approval-model · **Priority:** high · **Phase:** 4 · **Status:** proposed · **Approval gate required**
- **Evidence:** ADR-8 and Phase 4.5 already define Wazuh active-response as a proposal requiring explicit analyst approval with audit rows.
- **Factor affected:** human-approval-model — the WF5 `contain` verdict → approval workflow → audited action; scoring and decision engines unchanged.
- **Reason:** The reference skill's containment procedures (endpoint isolation, account disable, sinkhole) are instructive only. Our charter forbids autonomous containment: every runbook containment step is phrased as a proposal, executes only after explicit analyst approval, and writes audit rows either way.
- **Expected analyst action:** Approve or decline each containment proposal with a documented rationale; the audit log records who decided what, when.
- **Test required:** Integration — the approval endpoint rejects unauthenticated or unauthorized requests; no test or code path may execute a containment action without approval (negative-path tests included).

#### REC-PLAYBOOK-04 — Documented automation boundary (what runs automatically vs. what needs humans)
- **Component:** human-approval-model · **Priority:** medium · **Phase:** 3 · **Status:** proposed · **Approval gate required**
- **Evidence:** the existing separation — enrichment, scoring, routing, and notification are automated; verdicts, containment, and rule changes are human; WF1–WF6 define the orchestration surface.
- **Factor affected:** workflow documentation (n8n README) and runbooks — an explicit automation-boundary table; no engine change.
- **Reason:** The reference skill maps each playbook step to a SOAR action and defines the automation boundary. Making our existing boundary explicit per workflow prevents future scope creep toward autonomous response and is auditable in review.
- **Expected analyst action:** Understand which steps are never automated; raise a proposal if a step seems to cross the boundary.
- **Test required:** Static test — n8n workflow JSONs contain no containment-capable nodes (no remote-exec/SSH/PowerShell nodes), extending the existing workflow static tests.

#### REC-PLAYBOOK-05 — Playbook testing and maintenance cadence
- **Component:** analyst-runbooks · **Priority:** low · **Phase:** 3 · **Status:** proposed
- **Evidence:** the sample-alert corpus doubles as CI fixtures; the Phase 5.4 evaluation harness will replay history; runbook links are already carried in every notification.
- **Factor affected:** analyst-runbooks maintenance workflow and CI (runbook link resolution check); no scoring factor.
- **Reason:** The reference skill validates playbooks through exercises and scheduled review. The cheapest continuous exercise available here is CI replaying the sample corpus and verifying every runbook link resolves; quarterly human review remains the maintenance gate.
- **Expected analyst action:** Quarterly runbook review (owner, contact list, commands); annual tabletop using the sample scenarios.
- **Test required:** CI contract — runbook links in decisions resolve to existing files (new doc test); existing corpus replay stays green.

---

## What we deliberately did NOT adopt (and why)

| Reference-skill element | Rejected because | Our equivalent |
| --- | --- | --- |
| P1–P4 severity bands, 15-min/1-h containment SLAs, 30/90-day IOC TTLs, ≥70% confidence bands, 40–60 alerts/analyst targets | Guardrail 1 — thresholds must come from our corpus, not the reference | Existing 0–100 tier bands + SEV1/SEV2 SLAs; corpus-derived thresholds via [REC-IOC-06](#rec-ioc-06) |
| Endpoint isolation via EDR, account disable, DNS sinkhole, auto-contain | Guardrail 4 — no autonomous containment (ADR-8) | Human-approved containment *proposals* in runbooks + WF5 approval flow ([REC-PLAYBOOK-03](#rec-playbook-03)) |
| Rule auto-tuning / auto-exclusion from alert history | Guardrail 2 + charter — the platform never edits Wazuh rules | Evidence-backed tuning suggestions, human-applied via PR ([REC-FATIGUE-02](#rec-fatigue-02)) |
| Splunk-specific RBA/notable-event mechanics | Platform-foreign implementation detail | The platform already *is* risk-based; mapped to existing factors instead |
| STIX export, TheHive case mirroring as a requirement | Out of scope for the core loop (Phase 4+ optional) | Audit log + feedback tables remain the system of record |

---

## Determinism & explainability statement

Every recommendation preserves the core contract (ARCHITECTURE.md §8, ADR-5):

- Scores remain a **pure function** of (canonical alert, enrichments, validated policy).
- Any recommendation that would move a number requires **golden-file tests** proving the
  v1 scores are unchanged until a reviewed migration to a new policy version.
- Context additions (fidelity, correlation, detection lag, IOC age, shared-infrastructure
  tags, classification) are **advisory by design**: they appear in `decision.reasons`,
  payloads, and the console — never as hidden weights.
- All recommendations are non-secret, version-controlled, and reviewable as diffs, in
  line with §14's policy model.
