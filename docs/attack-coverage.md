# MITRE ATT&CK Mapping Framework

**Roadmap item:** Phase 6.2 — MITRE ATT&CK mapping framework.
**Machine-readable source of truth:** [`evaluation/attack_mappings.yaml`](../evaluation/attack_mappings.yaml)
**Validation:** [`app/tests/evaluation/test_attack_mappings.py`](../app/tests/evaluation/test_attack_mappings.py)
**Companion inventory (Phase 6.1):** [`evaluation/detection_catalog.yaml`](../evaluation/detection_catalog.yaml) · [`docs/detection-coverage.md`](detection-coverage.md)

This document renders, for humans, the technique-first view of the MITRE ATT&CK
mappings the repository's Wazuh detections and evaluation scenarios declare. It
makes each mapping traceable along one chain:

```
Wazuh detection → rule → ATT&CK technique → scenario → expected outcome
→ regression test → analyst/runbook context
```

**No ATT&CK reference data is used or claimed.** The repository pins no ATT&CK
matrix version and performs no STIX, API, or other external lookup. Every
technique id, name, and tactic below is *declared by a repository file* (the
custom ruleset declares ids only; the evaluation fixtures declare id, name, and
tactic triples) and is recorded verbatim with its provenance. The registry's
`attack_reference.matrix_verification: unverified` flag states exactly that:
declared values are traceable, not verified. Values that look wrong are still
recorded as declared — the one known conflict between sources is pinned under
[Known discrepancy (G5)](#known-discrepancy-g5) rather than resolved.

## What this framework is — and is not

- It is a **reporting and traceability layer**: registry data + a rendered view
  + static validation tests. The chain above can be followed in both
  directions, and every cell is either backed by repository evidence or an
  explicit `—`.
- It changes **no** runtime behavior. The triage pipeline keeps consuming the
  source-declared `rule.mitre` block verbatim; this registry never scores,
  routes, deduplicates, correlates, or enriches anything.
- It does **not** correct, complete, or validate ATT&CK metadata against an
  external matrix — that would require reference data the repository does not
  carry (see the flag above).
- It does **not** measure detection quality or live Wazuh rule coverage; that
  remains a documented gap of the Phase 6 framework (gap G8 in
  [`docs/detection-coverage.md`](detection-coverage.md), roadmap item 6.6).

`—` in any table cell means **no repository evidence exists for that cell** —
absence is recorded, never guessed.

## Technique registry (declared values, verbatim)

One row per distinct ATT&CK technique id declared by a repository source. Names
and tactics are the verbatim fixture declarations (`rule.mitre.technique` /
`rule.mitre.tactic`); they are empty (`—`) when no fixture declares them.

| Technique | Declared name(s) | Declared tactic(s) | Name/tactic provenance | Custom rule(s) | Fixture rule(s) | Scenario(s) | Runbook(s) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `T1110` | Brute Force: Password Guessing | Credential Access | `01_wazuh_ssh_brute_force.json`, `07_wazuh_ssh_brute_force_recurrence.json`, `11_custom_ssh_rule_100100.json`, `15_ssh_failed_auth_below_threshold.json` | `100100` | `5710`, `5712` | `SCN-01`, `SCN-07`, `SCN-11`, `SCN-15` | `docs/runbooks/ssh-brute-force.md` |
| `5712` | synthetic fixture | `15_ssh_failed_auth_below_threshold.json` | `T1110` | `SCN-15` |
| `T1136` | Create Account: Local Account | Persistence | `06_wazuh_windows_user_created.json` | — | `60180` | `SCN-06` | `docs/runbooks/account-creation.md` |
| `T1190` | Exploit Public-Facing Application | Initial Access | `05_wazuh_web_sql_injection.json`, `10_wazuh_web_sql_injection_staging.json`, `13_custom_web_rule_100120_env.json`, `14_custom_web_recurrence_rule_100121.json` | `100120`, `100121` | `31103` | `SCN-05`, `SCN-10`, `SCN-13`, `SCN-14` | `docs/runbooks/web-attack.md` |
| `T1204` | User Execution: Malicious File | Execution, Initial Access | `04_wazuh_malware_hash_virustotal.json`, `09_wazuh_malware_hash_critical_server.json` | — | `87105` | `SCN-04`, `SCN-09` | `docs/runbooks/malware-hash.md` |
| `T1565` | Data Manipulation | Impact | `12_custom_fim_rule_100110.json` | `100110` | — | `SCN-12` | `docs/runbooks/fim-critical-file.md` |
| `T1566` | Modify Authentication Process | Persistence, Privilege Escalation | `03_wazuh_fim_etc_passwd_change.json` | — | `550` | `SCN-03` | `docs/runbooks/fim-critical-file.md` |

**Reading notes**

- The technique set is exactly the set of ids the repository declares — the
  validation test enforces both directions (no invented id, none missing).
- `T1565` is declared by the custom ruleset only, so no name or tactic exists
  for it in any machine-readable source. The Phase 6.1 coverage document
  hand-annotates a tactic for it in prose; that annotation is documentation,
  not data, and is deliberately not recorded here.
- `T1566` and `T1565` describe the *same behavior class* through two different
  sources — see [Known discrepancy (G5)](#known-discrepancy-g5).
- Runbooks are joined through the scenarios that declare the technique (the
  Phase 6.1 catalog carries the scenario → runbook link).

## Rule → technique mappings

Every rule id the repository's detection content declares: the four custom
SOC-triage rules (`ruleset-xml` provenance) and the rule ids declared inside
the evaluation fixtures (`synthetic-fixture` provenance — illustrative
Wazuh-style ids, not live-manager-observed; see
[`docs/sample-alerts/README.md`](sample-alerts/README.md)).

| Rule | Source | Declared by | Techniques | Related catalog entries |
| --- | --- | --- | --- | --- |
| `100100` | custom ruleset | `soc-triage-rules.xml` | `T1110` | `DET-100100` · `SCN-01` (behavioral-overlap) |
| `100110` | custom ruleset | `soc-triage-rules.xml` | `T1565` | `DET-100110` · `SCN-03` (parent-rule) |
| `100120` | custom ruleset | `soc-triage-rules.xml` | `T1190` | `DET-100120` · `SCN-05` (behavioral-overlap) |
| `100121` | custom ruleset | `soc-triage-rules.xml` | `T1190` | `DET-100121` · `SCN-05` (behavioral-overlap) |
| `550` | synthetic fixture | `03_wazuh_fim_etc_passwd_change.json` | `T1566` | `SCN-03` |
| `5710` | synthetic fixture | `01_wazuh_ssh_brute_force.json`, `07_wazuh_ssh_brute_force_recurrence.json` | `T1110` | `SCN-01`, `SCN-07` |

| `5715` | synthetic fixture | `02_wazuh_ssh_brute_force_success.json` | — | `SCN-02` |
| `5716` | synthetic fixture | `08_wazuh_ssh_session_opened.json` | — | `SCN-08` |
| `31100` | synthetic fixture | `16_ordinary_web_request.json` | — | `SCN-16` |
| `31103` | synthetic fixture | `05_wazuh_web_sql_injection.json`, `10_wazuh_web_sql_injection_staging.json` | `T1190` | `SCN-05`, `SCN-10` |
| `60180` | synthetic fixture | `06_wazuh_windows_user_created.json` | `T1136` | `SCN-06` |
| `87105` | synthetic fixture | `04_wazuh_malware_hash_virustotal.json`, `09_wazuh_malware_hash_critical_server.json` | `T1204` | `SCN-04`, `SCN-09` |

**Reading notes**

- `100110` is a child of fixture rule `550` (`if_sid`) — the two sources
  disagree on the technique id for the same behavior; both mappings are
  recorded as declared and pinned as discrepancy G5 below.
- Rules `5715` and `5716` declare no technique (their fixtures carry no
  `rule.mitre` block); the absence is recorded, not inferred.
- Custom-rule mappings must stay equal to the detection catalog's
  `detections[].mitre_attack` lists; the validation test enforces it.

## Scenario → technique mappings

Every Phase 5/6.3 evaluation scenario, with the full chain from technique to
the pinned ground-truth outcome, the regression tests that pin it, and the
analyst runbook. Expected outcomes are the values asserted by
[`evaluation/ground_truth.json`](../evaluation/ground_truth.json) — ground truth
remains the single expected-outcome source; this table renders it.

| Scenario | Fixture | Rule (fixture-declared) | Techniques | Expected outcome | Regression test | Runbook |
| --- | --- | --- | --- | --- | --- | --- |
| `SCN-01` | `01_wazuh_ssh_brute_force.json` | `5710` (level 5) | `T1110` | `43` / `low` / `monitor` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_ingest_response_carries_score_and_decision` | `docs/runbooks/ssh-brute-force.md` |
| `SCN-02` | `02_wazuh_ssh_brute_force_success.json` | `5715` (level 3) | — | `27` / `low` / `monitor` | `test_evaluation.py::test_ground_truth_evaluation` | `docs/runbooks/ssh-brute-force.md` |
| `SCN-03` | `03_wazuh_fim_etc_passwd_change.json` | `550` (level 7) | `T1566` | `63` / `medium` / `queue_l1` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_fim_critical_asset_scores_medium_and_queues_l1` | `docs/runbooks/fim-critical-file.md` |
| `SCN-04` | `04_wazuh_malware_hash_virustotal.json` | `87105` (level 12) | `T1204` | `73` / `high` / `open_incident` (`SEV2`) | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_malware_alert_scores_high_and_opens_sev2` | `docs/runbooks/malware-hash.md` |
| `SCN-05` | `05_wazuh_web_sql_injection.json` | `31103` (level 10) | `T1190` | `59` / `medium` / `queue_l1` | `test_evaluation.py::test_ground_truth_evaluation` | `docs/runbooks/web-attack.md` |
| `SCN-06` | `06_wazuh_windows_user_created.json` | `60180` (level 5) | `T1136` | `47` / `medium` / `queue_l1` | `test_evaluation.py::test_ground_truth_evaluation` | `docs/runbooks/account-creation.md` |
| `SCN-07` | `07_wazuh_ssh_brute_force_recurrence.json` | `5710` (level 5) | `T1110` | `43` / `low` / `monitor` | `test_evaluation.py::test_ground_truth_evaluation`, `test_evaluation.py::test_recurrence_scenario_escalates_according_to_ground_truth`, `test_scoring_pipeline.py::test_recurrence_escalation_raises_the_score`, `test_scoring_pipeline.py::test_second_occurrence_below_rapid_burst_does_not_escalate` | `docs/runbooks/ssh-brute-force.md` |
| `SCN-08` | `08_wazuh_ssh_session_opened.json` | `5716` (level 3) | — | `14` / `informational` / `monitor` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_benign_informational_event_stays_informational` | `docs/runbooks/ssh-brute-force.md` |
| `SCN-09` | `09_wazuh_malware_hash_critical_server.json` | `87105` (level 12) | `T1204` | `88` / `critical` / `open_incident` (`SEV1`) | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_malware_on_critical_asset_scores_critical_and_opens_sev1` | `docs/runbooks/malware-hash.md` |
| `SCN-10` | `10_wazuh_web_sql_injection_staging.json` | `31103` (level 10) | `T1190` | `46` / `medium` / `queue_l1` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_low_criticality_asset_holds_medium` | `docs/runbooks/web-attack.md` |

**Reading notes**

- `SCN-07` is the recurrence case: the expected outcome above pins the *first*
  delivery; ground truth additionally pins the escalation after the third
  delivery (`55` / `medium` / `queue_l1`) under its `recurrence` block, which
  this table deliberately does not duplicate.
- `SCN-02` and `SCN-08` declare no technique (their fixtures carry no
  `rule.mitre` block). `SCN-08` is the corpus's benign baseline — its lack of
  ATT&CK metadata is part of what keeps it in the informational band (the
  `rule_groups_mitre` factor counts presence only).
- Regression-test references are abbreviated to `file::test`; full paths live
  in the detection catalog, which the validation tests keep in sync.
| `SCN-11` | `11_custom_ssh_rule_100100.json` | `100100` (level 10) | `T1110` | `59` / `medium` / `queue_l1` | `test_evaluation.py::test_ground_truth_evaluation` | `docs/runbooks/ssh-brute-force.md` |
| `SCN-12` | `12_custom_fim_rule_100110.json` | `100110` (level 8) | `T1565` | `60` / `medium` / `queue_l1` | `test_evaluation.py::test_ground_truth_evaluation` | `docs/runbooks/fim-critical-file.md` |
| `SCN-13` | `13_custom_web_rule_100120_env.json` | `100120` (level 10) | `T1190` | `55` / `medium` / `queue_l1` | `test_evaluation.py::test_ground_truth_evaluation` | `docs/runbooks/web-attack.md` |
| `SCN-14` | `14_custom_web_recurrence_rule_100121.json` | `100121` (level 7) | `T1190` | `47` / `medium` / `queue_l1` | `test_evaluation.py::test_ground_truth_evaluation`, `test_evaluation.py::test_recurrence_scenario_escalates_according_to_ground_truth` | `docs/runbooks/web-attack.md` |
| `SCN-15` | `15_ssh_failed_auth_below_threshold.json` | `5712` (level 5) | `T1110` | `43` / `low` / `monitor` | `test_evaluation.py::test_ground_truth_evaluation` | `docs/runbooks/ssh-brute-force.md` |
| `SCN-16` | `16_ordinary_web_request.json` | `31100` (level 3) | — | `27` / `low` / `monitor` | `test_evaluation.py::test_ground_truth_evaluation` | `docs/runbooks/web-attack.md` |

## Known discrepancy (G5)

The same FIM behavior (modification of a monitored file, e.g. `/etc/passwd`)
is declared as **two different technique ids by two repository sources**:

- `T1566` — declared by the evaluation fixture `SCN-03` (fixture-declared rule
  `550`), which also declares the technique name "Modify Authentication
  Process" and the tactics Persistence, Privilege Escalation.
- `T1565` — declared by the custom rule `DET-100110` (rule `100110`, a child
  of rule `550` via `if_sid`) in the custom ruleset.

Both values are recorded as declared; neither is corrected. The conflict is
pinned as a machine-readable, test-validated discrepancy
(`known_discrepancies` → `G5`, status `recorded-unresolved`) in the registry,
and the validation test fails if either source changes without the record
being updated — or if the record is removed while the conflict persists.
There is **no scoring impact**: `scoring.v1` counts ATT&CK *presence* only (the
`rule_groups_mitre` factor); technique identity never influences a score,
tier, or action. Resolving the conflict requires a deliberate change to one of
the two source files, accompanied by updates to the registry, the detection
catalog, and both coverage documents.

## Registry schema

`evaluation/attack_mappings.yaml` — YAML, `version: "1.0"`. Rules for the file
mirror the detection catalog's: every value must be verifiable from the
repository; nothing is inferred; absence is recorded with an empty list; known
conflicts are recorded, never resolved.

### `attack_reference`

| Field | Value | Meaning |
| --- | --- | --- |
| `source` | `none` | The repository carries no ATT&CK reference data |
| `matrix_verification` | `unverified` | Declared values are traceable, not verified against any ATT&CK release |

### `techniques[]`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | string | yes | Technique id as declared by a source (validated unique; no invented ids) |
| `declared_names` | list[string] | yes | Verbatim `rule.mitre.technique` values of the declaring fixtures (empty when none) |
| `declared_tactics` | list[string] | yes | Verbatim `rule.mitre.tactic` values of the declaring fixtures (empty when none) |
| `metadata_declared_by` | list[{file, path}] | yes | The fixtures declaring the id/name/tactic triple; must be exactly the declaring fixture set |

### `rule_mappings[]`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `rule_id` | string | yes | Unique; a custom rule id or a fixture-declared rule id |
| `source_kind` | string | yes | `ruleset-xml` (custom rule) or `synthetic-fixture` (fixture-declared) |
| `technique_ids` | list[string] | yes | Exactly what the cited sources declare (empty = absence recorded) |
| `declared_by` | list[{file, path}] | yes | Every fixture/ruleset file declaring this rule's techniques |
| `note` | string | no | Prose note (e.g. why a list is empty) |

### `scenario_mappings[]`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `scenario_id` | string | yes | `SCN-<nn>`; must exist in the detection catalog |
| `fixture` | string | yes | The fixture that declares the scenario's `rule.mitre` |
| `technique_ids` | list[string] | yes | Equals the fixture's `rule.mitre.id` and the catalog's `mitre_attack` |
| `path` | string | no | Locator within the fixture |
| `note` | string | no | Prose note (e.g. why a list is empty) |

### `known_discrepancies[]`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | string | yes | Discrepancy identifier (aligned with the coverage-document gap ids) |
| `status` | string | yes | `recorded-unresolved` |
| `summary` | string | yes | What conflicts, in plain language |
| `values` | list[{value, declared_by, detail}] | yes | ≥ 2 conflicting values, each with its source file/path |
| `scoring_impact` | string | yes | Explicit statement of (no) runtime impact |
| `resolution` | string | yes | What a resolution would require (none is applied) |

## Extending the framework

1. Change the *declaring source first* (a fixture, or the custom ruleset) —
   this framework records what sources declare; it never authors mappings.
2. Update `evaluation/attack_mappings.yaml` to mirror the new declarations,
   with provenance. If two sources now disagree, record a new
   `known_discrepancies` entry (both values, both sources) instead of picking
   a winner.
3. Update the tables in this document to match.
4. Run `cd app && pytest tests/evaluation -q` — both validation suites (this
   framework and the Phase 6.1 coverage framework) fail on any drift between
   the registry, the sources, the catalog, the ground truth, the runbooks,
   and this document.
5. Leave a cell as `—` when the evidence does not exist. Gaps are reported,
   not filled in.
