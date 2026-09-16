# Detection Coverage Framework

**Roadmap item:** Phase 6.1 — detection coverage framework (implementation task: Phase 6.2).
**Machine-readable source of truth:** [`evaluation/detection_catalog.yaml`](../evaluation/detection_catalog.yaml)
**Validation:** [`app/tests/evaluation/test_detection_coverage.py`](../app/tests/evaluation/test_detection_coverage.py)
**Quality gate (roadmap 6.6):** [`app/tests/evaluation/test_detection_quality_gates.py`](../app/tests/evaluation/test_detection_quality_gates.py)
**Related (roadmap 6.2):** the technique-first ATT&CK mapping registry [`evaluation/attack_mappings.yaml`](../evaluation/attack_mappings.yaml), rendered in [`docs/attack-coverage.md`](attack-coverage.md)

This document makes each supported detection traceable along one chain:

```
Wazuh rule → ATT&CK technique → evaluation scenario → expected triage outcome
           → analyst runbook → regression test
```

It is a **description of what exists**, not a plan and not a claim of live coverage. Every
value in the catalog is verified against repository files by the validation test above:

| Field | Verified against |
| --- | --- |
| Custom rules (id, level, ATT&CK ids, groups, trigger) | `wazuh/ruleset/rules/soc-triage-rules.xml` |
| Decoder references | `wazuh/ruleset/decoders/soc-triage-decoders.xml` |
| Scenario fixtures (rule id/level, ATT&CK ids) | `app/tests/fixtures/*.json` (and the identical copies in `docs/sample-alerts/`) |
| Expected score / tier / action / severity | `evaluation/ground_truth.json` |
| Scenario ↔ corpus membership | `evaluation/corpus.json` |
| Runbook references | the referenced file under `docs/runbooks/` |
| Regression-test references | the referenced file and `def <test_name>(` inside it |

**Scope limits — what this framework is not:**

- It changes **no** scoring or decision-routing behavior. There is no runtime code path:
  the catalog is data, the table below is its rendered view, and the validation is a
  read-only test.
- It does not measure live Wazuh rule coverage, rule health, or manager-side firing.
- It does not add, correct, or reinterpret ATT&CK metadata; it records what the rules and
  fixtures already declare (including the discrepancy listed in [Known gaps](#known-gaps)).

---

## Detection coverage (custom SOC-triage rules)

Every row below is a rule that exists in `wazuh/ruleset/rules/soc-triage-rules.xml`. The
ruleset is mounted read-only into the optional `full` compose profile.

| Detection ID | Wazuh rule ID | Detection / behavior | MITRE ATT&CK | Evaluation scenario | Expected score | Expected tier | Expected action | Analyst action / runbook | Regression test | Validation status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `DET-100100` | `100100` (level 10) | Repeated SSH authentication failures (`if_matched_sid` 5712, 5 in 300 s) | `T1110` (Credential Access) | `SCN-01` · behavioral overlap | — | — | — | `docs/runbooks/ssh-brute-force.md` (behavioral overlap, not policy-wired) | None — no fixture exercises this rule | **Authored** — not live-validated |
| `DET-100110` | `100110` (level 8) | Monitored file modified / FIM (`if_sid` 550) | `T1565` (Impact) | `SCN-03` · parent rule | — | — | — | `docs/runbooks/fim-critical-file.md` (parent-rule overlap, not policy-wired) | None — no fixture exercises this rule | **Authored** — not live-validated |
| `DET-100120` | `100120` (level 10) | Suspicious web request path (`decoded_as` `soc-web`) | `T1190` (Initial Access) | `SCN-05` · behavioral overlap | — | — | — | `docs/runbooks/web-attack.md` (behavioral overlap, not policy-wired) | None — no fixture exercises this rule | **Authored** — not live-validated |
| `DET-100121` | `100121` (level 7) | Repeated suspicious web requests (`if_matched_sid` 100120, 5 in 300 s) | `T1190` (Initial Access) | `SCN-05` · behavioral overlap | — | — | — | `docs/runbooks/web-attack.md` (behavioral overlap, not policy-wired) | None — no fixture exercises this rule | **Authored** — not live-validated |

**Legend**

- `—` in an outcome column means **no runtime expectation exists for that rule**. No
  evaluation fixture exercises these custom rules, so writing a score, tier, or action in
  those cells would be a fabricated claim. The real, pinned outcomes belong to the
  scenarios and are listed in the next table.
- **Scenario link kinds** (catalog field `scenario_link`) — how a rule relates to a
  scenario, with no implied equivalence:
  - `direct` — a fixture carries this exact rule id (not used today: no fixture carries a
    custom rule id).
  - `parent-rule` — the custom rule is a child of the rule the fixture carries
    (`if_sid`). True for `DET-100110`, whose parent `550` is the rule in `SCN-03`.
  - `behavioral-overlap` — same behavior class and a shared ATT&CK id, but a **different
    rule path**. `DET-100100` matches on `5712` while `SCN-01` carries `5710`;
    `DET-100120`/`DET-100121` require the lab `soc-web` decoder while `SCN-05` is a
    built-in web rule.
  - `none` — no scenario relationship.
- **Validation status** (catalog field `validation_status`):
  - `authored` — the rule exists in the ruleset; no fixture exercises it and no live
    Wazuh rule match has been recorded (matches the Phase 4.3 status: authored, not
    live-validated).
  - `validated` — exercised end-to-end or live-validated. **No custom rule is at this
    status today.**

---

## Scenario coverage (Phase 5 evaluation corpus, expanded in Phase 6.3)

Each scenario is one synthetic fixture in `app/tests/fixtures/` (identical copy in
`docs/sample-alerts/`) that is replayed through the real ingest path
(`normalize → dedupe → score → decide`) and compared against ground truth by
`test_evaluation.py`. Phase 6.3 grew the corpus from ten to sixteen scenarios and added its
first multi-delivery case (`SCN-07`, recurrence).

| Scenario ID | Fixture | Wazuh rule (fixture-declared) | MITRE ATT&CK | Expected score | Expected tier | Expected action | Analyst action / runbook | Regression test | Validation status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `SCN-01` | `01_wazuh_ssh_brute_force.json` | `5710` (level 5) | `T1110` | 43 | low | `monitor` | `docs/runbooks/ssh-brute-force.md` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_ingest_response_carries_score_and_decision` | **Locally validated** |
| `SCN-02` | `02_wazuh_ssh_brute_force_success.json` | `5715` (level 3) | — (none declared) | 27 | low | `monitor` | `docs/runbooks/ssh-brute-force.md` | `test_evaluation.py::test_ground_truth_evaluation` | **Locally validated** |
| `SCN-03` | `03_wazuh_fim_etc_passwd_change.json` | `550` (level 7) | `T1566` (as declared by the fixture — see gaps) | 63 | medium | `queue_l1` | `docs/runbooks/fim-critical-file.md` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_fim_critical_asset_scores_medium_and_queues_l1` | **Locally validated** |
| `SCN-04` | `04_wazuh_malware_hash_virustotal.json` | `87105` (level 12) | `T1204` | 73 | high | `open_incident` (`SEV2`) | `docs/runbooks/malware-hash.md` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_malware_alert_scores_high_and_opens_sev2` | **Locally validated** |
| `SCN-05` | `05_wazuh_web_sql_injection.json` | `31103` (level 10) | `T1190` | 59 | medium | `queue_l1` | `docs/runbooks/web-attack.md` | `test_evaluation.py::test_ground_truth_evaluation` | **Locally validated** |
| `SCN-06` | `06_wazuh_windows_user_created.json` | `60180` (level 5) | `T1136` | 47 | medium | `queue_l1` | `docs/runbooks/account-creation.md` | `test_evaluation.py::test_ground_truth_evaluation` | **Locally validated** |
| `SCN-07` | `07_wazuh_ssh_brute_force_recurrence.json` | `5710` (level 5) | `T1110` | 43 | low | `monitor` | `docs/runbooks/ssh-brute-force.md` | `test_evaluation.py::test_ground_truth_evaluation`, `test_evaluation.py::test_recurrence_scenario_escalates_according_to_ground_truth`, `test_scoring_pipeline.py::test_recurrence_escalation_raises_the_score`, `test_scoring_pipeline.py::test_second_occurrence_below_rapid_burst_does_not_escalate` | **Locally validated** |
| `SCN-08` | `08_wazuh_ssh_session_opened.json` | `5716` (level 3) | — (none declared) | 14 | informational | `monitor` | `docs/runbooks/ssh-brute-force.md` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_benign_informational_event_stays_informational` | **Locally validated** |
| `SCN-09` | `09_wazuh_malware_hash_critical_server.json` | `87105` (level 12) | `T1204` | 88 | critical | `open_incident` (`SEV1`) | `docs/runbooks/malware-hash.md` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_malware_on_critical_asset_scores_critical_and_opens_sev1` | **Locally validated** |
| `SCN-10` | `10_wazuh_web_sql_injection_staging.json` | `31103` (level 10) | `T1190` | 46 | medium | `queue_l1` | `docs/runbooks/web-attack.md` | `test_evaluation.py::test_ground_truth_evaluation`, `test_scoring_pipeline.py::test_low_criticality_asset_holds_medium` | **Locally validated** |
| `SCN-11` | `11_custom_ssh_rule_100100.json` | `100100` (level 10) | `T1110` | 59 | medium | `queue_l1` | `docs/runbooks/ssh-brute-force.md` | `test_evaluation.py::test_ground_truth_evaluation` | **Locally validated; synthetic custom-rule output** |
| `SCN-12` | `12_custom_fim_rule_100110.json` | `100110` (level 8) | `T1565` | 60 | medium | `queue_l1` | `docs/runbooks/fim-critical-file.md` | `test_evaluation.py::test_ground_truth_evaluation` | **Locally validated; synthetic custom-rule output** |
| `SCN-13` | `13_custom_web_rule_100120_env.json` | `100120` (level 10) | `T1190` | 55 | medium | `queue_l1` | `docs/runbooks/web-attack.md` | `test_evaluation.py::test_ground_truth_evaluation` | **Locally validated; synthetic custom-rule output** |
| `SCN-14` | `14_custom_web_recurrence_rule_100121.json` | `100121` (level 7) | `T1190` | 47 | medium | `queue_l1` | `docs/runbooks/web-attack.md` | `test_evaluation.py::test_ground_truth_evaluation`, `test_evaluation.py::test_recurrence_scenario_escalates_according_to_ground_truth` | **Locally validated; application recurrence only** |
| `SCN-15` | `15_ssh_failed_auth_below_threshold.json` | `5712` (level 5) | `T1110` | 43 | low | `monitor` | `docs/runbooks/ssh-brute-force.md` | `test_evaluation.py::test_ground_truth_evaluation` | **Locally validated; synthetic non-match shape** |
| `SCN-16` | `16_ordinary_web_request.json` | `31100` (level 3) | — (none declared) | 27 | low | `monitor` | `docs/runbooks/web-attack.md` | `test_evaluation.py::test_ground_truth_evaluation` | **Locally validated; synthetic non-match shape** |

**Reading notes**

- Rule ids here are **declared inside the synthetic fixtures**. `docs/sample-alerts/README.md`
  documents them as "illustrative Wazuh-style IDs — verify against your Wazuh version
  before using with a real manager" (catalog field `rule_provenance: synthetic-fixture`).
  Only the Phase 4.1/4.2 integrator path has been live-validated end-to-end, and that
  validation used built-in rule `60602`, which is **not** part of this corpus.
- `SCN-04` (SEV2) and `SCN-09` (SEV1) pin decision `severity` in ground truth; `SCN-09`
  is the only scenario in the critical tier.
- **Recurrence case (`SCN-07`).** The corpus case declares `deliveries: 3`; the harness
  replays the fixture as three distinct events of the same rule+agent group. Ground truth
  pins the first delivery under `expected` (43 / low / `monitor` — identical to `SCN-01`
  by design) and the escalation under a `recurrence` block: after the third delivery the
  score is 55, tier medium, action `queue_l1`, with `occurrences: 3` and a `repeated`
  dedupe status. The catalog mirrors that block verbatim; ground truth stays the single
  expected-outcome source.
- **Label semantics (Phase 6.3).** Corpus labels classify the *scenario*, not each pinned
  outcome: `negative` means every pinned outcome stays passive (`monitor`/`suppress`) —
  routing a benign case to L1/incident fails the evaluation; `positive` means an
  attack/malicious scenario whose pinned outcomes must never be `suppress`. A positive
  scenario whose first occurrence stays `monitor` (`SCN-01`, the UC-1 first-occurrence
  case) is an accepted under-triage result and is reported transparently as an FN by the
  harness metrics.
- Expected values are the ones pinned by `evaluation/ground_truth.json`; they are asserted
  by the runtime evaluation test, not estimated here.
- Test names are abbreviated to the file basename; full paths are in the catalog
  (`app/tests/evaluation/…`, `app/tests/integration/…`).

---

## Known gaps

Explicit and intentional: these are the parts of the chain that the repository does **not**
support today. Nothing below is "to be filled in later with a guess" — each item names what
is missing and, where one exists, the roadmap item that would close it.

| # | Gap | Evidence | Status |
| --- | --- | --- | --- |
| G1 | **No custom detection rule for `SCN-02`, `SCN-04`, `SCN-06`** — these scenarios rely solely on built-in rule ids declared in the fixture | `wazuh/ruleset/rules/soc-triage-rules.xml` defines only rules 100100–100121 (SSH, FIM, web) | Not mapped — outstanding |
| G2 | **No custom detection rule for account creation (Windows 4720)** — `SCN-06` has ATT&CK `T1136` and no corresponding rule | ruleset covers SSH/FIM/web only | Not mapped — outstanding |
| G3 | **No fixture exercises any custom rule** — `DET-100100`–`DET-100121` have no regression coverage; their runtime behavior (level → score path) is unproven | `regression_tests: []` in the catalog; already recorded as Phase 4.3 "authored, not live-validated" in `DEVELOPMENT_PLAN.md` | Outstanding |
| G4 | **The `soc-web` decoder path is not exercised** — `DET-100120`/`DET-100121` require `SOC_WEB` log lines decoded by `soc-web`; no fixture emits them | `wazuh/ruleset/decoders/soc-triage-decoders.xml` prematch `^SOC_WEB\s`; `SCN-05` uses built-in rule `31103` | Outstanding |
| G5 | **ATT&CK metadata discrepancy on `SCN-03`** — the fixture declares id `T1566` with technique name "Modify Authentication Process", while the custom FIM rule `DET-100110` declares `T1565`. This catalog records both as written rather than resolving them; Phase 6.2 pins the conflict as a machine-readable, test-validated discrepancy (`G5`, status `recorded-unresolved`) in `evaluation/attack_mappings.yaml`, rendered in `docs/attack-coverage.md` | `app/tests/fixtures/03_wazuh_fim_etc_passwd_change.json` vs `wazuh/ruleset/rules/soc-triage-rules.xml` | Recorded — unresolved (no scoring impact: the engine only counts ATT&CK *presence*, see `app/config/scoring.yaml` `rule_groups_mitre`) |
| G6 | **Runbook linkage is documentation-only** — the decision engine carries a `runbook` field and the n8n payload forwards it, but `app/config/decisions.yaml` assigns no runbook to any tier, so no runbook is attached at runtime. The runbook column above is an analyst-facing reference, not a wired control | `app/config/decisions.yaml` has no `runbook` key; `app/src/soc_triage/decisions/router.py` calls runbook lookup "future extension" | Not mapped — outstanding |
| G7 | **Cross-alert correlation is now an investigation context, not a detection outcome** — Phase 6.4 added a deterministic correlation entity (`correlation_contexts`/`correlation_members`, read API `GET /api/v1/correlations`): distinct alerts (different dedupe groups) that share explainable evidence (shared indicator, direction-matched source/destination IP, or same-agent+shared ATT&CK technique) within `TRIAGE_CORRELATION_WINDOW_SECONDS` are grouped into one investigation context. What remains open: correlation does not feed scoring, decisions, or incident lifecycle (deliberate — see `DEVELOPMENT_PLAN.md` 6.4), user-based correlation is unsupported (no stable canonical user field), and `SCN-01`/`SCN-02` pairing is still not asserted as a pinned corpus outcome | `app/src/soc_triage/correlation/`, `app/tests/integration/test_correlation.py`; `SCN-01`/`SCN-02` share source IP `203.0.113.50` and agent `001`, so they now correlate at runtime through `shared_source_ip` + `same_agent` evidence | Implemented as investigation context (Phase 6.4); outcome-level integration outstanding |
| G8 | **Corpus quality is gated in CI; live Wazuh coverage is still not measured** — Phase 6.6 added a static, read-only corpus-quality gate in `app/tests/evaluation/test_detection_quality_gates.py`. It validates corpus completeness (exactly 16 scenarios), fixture synchronization (corpus fixture names = ground-truth fixture names = catalog scenario fixtures), regression-test coverage (every catalog scenario has at least one existing `path::test_name` reference), positive/negative coverage, multi-delivery recurrence coverage, local-validation status (`validation_status=locally-validated` for every scenario), and G5 integrity (`id=G5`, `status=recorded-unresolved`). The gate prints deterministic counts — 16 total scenarios, 12 positive, 4 negative, 2 recurrence, 16 regression-covered — and runs automatically through the existing pytest CI job (no new workflow). This is a **corpus-quality** gate, not a claim of live Wazuh rule coverage, rule health, or manager-side firing, and it asserts **no percentage detection-coverage** metric. Traceability remains the job of `test_detection_coverage.py`. | `app/tests/evaluation/test_detection_quality_gates.py` | Implemented (Phase 6.6) — corpus-quality CI gate; not live Wazuh coverage |
| G9 | **Rule thresholds (`frequency`/`timeframe`) are not validated** — values are read from the ruleset; no test or lab run exercises burst behaviour at those thresholds | `wazuh/ruleset/rules/soc-triage-rules.xml` (`frequency="5" timeframe="300"`) | Outstanding |
| G10 | **Allowlist suppression is not reachable end-to-end through ingest** — `scoring.v1` subtracts the allowlist modifier and `decisions.v1` overrides to `suppress` only when an IOC carries a provider-attached `allowlist.matched` enrichment, and no allowlist provider/loader exists yet (Phase 2.2 outstanding). The corpus therefore cannot pin a `suppress` outcome; the behavior is covered at unit/engine level only | `app/src/soc_triage/models/ioc.py` (`ioc_is_allowlisted`), `app/config/scoring.yaml` (`allowlist`), `app/config/decisions.yaml` (`allowlisted_action`), `app/tests/unit/test_decisions.py` | Outstanding (Phase 2.2) |

---

## Catalog schema

`evaluation/detection_catalog.yaml` — YAML, `version: "1.0"`, two lists. Identifiers are
stable and unique: `DET-<rule_id>` for rule-backed detections, `SCN-<nn>` for scenarios.

### `detections[]`

| Field | Type | Required | Meaning / allowed values |
| --- | --- | --- | --- |
| `id` | string | yes | `DET-<rule_id>`; unique |
| `rule_id` | string | yes | Custom Wazuh rule id; must exist in `rule_source` |
| `rule_source` | string | yes | Repo-relative path to the ruleset file that defines the rule |
| `behavior` | string | yes | What the rule detects, matching the rule description |
| `rule_level` | int | yes | Must equal the rule's `level` attribute |
| `mitre_attack` | list[string] | yes | Must equal the `<mitre><id>` values in the rule (may be empty) |
| `groups` | list[string] | yes | Must equal the rule's `<group>` values, trimmed and without the trailing empty element |
| `trigger` | map | yes | `{kind, value}`; `kind` ∈ `if_sid`, `if_matched_sid`, `decoded_as`; the rule must contain that child element with that text |
| `reference_scenario` | string \| null | no | Scenario id this rule relates to; `null` when none |
| `scenario_link` | string | yes | `direct` \| `parent-rule` \| `behavioral-overlap` \| `none` (semantics in the legend above) |
| `regression_tests` | list[string] | yes | `path::test_name` references; empty list means no coverage (a gap, not a placeholder) |
| `validation_status` | string | yes | `authored` \| `validated` |

### `scenarios[]`

| Field | Type | Required | Meaning / allowed values |
| --- | --- | --- | --- |
| `id` | string | yes | `SCN-<nn>`; unique |
| `fixture` | string | yes | Filename present in both `app/tests/fixtures/` and `docs/sample-alerts/` (identical copies) |
| `rule_id` | string | yes | Rule id declared inside the fixture |
| `rule_level` | int | yes | Rule level declared inside the fixture |
| `rule_provenance` | string | yes | `synthetic-fixture` (the only value today) |
| `mitre_attack` | list[string] | yes | ATT&CK ids declared inside the fixture (empty when the fixture declares none) |
| `ground_truth` | map | yes | Must equal the fixture's `expected` block in `evaluation/ground_truth.json` (`score`, `tier`, `action`, optional `severity`) |
| `runbook` | string | yes | Repo-relative path; must exist; the runbook must name the fixture |
| `regression_tests` | list[string] | yes | `path::test_name` references; must exist |
| `validation_status` | string | yes | `locally-validated` \| `outstanding` |

### What the validation test asserts

`app/tests/evaluation/test_detection_coverage.py` checks, without touching any runtime
behavior: catalog structure and unique ids; every custom rule exists in the ruleset with
matching level, ATT&CK ids, groups and trigger; decoder references exist; scenario fixtures
exist in both locations and declare the cataloged rule id/level/ATT&CK ids; expected
outcomes equal `ground_truth.json` exactly (and any scenario `recurrence` block mirrors
the ground-truth recurrence block and the corpus delivery count); the scenario set equals
the corpus and ground-truth sets; runbooks exist and name their fixture; every referenced
test file and test function exists; every ATT&CK id in the catalog is declared by its
source file (no invented techniques); scenario-link semantics hold (`direct` ⇒ same rule
id, `parent-rule` ⇒ `if_sid` equals the scenario rule, `behavioral-overlap` ⇒ shared
ATT&CK id); and every id in this document exists in the catalog (no phantom rows), with
every catalog id appearing in the document.

---

## Extending the framework

1. Add the rule to `wazuh/ruleset/rules/soc-triage-rules.xml` (defensive only).
2. Add the catalog entry under `detections:` with the real rule id, level, ATT&CK ids,
   groups, and trigger.
3. If a fixture exists or is added, link it (`scenario_link: direct` only when the fixture
   carries that exact rule id) and reference the test that pins the outcome.
4. Add the row to the table above.
5. Run `cd app && pytest tests/evaluation -q` — the validation test fails on any drift
   between the catalog, the ruleset, the fixtures, ground truth, the runbooks, and this
   document.
6. Leave a cell as `—` / `Not mapped` when the evidence does not exist. Gaps are reported,
   not filled in.
