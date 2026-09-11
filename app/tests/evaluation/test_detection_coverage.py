"""Phase 6.1 detection coverage framework validation.

Static, read-only checks over ``evaluation/detection_catalog.yaml`` and the coverage
document ``docs/detection-coverage.md``. These tests add **no runtime behavior**: they do
not touch the scoring engine, the decision engine, the API, or any configuration.

They exist to make every documented mapping traceable to repository evidence — a mapping
that cannot be verified fails here instead of being silently believed:

* catalog structure, and unique ``DET-*`` / ``SCN-*`` ids;
* custom detections really exist in ``wazuh/ruleset/rules/soc-triage-rules.xml`` with the
  documented level, ATT&CK ids, groups and trigger (and their decoder exists);
* scenario fixtures exist in both ``app/tests/fixtures/`` and ``docs/sample-alerts/``
  (byte-identical) and declare the cataloged rule id, level and ATT&CK ids;
* expected outcomes equal ``evaluation/ground_truth.json`` exactly, and the scenario set
  equals the Phase 5 corpus / ground-truth fixture sets;
* runbook and regression-test references point at files and test functions that exist;
* no ATT&CK id is invented (every id is declared by its source file);
* scenario-link semantics are supported by evidence (``direct`` ⇒ same rule id,
  ``parent-rule`` ⇒ ``if_sid`` equals the scenario rule, ``behavioral-overlap`` ⇒ shared
  ATT&CK id);
* the coverage document lists every catalog id, and the catalog documents every id the
  document mentions.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG = REPO_ROOT / "evaluation" / "detection_catalog.yaml"
COVERAGE_DOC = REPO_ROOT / "docs" / "detection-coverage.md"
RULESET = REPO_ROOT / "wazuh" / "ruleset" / "rules" / "soc-triage-rules.xml"
DECODERS = REPO_ROOT / "wazuh" / "ruleset" / "decoders" / "soc-triage-decoders.xml"
FIXTURES_DIR = REPO_ROOT / "app" / "tests" / "fixtures"
SAMPLE_ALERTS_DIR = REPO_ROOT / "docs" / "sample-alerts"
GROUND_TRUTH = REPO_ROOT / "evaluation" / "ground_truth.json"
CORPUS = REPO_ROOT / "evaluation" / "corpus.json"

SCENARIO_LINKS = {"direct", "parent-rule", "behavioral-overlap", "none"}
DETECTION_STATUSES = {"authored", "validated"}
SCENARIO_STATUSES = {"locally-validated", "outstanding"}
TRIGGER_KINDS = {"if_sid", "if_matched_sid", "decoded_as"}
RULE_PROVENANCE = {"synthetic-fixture"}
OUTCOME_COLUMNS = ("Expected score", "Expected tier", "Expected action")

ID_PATTERN = re.compile(r"\b(?:DET|SCN)-\d+\b")
UNMAPPED_CELL = "—"

SAMPLE_ALERTS_NOTE = "docs/sample-alerts/README.md"

_CATALOG: dict[str, Any] = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
DETECTIONS: list[dict[str, Any]] = _CATALOG["detections"]
SCENARIOS: list[dict[str, Any]] = _CATALOG["scenarios"]
DETECTIONS_BY_ID = {entry["id"]: entry for entry in DETECTIONS}
SCENARIOS_BY_ID = {entry["id"]: entry for entry in SCENARIOS}


# ---------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------
def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_fixture(name: str) -> dict[str, Any]:
    return _load_json(FIXTURES_DIR / name)


def _rules_by_id() -> dict[str, ET.Element]:
    root = ET.fromstring(RULESET.read_text(encoding="utf-8"))
    rules: dict[str, ET.Element] = {}
    for rule in root.iter("rule"):
        rule_id = rule.get("id")
        if rule_id is not None:
            rules[rule_id] = rule
    return rules


def _decoder_names() -> set[str]:
    """Decoder names from the custom decoders file.

    Wazuh decoder files carry several top-level ``<decoder>`` elements (no single root),
    so the text is wrapped in a synthetic root before parsing. The file itself is
    untouched.
    """
    text = DECODERS.read_text(encoding="utf-8")
    root = ET.fromstring(f"<decoders>{text}</decoders>")
    return {name for decoder in root.iter("decoder") if (name := decoder.get("name")) is not None}


def _rule_groups(rule: ET.Element) -> list[str]:
    groups: list[str] = []
    for element in rule.findall("group"):
        groups.extend(part.strip() for part in (element.text or "").split(","))
    return sorted(group for group in groups if group)


def _rule_mitre_ids(rule: ET.Element) -> list[str]:
    return [element.text or "" for element in rule.findall("./mitre/id")]


def _fixture_mitre_ids(fixture: dict[str, Any]) -> list[str]:
    mitre = fixture.get("rule", {}).get("mitre") or {}
    return list(mitre.get("id", []))


def _cells(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _parse_table(document: str, first_header: str) -> list[dict[str, str]]:
    """Parse the first markdown table whose first header cell is ``first_header``."""
    lines = document.splitlines()
    for index, line in enumerate(lines):
        header = _cells(line)
        if header and header[0] == first_header:
            rows: list[dict[str, str]] = []
            for row_line in lines[index + 2 :]:
                row = _cells(row_line)
                if not row:
                    break
                rows.append(dict(zip(header, row, strict=False)))
            return rows
    raise AssertionError(f"coverage document has no table starting with {first_header!r}")


def _assert_test_reference_exists(reference: str) -> None:
    path_part, _, test_name = reference.partition("::")
    assert test_name, f"{reference!r} must be 'path::test_name'"
    path = REPO_ROOT / path_part
    assert path.is_file(), f"referenced test file does not exist: {path_part}"
    assert f"def {test_name}(" in path.read_text(encoding="utf-8"), (
        f"{path_part} has no test function named {test_name}"
    )


# ---------------------------------------------------------------------------------
# catalog structure
# ---------------------------------------------------------------------------------
def test_catalog_structure_and_unique_ids() -> None:
    """The catalog is well formed, uses documented enum values, and has unique ids."""
    assert _CATALOG["version"] == "1.0"
    assert DETECTIONS and SCENARIOS

    ids = [entry["id"] for entry in DETECTIONS + SCENARIOS]
    assert len(ids) == len(set(ids)), f"duplicate catalog ids: {ids}"

    for detection in DETECTIONS:
        assert detection["id"] == f"DET-{detection['rule_id']}"
        assert (REPO_ROOT / detection["rule_source"]).is_file()
        assert detection["behavior"]
        assert detection["scenario_link"] in SCENARIO_LINKS
        assert detection["validation_status"] in DETECTION_STATUSES
        assert isinstance(detection["regression_tests"], list)
        assert detection["trigger"]["kind"] in TRIGGER_KINDS

    for scenario in SCENARIOS:
        assert re.fullmatch(r"SCN-\d{2}", scenario["id"])
        assert scenario["rule_provenance"] in RULE_PROVENANCE
        assert scenario["validation_status"] in SCENARIO_STATUSES
        assert isinstance(scenario["regression_tests"], list) and scenario["regression_tests"]
        assert set(scenario["ground_truth"]) <= {"score", "tier", "action", "severity"}


# ---------------------------------------------------------------------------------
# detections: ruleset traceability
# ---------------------------------------------------------------------------------
@pytest.mark.parametrize("detection", DETECTIONS, ids=[d["id"] for d in DETECTIONS])
def test_detection_matches_the_custom_ruleset(detection: dict[str, Any]) -> None:
    """Each custom detection exists with the documented level, ATT&CK ids and groups."""
    rule = _rules_by_id().get(detection["rule_id"])
    assert rule is not None, f"rule {detection['rule_id']} is not in {RULESET.name}"

    assert int(rule.get("level", "0")) == detection["rule_level"]
    assert _rule_mitre_ids(rule) == detection["mitre_attack"]
    assert _rule_groups(rule) == sorted(detection["groups"])
    assert detection["behavior"]


@pytest.mark.parametrize("detection", DETECTIONS, ids=[d["id"] for d in DETECTIONS])
def test_detection_trigger_and_decoder_exist(detection: dict[str, Any]) -> None:
    """The documented trigger element exists, and any decoder it needs is defined."""
    rule = _rules_by_id()[detection["rule_id"]]
    trigger = detection["trigger"]

    element = rule.find(trigger["kind"])
    assert element is not None, f"rule {detection['rule_id']} has no <{trigger['kind']}>"
    assert (element.text or "").strip() == trigger["value"]

    if trigger["kind"] == "decoded_as":
        assert trigger["value"] in _decoder_names(), (
            f"decoder {trigger['value']!r} is not defined in {DECODERS.name}"
        )


def test_detections_have_no_unmapped_or_unknown_scenario_reference() -> None:
    """Scenario references resolve, and 'none' links carry no reference."""
    for detection in DETECTIONS:
        reference = detection["reference_scenario"]
        if detection["scenario_link"] == "none":
            assert reference is None, f"{detection['id']}: 'none' link must not name a scenario"
            continue
        assert reference in SCENARIOS_BY_ID, f"{detection['id']}: unknown scenario {reference}"


# ---------------------------------------------------------------------------------
# scenarios: fixture, corpus and ground-truth traceability
# ---------------------------------------------------------------------------------
@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_scenario_fixture_declares_the_cataloged_rule(scenario: dict[str, Any]) -> None:
    """The fixture exists in both locations (identical) and declares the cataloged rule."""
    fixture_path = FIXTURES_DIR / scenario["fixture"]
    sample_path = SAMPLE_ALERTS_DIR / scenario["fixture"]

    assert fixture_path.is_file(), f"missing fixture: {scenario['fixture']}"
    assert sample_path.is_file(), f"missing sample alert: {scenario['fixture']}"
    assert fixture_path.read_bytes() == sample_path.read_bytes(), (
        f"{scenario['fixture']} differs between app/tests/fixtures and docs/sample-alerts"
    )

    fixture = _load_fixture(scenario["fixture"])
    assert str(fixture["rule"]["id"]) == scenario["rule_id"]
    assert int(fixture["rule"]["level"]) == scenario["rule_level"]
    assert _fixture_mitre_ids(fixture) == scenario["mitre_attack"]


def test_scenario_set_matches_corpus_and_ground_truth() -> None:
    """The catalog covers exactly the Phase 5 corpus, and ground truth covers it too."""
    catalog_fixtures = {scenario["fixture"] for scenario in SCENARIOS}

    corpus = _load_json(CORPUS)
    corpus_fixtures = {case["fixture"] for case in corpus["cases"]}

    ground_truth = _load_json(GROUND_TRUTH)
    ground_truth_fixtures = set(ground_truth["fixtures"])

    assert catalog_fixtures == corpus_fixtures, "catalog and corpus disagree on fixtures"
    assert catalog_fixtures == ground_truth_fixtures, (
        "catalog and ground truth disagree on fixtures"
    )


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_scenario_outcomes_match_ground_truth_exactly(scenario: dict[str, Any]) -> None:
    """Expected outcomes are copied from ground truth, never estimated."""
    expected = _load_json(GROUND_TRUTH)["fixtures"][scenario["fixture"]]["expected"]
    assert scenario["ground_truth"] == expected, (
        f"{scenario['id']}: catalog outcome differs from {GROUND_TRUTH.name}"
    )


def test_scenario_recurrence_blocks_match_ground_truth() -> None:
    """A scenario's optional ``recurrence`` block mirrors ground truth exactly.

    ``recurrence`` (Phase 6.3) is only valid for multi-delivery corpus cases:
    it must match the fixture's ``recurrence`` block in ground_truth.json, and
    the corpus case must declare the same delivery count. Ground truth stays
    the single expected-outcome source; the catalog only mirrors it.
    """
    corpus = _load_json(CORPUS)
    deliveries_by_fixture = {
        case["fixture"]: int(case.get("deliveries", 1)) for case in corpus["cases"]
    }

    for scenario in SCENARIOS:
        record = _load_json(GROUND_TRUTH)["fixtures"][scenario["fixture"]]
        block = scenario.get("recurrence")

        if block is None:
            # A multi-delivery case without a mirrored block would leave the
            # escalation unpinned by the catalog.
            assert "recurrence" not in record or deliveries_by_fixture[scenario["fixture"]] == 1, (
                f"{scenario['id']}: multi-delivery ground-truth case is not mirrored in the catalog"
            )
            continue

        assert record.get("recurrence") == block, (
            f"{scenario['id']}: catalog recurrence block differs from {GROUND_TRUTH.name}"
        )
        assert block["deliveries"] > 1
        assert block["deliveries"] == deliveries_by_fixture[scenario["fixture"]], (
            f"{scenario['id']}: catalog deliveries differ from the corpus case"
        )
        assert set(block["after_final_delivery"]) <= {"score", "tier", "action", "severity"}
        assert block["occurrences"] >= block["deliveries"]


# ---------------------------------------------------------------------------------
# references: runbooks and regression tests
# ---------------------------------------------------------------------------------
@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_runbook_reference_exists_and_covers_the_fixture(scenario: dict[str, Any]) -> None:
    """The runbook file exists and names the fixture it is mapped to."""
    runbook = REPO_ROOT / scenario["runbook"]
    assert runbook.is_file(), f"missing runbook: {scenario['runbook']}"
    assert scenario["fixture"] in runbook.read_text(encoding="utf-8"), (
        f"{scenario['runbook']} does not reference {scenario['fixture']}"
    )


def test_all_regression_test_references_exist() -> None:
    """Every referenced test file and test function exists (detections and scenarios)."""
    for detection in DETECTIONS:
        for reference in detection["regression_tests"]:
            _assert_test_reference_exists(reference)
    for scenario in SCENARIOS:
        for reference in scenario["regression_tests"]:
            _assert_test_reference_exists(reference)


# ---------------------------------------------------------------------------------
# no fabricated ATT&CK ids, evidence-backed link semantics
# ---------------------------------------------------------------------------------
def test_attack_ids_are_declared_by_a_repository_source() -> None:
    """No ATT&CK id appears that is not declared by the ruleset or a fixture."""
    declared = set()
    for rule in _rules_by_id().values():
        declared.update(_rule_mitre_ids(rule))
    for scenario in SCENARIOS:
        declared.update(_fixture_mitre_ids(_load_fixture(scenario["fixture"])))

    catalog_ids = {
        attack_id for entry in DETECTIONS + SCENARIOS for attack_id in entry["mitre_attack"]
    }
    assert catalog_ids <= declared, f"undeclared ATT&CK ids: {sorted(catalog_ids - declared)}"
    assert SAMPLE_ALERTS_NOTE  # fixtures are documented as illustrative rule metadata


@pytest.mark.parametrize("detection", DETECTIONS, ids=[d["id"] for d in DETECTIONS])
def test_scenario_link_semantics_are_evidence_backed(detection: dict[str, Any]) -> None:
    """A link is only allowed when the repository supports it, and never implies equality."""
    link = detection["scenario_link"]
    if link == "none":
        return

    scenario = SCENARIOS_BY_ID[detection["reference_scenario"]]

    if link == "direct":
        assert detection["rule_id"] == scenario["rule_id"]
    else:
        assert detection["rule_id"] != scenario["rule_id"], (
            f"{detection['id']}: distinct rule ids must not be linked as {link}"
        )

    if link == "parent-rule":
        parent = _rules_by_id()[detection["rule_id"]].find("if_sid")
        assert parent is not None and (parent.text or "").strip() == scenario["rule_id"]
    if link == "behavioral-overlap":
        assert set(detection["mitre_attack"]) & set(scenario["mitre_attack"]), (
            f"{detection['id']}: behavioral overlap needs a shared ATT&CK id"
        )


# ---------------------------------------------------------------------------------
# the coverage document stays in sync with the catalog
# ---------------------------------------------------------------------------------
def test_coverage_document_lists_every_catalog_id() -> None:
    """No phantom rows in the doc; no undocumented catalog entries."""
    document = COVERAGE_DOC.read_text(encoding="utf-8")
    documented = set(ID_PATTERN.findall(document))
    catalog_ids = set(DETECTIONS_BY_ID) | set(SCENARIOS_BY_ID)

    assert catalog_ids <= documented, f"documented nowhere: {sorted(catalog_ids - documented)}"
    assert documented <= catalog_ids, f"unknown ids in doc: {sorted(documented - catalog_ids)}"


def test_detection_table_keeps_outcomes_unmapped() -> None:
    """Detection rows must not pin an outcome: no fixture exercises those rules."""
    rows = _parse_table(COVERAGE_DOC.read_text(encoding="utf-8"), "Detection ID")
    assert len(rows) == len(DETECTIONS)

    for row in rows:
        detection_id = row["Detection ID"].strip("`")
        assert detection_id in DETECTIONS_BY_ID, f"unknown detection row: {detection_id}"
        detection = DETECTIONS_BY_ID[detection_id]
        assert str(detection["rule_id"]) in row["Wazuh rule ID"]
        for column in OUTCOME_COLUMNS:
            assert row[column] == UNMAPPED_CELL, (
                f"{detection_id}: {column} must stay unmapped while no fixture exercises it"
            )
        assert detection["validation_status"] in row["Validation status"].lower()


def test_scenario_table_matches_the_catalog() -> None:
    """The rendered scenario table agrees with the catalog on every pinned value."""
    rows = _parse_table(COVERAGE_DOC.read_text(encoding="utf-8"), "Scenario ID")
    assert len(rows) == len(SCENARIOS)

    for row in rows:
        scenario_id = row["Scenario ID"].strip("`")
        assert scenario_id in SCENARIOS_BY_ID, f"unknown scenario row: {scenario_id}"
        scenario = SCENARIOS_BY_ID[scenario_id]
        outcome = scenario["ground_truth"]

        assert row["Fixture"].strip("`") == scenario["fixture"]
        assert scenario["rule_id"] in row["Wazuh rule (fixture-declared)"]
        assert str(outcome["score"]) == row["Expected score"].strip("`")
        assert outcome["tier"] == row["Expected tier"].strip("`")
        assert outcome["action"] in row["Expected action"]
        if "severity" in outcome:
            assert outcome["severity"] in row["Expected action"]

        for attack_id in scenario["mitre_attack"]:
            assert attack_id in row["MITRE ATT&CK"]
        if not scenario["mitre_attack"]:
            assert "none declared" in row["MITRE ATT&CK"].lower()


def test_scenario_table_runbook_and_test_references_resolve() -> None:
    """Runbook and regression-test cells in the doc resolve, and match the catalog."""
    rows = _parse_table(COVERAGE_DOC.read_text(encoding="utf-8"), "Scenario ID")

    for row in rows:
        scenario = SCENARIOS_BY_ID[row["Scenario ID"].strip("`")]

        assert scenario["runbook"] in row["Analyst action / runbook"], (
            f"{scenario['id']}: doc runbook cell does not name {scenario['runbook']}"
        )

        referenced = re.findall(r"`([\w./-]+\.py)::(\w+)`", row["Regression test"])
        assert referenced, f"{scenario['id']}: doc lists no regression tests"
        for file_name, test_name in referenced:
            matches = sorted(Path(REPO_ROOT / "app" / "tests").rglob(file_name))
            assert len(matches) == 1, f"{scenario['id']}: {file_name} resolves to {matches}"
            assert f"def {test_name}(" in matches[0].read_text(encoding="utf-8"), (
                f"{scenario['id']}: {file_name} has no test {test_name}"
            )

        catalog_tests = {
            f"{Path(reference.partition('::')[0]).name}::{reference.partition('::')[2]}"
            for reference in scenario["regression_tests"]
        }
        assert catalog_tests == {f"{f}::{t}" for f, t in referenced}, (
            f"{scenario['id']}: doc and catalog regression tests disagree"
        )
