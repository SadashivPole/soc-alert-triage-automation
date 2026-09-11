"""Phase 6.2 MITRE ATT&CK mapping registry validation.

Static, read-only checks over ``evaluation/attack_mappings.yaml``, its declaring
sources (the custom Wazuh ruleset and the evaluation fixtures), the Phase 6.1
detection catalog, the analyst runbooks, the ground truth, and the rendered
document ``docs/attack-coverage.md``. Like the Phase 6.1 coverage validation,
these tests add **no runtime behavior**: they never import ``soc_triage``, and
they do not touch the scoring engine, the decision engine, the API, or any
configuration.

They exist to make every recorded ATT&CK mapping traceable to repository
evidence — a mapping that cannot be verified fails here instead of being
silently believed:

* registry structure and version, including the permanent
  ``attack_reference.matrix_verification: unverified`` flag;
* unique technique / rule / scenario identifiers;
* every provenance reference points at an existing repository file;
* the technique set is exactly the set of ids the repository declares —
  no invented ids, and none missing;
* custom-rule mappings equal the ruleset's ``<mitre><id>`` values and the
  detection catalog's ``detections[].mitre_attack``;
* fixture-rule mappings equal what each cited fixture declares;
* scenario mappings equal the detection catalog's ``scenarios[].mitre_attack``
  and each fixture's declared ``rule.mitre.id``;
* technique names/tactics are the verbatim fixture declarations, with complete
  metadata provenance;
* the cited fixtures' ``docs/sample-alerts/`` copies stay byte-identical;
* the G5 discrepancy stays *live*: both sources still declare the recorded
  conflicting values, and the record still exists while they do;
* runbook "MITRE ATT&CK" sections agree with the fixtures they cover;
* the rendered document stays in sync: every registry/catalog id appears in
  ``docs/attack-coverage.md`` and every id there is registered, and the
  technique / rule / scenario table cells match the registry, the catalog,
  and the ground truth exactly.
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
REGISTRY = REPO_ROOT / "evaluation" / "attack_mappings.yaml"
ATTACK_DOC = REPO_ROOT / "docs" / "attack-coverage.md"
COVERAGE_DOC = REPO_ROOT / "docs" / "detection-coverage.md"
RULESET = REPO_ROOT / "wazuh" / "ruleset" / "rules" / "soc-triage-rules.xml"
CATALOG = REPO_ROOT / "evaluation" / "detection_catalog.yaml"
GROUND_TRUTH = REPO_ROOT / "evaluation" / "ground_truth.json"
FIXTURES_DIR = REPO_ROOT / "app" / "tests" / "fixtures"
SAMPLE_ALERTS_DIR = REPO_ROOT / "docs" / "sample-alerts"

SOURCE_KINDS = {"ruleset-xml", "synthetic-fixture"}
DISCREPANCY_STATUSES = {"recorded-unresolved"}
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
DOC_TECHNIQUE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
DOC_CATALOG_ID_PATTERN = re.compile(r"\b(?:DET|SCN)-\d+\b")
UNMAPPED_CELL = "—"

_REGISTRY: dict[str, Any] = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
TECHNIQUES: list[dict[str, Any]] = _REGISTRY["techniques"]
RULE_MAPPINGS: list[dict[str, Any]] = _REGISTRY["rule_mappings"]
SCENARIO_MAPPINGS: list[dict[str, Any]] = _REGISTRY["scenario_mappings"]
DISCREPANCIES: list[dict[str, Any]] = _REGISTRY["known_discrepancies"]
TECHNIQUES_BY_ID = {entry["id"]: entry for entry in TECHNIQUES}

_CATALOG: dict[str, Any] = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
DETECTIONS: list[dict[str, Any]] = _CATALOG["detections"]
CATALOG_SCENARIOS: list[dict[str, Any]] = _CATALOG["scenarios"]

_GROUND_TRUTH: dict[str, Any] = json.loads(GROUND_TRUTH.read_text(encoding="utf-8-sig"))

_RULESET_RULES: dict[str, ET.Element] = {
    rule.get("id"): rule
    for rule in ET.fromstring(RULESET.read_text(encoding="utf-8")).iter("rule")
    if rule.get("id") is not None
}


# ---------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------
def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _fixture_by_catalog_name(name: str) -> dict[str, Any]:
    return _load_json(FIXTURES_DIR / name)


def _fixture_mitre(fixture: dict[str, Any]) -> dict[str, Any]:
    mitre = fixture.get("rule", {}).get("mitre")
    return mitre if isinstance(mitre, dict) else {}


def _fixture_mitre_ids(fixture: dict[str, Any]) -> list[str]:
    ids = _fixture_mitre(fixture).get("id", [])
    return [value for value in ids if isinstance(value, str)] if isinstance(ids, list) else []


def _fixture_mitre_list(fixture: dict[str, Any], key: str) -> list[str]:
    values = _fixture_mitre(fixture).get(key, [])
    return [value for value in values if isinstance(value, str)] if isinstance(values, list) else []


def _rule_mitre_ids(rule: ET.Element) -> list[str]:
    return [element.text or "" for element in rule.findall("./mitre/id")]


def _cells(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _doc_row(doc_text: str, first_cell: str) -> str:
    prefix = f"| `{first_cell}` |"
    matches = [line for line in doc_text.splitlines() if line.startswith(prefix)]
    assert len(matches) == 1, (
        f"expected exactly one table row starting with {prefix!r} in the document, "
        f"found {len(matches)}"
    )
    return matches[0]


def _sorted_ids(values: list[str]) -> list[str]:
    return sorted(values, key=lambda value: (0, int(value)) if value.isdigit() else (1, value))


def _registry_rule_ids(*, source_kind: str) -> list[str]:
    return [entry["rule_id"] for entry in RULE_MAPPINGS if entry["source_kind"] == source_kind]


def _technique_cell(technique_ids: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in technique_ids) if technique_ids else UNMAPPED_CELL


def _outcome_cell(expected: dict[str, Any]) -> str:
    cell = f"`{expected['score']}` / `{expected['tier']}` / `{expected['action']}`"
    if expected.get("severity"):
        cell += f" (`{expected['severity']}`)"
    return cell


def _all_provenance_files() -> set[str]:
    files: set[str] = set()
    for technique in TECHNIQUES:
        files.update(source["file"] for source in technique["metadata_declared_by"])
    for mapping in RULE_MAPPINGS:
        files.update(source["file"] for source in mapping["declared_by"])
    for mapping in SCENARIO_MAPPINGS:
        files.add(mapping["fixture"])
    for discrepancy in DISCREPANCIES:
        for value in discrepancy["values"]:
            files.add(value["declared_by"]["file"])
    return files


# ---------------------------------------------------------------------------------
# schema / version / uniqueness / provenance
# ---------------------------------------------------------------------------------
def test_registry_structure_and_version() -> None:
    assert set(_REGISTRY) == {
        "version",
        "attack_reference",
        "techniques",
        "rule_mappings",
        "scenario_mappings",
        "known_discrepancies",
    }
    assert _REGISTRY["version"] == "1.0"
    # Guardrail: the repository pins no ATT&CK reference data, so this flag is
    # a property of the registry, not a TODO. It may only change deliberately.
    assert _REGISTRY["attack_reference"] == {"source": "none", "matrix_verification": "unverified"}

    for technique in TECHNIQUES:
        assert {"id", "declared_names", "declared_tactics", "metadata_declared_by"} <= set(
            technique
        )
        assert set(technique) <= {
            "id",
            "declared_names",
            "declared_tactics",
            "metadata_declared_by",
            "note",
        }
        assert isinstance(technique["declared_names"], list)
        assert isinstance(technique["declared_tactics"], list)
        for source in technique["metadata_declared_by"]:
            assert set(source) == {"file", "path"}

    for mapping in RULE_MAPPINGS:
        assert {"rule_id", "source_kind", "technique_ids", "declared_by"} <= set(mapping)
        assert set(mapping) <= {
            "rule_id",
            "source_kind",
            "technique_ids",
            "declared_by",
            "note",
        }
        assert mapping["source_kind"] in SOURCE_KINDS
        assert isinstance(mapping["technique_ids"], list)
        for source in mapping["declared_by"]:
            assert set(source) == {"file", "path"}

    for mapping in SCENARIO_MAPPINGS:
        assert {"scenario_id", "fixture", "technique_ids"} <= set(mapping)
        assert set(mapping) <= {"scenario_id", "fixture", "technique_ids", "path", "note"}
        assert isinstance(mapping["technique_ids"], list)

    for discrepancy in DISCREPANCIES:
        assert {
            "id",
            "status",
            "summary",
            "values",
            "scoring_impact",
            "resolution",
        } <= set(discrepancy)
        assert discrepancy["status"] in DISCREPANCY_STATUSES
        assert len(discrepancy["values"]) >= 2
        for value in discrepancy["values"]:
            assert {"value", "declared_by", "detail"} <= set(value)
            assert set(value["declared_by"]) == {"file", "path"}


def test_technique_ids_are_unique_and_well_formed() -> None:
    ids = [technique["id"] for technique in TECHNIQUES]
    assert len(ids) == len(set(ids)), "duplicate technique ids in the registry"
    for technique_id in ids:
        assert TECHNIQUE_ID_PATTERN.match(technique_id), f"malformed technique id {technique_id!r}"


def test_rule_and_scenario_mapping_ids_are_unique() -> None:
    rule_ids = [mapping["rule_id"] for mapping in RULE_MAPPINGS]
    assert len(rule_ids) == len(set(rule_ids)), "duplicate rule ids in rule_mappings"
    scenario_ids = [mapping["scenario_id"] for mapping in SCENARIO_MAPPINGS]
    assert len(scenario_ids) == len(set(scenario_ids)), "duplicate scenario ids"
    discrepancy_ids = [discrepancy["id"] for discrepancy in DISCREPANCIES]
    assert len(discrepancy_ids) == len(set(discrepancy_ids)), "duplicate discrepancy ids"


def test_every_provenance_reference_points_at_an_existing_file() -> None:
    for file in sorted(_all_provenance_files()):
        assert (REPO_ROOT / file).is_file(), f"provenance references missing file {file!r}"


def test_provenance_paths_are_well_formed() -> None:
    """Paths are structural locators, not prose — each must take its exact expected form."""

    def _check(source: dict[str, Any], *, expected: str) -> None:
        assert source["path"] == expected, (
            f"provenance path for {source['file']!r} must be {expected!r}, found {source['path']!r}"
        )

    for mapping in RULE_MAPPINGS:
        if mapping["source_kind"] == "ruleset-xml":
            expected = f"rule[@id='{mapping['rule_id']}']/mitre/id"
            assert len(mapping["declared_by"]) == 1
            _check(mapping["declared_by"][0], expected=expected)
        else:
            expected = "rule.mitre.id" if mapping["technique_ids"] else "rule.mitre"
            for source in mapping["declared_by"]:
                _check(source, expected=expected)

    for mapping in SCENARIO_MAPPINGS:
        assert "path" in mapping
        _check(
            {"file": mapping["fixture"], "path": mapping["path"]},
            expected="rule.mitre.id" if mapping["technique_ids"] else "rule.mitre",
        )

    for technique in TECHNIQUES:
        for source in technique["metadata_declared_by"]:
            _check(source, expected="rule.mitre")

    for discrepancy in DISCREPANCIES:
        for value in discrepancy["values"]:
            declared_by = value["declared_by"]
            if declared_by["file"].endswith(".json"):
                _check(declared_by, expected="rule.mitre.id")
            else:
                assert re.fullmatch(r"rule\[@id='\d+'\]/mitre/id", declared_by["path"]), (
                    f"ruleset provenance path must locate a rule's mitre id, "
                    f"found {declared_by['path']!r}"
                )


# ---------------------------------------------------------------------------------
# no invented ids — the registry equals what the repository declares
# ---------------------------------------------------------------------------------
def test_technique_set_equals_the_repository_declared_universe() -> None:
    declared: set[str] = set()
    for rule in _RULESET_RULES.values():
        declared.update(_rule_mitre_ids(rule))
    for scenario in CATALOG_SCENARIOS:
        declared.update(_fixture_mitre_ids(_fixture_by_catalog_name(scenario["fixture"])))

    registered = {technique["id"] for technique in TECHNIQUES}
    assert registered == declared, (
        "registry technique set must exactly equal the ids declared by the ruleset "
        f"and the corpus fixtures (missing: {sorted(declared - registered)}, "
        f"invented: {sorted(registered - declared)})"
    )


# ---------------------------------------------------------------------------------
# rule mappings — ruleset, fixtures, and catalog equivalence
# ---------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "mapping",
    [entry for entry in RULE_MAPPINGS if entry["source_kind"] == "ruleset-xml"],
    ids=lambda entry: f"rule-{entry['rule_id']}",
)
def test_ruleset_rule_mapping_matches_the_ruleset(mapping: dict[str, Any]) -> None:
    rule = _RULESET_RULES.get(mapping["rule_id"])
    assert rule is not None, f"rule {mapping['rule_id']} does not exist in the ruleset"
    assert _rule_mitre_ids(rule) == mapping["technique_ids"]
    for source in mapping["declared_by"]:
        assert source["file"] == "wazuh/ruleset/rules/soc-triage-rules.xml"


def test_ruleset_rule_mappings_are_complete() -> None:
    assert set(_RULESET_RULES) == set(_registry_rule_ids(source_kind="ruleset-xml")), (
        "every ruleset rule id must be mapped (an unmapped rule is recorded with an "
        "empty technique_ids list, never omitted)"
    )


@pytest.mark.parametrize(
    "mapping",
    [entry for entry in RULE_MAPPINGS if entry["source_kind"] == "synthetic-fixture"],
    ids=lambda entry: f"rule-{entry['rule_id']}",
)
def test_fixture_rule_mapping_matches_its_fixtures(mapping: dict[str, Any]) -> None:
    assert mapping["declared_by"], "fixture rule mapping must cite at least one fixture"
    for source in mapping["declared_by"]:
        fixture = _load_json(REPO_ROOT / source["file"])
        assert fixture["rule"]["id"] == mapping["rule_id"], (
            f"{source['file']} declares rule {fixture['rule']['id']}, not {mapping['rule_id']}"
        )
        assert _fixture_mitre_ids(fixture) == mapping["technique_ids"]


def test_fixture_rule_mappings_are_complete() -> None:
    fixture_rule_ids = {
        _fixture_by_catalog_name(scenario["fixture"])["rule"]["id"]
        for scenario in CATALOG_SCENARIOS
    }
    assert fixture_rule_ids == set(_registry_rule_ids(source_kind="synthetic-fixture")), (
        "every rule id declared by a corpus fixture must be mapped (absence is recorded "
        "with an empty technique_ids list, never omitted)"
    )


def test_rule_mappings_match_the_detection_catalog() -> None:
    catalog_rules = {detection["rule_id"]: detection["mitre_attack"] for detection in DETECTIONS}
    registry_rules = {
        mapping["rule_id"]: mapping["technique_ids"]
        for mapping in RULE_MAPPINGS
        if mapping["source_kind"] == "ruleset-xml"
    }
    assert registry_rules == catalog_rules


# ---------------------------------------------------------------------------------
# scenario mappings — catalog and fixture equivalence
# ---------------------------------------------------------------------------------
def test_scenario_mappings_match_the_detection_catalog() -> None:
    catalog_scenarios = {scenario["id"]: scenario["mitre_attack"] for scenario in CATALOG_SCENARIOS}
    registry_scenarios = {
        mapping["scenario_id"]: mapping["technique_ids"] for mapping in SCENARIO_MAPPINGS
    }
    assert registry_scenarios == catalog_scenarios


@pytest.mark.parametrize("mapping", SCENARIO_MAPPINGS, ids=lambda entry: entry["scenario_id"])
def test_scenario_mapping_matches_its_fixture(mapping: dict[str, Any]) -> None:
    fixture = _load_json(REPO_ROOT / mapping["fixture"])
    assert _fixture_mitre_ids(fixture) == mapping["technique_ids"]
    catalog_entry = next(
        (scenario for scenario in CATALOG_SCENARIOS if scenario["id"] == mapping["scenario_id"]),
        None,
    )
    assert catalog_entry is not None
    assert catalog_entry["fixture"] == Path(mapping["fixture"]).name


# ---------------------------------------------------------------------------------
# technique metadata — verbatim, fully sourced
# ---------------------------------------------------------------------------------
def test_technique_metadata_is_verbatim_and_fully_sourced() -> None:
    for technique in TECHNIQUES:
        technique_id = technique["id"]
        declaring: dict[str, dict[str, Any]] = {}
        for scenario in CATALOG_SCENARIOS:
            fixture_path = str(FIXTURES_DIR / scenario["fixture"])
            fixture = _fixture_by_catalog_name(scenario["fixture"])
            if technique_id in _fixture_mitre_ids(fixture):
                declaring[fixture_path] = fixture

        expected_names: set[str] = set()
        expected_tactics: set[str] = set()
        for fixture in declaring.values():
            expected_names.update(_fixture_mitre_list(fixture, "technique"))
            expected_tactics.update(_fixture_mitre_list(fixture, "tactic"))
        assert set(technique["declared_names"]) == expected_names, (
            f"{technique_id}: declared_names must be the verbatim fixture technique names"
        )
        assert set(technique["declared_tactics"]) == expected_tactics, (
            f"{technique_id}: declared_tactics must be the verbatim fixture tactics"
        )

        cited = {source["file"] for source in technique["metadata_declared_by"]}
        expected_cited = {
            f"app/tests/fixtures/{scenario['fixture']}"
            for scenario in CATALOG_SCENARIOS
            if technique_id in _fixture_mitre_ids(_fixture_by_catalog_name(scenario["fixture"]))
        }
        assert cited == expected_cited, (
            f"{technique_id}: metadata provenance must cite exactly the fixtures that "
            f"declare the id (missing: {sorted(expected_cited - cited)}, "
            f"extra: {sorted(cited - expected_cited)})"
        )


def test_cited_fixture_copies_stay_byte_identical() -> None:
    cited_fixtures = {
        Path(file).name
        for file in _all_provenance_files()
        if file.startswith("app/tests/fixtures/")
    }
    assert cited_fixtures, "registry must cite at least one fixture"
    for name in sorted(cited_fixtures):
        original = (FIXTURES_DIR / name).read_bytes()
        copy = SAMPLE_ALERTS_DIR / name
        assert copy.is_file(), f"docs/sample-alerts/{name} is missing"
        assert copy.read_bytes() == original, f"docs/sample-alerts/{name} drifted from the fixture"


# ---------------------------------------------------------------------------------
# the G5 discrepancy — recorded, unresolved, and live
# ---------------------------------------------------------------------------------
def test_g5_discrepancy_is_recorded_and_live() -> None:
    assert len(DISCREPANCIES) == 1, "exactly one known discrepancy is recorded today (G5)"
    g5 = DISCREPANCIES[0]
    assert g5["id"] == "G5"
    assert g5["status"] == "recorded-unresolved"
    assert {value["value"] for value in g5["values"]} == {"T1566", "T1565"}

    # Liveness side 1: the fixture still declares T1566 (with the recorded name).
    fixture_value = next(value for value in g5["values"] if value["value"] == "T1566")
    fixture = _load_json(REPO_ROOT / fixture_value["declared_by"]["file"])
    assert fixture["rule"]["id"] == "550"
    assert _fixture_mitre_ids(fixture) == ["T1566"]
    assert _fixture_mitre_list(fixture, "technique") == ["Modify Authentication Process"]

    # Liveness side 2: the custom rule still declares T1565.
    ruleset_value = next(value for value in g5["values"] if value["value"] == "T1565")
    assert ruleset_value["declared_by"]["file"] == "wazuh/ruleset/rules/soc-triage-rules.xml"
    assert _rule_mitre_ids(_RULESET_RULES["100110"]) == ["T1565"]

    # Both rendered documents still record the conflict.
    for doc, needle in ((COVERAGE_DOC, "| G5 |"), (ATTACK_DOC, "G5")):
        text = doc.read_text(encoding="utf-8")
        assert needle in text, f"{doc.name} no longer records the G5 discrepancy"
        assert "T1566" in text and "T1565" in text, (
            f"{doc.name} must mention both conflicting values of G5"
        )


# ---------------------------------------------------------------------------------
# runbooks — the analyst layer agrees with the fixtures it covers
# ---------------------------------------------------------------------------------
def _runbook_mitre_section_ids(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"^## MITRE ATT&CK\s*$", text, flags=re.MULTILINE)
    if match is None:
        return set()
    rest = text[match.end() :]
    next_section = re.search(r"^## ", rest, flags=re.MULTILINE)
    section = rest[: next_section.start()] if next_section else rest
    return set(DOC_TECHNIQUE_ID_PATTERN.findall(section))


def test_runbook_attack_sections_match_the_fixtures_they_cover() -> None:
    by_runbook: dict[str, list[dict[str, Any]]] = {}
    for scenario in CATALOG_SCENARIOS:
        by_runbook.setdefault(scenario["runbook"], []).append(scenario)

    assert by_runbook, "the catalog must reference at least one runbook"
    for runbook, scenarios in sorted(by_runbook.items()):
        path = REPO_ROOT / runbook
        assert path.is_file(), f"runbook {runbook} does not exist"
        expected: set[str] = set()
        for scenario in scenarios:
            expected.update(_fixture_mitre_ids(_fixture_by_catalog_name(scenario["fixture"])))
        found = _runbook_mitre_section_ids(path)
        assert found == expected, (
            f"{runbook}: its MITRE ATT&CK section declares {sorted(found)} while the "
            f"fixtures it covers declare {sorted(expected)} — runbook prose must not "
            "introduce or drop technique ids"
        )


# ---------------------------------------------------------------------------------
# the rendered document — docs/attack-coverage.md stays in sync
# ---------------------------------------------------------------------------------
def test_attack_coverage_document_id_sync() -> None:
    text = ATTACK_DOC.read_text(encoding="utf-8")

    doc_techniques = set(DOC_TECHNIQUE_ID_PATTERN.findall(text))
    registry_techniques = {technique["id"] for technique in TECHNIQUES}
    assert doc_techniques == registry_techniques, (
        "every registry technique id must appear in docs/attack-coverage.md and the "
        "document must not mention any unregistered technique id"
    )

    doc_catalog_ids = set(DOC_CATALOG_ID_PATTERN.findall(text))
    catalog_ids = {detection["id"] for detection in DETECTIONS} | {
        scenario["id"] for scenario in CATALOG_SCENARIOS
    }
    assert doc_catalog_ids == catalog_ids, (
        "every detection/scenario id must appear in docs/attack-coverage.md and the "
        "document must not mention any uncataloged DET-/SCN- id"
    )


def test_attack_coverage_technique_table_matches_the_registry() -> None:
    text = ATTACK_DOC.read_text(encoding="utf-8")

    custom_rules_by_technique: dict[str, list[str]] = {}
    fixture_rules_by_technique: dict[str, list[str]] = {}
    for mapping in RULE_MAPPINGS:
        target = (
            custom_rules_by_technique
            if mapping["source_kind"] == "ruleset-xml"
            else fixture_rules_by_technique
        )
        for technique_id in mapping["technique_ids"]:
            target.setdefault(technique_id, []).append(mapping["rule_id"])

    scenarios_by_technique: dict[str, list[str]] = {}
    for mapping in SCENARIO_MAPPINGS:
        for technique_id in mapping["technique_ids"]:
            scenarios_by_technique.setdefault(technique_id, []).append(mapping["scenario_id"])

    runbooks_by_scenario = {scenario["id"]: scenario["runbook"] for scenario in CATALOG_SCENARIOS}

    for technique in TECHNIQUES:
        technique_id = technique["id"]
        cells = _cells(_doc_row(text, technique_id))

        runbooks = sorted(
            {
                runbooks_by_scenario[sid]
                for sid in scenarios_by_technique.get(technique_id, [])
                if sid in runbooks_by_scenario
            }
        )

        assert cells[1] == (", ".join(technique["declared_names"]) or UNMAPPED_CELL)
        assert cells[2] == (", ".join(technique["declared_tactics"]) or UNMAPPED_CELL)
        assert cells[3] == (
            ", ".join(
                f"`{Path(source['file']).name}`" for source in technique["metadata_declared_by"]
            )
            or UNMAPPED_CELL
        )
        assert cells[4] == (
            ", ".join(
                f"`{rid}`" for rid in _sorted_ids(custom_rules_by_technique.get(technique_id, []))
            )
            or UNMAPPED_CELL
        )
        assert cells[5] == (
            ", ".join(
                f"`{rid}`" for rid in _sorted_ids(fixture_rules_by_technique.get(technique_id, []))
            )
            or UNMAPPED_CELL
        )
        assert cells[6] == (
            ", ".join(f"`{sid}`" for sid in sorted(scenarios_by_technique.get(technique_id, [])))
            or UNMAPPED_CELL
        )
        assert cells[7] == (", ".join(f"`{rb}`" for rb in runbooks) or UNMAPPED_CELL)


def test_attack_coverage_rule_table_matches_the_registry() -> None:
    text = ATTACK_DOC.read_text(encoding="utf-8")
    catalog_detections_by_rule = {detection["rule_id"]: detection for detection in DETECTIONS}

    for mapping in RULE_MAPPINGS:
        cells = _cells(_doc_row(text, mapping["rule_id"]))
        assert cells[1] == (
            "custom ruleset" if mapping["source_kind"] == "ruleset-xml" else "synthetic fixture"
        )
        assert cells[2] == ", ".join(
            f"`{Path(source['file']).name}`" for source in mapping["declared_by"]
        )
        assert cells[3] == _technique_cell(mapping["technique_ids"])

        if mapping["source_kind"] == "ruleset-xml":
            detection = catalog_detections_by_rule[mapping["rule_id"]]
            related = f"`{detection['id']}`"
            if detection.get("reference_scenario"):
                related += f" · `{detection['reference_scenario']}` ({detection['scenario_link']})"
        else:
            related = ", ".join(
                f"`{scenario['id']}`"
                for scenario in CATALOG_SCENARIOS
                if scenario["rule_id"] == mapping["rule_id"]
            )
        assert cells[4] == related


def test_attack_coverage_scenario_table_matches_ground_truth_and_catalog() -> None:
    text = ATTACK_DOC.read_text(encoding="utf-8")
    registry_scenarios = {mapping["scenario_id"]: mapping for mapping in SCENARIO_MAPPINGS}

    for scenario in CATALOG_SCENARIOS:
        cells = _cells(_doc_row(text, scenario["id"]))
        expected = _GROUND_TRUTH["fixtures"][scenario["fixture"]]["expected"]

        assert cells[1] == f"`{scenario['fixture']}`"
        assert cells[2] == f"`{scenario['rule_id']}` (level {scenario['rule_level']})"
        assert cells[3] == _technique_cell(registry_scenarios[scenario["id"]]["technique_ids"])
        assert cells[4] == _outcome_cell(expected)
        assert cells[5] == ", ".join(
            f"`{Path(reference.split('::')[0]).name}::{reference.split('::')[1]}`"
            for reference in scenario["regression_tests"]
        )
        assert cells[6] == f"`{scenario['runbook']}`"
