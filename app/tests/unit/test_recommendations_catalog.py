"""Contract tests for the skill-derived recommendations catalogue.

Validates ``docs/recommendations/recommendations.yaml`` against the contract
defined in ``docs/recommendations/README.md`` and mechanically enforces the
catalogue guardrails:

* every recommendation identifies the five required elements — evidence,
  factor affected, reason, expected analyst action, test required;
* ``component`` maps into one of the five existing platform components;
* no offensive actions and no autonomous containment (``offensive`` and
  ``autonomous_containment`` must always be false);
* any recommendation whose wording touches response-like actions must carry
  ``requires_approval: true`` and an approval-gated analyst action;
* the existing ``scoring.v1`` policy is never replaced: no recommendation may
  invent a scoring factor (future factors must be declared as such), and
  ``app/config/scoring.yaml`` / ``app/config/decisions.yaml`` keep their
  versioned policy shape;
* the analyst-runbook contract: a template exists and every non-template
  runbook contains the required sections and approval-gated containment
  wording.

No external services, no I/O beyond local files — deterministic and fast.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
RECOMMENDATIONS_DIR = REPO_ROOT / "docs" / "recommendations"
CATALOG_PATH = RECOMMENDATIONS_DIR / "recommendations.yaml"
SCORING_POLICY_PATH = REPO_ROOT / "app" / "config" / "scoring.yaml"
DECISION_POLICY_PATH = REPO_ROOT / "app" / "config" / "decisions.yaml"
RUNBOOKS_DIR = REPO_ROOT / "docs" / "runbooks"

SKILLS = {
    "triaging-security-incident",
    "implementing-alert-fatigue-reduction",
    "analyzing-indicators-of-compromise",
    "building-incident-response-playbook",
}

#: The five existing platform components recommendations may map into.
COMPONENTS = {
    "scoring-engine",
    "decision-engine",
    "ioc-provenance",
    "analyst-runbooks",
    "human-approval-model",
}

#: Secondary surfaces a recommendation may additionally touch.
ALSO_SURFACES = {"ingest-dedupe", "notifications-feedback", "observability", "testing-ci"}

PRIORITIES = {"high", "medium", "low"}
PHASES = {"now", "2", "3", "4", "5"}
STATUSES = {"proposed", "delivered"}

#: The existing scoring.v1 factor names (app/config/scoring.yaml). The engine
#: contract (ARCHITECTURE.md §8) forbids inventing new factors in v1.
SCORING_V1_FACTORS = {
    "rule_severity",
    "rule_groups_mitre",
    "asset_criticality",
    "recurrence_velocity",
    "ioc_evidence",
    "enrichment_status",
    "allowlist_modifier",
}

#: Wording that implies a response-like action; such recommendations MUST carry
#: an explicit human approval gate. Matched as substrings, minus the innocuous
#: word contexts below ("skill" contains "kill", "contains" contains "contain").
APPROVAL_TRIGGER_WORDS = (
    "contain",
    "isolate",
    "block",
    "disable",
    "quarantine",
    "reset",
    "terminate",
    "kill",
    "delete",
)
#: Innocuous substrings that would otherwise false-positive the trigger scan.
INNOCUOUS_CONTEXTS = ("skill", "skills", "contains", "containing")
APPROVAL_WORDING = ("approv", "proposal", "human")

REQUIRED_FIELDS = ("evidence", "factor_affected", "reason", "analyst_action", "test_required")
GUARDRAIL_FLAGS = ("offensive", "autonomous_containment")

ID_PATTERN = re.compile(r"^REC-(TRIAGE|FATIGUE|IOC|PLAYBOOK)-\d{2}$")
#: `scoring.<factor>` references; version markers (scoring.v1/v2) are ignored.
SCORING_FACTOR_RE = re.compile(r"scoring\.(?!v\d+)([a-z_]+)")


@pytest.fixture(scope="module")
def catalog() -> list[dict]:
    """Load the machine-readable recommendations catalogue."""
    raw = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, dict) and "recommendations" in raw, (
        "catalogue must be a mapping with a recommendations key"
    )
    recommendations = raw["recommendations"]
    assert isinstance(recommendations, list) and recommendations, "catalogue must not be empty"
    return recommendations


def _field_text(item: dict, field: str) -> str:
    value = item[field]
    assert isinstance(value, str) and value.strip(), (
        f"{item['id']}: {field} must be a non-empty string"
    )
    return value


# ---------------------------------------------------------------------------
# Structure: five required elements + metadata
# ---------------------------------------------------------------------------


def test_every_recommendation_has_required_fields(catalog: list[dict]) -> None:
    for item in catalog:
        assert isinstance(item, dict), "each recommendation must be a mapping"
        assert item.get("id"), "each recommendation must have an id"
        for field in REQUIRED_FIELDS:
            _field_text(item, field)
        for field in GUARDRAIL_FLAGS:
            assert isinstance(item.get(field), bool), f"{item['id']}: {field} must be a boolean"


def test_ids_are_unique_and_well_formed(catalog: list[dict]) -> None:
    ids = [item["id"] for item in catalog]
    assert len(ids) == len(set(ids)), "recommendation ids must be unique"
    for item in catalog:
        assert ID_PATTERN.match(item["id"]), f"{item['id']}: id must match {ID_PATTERN.pattern}"


def test_metadata_values_are_valid(catalog: list[dict]) -> None:
    for item in catalog:
        assert item["skill"] in SKILLS, f"{item['id']}: unknown skill {item['skill']!r}"
        assert item["component"] in COMPONENTS, (
            f"{item['id']}: unknown component {item['component']!r}"
        )
        assert item["priority"] in PRIORITIES, (
            f"{item['id']}: unknown priority {item['priority']!r}"
        )
        assert item["phase"] in PHASES, f"{item['id']}: unknown phase {item['phase']!r}"
        assert item["status"] in STATUSES, f"{item['id']}: unknown status {item['status']!r}"
        assert isinstance(item.get("requires_approval"), bool), (
            f"{item['id']}: requires_approval must be a boolean"
        )
        for surface in item.get("also", []):
            assert surface in ALSO_SURFACES, f"{item['id']}: unknown secondary surface {surface!r}"


def test_catalogue_covers_every_skill_and_component(catalog: list[dict]) -> None:
    assert len(catalog) >= 20, "catalogue unexpectedly small — did a recommendation get dropped?"
    covered_skills = {item["skill"] for item in catalog}
    assert covered_skills == SKILLS, (
        f"catalogue must cover all four reference skills: {SKILLS - covered_skills}"
    )
    covered_components = {item["component"] for item in catalog}
    assert covered_components == COMPONENTS, (
        f"catalogue must map into all five components: {COMPONENTS - covered_components}"
    )


# ---------------------------------------------------------------------------
# Guardrails: no offensive actions, no autonomous containment
# ---------------------------------------------------------------------------


def test_offensive_and_autonomous_containment_are_forbidden(catalog: list[dict]) -> None:
    for item in catalog:
        assert item["offensive"] is False, f"{item['id']}: offensive actions are out of scope"
        assert item["autonomous_containment"] is False, (
            f"{item['id']}: autonomous containment is out of scope (ADR-8)"
        )


def test_response_wording_requires_an_approval_gate(catalog: list[dict]) -> None:
    """Response-like wording must be accompanied by a human approval gate."""
    for item in catalog:
        scanned = " ".join(
            _field_text(item, field).lower()
            for field in ("evidence", "reason", "analyst_action", "test_required")
        )
        for context in INNOCUOUS_CONTEXTS:
            scanned = scanned.replace(context, "")
        if any(word in scanned for word in APPROVAL_TRIGGER_WORDS):
            assert item["requires_approval"] is True, (
                f"{item['id']}: response-like wording requires requires_approval: true"
            )
            action = _field_text(item, "analyst_action").lower()
            assert any(marker in action for marker in APPROVAL_WORDING), (
                f"{item['id']}: approval-gated analyst action must mention approval/proposal/human"
            )


# ---------------------------------------------------------------------------
# Guardrail: the existing scoring.v1 policy is never replaced
# ---------------------------------------------------------------------------


def test_no_invented_scoring_factors(catalog: list[dict]) -> None:
    for item in catalog:
        factor_affected = _field_text(item, "factor_affected")
        for factor in SCORING_FACTOR_RE.findall(factor_affected):
            if factor in SCORING_V1_FACTORS:
                continue
            reason = _field_text(item, "reason").lower()
            assert "future" in reason and "scoring.v2" in reason, (
                f"{item['id']}: new scoring factor {factor!r} must be declared as future in a new policy version"
            )


def test_scoring_v1_policy_is_not_replaced() -> None:
    raw = yaml.safe_load(SCORING_POLICY_PATH.read_text(encoding="utf-8"))
    assert raw["engine_version"] == "scoring.v1", "engine_version must remain scoring.v1"
    expected_factors = {
        "rule_severity",
        "rule_groups_mitre",
        "asset_criticality",
        "recurrence_velocity",
        "ioc_evidence",
        "enrichment_status",
        "allowlist",
        "tiers",
    }
    assert set(raw) >= expected_factors, "scoring.v1 factor set must remain intact"


def test_decision_policy_shape_is_unchanged() -> None:
    raw = yaml.safe_load(DECISION_POLICY_PATH.read_text(encoding="utf-8"))
    assert raw["policy_version"] == "decisions.v1", "decision policy must remain decisions.v1"
    assert raw["tier_actions"] == {
        "informational": {"action": "monitor"},
        "low": {"action": "monitor"},
        "medium": {"action": "queue_l1"},
        "high": {"action": "open_incident", "severity": "SEV2"},
        "critical": {"action": "open_incident", "severity": "SEV1"},
    }
    assert raw["allowlisted_action"] == "suppress"


# ---------------------------------------------------------------------------
# Analyst-runbook contract (REC-PLAYBOOK-01, REC-PLAYBOOK-03)
# ---------------------------------------------------------------------------

REQUIRED_RUNBOOK_SECTIONS = (
    "## Metadata",
    "## Detection & triage",
    "## Investigation steps",
    "## Containment proposals",
    "## Escalation criteria",
    "## Closure & feedback",
    "## Communication",
)

#: Sentence every runbook must carry so containment stays approval-gated.
APPROVAL_GATE_SENTENCE = "requires explicit analyst approval and is audit-logged"
NO_AUTONOMOUS_SENTENCE = "step is ever executed automatically"


def test_runbook_template_and_exemplar_exist() -> None:
    assert (RUNBOOKS_DIR / "_template.md").is_file(), "runbook template missing (REC-PLAYBOOK-01)"
    assert (RUNBOOKS_DIR / "ssh-brute-force.md").is_file(), "exemplar runbook missing"


def test_every_runbook_matches_the_template_contract() -> None:
    runbooks = [
        path for path in RUNBOOKS_DIR.glob("*.md") if path.name not in {"README.md", "_template.md"}
    ]
    assert runbooks, "at least one non-template runbook must exist"
    for path in runbooks:
        text = path.read_text(encoding="utf-8")
        for section in REQUIRED_RUNBOOK_SECTIONS:
            assert section in text, f"{path.name}: missing required section {section!r}"
        # Normalize markdown line wraps and blockquote markers before matching.
        joined = " ".join(line.strip().lstrip(">").strip() for line in text.splitlines())
        normalized = re.sub(r"\s+", " ", joined).lower()
        assert APPROVAL_GATE_SENTENCE in normalized, (
            f"{path.name}: containment must be phrased as an approval-gated proposal"
        )
        assert NO_AUTONOMOUS_SENTENCE in normalized, (
            f"{path.name}: must state that nothing is executed automatically"
        )
