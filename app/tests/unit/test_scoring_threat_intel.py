"""Unit tests for the Phase 2.5 ``threat_intel`` scoring factor.

The factor is the only behavioral change of ``scoring.v2``: it turns the
*sanitized* VT/MISP verdicts that enrichment attaches to indicators into
intel-specific points (ARCHITECTURE.md §8.2). Everything here is pure engine +
policy work — no HTTP, no providers, no database.

Covered contracts:

* the documented Virustotal bands and the MISP event/threat-actor awards;
* per-indicator summation and the factor cap;
* fail-safe behavior for unavailable lookups, absent payloads and malformed
  provider data (a 0 contribution, never an exception);
* determinism: enrichment order must not change points, tier, or the
  explanation text;
* explanation bounds and *no upstream free-text leakage* (SECURITY.md §7);
* policy-driven weights (tuning without a code change);
* ``scoring.v1`` backward compatibility — no ``threat_intel`` key ⇒ no factor.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from tests.conftest import (
    LEGACY_FACTOR_NAMES,
    V2_FACTOR_NAMES,
    make_canonical_alert,
    make_ioc,
    make_misp_payload,
    make_vt_payload,
)

from soc_triage.models.assessment import RiskTier, ScoreFactor
from soc_triage.models.canonical import CanonicalAlert
from soc_triage.models.ioc import IOC, IOCType
from soc_triage.scoring import (
    default_scoring_policy,
    score_alert,
    scoring_policy_from_mapping,
)
from soc_triage.scoring.engine import _FACTOR_ORDER

POLICY = default_scoring_policy()
#: The shipped 2.5 weights (ARCHITECTURE.md §8.2) restated once, so the band
#: tests below read as a table rather than as magic numbers.
VT_HIGH = POLICY.threat_intel.virustotal.malicious_high_points  # 15
VT_LOW = POLICY.threat_intel.virustotal.malicious_low_points  # 8
VT_SUSPICIOUS = POLICY.threat_intel.virustotal.suspicious_only_points  # 4
MISP_MATCH = POLICY.threat_intel.misp.event_match_points  # 10
MISP_ACTOR = POLICY.threat_intel.misp.threat_actor_bonus_points  # 5
INTEL_MAX = POLICY.threat_intel.max  # 25


def _intel_factor(alert: CanonicalAlert, policy=POLICY) -> ScoreFactor:
    return next(f for f in score_alert(alert, policy=policy).factors if f.name == "threat_intel")


def _sha(index: int) -> str:
    """A distinct, deterministic synthetic sha256 (``00…01`` … ``00…0a``)."""
    return f"{index:064x}"


def _ipv4(last_octet: int) -> str:
    """A documentation-range IPv4 (RFC 5737), one per test indicator."""
    return f"203.0.113.{last_octet}"


def _vt_ioc(index: int, **payload_kwargs: int | str) -> IOC:
    """A sha256 indicator carrying a Virustotal lookup record."""
    return make_ioc(
        _sha(index),
        type=IOCType.SHA256,
        enrichment={"virustotal": make_vt_payload(**payload_kwargs)},
    )


def _misp_ioc(last_octet: int, **payload_kwargs: object) -> IOC:
    """An IPv4 indicator carrying a MISP lookup record."""
    return make_ioc(
        _ipv4(last_octet),
        type=IOCType.IPV4,
        enrichment={"misp": make_misp_payload(**payload_kwargs)},
    )


def _alert(*iocs: IOC) -> CanonicalAlert:
    """An enrichment-complete alert carrying exactly the given indicators."""
    return make_canonical_alert(iocs=list(iocs), enrichment_status="complete")


# ---------------------------------------------------------------------------
# The factor exists in scoring.v2, in its documented position
# ---------------------------------------------------------------------------


def test_v2_factor_set_and_order() -> None:
    result = score_alert(make_canonical_alert(), policy=POLICY)
    assert [f.name for f in result.factors] == list(V2_FACTOR_NAMES)
    assert result.engine_version == "scoring.v2"
    assert result.factors[-1].name == "allowlist_modifier"
    # The emitted order is exactly the engine's declared constant.
    assert [f.name for f in result.factors] == [
        name for name in _FACTOR_ORDER if name != "threat_intel" or POLICY.threat_intel is not None
    ]
    assert POLICY.threat_intel is not None


def test_absent_verdicts_contribute_zero_points() -> None:
    """No indicators at all ⇒ the factor is present but neutral (0/max)."""
    factor = _intel_factor(make_canonical_alert())
    assert factor.points == 0
    assert factor.max == INTEL_MAX
    assert "no corroborating threat-intel verdicts" in factor.detail


# ---------------------------------------------------------------------------
# VirusTotal bands (ARCHITECTURE.md §8.2: >=10 -> 15, 2-9 -> 8, suspicious-only -> 4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("malicious", "suspicious", "expected"),
    [
        (10, 0, VT_HIGH),  # lower bound of the high band
        (38, 4, VT_HIGH),  # the sample-alert shape (fixture 04)
        (100, 0, VT_HIGH),
        (9, 40, VT_LOW),  # top of the low band — suspicious does not stack
        (2, 0, VT_LOW),
        (1, 0, VT_LOW),  # a single engine still earns the low band (documented)
        (0, 5, VT_SUSPICIOUS),  # suspicious-only
        (0, 1, VT_SUSPICIOUS),
        (0, 0, 0),  # a clean report
    ],
)
def test_virustotal_bands(malicious: int, suspicious: int, expected: int) -> None:
    alert = _alert(_vt_ioc(1, malicious=malicious, suspicious=suspicious))
    assert _intel_factor(alert).points == expected


def test_virustotal_not_found_answer_scores_zero() -> None:
    """``not_found`` is a definitive *negative* answer: no points, no penalty."""
    alert = _alert(_vt_ioc(1, malicious=0, suspicious=0, lookup_status="not_found"))
    factor = _intel_factor(alert)
    assert factor.points == 0
    assert "no corroborating threat-intel verdicts" in factor.detail


# ---------------------------------------------------------------------------
# MISP awards (event match → +10, threat-actor tag → +5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        ([], MISP_MATCH),
        (["tlp:amber", "PAP:TLP:AMBER"], MISP_MATCH),  # non-actor tags: no bonus
        (["apt"], MISP_MATCH + MISP_ACTOR),
        (["APT:38"], MISP_MATCH + MISP_ACTOR),  # prefix match, case-insensitive
        (["Threat-Actor"], MISP_MATCH + MISP_ACTOR),
        (["intrusion-set"], MISP_MATCH + MISP_ACTOR),
    ],
)
def test_misp_event_match_and_threat_actor_bonus(tags: list[str], expected: int) -> None:
    alert = _alert(_misp_ioc(50, match_count=1, event_ids=["1024"], tags=tags))
    assert _intel_factor(alert).points == expected


def test_misp_match_without_result_payload_still_counts() -> None:
    """A bare ``not_found``-shaped answer with no attributes earns nothing."""
    alert = _alert(_misp_ioc(50, match_count=0, event_ids=[], tags=[]))
    assert _intel_factor(alert).points == 0


def test_misp_event_ids_alone_count_as_a_match() -> None:
    ioc = make_ioc(
        _ipv4(51),
        type=IOCType.IPV4,
        enrichment={
            "misp": {
                "provider": "misp",
                "indicator_type": "ipv4",
                "lookup_status": "found",
                "timestamp": "2026-08-29T10:15:00+00:00",
                "result": {"event_ids": ["2048"], "tags": ["apt"]},
            }
        },
    )
    factor = _intel_factor(_alert(ioc))
    assert factor.points == MISP_MATCH + MISP_ACTOR


def test_threat_actor_bonus_is_awarded_once_per_indicator() -> None:
    """Five actor tags on one indicator must not stack five bonuses."""
    alert = _alert(_misp_ioc(52, match_count=3, tags=["apt", "threat-actor", "intrusion-set"]))
    assert _intel_factor(alert).points == MISP_MATCH + MISP_ACTOR


# ---------------------------------------------------------------------------
# Summation + cap
# ---------------------------------------------------------------------------


def test_both_providers_stack() -> None:
    alert = _alert(_vt_ioc(2, malicious=38, suspicious=4), _misp_ioc(53, tags=["tlp:white"]))
    assert _intel_factor(alert).points == VT_HIGH + MISP_MATCH


def test_per_indicator_summation_then_cap() -> None:
    """Three VT hits (15 each) and a MISP match would be 55 — capped to 25."""
    alert = _alert(
        _vt_ioc(3, malicious=60),
        _vt_ioc(4, malicious=60),
        _vt_ioc(5, malicious=60),
        _misp_ioc(54, tags=["apt"]),
    )
    factor = _intel_factor(alert)
    assert factor.points == factor.max == INTEL_MAX


def test_intel_points_move_the_tier() -> None:
    """The factor is load-bearing: the same alert escalates with intel."""
    base = score_alert(make_canonical_alert(), policy=POLICY)
    with_intel = score_alert(_alert(_vt_ioc(6, malicious=38)), policy=POLICY)
    assert base.score == 22 and base.tier is RiskTier.INFORMATIONAL  # 14 + 8, no intel
    assert (
        with_intel.score == 45 and with_intel.tier is RiskTier.MEDIUM
    )  # +3 ioc, +5 status, +15 intel
    assert with_intel.tier is not base.tier


# ---------------------------------------------------------------------------
# Fail-safe: unavailable or unusable intel must never corrupt scoring
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("lookup_status", ["error", "timeout", "rate_limited"])
def test_unavailable_lookups_contribute_nothing(lookup_status: str) -> None:
    alert = _alert(
        _vt_ioc(7, malicious=50, lookup_status=lookup_status),
        _misp_ioc(55, match_count=2, tags=["apt"], lookup_status=lookup_status),
    )
    factor = _intel_factor(alert)
    assert factor.points == 0
    assert factor.detail.strip()


def test_payload_for_a_different_provider_is_ignored() -> None:
    """``abuseipdb``-style payloads are not VT/MISP evidence and score 0."""
    ioc = make_ioc(
        _ipv4(56),
        type=IOCType.IPV4,
        enrichment={"abuseipdb": {"lookup_status": "found", "result": {"malicious": 99}}},
    )
    assert _intel_factor(_alert(ioc)).points == 0


def test_non_mapping_provider_payload_is_rejected_upstream() -> None:
    """A malformed payload cannot even reach the engine: the IOC model is the
    first line of defence (SECURITY.md §5 — only structured provenance)."""
    with pytest.raises(ValidationError):
        IOC(type=IOCType.SHA256, value=_sha(8), enrichment={"virustotal": "not-a-mapping"})  # type: ignore[dict-item]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"lookup_status": "found", "result": "not-a-mapping"},
        {"lookup_status": "found", "result": {"malicious": "38"}},  # str, not int
        {"lookup_status": "found", "result": {"malicious": True}},  # bool
        {"lookup_status": "found", "result": {"malicious": -5}},  # negative
        {"lookup_status": "found", "result": {"malicious": None}},
        {"result": {"malicious": 38}},  # missing lookup_status is tolerated
    ],
)
def test_malformed_provider_payloads_are_total_and_safe(payload: object) -> None:
    """No provider payload shape can make scoring raise or guess upward."""
    ioc = IOC(type=IOCType.SHA256, value=_sha(8), enrichment={"virustotal": payload})
    result = score_alert(_alert(ioc), policy=POLICY)
    expected = VT_HIGH if payload == {"result": {"malicious": 38}} else 0
    factor = next(f for f in result.factors if f.name == "threat_intel")
    assert factor.points == expected
    assert factor.detail.strip()


def test_email_indicators_are_never_inspected() -> None:
    """Emails are outside both providers' handled types (§7.1)."""
    ioc = make_ioc(
        "actor@example.com",
        type=IOCType.EMAIL,
        enrichment={"virustotal": make_vt_payload(malicious=50)},
    )
    assert _intel_factor(_alert(ioc)).points == 0


# ---------------------------------------------------------------------------
# Determinism (ARCHITECTURE.md §8, §17 — the explainability contract)
# ---------------------------------------------------------------------------


def test_order_of_indicators_does_not_change_the_assessment() -> None:
    first = _alert(
        _vt_ioc(10, malicious=38, suspicious=4),
        _misp_ioc(57, tags=["apt"]),
        _misp_ioc(58, tags=["tlp:white"]),
    )
    reversed_alert = _alert(
        _misp_ioc(58, tags=["tlp:white"]),
        _misp_ioc(57, tags=["apt"]),
        _vt_ioc(10, malicious=38, suspicious=4),
    )
    a = score_alert(first, policy=POLICY)
    b = score_alert(reversed_alert, policy=POLICY)
    assert a.model_dump(mode="json") == b.model_dump(mode="json")


def test_rescoring_the_same_alert_is_byte_identical() -> None:
    alert = _alert(_vt_ioc(11, malicious=12), _misp_ioc(59, tags=["apt"]))
    assert json.dumps(
        score_alert(alert, policy=POLICY).model_dump(mode="json"), sort_keys=True
    ) == json.dumps(score_alert(alert, policy=POLICY).model_dump(mode="json"), sort_keys=True)


def test_scoring_touches_nothing_but_the_alert_and_policy() -> None:
    """The pure function stays I/O-free with intel present (no provider calls)."""
    alert = _alert(_vt_ioc(12, malicious=38))
    before = alert.model_dump(mode="json")
    score_alert(alert, policy=POLICY)
    assert alert.model_dump(mode="json") == before


# ---------------------------------------------------------------------------
# Explanation text: bounded, present, and free of upstream payload content
# ---------------------------------------------------------------------------


def test_detail_is_non_empty_and_bounded_across_many_indicators() -> None:
    limit = POLICY.threat_intel.detail_max_iocs
    iocs = [_vt_ioc(index, malicious=20 + index) for index in range(1, limit + 5)]
    short = _intel_factor(_alert(_vt_ioc(1, malicious=38)))
    long = _intel_factor(_alert(*iocs))
    assert short.detail and long.detail
    assert len(long.detail) < 3 * len(short.detail)
    assert f"{INTEL_MAX}/{INTEL_MAX}" in long.detail


def test_only_safe_tag_names_are_quoted_in_the_detail() -> None:
    """A tag-shaped-but-hostile value still boosts (prefix match), yet is never
    echoed into the stored explanation."""
    hostile = "apt:38 full_log=/etc/shadow secret"
    factor = _intel_factor(_alert(_misp_ioc(60, tags=[hostile])))
    assert factor.points == MISP_MATCH + MISP_ACTOR
    assert "full_log" not in factor.detail
    assert "/etc/shadow" not in factor.detail
    assert "apt" not in factor.detail  # the hostile value is never quoted at all
    assert "\n" not in factor.detail


@pytest.mark.parametrize(
    ("tag", "earns_bonus"),
    [
        ("apt", True),
        ("APT", True),
        ("apt:38", True),
        ("threat-actor", True),
        ("capture", False),  # substring, not a taxonomy prefix
        ("tlp:amber", False),
    ],
)
def test_threat_actor_tag_matching_is_prefix_not_substring(tag: str, earns_bonus: bool) -> None:
    points = MISP_MATCH + (MISP_ACTOR if earns_bonus else 0)
    assert _intel_factor(_alert(_misp_ioc(65, tags=[tag]))).points == points


def test_detail_names_the_matched_evidence() -> None:
    factor = _intel_factor(
        _alert(_vt_ioc(13, malicious=38, suspicious=4), _misp_ioc(61, tags=["apt"]))
    )
    assert "Virustotal" in factor.detail
    assert "MISP" in factor.detail
    assert "apt" in factor.detail


# ---------------------------------------------------------------------------
# Golden: a MISP/VT-matched alert scores exactly as pinned (Phase 2.5 gate)
# ---------------------------------------------------------------------------


def test_golden_matched_malware_alert_assessment() -> None:
    """Pins the full assessment for the §8.2 example alert shape.

    Fixture 04 (``malicious=38``) enriched with a corroborating MISP event:
    rule 12 → 40, groups/MITRE → 11, asset ``standard`` → 10, no recurrence,
    2 indicators → 6, enrichment ``complete`` → 5, intel capped → 25,
    no allowlist ⇒ raw 97, tier ``critical``.
    """
    alert = make_canonical_alert(
        iocs=[
            _vt_ioc(14, malicious=38, suspicious=4, harmless=0, undetected=60),
            _misp_ioc(62, tags=["apt"]),
        ],
        enrichment_status="complete",
        level=12,
        groups=("malware",),
        mitre={"id": ["T1204"], "tactic": ["Execution", "Initial Access"]},
        asset_tier="standard",
    )
    result = score_alert(alert, policy=POLICY)
    assert {f.name: f.points for f in result.factors} == {
        "rule_severity": 40,
        "rule_groups_mitre": 11,
        "asset_criticality": 10,
        "recurrence_velocity": 0,
        "ioc_evidence": 6,
        "enrichment_status": 5,
        "threat_intel": 25,
        "allowlist_modifier": 0,
    }
    assert (result.score, result.tier, result.engine_version) == (
        97,
        RiskTier.CRITICAL,
        "scoring.v2",
    )


# ---------------------------------------------------------------------------
# Policy-driven tuning + scoring.v1 backward compatibility
# ---------------------------------------------------------------------------


def _v1_mapping() -> dict:
    """A complete ``scoring.v1``-shaped policy: no ``threat_intel`` key."""
    return {
        "engine_version": "scoring.v1",
        "rule_severity": {"max": 40, "bands": [{"min": 0, "max": 15, "points": 40}]},
        "rule_groups_mitre": {
            "max": 15,
            "group_keywords": [],
            "group_points": 4,
            "mitre_points": 4,
            "multi_tactic_points": 3,
            "multi_tactic_threshold": 2,
        },
        "asset_criticality": {"max": 25, "unknown_points": 8, "bands": {"critical": 25}},
        "recurrence_velocity": {"max": 20, "rules": []},
        "ioc_evidence": {"max": 15, "per_indicator": 3, "max_counted": 5},
        "enrichment_status": {"max": 5, "points": {"complete": 5}},
        "allowlist": {"subtract": 20},
        "tiers": [
            {"name": "informational", "min": 0, "max": 24},
            {"name": "low", "min": 25, "max": 44},
            {"name": "medium", "min": 45, "max": 69},
            {"name": "high", "min": 70, "max": 84},
            {"name": "critical", "min": 85, "max": 100},
        ],
    }


def test_v1_policy_yields_exactly_the_legacy_seven_factors() -> None:
    policy = scoring_policy_from_mapping(_v1_mapping())
    alert = make_canonical_alert(iocs=[_vt_ioc(15, malicious=99)])
    result = score_alert(alert, policy=policy)
    assert [f.name for f in result.factors] == list(LEGACY_FACTOR_NAMES)
    assert result.engine_version == "scoring.v1"

    # Stronger form of the same contract: the *bundled* v2 policy minus its
    # threat_intel block reproduces scoring.v1 exactly, factor for factor.
    bundled = POLICY.model_dump(mode="json")
    bundled.pop("threat_intel")
    legacy = scoring_policy_from_mapping(bundled)
    with_intel = score_alert(alert, policy=POLICY)
    without = score_alert(alert, policy=legacy)
    assert [f.name for f in without.factors] == list(LEGACY_FACTOR_NAMES)
    assert {f.name: f.points for f in without.factors} == {
        f.name: f.points for f in with_intel.factors if f.name != "threat_intel"
    }
    # …and the only score difference is the intel award itself.
    assert with_intel.score - without.score == VT_HIGH


def test_intel_weights_are_tunable_without_a_code_change() -> None:
    """The factor is config-driven like every other (§8, §14)."""
    mapping = _v1_mapping()
    mapping["engine_version"] = "scoring.v2"
    mapping["threat_intel"] = {
        "max": 4,
        "detail_max_iocs": 1,
        "handled_types": ["ipv4"],
        "virustotal": {
            "malicious_high_min": 10,
            "malicious_high_points": 4,
            "malicious_low_points": 2,
            "suspicious_only_points": 1,
        },
        "misp": {"event_match_points": 0, "threat_actor_bonus_points": 0},
    }
    policy = scoring_policy_from_mapping(mapping)
    alert = make_canonical_alert(
        iocs=[
            _misp_ioc(63, tags=["apt"]),
            make_ioc(
                _ipv4(64),
                type=IOCType.IPV4,
                enrichment={"virustotal": make_vt_payload(malicious=11)},
            ),
        ],
        enrichment_status="complete",
    )
    factor = _intel_factor(alert, policy)
    assert factor.points == 4  # 0 (misp) + 4 (vt) capped at the custom max
    assert factor.max == 4
    assert "Virustotal" in factor.detail
    assert "MISP" not in factor.detail  # a zero-weight provider is not narrated
