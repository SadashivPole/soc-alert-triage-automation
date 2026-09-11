"""Phase 6.4 unit tests: the pure correlation evidence engine.

Covers :mod:`soc_triage.correlation.evidence` — pairwise evidence derivation,
the sufficiency policy (``correlation.v1``), deterministic ordering, and the
explanation strings. Pure functions only: no I/O, no clock, no database.
"""

from __future__ import annotations

from tests.conftest import make_canonical_alert

from soc_triage.correlation.evidence import (
    CORRELATION_POLICY_VERSION,
    EVIDENCE_TYPE_ORDER,
    EvidenceItem,
    EvidenceType,
    evidence_reason,
    evidence_reasons,
    is_sufficient,
    pairwise_evidence,
    sort_evidence,
)
from soc_triage.models.canonical import CanonicalAlert
from soc_triage.models.ioc import EXTRACTOR_TYPED_FIELD, IOC, IOCProvenance, IOCType


def _ioc(
    value: str,
    ioc_type: IOCType = IOCType.IPV4,
    *,
    fields: tuple[str, ...] = (),
    allowlisted: bool = False,
) -> IOC:
    """Build an indicator with typed-field provenance (as the extractor does)."""
    enrichment = {"allowlist": {"matched": True}} if allowlisted else {}
    return IOC(
        type=ioc_type,
        value=value,
        provenance=tuple(
            IOCProvenance(
                field=field,
                extractor=EXTRACTOR_TYPED_FIELD,
                raw_value=value,
            )
            for field in fields
        ),
        enrichment=enrichment,
    )


def _alert(
    *,
    rule_id: str = "5710",
    agent_id: str | None = None,
    mitre: dict | None = None,
    iocs: list[IOC] | None = None,
) -> CanonicalAlert:
    """Build a canonical alert, overriding agent id / MITRE / IOCs."""
    alert = make_canonical_alert(rule_id=rule_id, mitre=mitre, iocs=iocs or [])
    if agent_id is not None:
        agent = alert.source_event.agent.model_copy(update={"id": agent_id})
        event = alert.source_event.model_copy(update={"agent": agent})
        alert = alert.model_copy(update={"source_event": event})
    return alert


# ---------------------------------------------------------------------------
# Evidence derivation
# ---------------------------------------------------------------------------


def test_same_agent_evidence() -> None:
    a = _alert(rule_id="5710", agent_id="001")
    b = _alert(rule_id="5715", agent_id="001")
    items = pairwise_evidence(a, b)
    assert items == [EvidenceItem(evidence_type=EvidenceType.SAME_AGENT, value="001")]
    # …which alone is NOT sufficient (busy hosts produce unrelated alerts).
    assert not is_sufficient(items)


def test_same_rule_evidence_requires_different_groups_by_caller() -> None:
    """same_rule is derived pairwise; the service excludes same-group siblings."""
    a = _alert(rule_id="5710", agent_id="001")
    b = _alert(rule_id="5710", agent_id="002")
    items = pairwise_evidence(a, b)
    assert EvidenceItem(evidence_type=EvidenceType.SAME_RULE, value="5710") in items
    assert not is_sufficient(items)


def test_shared_technique_evidence_sorted_and_deduplicated() -> None:
    a = _alert(rule_id="5710", agent_id="001", mitre={"id": ["T1110", "T1021", "T1110"]})
    b = _alert(rule_id="5715", agent_id="002", mitre={"id": ["T1110", "T1021", "T1059"]})
    items = pairwise_evidence(a, b)
    techniques = [
        item.value for item in items if item.evidence_type is EvidenceType.SHARED_TECHNIQUE
    ]
    assert techniques == ["T1021", "T1110"]  # sorted, deduplicated
    # No same-agent evidence here: technique alone is not sufficient.
    assert not is_sufficient(items)


def test_malformed_or_missing_mitre_yields_no_techniques() -> None:
    a = _alert(mitre={"tactic": ["credential_access"]})  # no "id" list
    b = _alert(mitre={"id": "T1110"})  # id is not a list
    c = _alert(mitre=None)
    for other in (b, c):
        items = pairwise_evidence(a, other)
        assert all(item.evidence_type is not EvidenceType.SHARED_TECHNIQUE for item in items)


def test_shared_source_ip_via_typed_provenance() -> None:
    a = _alert(
        rule_id="5710",
        agent_id="001",
        iocs=[_ioc("203.0.113.50", fields=("source_event.data.srcip",))],
    )
    b = _alert(
        rule_id="5715",
        agent_id="002",
        iocs=[_ioc("203.0.113.50", fields=("source_event.data.srcip",))],
    )
    items = pairwise_evidence(a, b)
    assert EvidenceItem(evidence_type=EvidenceType.SHARED_SOURCE_IP, value="203.0.113.50") in items
    assert is_sufficient(items)


def test_shared_destination_ip_via_typed_provenance() -> None:
    a = _alert(
        rule_id="5710",
        agent_id="001",
        iocs=[_ioc("198.51.100.7", fields=("source_event.data.dstip",))],
    )
    b = _alert(
        rule_id="5715",
        agent_id="002",
        iocs=[_ioc("198.51.100.7", fields=("source_event.data.dstip",))],
    )
    items = pairwise_evidence(a, b)
    assert (
        EvidenceItem(evidence_type=EvidenceType.SHARED_DESTINATION_IP, value="198.51.100.7")
        in items
    )
    assert is_sufficient(items)


def test_cross_direction_ip_falls_back_to_shared_indicator() -> None:
    """srcip in one alert, dstip in the other: shared, but direction-agnostic."""
    a = _alert(iocs=[_ioc("203.0.113.50", fields=("source_event.data.srcip",))])
    b = _alert(iocs=[_ioc("203.0.113.50", fields=("source_event.data.dstip",))])
    items = pairwise_evidence(a, b)
    assert EvidenceItem(evidence_type=EvidenceType.SHARED_IOC, value="ipv4:203.0.113.50") in items
    assert all(item.evidence_type is not EvidenceType.SHARED_SOURCE_IP for item in items)
    assert is_sufficient(items)


def test_ip_without_directional_provenance_is_generic_indicator() -> None:
    a = _alert(iocs=[_ioc("203.0.113.50")])  # e.g. text-scan provenance only
    b = _alert(iocs=[_ioc("203.0.113.50")])
    items = pairwise_evidence(a, b)
    assert EvidenceItem(evidence_type=EvidenceType.SHARED_IOC, value="ipv4:203.0.113.50") in items


def test_shared_non_ip_indicators() -> None:
    sha = "a" * 64
    a = _alert(
        iocs=[
            _ioc(sha, IOCType.SHA256, fields=("source_event.syscheck.sha256_after",)),
            _ioc("evil.example.com", IOCType.DOMAIN),
            _ioc("http://evil.example.com/x", IOCType.URL),
            _ioc("bob@evil.example.com", IOCType.EMAIL),
        ]
    )
    b = _alert(
        iocs=[
            _ioc(sha, IOCType.SHA256, fields=("source_event.data.virustotal.sha256",)),
            _ioc("evil.example.com", IOCType.DOMAIN),
            _ioc("http://evil.example.com/x", IOCType.URL),
            _ioc("bob@evil.example.com", IOCType.EMAIL),
        ]
    )
    items = pairwise_evidence(a, b)
    values = {(item.evidence_type, item.value) for item in items}
    assert (EvidenceType.SHARED_IOC, f"sha256:{sha}") in values
    assert (EvidenceType.SHARED_IOC, "domain:evil.example.com") in values
    assert (EvidenceType.SHARED_IOC, "url:http://evil.example.com/x") in values
    assert (EvidenceType.SHARED_IOC, "email:bob@evil.example.com") in values
    assert is_sufficient(items)


def test_disjoint_indicators_yield_no_ioc_evidence() -> None:
    a = _alert(iocs=[_ioc("203.0.113.50", fields=("source_event.data.srcip",))])
    b = _alert(iocs=[_ioc("198.51.100.77", fields=("source_event.data.srcip",))])
    items = pairwise_evidence(a, b)
    assert all(item.evidence_type is not EvidenceType.SHARED_SOURCE_IP for item in items)
    assert all(item.evidence_type is not EvidenceType.SHARED_IOC for item in items)


def test_allowlisted_indicator_is_not_evidence() -> None:
    a = _alert(iocs=[_ioc("microsoft.com", IOCType.DOMAIN, allowlisted=True)])
    b = _alert(iocs=[_ioc("microsoft.com", IOCType.DOMAIN, allowlisted=True)])
    items = pairwise_evidence(a, b)
    assert all(item.evidence_type is not EvidenceType.SHARED_IOC for item in items)
    assert not is_sufficient(items)


def test_no_shared_evidence_at_all() -> None:
    a = _alert(rule_id="5710", agent_id="001", mitre={"id": ["T1110"]})
    b = _alert(rule_id="31103", agent_id="002", mitre={"id": ["T1190"]})
    assert pairwise_evidence(a, b) == []
    assert not is_sufficient([])


def test_pairwise_evidence_is_symmetric() -> None:
    a = _alert(
        rule_id="5710",
        agent_id="001",
        mitre={"id": ["T1110"]},
        iocs=[_ioc("203.0.113.50", fields=("source_event.data.srcip",))],
    )
    b = _alert(
        rule_id="5715",
        agent_id="001",
        mitre={"id": ["T1110", "T1021"]},
        iocs=[
            _ioc("203.0.113.50", fields=("source_event.data.srcip",)),
            _ioc("evil.example.com", IOCType.DOMAIN),
        ],
    )
    assert pairwise_evidence(a, b) == pairwise_evidence(b, a)


# ---------------------------------------------------------------------------
# Sufficiency policy (correlation.v1)
# ---------------------------------------------------------------------------


def test_policy_version_is_pinned() -> None:
    assert CORRELATION_POLICY_VERSION == "correlation.v1"


def test_strong_evidence_alone_is_sufficient() -> None:
    for evidence_type in (
        EvidenceType.SHARED_SOURCE_IP,
        EvidenceType.SHARED_DESTINATION_IP,
        EvidenceType.SHARED_IOC,
    ):
        assert is_sufficient([EvidenceItem(evidence_type=evidence_type, value="x")])


def test_agent_plus_technique_is_sufficient() -> None:
    items = [
        EvidenceItem(evidence_type=EvidenceType.SAME_AGENT, value="001"),
        EvidenceItem(evidence_type=EvidenceType.SHARED_TECHNIQUE, value="T1110"),
    ]
    assert is_sufficient(items)


def test_supporting_evidence_alone_is_never_sufficient() -> None:
    assert not is_sufficient([EvidenceItem(evidence_type=EvidenceType.SAME_AGENT, value="001")])
    assert not is_sufficient([EvidenceItem(evidence_type=EvidenceType.SAME_RULE, value="5710")])
    assert not is_sufficient(
        [EvidenceItem(evidence_type=EvidenceType.SHARED_TECHNIQUE, value="T1110")]
    )
    assert not is_sufficient(
        [
            EvidenceItem(evidence_type=EvidenceType.SAME_RULE, value="5710"),
            EvidenceItem(evidence_type=EvidenceType.SHARED_TECHNIQUE, value="T1110"),
        ]
    )
    assert not is_sufficient([])


# ---------------------------------------------------------------------------
# Deterministic ordering + explanations
# ---------------------------------------------------------------------------


def test_evidence_ordering_is_deterministic() -> None:
    items = [
        EvidenceItem(evidence_type=EvidenceType.SHARED_IOC, value="sha256:" + "a" * 64),
        EvidenceItem(evidence_type=EvidenceType.SAME_AGENT, value="001"),
        EvidenceItem(evidence_type=EvidenceType.SHARED_SOURCE_IP, value="10.0.0.2"),
        EvidenceItem(evidence_type=EvidenceType.SAME_RULE, value="5710"),
        EvidenceItem(evidence_type=EvidenceType.SHARED_TECHNIQUE, value="T1110"),
        EvidenceItem(evidence_type=EvidenceType.SAME_AGENT, value="000"),
        EvidenceItem(evidence_type=EvidenceType.SHARED_SOURCE_IP, value="10.0.0.1"),
    ]
    ordered = sort_evidence(items)
    assert ordered == sort_evidence(list(reversed(items)))
    assert [item.evidence_type for item in ordered] == [
        EvidenceType.SAME_AGENT,
        EvidenceType.SAME_AGENT,
        EvidenceType.SAME_RULE,
        EvidenceType.SHARED_TECHNIQUE,
        EvidenceType.SHARED_SOURCE_IP,
        EvidenceType.SHARED_SOURCE_IP,
        EvidenceType.SHARED_IOC,
    ]
    # Within a type, values sort ascending.
    assert [item.value for item in ordered if item.evidence_type is EvidenceType.SAME_AGENT] == [
        "000",
        "001",
    ]


def test_evidence_type_order_covers_all_types() -> None:
    assert sorted(EVIDENCE_TYPE_ORDER) == sorted(EvidenceType)


def test_reasons_are_human_readable_and_deterministic() -> None:
    item = EvidenceItem(evidence_type=EvidenceType.SHARED_SOURCE_IP, value="203.0.113.50")
    assert item.reason == "shared source IP 203.0.113.50"
    assert evidence_reason("shared_source_ip", "203.0.113.50") == item.reason
    assert evidence_reasons([item]) == [item.reason]


def test_evidence_reason_degrades_gracefully_on_unknown_type() -> None:
    assert evidence_reason("some_future_type", "x") == "shared some_future_type x"
