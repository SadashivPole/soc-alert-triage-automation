"""Cross-alert correlation evidence (Phase 6.4).

Correlation answers a question that is deliberately **distinct** from
deduplication (ARCHITECTURE.md §6, DEVELOPMENT_PLAN.md item 6.4):

* **Deduplication / recurrence** — "is this delivery the same source event, or
  another event of the same ``rule.id + agent.id`` group?" (Phase 1C/1D).
* **Correlation** — "are these *distinct* alerts (different dedupe groups)
  related enough to present as one investigation context?"

This module is the pure half of the correlation engine: given two canonical
alerts it deterministically derives the **evidence** they share, and a policy
that decides whether that evidence is sufficient to group them. No I/O, no
clock, no randomness, no ML/LLM — every decision is explainable from the
evidence list it returns.

Evidence contract
-----------------

An :class:`EvidenceItem` is one shared, normalized attribute between two
alerts. Only attributes the canonical alert model can derive **safely** are
evidence (nothing is assumed just because Wazuh often provides it):

======================  ======  ==================================================
evidence type           weight  semantics
======================  ======  ==================================================
``same_agent``          support both alerts carry the same canonical ``agent.id``
``same_rule``           support both alerts fired the same rule id (they are in
                                different dedupe groups, so this means the same
                                detection on different agents)
``shared_technique``    support both rules declare the same MITRE ATT&CK
                                technique id (``rule.mitre.id``)
``shared_source_ip``    strong  both alerts contain the same IPv4 indicator,
                                read from the typed ``data.srcip`` field in
                                each alert
``shared_destination_ip`` strong same, via the typed ``data.dstip`` field
``shared_ioc``          strong  both alerts contain the same normalized
                                indicator of any other type (hash, domain,
                                url, email, or an IP whose roles do not match)
======================  ======  ==================================================

Sufficiency policy (:data:`CORRELATION_POLICY_VERSION` ``correlation.v1``):

* any **strong** evidence (a shared indicator) alone justifies correlation —
  two alerts sharing a hash, URL, domain, email or matched-direction IP are
  one investigation;
* ``same_agent`` **plus** ``shared_technique`` justify correlation — two
  different detections on one host mapping to the same ATT&CK technique
  within the window is a coherent host-focused investigation;
* ``same_agent`` alone never justifies correlation: a busy host produces many
  unrelated alerts, and agent-only grouping would turn every context into
  noise (DEVELOPMENT_PLAN.md 6.4 noise requirement);
* ``same_rule`` / ``shared_technique`` alone never justify correlation for
  the same reason (a rule firing across many hosts is routine).

Explicitly **unsupported** dimensions (no stable canonical field exists —
see ``models/canonical.py``): usernames (``data.srcuser`` / ``data.dstuser``
only surface as *email indicators* when they validate as one, so a
``shared_user`` evidence type would be inferred from data the model does not
guarantee), and free-text log similarity (``full_log`` is never an evidence
source, SECURITY.md §5).

Allowlisted indicators (``ioc_is_allowlisted`` — e.g. a benign domain marked
by an enrichment provider) are excluded from evidence: grouping on known
benign shared infrastructure would be pure noise.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from ..models.canonical import CanonicalAlert
from ..models.ioc import IOCType, ioc_is_allowlisted, ioc_key

#: Version tag of the correlation evidence policy. Bump when the evidence
#: types or the sufficiency policy change meaningfully.
CORRELATION_POLICY_VERSION = "correlation.v1"

#: Canonical provenance field paths that carry directional IP semantics
#: (typed fields — whole-value validation, ARCHITECTURE.md §7.1).
_SOURCE_IP_FIELD = "source_event.data.srcip"
_DESTINATION_IP_FIELD = "source_event.data.dstip"

#: Internal role tags an alert can assign to one indicator. ``indicator`` is
#: always present (any IOC is at least a shared indicator); the IP roles are
#: added only when the provenance proves the direction in that alert.
_ROLE_INDICATOR = "indicator"
_ROLE_SOURCE_IP = "source_ip"
_ROLE_DESTINATION_IP = "destination_ip"

#: Role priority when a shared indicator qualifies for more than one role:
#: the most specific shared semantics wins (deterministic).
_ROLE_PRIORITY: tuple[str, ...] = (_ROLE_SOURCE_IP, _ROLE_DESTINATION_IP, _ROLE_INDICATOR)


class EvidenceType(StrEnum):
    """Kind of shared attribute between two distinct alerts.

    Values are part of the correlation API contract (``evidence_type``
    field) and are stored verbatim in membership evidence rows.
    """

    SAME_AGENT = "same_agent"
    SAME_RULE = "same_rule"
    SHARED_TECHNIQUE = "shared_technique"
    SHARED_SOURCE_IP = "shared_source_ip"
    SHARED_DESTINATION_IP = "shared_destination_ip"
    SHARED_IOC = "shared_ioc"


#: Deterministic display/storage order for evidence lists (weakest context
#: first, strongest indicator evidence last). All orderings in the
#: correlation engine sort by ``(index in this tuple, value)``.
EVIDENCE_TYPE_ORDER: tuple[EvidenceType, ...] = (
    EvidenceType.SAME_AGENT,
    EvidenceType.SAME_RULE,
    EvidenceType.SHARED_TECHNIQUE,
    EvidenceType.SHARED_SOURCE_IP,
    EvidenceType.SHARED_DESTINATION_IP,
    EvidenceType.SHARED_IOC,
)

#: Evidence strong enough to justify correlation on its own: a shared
#: normalized indicator (hash, domain, url, email, or a direction-matched IP).
STRONG_EVIDENCE_TYPES: frozenset[EvidenceType] = frozenset(
    {
        EvidenceType.SHARED_SOURCE_IP,
        EvidenceType.SHARED_DESTINATION_IP,
        EvidenceType.SHARED_IOC,
    }
)

#: Supporting evidence that only justifies correlation in the combination
#: "same host + same ATT&CK technique" (never alone, never with just one of
#: the two — see the module docstring for the noise rationale).
_SUPPORTING_COMBINATION: frozenset[EvidenceType] = frozenset(
    {EvidenceType.SAME_AGENT, EvidenceType.SHARED_TECHNIQUE}
)

_REASON_TEMPLATES: dict[EvidenceType, str] = {
    EvidenceType.SAME_AGENT: "same agent {value}",
    EvidenceType.SAME_RULE: "same rule {value} fired on different agents",
    EvidenceType.SHARED_TECHNIQUE: "shared MITRE ATT&CK technique {value}",
    EvidenceType.SHARED_SOURCE_IP: "shared source IP {value}",
    EvidenceType.SHARED_DESTINATION_IP: "shared destination IP {value}",
    EvidenceType.SHARED_IOC: "shared indicator {value}",
}


class EvidenceItem(BaseModel):
    """One shared attribute between two alerts (immutable, explainable).

    ``value`` is the normalized reference both alerts share: the agent id,
    the rule id, the ATT&CK technique id, the bare IPv4 for directional IP
    evidence, or the indicator key ``"{type}:{value}"`` for generic
    indicator evidence.
    """

    model_config = {"frozen": True}

    evidence_type: EvidenceType
    value: str = Field(min_length=1)

    @property
    def reason(self) -> str:
        """Human-readable, deterministic explanation of this evidence."""
        return _REASON_TEMPLATES[self.evidence_type].format(value=self.value)

    @property
    def sort_key(self) -> tuple[int, str]:
        """Deterministic ordering key: evidence-type order, then value."""
        return (EVIDENCE_TYPE_ORDER.index(self.evidence_type), self.value)


def evidence_reason(evidence_type: str, value: str) -> str:
    """Explanation string for a stored ``(evidence_type, value)`` pair.

    Accepts the string form persisted in membership rows so read-side
    serializers never need to reconstruct pydantic models. Unknown types
    (possible only through schema drift) degrade to a generic sentence
    instead of failing the read.
    """
    try:
        typed = EvidenceType(evidence_type)
    except ValueError:
        return f"shared {evidence_type} {value}"
    return _REASON_TEMPLATES[typed].format(value=value)


def sort_evidence(items: list[EvidenceItem]) -> list[EvidenceItem]:
    """Return the evidence list in deterministic (type-order, value) order."""
    return sorted(items, key=lambda item: item.sort_key)


def _technique_ids(canonical: CanonicalAlert) -> list[str]:
    """MITRE ATT&CK technique ids a rule declares (sorted, deduplicated).

    ``rule.mitre`` is the verbatim ``WazuhMitre`` dump — ``{"id": [...],
    "tactic": [...], ...}``. Anything that is not a list of non-empty strings
    yields no techniques (never guessed).
    """
    mitre = canonical.source_event.rule.mitre
    if not isinstance(mitre, dict):
        return []
    ids = mitre.get("id")
    if not isinstance(ids, list):
        return []
    return sorted({str(item).strip() for item in ids if isinstance(item, str) and item.strip()})


def _indicator_roles(canonical: CanonicalAlert) -> dict[str, set[str]]:
    """Map each indicator key to the roles this alert proves for it.

    The key is the stable indicator identity ``"{type}:{value}"`` (so the
    same hash/IP/domain/url/email found anywhere in two alerts meets on one
    key); the roles carry the directional semantics the *provenance* proves
    in this alert (``data.srcip`` / ``data.dstip`` typed fields only).
    Allowlisted indicators are skipped entirely.
    """
    index: dict[str, set[str]] = {}
    for ioc in canonical.iocs:
        if ioc_is_allowlisted(ioc):
            continue
        key = ioc_key(ioc)
        roles = index.setdefault(key, set())
        roles.add(_ROLE_INDICATOR)
        if ioc.type is IOCType.IPV4:
            for provenance in ioc.provenance:
                if provenance.field == _SOURCE_IP_FIELD:
                    roles.add(_ROLE_SOURCE_IP)
                elif provenance.field == _DESTINATION_IP_FIELD:
                    roles.add(_ROLE_DESTINATION_IP)
    return index


def _best_shared_role(roles_a: set[str], roles_b: set[str]) -> str | None:
    """Most specific role both alerts prove for the same indicator."""
    shared = roles_a & roles_b
    for role in _ROLE_PRIORITY:
        if role in shared:
            return role
    return None


def pairwise_evidence(a: CanonicalAlert, b: CanonicalAlert) -> list[EvidenceItem]:
    """Deterministically derive every evidence item two alerts share.

    Pure and symmetric: ``pairwise_evidence(a, b) == pairwise_evidence(b, a)``.
    The caller (the correlation service) is responsible for the guards that
    live outside this function: an alert never correlates with itself, and
    alerts of the *same* dedupe group never correlate with each other (that
    relationship is already expressed by recurrence — correlation only
    relates distinct alerts).
    """
    items: list[EvidenceItem] = []

    agent_a = a.source_event.agent.id
    agent_b = b.source_event.agent.id
    if agent_a and agent_a == agent_b:
        items.append(EvidenceItem(evidence_type=EvidenceType.SAME_AGENT, value=agent_a))

    rule_a = a.source_event.rule.id
    rule_b = b.source_event.rule.id
    if rule_a and rule_a == rule_b:
        items.append(EvidenceItem(evidence_type=EvidenceType.SAME_RULE, value=rule_a))

    for technique in sorted(set(_technique_ids(a)) & set(_technique_ids(b))):
        items.append(EvidenceItem(evidence_type=EvidenceType.SHARED_TECHNIQUE, value=technique))

    roles_a = _indicator_roles(a)
    roles_b = _indicator_roles(b)
    # Directional roles exist only for IPv4 indicators, so stripping the
    # "ipv4:" prefix of the shared key yields the bare address for the
    # directional evidence values.
    for key in sorted(set(roles_a) & set(roles_b)):
        role = _best_shared_role(roles_a[key], roles_b[key])
        if role is None:  # pragma: no cover - indicator role is always present
            continue
        if role is _ROLE_SOURCE_IP:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.SHARED_SOURCE_IP,
                    value=_bare_indicator_value(key),
                )
            )
        elif role is _ROLE_DESTINATION_IP:
            items.append(
                EvidenceItem(
                    evidence_type=EvidenceType.SHARED_DESTINATION_IP,
                    value=_bare_indicator_value(key),
                )
            )
        else:
            items.append(EvidenceItem(evidence_type=EvidenceType.SHARED_IOC, value=key))

    return sort_evidence(items)


def _bare_indicator_value(key: str) -> str:
    """Strip the ``"{type}:"`` prefix from an indicator key."""
    return key.split(":", 1)[1] if ":" in key else key


def is_sufficient(items: list[EvidenceItem]) -> bool:
    """Whether the evidence between two alerts justifies correlation.

    Policy ``correlation.v1`` (see module docstring): any strong (shared
    indicator) evidence suffices; otherwise the combination same-agent +
    shared-technique suffices; everything else does not.
    """
    types = {item.evidence_type for item in items}
    if types & STRONG_EVIDENCE_TYPES:
        return True
    return types >= _SUPPORTING_COMBINATION


def evidence_reasons(items: list[EvidenceItem]) -> list[str]:
    """Deterministic explanation strings for an evidence list (audit/logs)."""
    return [item.reason for item in sort_evidence(items)]


__all__ = [
    "CORRELATION_POLICY_VERSION",
    "EVIDENCE_TYPE_ORDER",
    "STRONG_EVIDENCE_TYPES",
    "EvidenceItem",
    "EvidenceType",
    "evidence_reason",
    "evidence_reasons",
    "is_sufficient",
    "pairwise_evidence",
    "sort_evidence",
]
