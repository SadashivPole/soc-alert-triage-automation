"""Deterministic risk scoring engine (Phase 1F, extended by Phase 2.5).

:func:`score_alert` is the **pure** scoring function:
``(CanonicalAlert, ScoringPolicy) → RiskAssessment``. It performs no I/O, no
clock reads (``decided_at`` aside), no logging, and no randomness, so the same
alert + policy always yields an identical score, tier, factor breakdown, and
summary — the explainability contract (ARCHITECTURE.md §8, §17).

Factors (each config-driven, each emitting a human-readable ``detail``):

* ``rule_severity`` — Wazuh ``rule.level`` band map;
* ``rule_groups_mitre`` — suspicious rule groups + MITRE technique/tactic
  presence;
* ``asset_criticality`` — asset tier (from ``asset.tier``) via the policy's
  tier→band mapping, with an *unknown* neutral fallback;
* ``recurrence_velocity`` — occurrence count within the generation span,
  against policy thresholds;
* ``ioc_evidence`` — distinct extracted indicators (count-capped);
* ``enrichment_status`` — corroboration credit (``complete``/``partial``);
* ``threat_intel`` — **Phase 2.5**: sanitized VT/MISP verdicts attached to the
  indicators (present only when ``threat_intel`` is configured, i.e. under
  ``scoring.v2``);
* ``allowlist_modifier`` — a *subtractive* modifier when an indicator is
  allowlisted (floor at 0).

The raw sum is clipped to 0-100 and mapped to a :class:`RiskTier` via the
policy's tier bands.

**Fail-safely.** The pure function is total for any well-formed alert and
validated policy; missing optional fields (no MITRE, no asset tier, no dedupe
info, no IOCs, enrichment ``failed``/``skipped``) simply contribute zero
points — enrichment unavailability never blocks or corrupts scoring. The
:class:`RiskScorer` wrapper adds the ARCHITECTURE.md §16 degraded fallback:
if the engine ever raises, it returns a rule-severity-only assessment flagged
``degraded=True`` rather than crashing ingest.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.logging import get_logger
from ..models.assessment import RiskAssessment, RiskTier, ScoreFactor
from ..models.canonical import CanonicalAlert, CanonicalAsset, CanonicalDedupe, CanonicalRule
from ..models.ioc import IOC, IOCType, ioc_is_allowlisted
from .policy import (
    AllowlistConfig,
    AssetCriticalityConfig,
    EnrichmentStatusConfig,
    IocEvidenceConfig,
    RecurrenceVelocityConfig,
    RuleGroupsMitreConfig,
    RuleSeverityConfig,
    ScoringPolicy,
    ThreatIntelConfig,
)

logger = get_logger("soc_triage.scoring.engine")

#: Stable factor ordering (deterministic output + summary, ARCHITECTURE.md §8).
#: ``threat_intel`` is only emitted when the policy configures it (2.5), and
#: ``allowlist_modifier`` stays last so the subtractive modifier reads as the
#: final adjustment in every version of the factor set.
_FACTOR_ORDER: tuple[str, ...] = (
    "rule_severity",
    "rule_groups_mitre",
    "asset_criticality",
    "recurrence_velocity",
    "ioc_evidence",
    "enrichment_status",
    "threat_intel",
    "allowlist_modifier",
)


def _clamp(score: int) -> int:
    """Clip a raw score to the 0-100 contract."""
    return max(0, min(100, score))


def _rule_severity_factor(rule: CanonicalRule, cfg: RuleSeverityConfig) -> ScoreFactor:
    level = rule.level
    for band in cfg.bands:
        if band.min <= level <= band.max:
            return ScoreFactor(
                name="rule_severity",
                points=band.points,
                max=cfg.max,
                detail=(
                    f"Wazuh rule level {level} → severity band {band.min}-{band.max} "
                    f"({band.points}/{cfg.max})"
                ),
            )
    return ScoreFactor(
        name="rule_severity",
        points=0,
        max=cfg.max,
        detail=f"Wazuh rule level {level} is outside all configured severity bands (0/{cfg.max})",
    )


def _rule_groups_mitre_factor(rule: CanonicalRule, cfg: RuleGroupsMitreConfig) -> ScoreFactor:
    points = 0
    notes: list[str] = []

    matched_groups = [group for group in rule.groups if group in cfg.group_keywords]
    if matched_groups:
        points += cfg.group_points * len(matched_groups)
        notes.append(f"groups {', '.join(matched_groups)}")

    mitre = rule.mitre or {}
    technique_ids = mitre.get("id") or []
    technique_names = mitre.get("technique") or []
    tactics = mitre.get("tactic") or []
    has_technique = bool(technique_ids) or bool(technique_names)
    if has_technique:
        points += cfg.mitre_points
        notes.append("MITRE technique present")
    if len(tactics) >= cfg.multi_tactic_threshold:
        points += cfg.multi_tactic_points
        notes.append(f"{len(tactics)} MITRE tactics")

    points = min(points, cfg.max)
    if not notes:
        notes.append("no suspicious groups or MITRE technique")
    return ScoreFactor(
        name="rule_groups_mitre",
        points=points,
        max=cfg.max,
        detail=f"{'; '.join(notes)} ({points}/{cfg.max})",
    )


def _asset_criticality_factor(
    asset: CanonicalAsset | None, cfg: AssetCriticalityConfig
) -> ScoreFactor:
    tier = asset.tier if asset is not None else None
    band = cfg.resolve(tier)
    if band is None:
        points = cfg.unknown_points
        label = f"tier {tier!r}" if tier else "no tier label"
        return ScoreFactor(
            name="asset_criticality",
            points=points,
            max=cfg.max,
            detail=f"asset {label} → unknown ({points}/{cfg.max})",
        )
    points = cfg.bands.get(band, 0)
    return ScoreFactor(
        name="asset_criticality",
        points=points,
        max=cfg.max,
        detail=f"asset tier {tier!r} → {band} ({points}/{cfg.max})",
    )


def _recurrence_velocity_factor(
    dedupe: CanonicalDedupe | None, cfg: RecurrenceVelocityConfig
) -> ScoreFactor:
    if dedupe is None:
        return ScoreFactor(
            name="recurrence_velocity",
            points=0,
            max=cfg.max,
            detail=f"no recurrence data (0/{cfg.max})",
        )
    occurrences = dedupe.occurrences
    span = max(0.0, (dedupe.last_seen - dedupe.first_seen).total_seconds())

    matched: list[str] = []
    total = 0
    for rule in cfg.rules:
        if occurrences >= rule.min_occurrences and span <= rule.max_window_seconds:
            total += rule.points
            matched.append(rule.name)

    points = min(total, cfg.max)
    if matched:
        detail = (
            f"{occurrences} occurrence(s) over {span:.0f}s; "
            f"matched {', '.join(matched)} ({points}/{cfg.max})"
        )
    else:
        detail = (
            f"{occurrences} occurrence(s) over {span:.0f}s; "
            f"no recurrence threshold met (0/{cfg.max})"
        )
    return ScoreFactor(
        name="recurrence_velocity",
        points=points,
        max=cfg.max,
        detail=detail,
    )


def _ioc_evidence_factor(iocs: list[IOC], cfg: IocEvidenceConfig) -> ScoreFactor:
    count = len(iocs)
    counted = min(count, cfg.max_counted)
    points = min(counted * cfg.per_indicator, cfg.max)
    types = sorted({ioc.type.value for ioc in iocs})
    if types:
        detail = f"{count} indicator(s) ({', '.join(types)}) → {points}/{cfg.max}"
    else:
        detail = f"no indicators extracted (0/{cfg.max})"
    return ScoreFactor(
        name="ioc_evidence",
        points=points,
        max=cfg.max,
        detail=detail,
    )


def _enrichment_status_factor(status: str | None, cfg: EnrichmentStatusConfig) -> ScoreFactor:
    normalized = (status or "skipped").strip().lower()
    points = cfg.points.get(normalized, 0)
    if normalized == "failed":
        detail = f"enrichment unavailable ({normalized}) → 0/{cfg.max} (fail-safe)"
    elif points:
        detail = f"enrichment {normalized} → {points}/{cfg.max}"
    else:
        detail = f"enrichment {normalized} → 0/{cfg.max}"
    return ScoreFactor(
        name="enrichment_status",
        points=points,
        max=cfg.max,
        detail=detail,
    )


#: Lookup outcomes that carry *no* intel conclusion (fail-safe ⇒ 0 points).
_INTEL_UNAVAILABLE_STATUSES: frozenset[str] = frozenset({"error", "timeout", "rate_limited"})

#: Indicator sets the two intel providers can answer for (mirrors their
#: ``handled_types``): an email is never a VirusTotal lookup, so a payload on
#: an unhandled type is ignored rather than trusted.
_VT_HANDLED_TYPES: frozenset[IOCType] = frozenset(
    {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }
)
_MISP_HANDLED_TYPES: frozenset[IOCType] = frozenset(IOCType)

#: Provider tags are free-text upstream data; only a conservative shape may be
#: quoted in a stored factor explanation (SECURITY.md §2, §7). A tag that looks
#: like payload content still earns its bonus — it is simply never echoed.
_SAFE_TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:.+_@/-]{0,63}")


def _provider_payload(ioc: IOC, provider: str) -> dict[str, Any] | None:
    """The sanitized payload one provider attached to an indicator, if any.

    A non-mapping value (a payload written by a foreign provider) reads as *no
    evidence* instead of raising: the scoring function must stay total.
    """
    payload = ioc.enrichment.get(provider)
    return payload if isinstance(payload, dict) else None


def _lookup_available(payload: dict[str, Any]) -> bool:
    """Whether a lookup answered definitively (vs failed / timed out / limited)."""
    return str(payload.get("lookup_status") or "") not in _INTEL_UNAVAILABLE_STATUSES


def _payload_result(payload: dict[str, Any]) -> dict[str, Any]:
    """The ``result`` sub-mapping of a lookup record (``{}`` when malformed)."""
    result = payload.get("result")
    return result if isinstance(result, dict) else {}


def _evidence_count(payload: dict[str, Any], key: str) -> int:
    """A non-negative integer evidence count; absent/malformed/negative → 0."""
    value = payload.get(key)
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value if value > 0 else 0
    return 0


def _string_list(payload: dict[str, Any], key: str) -> tuple[str, ...]:
    """A list of strings from a payload (non-lists and non-strings are dropped)."""
    values = payload.get(key)
    if not isinstance(values, (list, tuple)):
        return ()
    return tuple(str(value) for value in values if isinstance(value, (str, int)))


def _virustotal_award(result: dict[str, Any], cfg: ThreatIntelConfig) -> int:
    """Per-indicator Virustotal award (ARCHITECTURE.md §8.2 bands)."""
    vt = cfg.virustotal
    malicious = _evidence_count(result, "malicious")
    if malicious >= vt.malicious_high_min:
        return vt.malicious_high_points
    if malicious > 0:
        return vt.malicious_low_points
    if _evidence_count(result, "suspicious") >= vt.suspicious_min:
        return vt.suspicious_only_points
    return 0


def _intel_detail(
    cfg: ThreatIntelConfig,
    points: int,
    *,
    vt_hits: list[str],
    vt_malicious: dict[str, int],
    vt_suspicious_total: int,
    misp_hits: list[str],
    misp_actor_tags: dict[str, None],
) -> str:
    """Compose the ``threat_intel`` explanation, bounded and deterministic.

    Only aggregate counts plus the first ``detail_max_iocs`` indicator keys are
    quoted, so the text cannot grow with the IOC count; the lists arrive
    already sorted, so identical evidence always renders identically.
    """
    limit = cfg.detail_max_iocs
    parts: list[str] = []

    if vt_hits:
        worst = max(vt_malicious.values())
        listed = ", ".join(vt_hits[:limit])
        more = len(vt_hits) - limit
        suffix = f" (+{more} more)" if more > 0 else ""
        parts.append(
            f"Virustotal: {len(vt_hits)} indicator(s) with malicious verdicts "
            f"[{listed}{suffix}], max {worst} engine(s) flagging"
        )
    if vt_suspicious_total:
        label = "suspicious-only evidence" if not vt_hits else "further suspicious hits"
        parts.append(f"Virustotal: {label}, {vt_suspicious_total} suspicious engine hit(s)")

    if misp_hits:
        listed = ", ".join(misp_hits[:limit])
        more = len(misp_hits) - limit
        suffix = f" (+{more} more)" if more > 0 else ""
        line = f"MISP: {len(misp_hits)} indicator(s) matched events [{listed}{suffix}]"
        if misp_actor_tags:
            line += f"; threat-actor tags {', '.join(sorted(misp_actor_tags)[:limit])}"
        parts.append(line)

    if not parts:
        return f"no corroborating threat-intel verdicts (0/{cfg.max})"
    return f"{'; '.join(parts)} → {points}/{cfg.max}"


def _threat_intel_factor(iocs: list[IOC], cfg: ThreatIntelConfig) -> ScoreFactor:
    """``threat_intel`` factor: VirusTotal + MISP verdicts (ARCHITECTURE §8.2).

    Reads **only** the sanitized payloads enrichment already attached to the
    indicators (``IOC.enrichment[provider]``) — never a live service and never
    a raw upstream body. Per-indicator awards from both providers are summed
    and capped at ``cfg.max``. A provider that is disabled, missing, errored,
    timed out or rate-limited contributes nothing, so an intel outage can only
    ever *lower* the intel contribution, never corrupt it (§16 fail-safe).
    """
    vt = cfg.virustotal
    misp = cfg.misp
    total = 0

    vt_hits: list[str] = []
    vt_malicious: dict[str, int] = {}
    vt_suspicious_total = 0
    # A zero-weight provider (a deliberate no-op in the policy) earns no
    # points, so its matches are not narrated in the explanation either.
    narrate_misp = misp.event_match_points > 0 or misp.threat_actor_bonus_points > 0
    misp_hits: list[str] = []
    misp_actor_tags: dict[str, None] = {}

    # Sorted by indicator key so both the arithmetic and the explanation are
    # independent of enrichment ordering (dedupe is by key, so awarding each
    # indicator once per provider keeps the factor idempotent).
    for ioc in sorted(iocs, key=lambda candidate: candidate.key):
        if ioc.type.value not in cfg.handled_types:
            continue

        payload = _provider_payload(ioc, vt.provider)
        if payload is not None and _lookup_available(payload) and ioc.type in _VT_HANDLED_TYPES:
            result = _payload_result(payload)
            award = _virustotal_award(result, cfg)
            malicious = _evidence_count(result, "malicious")
            if award:
                total += award
                vt_hits.append(ioc.key)
                vt_malicious[ioc.key] = malicious
            vt_suspicious_total += _evidence_count(result, "suspicious")

        payload = _provider_payload(ioc, misp.provider)
        if payload is None or not _lookup_available(payload) or ioc.type not in _MISP_HANDLED_TYPES:
            continue
        result = _payload_result(payload)
        event_ids = _string_list(result, "event_ids")
        if _evidence_count(result, "match_count") <= 0 and not event_ids:
            continue
        total += misp.event_match_points
        if narrate_misp:
            misp_hits.append(ioc.key)
        for tag in _string_list(result, "tags"):
            if not misp.is_threat_actor_tag(tag):
                continue
            total += misp.threat_actor_bonus_points
            if _SAFE_TAG_RE.fullmatch(tag) and narrate_misp:
                misp_actor_tags[tag] = None
            break

    points = min(total, cfg.max)
    return ScoreFactor(
        name="threat_intel",
        points=points,
        max=cfg.max,
        detail=_intel_detail(
            cfg,
            points,
            vt_hits=sorted(vt_hits),
            vt_malicious=vt_malicious,
            vt_suspicious_total=vt_suspicious_total,
            misp_hits=sorted(misp_hits),
            misp_actor_tags=misp_actor_tags,
        ),
    )


def _allowlist_factor(iocs: list[IOC], cfg: AllowlistConfig) -> ScoreFactor:
    allowlisted = any(ioc_is_allowlisted(ioc) for ioc in iocs)
    if allowlisted:
        return ScoreFactor(
            name="allowlist_modifier",
            points=-cfg.subtract,
            max=cfg.subtract,
            detail=f"allowlisted indicator present → -{cfg.subtract}",
        )
    return ScoreFactor(
        name="allowlist_modifier",
        points=0,
        max=cfg.subtract,
        detail="no allowlisted indicators",
    )


def _summary(score: int, tier: RiskTier, factors: tuple[ScoreFactor, ...]) -> str:
    parts = ", ".join(f"{f.name} {f.points:+d}/{f.max}" for f in factors)
    return f"Score {score} ({tier.value}): {parts}."


def score_alert(
    alert: CanonicalAlert,
    *,
    policy: ScoringPolicy,
) -> RiskAssessment:
    """Compute a deterministic, explainable risk assessment for an alert.

    Pure and side-effect free: identical inputs yield identical output
    (including factor order and summary text). All inputs are read from the
    canonical alert itself (rule metadata, asset tier, recurrence info,
    indicators with their attached provider payloads, and ``enrichment_status``).

    The factor *set* is policy-driven: a policy without a ``threat_intel``
    block (``scoring.v1``) yields the original 7 factors, byte-identically to
    before Phase 2.5; a policy that configures it (``scoring.v2``) adds the
    intel factor in its documented position.

    Args:
        alert: The canonical alert (IOCs, dedupe info, asset, and enrichment
            status should already be populated by upstream phases).
        policy: The validated, immutable scoring policy.

    Returns:
        A :class:`RiskAssessment` with score (0-100), tier, per-factor
        breakdown, and a generated summary.
    """
    rule = alert.source_event.rule
    iocs = list(alert.iocs)
    built: dict[str, ScoreFactor] = {
        "rule_severity": _rule_severity_factor(rule, policy.rule_severity),
        "rule_groups_mitre": _rule_groups_mitre_factor(rule, policy.rule_groups_mitre),
        "asset_criticality": _asset_criticality_factor(alert.asset, policy.asset_criticality),
        "recurrence_velocity": _recurrence_velocity_factor(
            alert.dedupe, policy.recurrence_velocity
        ),
        "ioc_evidence": _ioc_evidence_factor(iocs, policy.ioc_evidence),
        "enrichment_status": _enrichment_status_factor(
            alert.enrichment_status, policy.enrichment_status
        ),
        "allowlist_modifier": _allowlist_factor(iocs, policy.allowlist),
    }
    intel = policy.threat_intel
    if intel is not None:  # scoring.v2 only: the factor is absent under v1 policies
        built["threat_intel"] = _threat_intel_factor(iocs, intel)
    # Emitted in the declared factor order, not construction order.
    factors = tuple(built[name] for name in _FACTOR_ORDER if name in built)

    raw = sum(factor.points for factor in factors)
    score = _clamp(raw)
    tier = policy.tier_for(score)
    return RiskAssessment(
        score=score,
        tier=tier,
        engine_version=policy.engine_version,
        factors=factors,
        summary=_summary(score, tier, factors),
    )


def degraded_score(alert: CanonicalAlert, *, policy: ScoringPolicy) -> RiskAssessment:
    """Rule-severity-only fallback assessment (ARCHITECTURE.md §16).

    Used only when the full engine raises. It never touches enrichment or IOC
    data, so it cannot fail for the same reason the engine did; the score is
    still deterministic and within 0-100.
    """
    factor = _rule_severity_factor(alert.source_event.rule, policy.rule_severity)
    score = _clamp(factor.points)
    tier = policy.tier_for(score)
    return RiskAssessment(
        score=score,
        tier=tier,
        engine_version=policy.engine_version,
        factors=(factor,),
        summary=(f"Degraded fallback: {factor.detail}; score {score} ({tier.value})."),
        degraded=True,
    )


class RiskScorer:
    """Resilient wrapper around the pure :func:`score_alert`.

    Ingest uses this so a scoring-engine failure can never break the pipeline
    (ARCHITECTURE.md §16): any exception is logged (type only, no payloads)
    and replaced by the rule-severity-only :func:`degraded_score`.
    """

    def __init__(self, policy: ScoringPolicy) -> None:
        self._policy = policy

    @property
    def policy(self) -> ScoringPolicy:
        """The scorer's validated policy."""
        return self._policy

    def score(self, alert: CanonicalAlert) -> RiskAssessment:
        """Score an alert, falling back to a degraded score on engine failure."""
        try:
            return score_alert(alert, policy=self._policy)
        except Exception as exc:  # fail-open, never crash ingest (ARCHITECTURE §16)
            logger.warning(
                "scoring_engine_degraded",
                component="scoring",
                alert_id=str(alert.alert_id),
                error_type=type(exc).__name__,
            )
            return degraded_score(alert, policy=self._policy)


__all__ = [
    "RiskScorer",
    "degraded_score",
    "score_alert",
]
