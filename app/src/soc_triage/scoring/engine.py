"""Deterministic risk scoring engine (Phase 1F).

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

from ..core.logging import get_logger
from ..models.assessment import RiskAssessment, RiskTier, ScoreFactor
from ..models.canonical import CanonicalAlert, CanonicalAsset, CanonicalDedupe, CanonicalRule
from ..models.ioc import IOC, ioc_is_allowlisted
from .policy import (
    AllowlistConfig,
    AssetCriticalityConfig,
    EnrichmentStatusConfig,
    IocEvidenceConfig,
    RecurrenceVelocityConfig,
    RuleGroupsMitreConfig,
    RuleSeverityConfig,
    ScoringPolicy,
)

logger = get_logger("soc_triage.scoring.engine")

#: Stable factor ordering (deterministic output + summary, ARCHITECTURE.md §8).
_FACTOR_ORDER: tuple[str, ...] = (
    "rule_severity",
    "rule_groups_mitre",
    "asset_criticality",
    "recurrence_velocity",
    "ioc_evidence",
    "enrichment_status",
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
    indicators, and ``enrichment_status``).

    Args:
        alert: The canonical alert (IOCs, dedupe info, asset, and enrichment
            status should already be populated by upstream phases).
        policy: The validated, immutable scoring policy.

    Returns:
        A :class:`RiskAssessment` with score (0-100), tier, per-factor
        breakdown, and a generated summary.
    """
    rule = alert.source_event.rule
    factors = (
        _rule_severity_factor(rule, policy.rule_severity),
        _rule_groups_mitre_factor(rule, policy.rule_groups_mitre),
        _asset_criticality_factor(alert.asset, policy.asset_criticality),
        _recurrence_velocity_factor(alert.dedupe, policy.recurrence_velocity),
        _ioc_evidence_factor(list(alert.iocs), policy.ioc_evidence),
        _enrichment_status_factor(alert.enrichment_status, policy.enrichment_status),
        _allowlist_factor(list(alert.iocs), policy.allowlist),
    )

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
