"""Configuration-driven scoring policy (Phase 1F, extended by Phase 2.5).

The deterministic scoring engine is fully driven by a validated, immutable
:class:`ScoringPolicy`: factor weights, severity bands, asset-tier mapping,
recurrence thresholds, indicator weights, enrichment-status mapping, the
threat-intelligence weights (:class:`ThreatIntelConfig`, Phase 2.5), the
allowlist modifier, and the 0-100 tier boundaries. Tuning is a change to the
versioned, non-secret YAML under ``app/config/scoring.yaml`` (loaded and
validated by :mod:`soc_triage.scoring.config`) — never a code change
(ARCHITECTURE.md §8, §14).

Validation is strict and *fail-loud*: an invalid policy (missing tiers,
non-contiguous score coverage, unknown tier names, negative weights) raises a
:class:`pydantic.ValidationError` at load time rather than silently producing
wrong scores. The engine therefore never has to re-check its configuration.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator, model_validator

from ..models.assessment import RiskTier
from ..models.ioc import IOCType

#: Valid enrichment status values the policy may map (ARCHITECTURE.md §5.2).
ENRICHMENT_STATUSES: tuple[str, ...] = ("complete", "partial", "failed", "skipped")

#: Indicator names the ``threat_intel`` factor may inspect (mirrors
#: :class:`~soc_triage.models.ioc.IOCType`; Phase 2.5).
_IOC_TYPE_NAMES: frozenset[str] = frozenset(t.value for t in IOCType)


class SeverityBand(BaseModel):
    """A contiguous Wazuh ``rule.level`` range mapping to a point award."""

    model_config = {"frozen": True}

    min: int = Field(ge=0, le=15)
    max: int = Field(ge=0, le=15)
    points: int = Field(ge=0)

    @model_validator(mode="after")
    def _ordered(self) -> SeverityBand:
        if self.max < self.min:
            raise ValueError(f"severity band {self.min}-{self.max} is inverted")
        return self


class RuleSeverityConfig(BaseModel):
    """``rule_severity`` factor: Wazuh level → points (band map)."""

    model_config = {"frozen": True}

    max: int = Field(ge=0)
    bands: tuple[SeverityBand, ...]

    @field_validator("bands")
    @classmethod
    def _non_empty(cls, value: tuple[SeverityBand, ...]) -> tuple[SeverityBand, ...]:
        if not value:
            raise ValueError("rule_severity.bands must not be empty")
        return value


class RuleGroupsMitreConfig(BaseModel):
    """``rule_groups_mitre`` factor: suspicious groups + MITRE presence."""

    model_config = {"frozen": True}

    max: int = Field(ge=0)
    #: Rule group names that each add ``group_points``.
    group_keywords: tuple[str, ...] = ()
    group_points: int = Field(ge=0)
    #: Awarded when any MITRE technique id/name is present.
    mitre_points: int = Field(ge=0)
    #: Awarded when the number of MITRE tactics meets the threshold.
    multi_tactic_points: int = Field(ge=0)
    multi_tactic_threshold: int = Field(ge=2)


class AssetCriticalityConfig(BaseModel):
    """``asset_criticality`` factor: asset tier → points.

    ``bands`` maps a *canonical* criticality (``critical``/``high``/
    ``medium``/``low``) to points; ``tier_aliases`` maps the raw tier labels a
    source may emit (``tier-1``, ``standard``, …) onto those bands. Labels not
    present in any alias resolve to ``unknown_points``.
    """

    model_config = {"frozen": True}

    max: int = Field(ge=0)
    unknown_points: int = Field(ge=0)
    bands: dict[str, int] = Field(default_factory=dict)
    tier_aliases: dict[str, tuple[str, ...]] = Field(default_factory=dict)

    @field_validator("bands")
    @classmethod
    def _band_names(cls, value: dict[str, int]) -> dict[str, int]:
        for name in value:
            if name not in {"critical", "high", "medium", "low"}:
                raise ValueError(f"unknown asset band {name!r}")
        return value

    @field_validator("tier_aliases")
    @classmethod
    def _alias_targets(cls, value: dict[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
        for target in value:
            if target not in {"critical", "high", "medium", "low"}:
                raise ValueError(f"tier alias targets unknown band {target!r}")
        return value

    def resolve(self, tier: str | None) -> str | None:
        """Map a raw tier label to a canonical band name, or ``None`` if unknown."""
        label = (tier or "").strip().lower()
        if not label:
            return None
        for band, aliases in self.tier_aliases.items():
            if label == band or label in {a.strip().lower() for a in aliases}:
                return band
        return None


class RecurrenceRule(BaseModel):
    """One recurrence-velocity threshold (occurrences within a window)."""

    model_config = {"frozen": True}

    name: str = Field(min_length=1)
    min_occurrences: int = Field(ge=1)
    #: The generation span (seconds) within which the threshold must be met.
    max_window_seconds: int = Field(ge=0)
    points: int = Field(ge=0)


class RecurrenceVelocityConfig(BaseModel):
    """``recurrence_velocity`` factor: recurrence thresholds (cap = ``max``)."""

    model_config = {"frozen": True}

    max: int = Field(ge=0)
    rules: tuple[RecurrenceRule, ...] = ()


class IocEvidenceConfig(BaseModel):
    """``ioc_evidence`` factor: distinct indicators as evidence."""

    model_config = {"frozen": True}

    max: int = Field(ge=0)
    #: Points awarded per counted indicator.
    per_indicator: int = Field(ge=0)
    #: Maximum number of indicators counted (bounds the factor).
    max_counted: int = Field(ge=0)


class EnrichmentStatusConfig(BaseModel):
    """``enrichment_status`` factor: corroboration credit for intel coverage."""

    model_config = {"frozen": True}

    max: int = Field(ge=0)
    #: Enrichment status value → points (absent statuses yield 0, fail-safe).
    points: dict[str, int] = Field(default_factory=dict)

    @field_validator("points")
    @classmethod
    def _known_statuses(cls, value: dict[str, int]) -> dict[str, int]:
        for status in value:
            if status not in ENRICHMENT_STATUSES:
                raise ValueError(f"unknown enrichment status {status!r}")
        return value


class VirustotalIntelConfig(BaseModel):
    """VirusTotal half of the ``threat_intel`` factor (ARCHITECTURE.md §8.2).

    Drives one per-indicator award from the sanitized
    ``last_analysis_stats`` counts a VT ``found`` verdict carries:

    * ``malicious >= malicious_high_min`` → :attr:`malicious_high_points`;
    * ``malicious >= 1`` (i.e. below ``malicious_high_min``) →
      :attr:`malicious_low_points`;
    * no malicious verdicts but ``suspicious >= suspicious_min`` →
      :attr:`suspicious_only_points`;
    * anything else (a clean or "no report" answer) → 0.

    The documented bands are ">=10 -> 15" and "2-9 -> 8"; the implementation
    keeps the lower band open-ended at ``malicious >= 1`` so every positive
    detection is credited — a single-engine detection is simply worth the low
    band. ``malicious_high_min`` may not be tuned below ``1`` (that would
    invert the two bands).
    """

    model_config = {"frozen": True}

    #: Provider payload key under ``IOC.enrichment`` (``VirusTotalProvider.name``).
    provider: str = "virustotal"
    malicious_high_min: int = Field(default=10, ge=1)
    malicious_high_points: int = Field(default=15, ge=0)
    malicious_low_points: int = Field(default=8, ge=0)
    suspicious_min: int = Field(default=1, ge=1)
    suspicious_only_points: int = Field(default=4, ge=0)

    @model_validator(mode="after")
    def _bands_ordered(self) -> VirustotalIntelConfig:
        """Bands must be monotonic, or a noisier verdict could score less than a worse one."""
        if self.malicious_high_points < self.malicious_low_points:
            raise ValueError("virustotal malicious_high_points must be >= malicious_low_points")
        if self.malicious_low_points < self.suspicious_only_points:
            raise ValueError("virustotal malicious_low_points must be >= suspicious_only_points")
        return self


class MispIntelConfig(BaseModel):
    """MISP half of the ``threat_intel`` factor (ARCHITECTURE.md §8.2).

    A MISP ``found`` verdict carrying at least one matched attribute earns
    :attr:`event_match_points`, plus :attr:`threat_actor_bonus_points` when one
    of its (sanitized) tags names a threat actor. Tag text is matched
    case-insensitively against :attr:`threat_actor_tags` only — unlisted tags
    never influence a score and are never reproduced in a factor explanation
    (SECURITY.md §7: upstream strings are not log-safe).
    """

    model_config = {"frozen": True}

    #: Provider payload key under ``IOC.enrichment`` (``MISPProvider.name``).
    provider: str = "misp"
    event_match_points: int = Field(default=10, ge=0)
    threat_actor_bonus_points: int = Field(default=5, ge=0)
    #: Lowercased tag names treated as threat-actor attribution.
    threat_actor_tags: tuple[str, ...] = ("apt", "threat-actor", "intrusion-set")

    @field_validator("threat_actor_tags")
    @classmethod
    def _normalized_tags(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for tag in value:
            cleaned = tag.strip().lower()
            if not cleaned:
                raise ValueError("threat_actor_tags must not contain a blank tag")
            if cleaned not in normalized:
                normalized.append(cleaned)
        return tuple(normalized)

    def is_threat_actor_tag(self, tag: str) -> bool:
        """Whether a MISP tag names a threat actor under this policy.

        Matching is case-insensitive and accepts both an exact tag (``apt``)
        and its qualified forms (``apt:38``), because MISP taxonomies append a
        colon-suffix to the taxonomy name. It is deliberately *not* substring
        matching: an unrelated tag such as ``capture`` must not inherit the
        bonus.
        """
        cleaned = tag.strip().lower()
        for listed in self.threat_actor_tags:
            if cleaned == listed or cleaned.startswith(f"{listed}:"):
                return True
        return False


class ThreatIntelConfig(BaseModel):
    """``threat_intel`` factor: VT/MISP verdicts as evidence (Phase 2.5).

    Optional in the policy: a ``scoring.v1``-shaped policy without this block
    simply has no ``threat_intel`` factor at all (the engine omits it), which is
    what keeps every pre-2.5 golden and stored assessment interpretable.

    The factor is **evidence-only**: it reads the *sanitized* provider payloads
    attached to indicators by enrichment and never performs I/O, so an
    unavailable provider (disabled / failed / timed out / rate-limited) yields
    0 points rather than a guess — the same fail-safe contract as
    :class:`EnrichmentStatusConfig`.
    """

    model_config = {"frozen": True}

    max: int = Field(ge=0)
    #: Upper bound on indicators folded into the explanation text (the sum is
    #: computed over all indicators; only the *detail* string is bounded).
    detail_max_iocs: int = Field(default=3, ge=1)
    #: Indicator types each provider may have looked up (union of the VT and
    #: MISP ``handled_types``); other indicators are skipped without inspection.
    handled_types: tuple[str, ...] = ("ipv4", "domain", "url", "md5", "sha1", "sha256")
    virustotal: VirustotalIntelConfig = Field(default_factory=VirustotalIntelConfig)
    misp: MispIntelConfig = Field(default_factory=MispIntelConfig)

    @field_validator("handled_types")
    @classmethod
    def _known_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("threat_intel.handled_types must not be empty")
        for name in value:
            if name not in _IOC_TYPE_NAMES:
                raise ValueError(f"unknown indicator type {name!r} in threat_intel.handled_types")
        return tuple(sorted(set(value)))


class AllowlistConfig(BaseModel):
    """``allowlist_modifier``: subtraction applied when a source is allowlisted."""

    model_config = {"frozen": True}

    subtract: int = Field(ge=0)


class TierBand(BaseModel):
    """One score band mapping a range to a risk tier."""

    model_config = {"frozen": True}

    name: RiskTier
    min: int = Field(ge=0, le=100)
    max: int = Field(ge=0, le=100)


class ScoringPolicy(BaseModel):
    """The complete, validated scoring policy (factor config + tier bands)."""

    model_config = {"frozen": True}

    engine_version: str = Field(min_length=1)
    rule_severity: RuleSeverityConfig
    rule_groups_mitre: RuleGroupsMitreConfig
    asset_criticality: AssetCriticalityConfig
    recurrence_velocity: RecurrenceVelocityConfig
    ioc_evidence: IocEvidenceConfig
    enrichment_status: EnrichmentStatusConfig
    #: Phase 2.5 intel factor; ``None`` ⇒ the factor is absent entirely
    #: (a scoring.v1-shaped policy keeps its 7-factor contract).
    threat_intel: ThreatIntelConfig | None = None
    allowlist: AllowlistConfig
    tiers: tuple[TierBand, ...]

    @model_validator(mode="after")
    def _tiers_cover_0_to_100(self) -> ScoringPolicy:
        """Require non-overlapping, contiguous, complete 0-100 tier coverage."""
        expected = 0
        seen: set[RiskTier] = set()
        for band in self.tiers:
            if band.name in seen:
                raise ValueError(f"duplicate tier {band.name.value!r}")
            if band.min != expected:
                raise ValueError(
                    f"tier {band.name.value!r} starts at {band.min}, expected {expected}"
                )
            if band.max < band.min:
                raise ValueError(f"tier {band.name.value!r} is inverted")
            seen.add(band.name)
            expected = band.max + 1
        if expected != 101:
            raise ValueError(f"tiers must cover 0-100 contiguously (ends at {expected - 1})")
        return self

    @model_validator(mode="after")
    def _intel_weights_within_factor_max(self) -> ScoringPolicy:
        """Reject intel weights that cannot fit inside the factor's own cap.

        Without this, a typo in ``scoring.yaml`` could make the documented
        maximum unreachable (or meaningless) and silently change every
        intel-bearing golden.
        """
        intel = self.threat_intel
        if intel is None:
            return self
        vt = intel.virustotal
        misp = intel.misp
        vt_max = max(vt.malicious_high_points, vt.malicious_low_points, vt.suspicious_only_points)
        misp_max = misp.event_match_points + misp.threat_actor_bonus_points
        if vt_max > intel.max:
            raise ValueError(
                f"threat_intel max {intel.max} is below the largest Virustotal "
                f"award {vt_max} (an intel band would be silently clipped)"
            )
        if misp_max > intel.max:
            raise ValueError(
                f"threat_intel max {intel.max} is below the maximum MISP award "
                f"{misp_max} — event match plus threat-actor bonus would be clipped"
            )
        return self

    def tier_for(self, score: int) -> RiskTier:
        """Return the risk tier for a (clipped) score."""
        for band in self.tiers:
            if band.min <= score <= band.max:
                return band.name
        # Defensive: tiers are validated to cover 0-100, so this is unreachable.
        return RiskTier.CRITICAL if score > 100 else RiskTier.INFORMATIONAL


__all__ = [
    "ENRICHMENT_STATUSES",
    "AllowlistConfig",
    "AssetCriticalityConfig",
    "EnrichmentStatusConfig",
    "IocEvidenceConfig",
    "MispIntelConfig",
    "RecurrenceRule",
    "RecurrenceVelocityConfig",
    "RuleGroupsMitreConfig",
    "RuleSeverityConfig",
    "ScoringPolicy",
    "SeverityBand",
    "ThreatIntelConfig",
    "TierBand",
    "VirustotalIntelConfig",
]
