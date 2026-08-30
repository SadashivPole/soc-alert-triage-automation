"""Configuration-driven scoring policy (Phase 1F).

The deterministic scoring engine is fully driven by a validated, immutable
:class:`ScoringPolicy`: factor weights, severity bands, asset-tier mapping,
recurrence thresholds, indicator weights, enrichment-status mapping, the
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

#: Valid enrichment status values the policy may map (ARCHITECTURE.md §5.2).
ENRICHMENT_STATUSES: tuple[str, ...] = ("complete", "partial", "failed", "skipped")


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
    "RecurrenceRule",
    "RecurrenceVelocityConfig",
    "RuleGroupsMitreConfig",
    "RuleSeverityConfig",
    "ScoringPolicy",
    "SeverityBand",
    "TierBand",
]
