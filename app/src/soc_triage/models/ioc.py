"""Indicator-of-compromise (IOC) domain model (Phase 1E).

An :class:`IOC` is the normalized representation of one indicator found in a
canonical alert, together with its **provenance** — exactly where it came
from. Extraction is a pure function (:mod:`soc_triage.enrichment.extractor`);
enrichment providers attach verdicts to the ``enrichment`` mapping later
(:mod:`soc_triage.enrichment.providers`).

Provenance design (ARCHITECTURE.md §7.1, SECURITY.md §5):

* ``field`` — canonical dotted path the indicator was read from
  (e.g. ``source_event.data.srcip``), so an analyst can trace the value back
  to the payload Wazuh delivered;
* ``location`` — the alert's source location (log file / event channel), i.e.
  *where in the monitored system* the evidence surfaced;
* ``offset`` + ``raw_value`` — the character offset and the exact substring
  inside a free-text field (``None`` for typed fields, where the whole value
  had to validate);
* ``extractor`` — which strategy produced it (``typed_field`` / ``text_scan``).

Only the indicator itself is stored — never the surrounding raw log
(SECURITY.md §5: the platform keeps raw payloads to what Wazuh already
logged, and IOC data must stay small enough for logs, responses and audit).

This module is deliberately dependency-free (it imports nothing from the rest
of the package) so both :mod:`soc_triage.models.canonical` and
:mod:`soc_triage.enrichment` can depend on it without import cycles.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

#: :attr:`IOCProvenance.extractor` value for IOCs read from a *typed*
#: canonical field: the whole field value had to validate as that type.
EXTRACTOR_TYPED_FIELD = "typed_field"

#: :attr:`IOCProvenance.extractor` value for IOCs matched inside a free-text
#: field by pattern scan.
EXTRACTOR_TEXT_SCAN = "text_scan"


class IOCType(StrEnum):
    """Supported indicator types (ARCHITECTURE.md §7.1, Phase 1E scope)."""

    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


#: Expected hex length per hash type (format validation, never content checks).
HASH_LENGTHS: dict[IOCType, int] = {
    IOCType.MD5: 32,
    IOCType.SHA1: 40,
    IOCType.SHA256: 64,
}


class IOCProvenance(BaseModel):
    """Where and how one indicator was found (immutable evidence record)."""

    model_config = {"frozen": True}

    #: Canonical dotted path, e.g. ``source_event.data.srcip``.
    field: str = Field(min_length=1)
    #: Extraction strategy: :data:`EXTRACTOR_TYPED_FIELD` or
    #: :data:`EXTRACTOR_TEXT_SCAN`.
    extractor: str = Field(min_length=1)
    #: The exact substring as it appeared in the field (pre-normalization).
    raw_value: str
    #: Character offset of ``raw_value`` inside the field value (scan only).
    offset: int | None = Field(default=None, ge=0)
    #: Alert source location (log file / event channel), when known.
    location: str | None = None


class IOC(BaseModel):
    """One normalized indicator with its provenance and enrichment payloads.

    ``value`` is the **normalized representation** (lowercased hashes and
    domains, canonical URL form, dotted-quad IPv4). The same indicator found
    in several fields collapses into a single :class:`IOC` whose
    ``provenance`` lists every source — that is what makes extraction
    idempotent and keeps later enrichment lookups one-per-indicator.
    """

    model_config = {"frozen": True}

    type: IOCType
    #: Normalized representation of the indicator.
    value: str = Field(min_length=1)
    provenance: tuple[IOCProvenance, ...] = ()
    #: Provider name → provider payload (populated by enrichment providers;
    #: empty until a provider runs — Phase 2 adds VirusTotal/MISP).
    enrichment: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        """Stable identity of this indicator (``"{type}:{value}"``)."""
        return ioc_key(self)


def ioc_key(ioc: IOC) -> str:
    """Return the stable string key of an indicator (used by providers)."""
    return f"{ioc.type.value}:{ioc.value}"


def ioc_sort_key(ioc: IOC) -> tuple[str, str]:
    """Deterministic ordering key: indicator type first, then value.

    Extraction and enrichment both order by this key so repeated runs — and
    the response an analyst sees — are byte-identical.
    """
    return (ioc.type.value, ioc.value)


__all__ = [
    "EXTRACTOR_TEXT_SCAN",
    "EXTRACTOR_TYPED_FIELD",
    "HASH_LENGTHS",
    "IOC",
    "IOCProvenance",
    "IOCType",
    "ioc_key",
    "ioc_sort_key",
]
