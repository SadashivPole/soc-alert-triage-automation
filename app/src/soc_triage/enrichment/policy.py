"""False-positive policy for IOC extraction (Phase 1E).

Extraction must be conservative: a noisy indicator set burns threat-intel
quota later and erodes analyst trust. This module holds the *policy* — which
fields are read, which address ranges count as evidence — separated from the
mechanical pattern matching in :mod:`soc_triage.enrichment.extractor`, so
tuning is a one-line, reviewable change and is fully unit-testable.

Project policy (SECURITY.md §5, ARCHITECTURE.md §7.1):

* **RFC 1918 / non-routable IPv4 is dropped by default.** Private, loopback,
  link-local, CGNAT, multicast, reserved and unspecified addresses describe
  the lab's own estate, not external evidence.
* **Documentation ranges (RFC 5737 / RFC 2544) are kept by default.** The
  whole sample corpus is synthetic and uses ``192.0.2.0/24``,
  ``198.51.100.0/24`` and ``203.0.113.0/24`` (SECURITY.md §5); dropping them
  would make every fixture yield zero indicators. Deployments ingesting real
  alerts can set ``include_documentation_ipv4=False``.
* **``full_log`` is not an extraction source by default** (ARCHITECTURE.md
  §7.1: "Regex/grammar extraction from canonical fields, **not** from
  arbitrary ``full_log`` text in the MVP"). It is opt-in per deployment.
"""

from __future__ import annotations

import ipaddress
from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, Field

#: Documentation / benchmarking ranges — *not* evidence in production, but the
#: only addresses the synthetic lab corpus contains (SECURITY.md §5).
DOCUMENTATION_IPV4_NETWORKS: tuple[IPv4Network, ...] = (
    ipaddress.IPv4Network("192.0.2.0/24"),  # RFC 5737 TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),  # RFC 5737 TEST-NET-3
    ipaddress.IPv4Network("192.18.0.0/15"),  # RFC 2544 benchmarking
    ipaddress.IPv4Network("198.18.0.0/15"),  # RFC 2544 benchmarking
)


class IOCExtractionPolicy(BaseModel):
    """Immutable extraction policy (defaults are the project policy)."""

    model_config = {"frozen": True}

    #: Keep non-routable IPv4 (RFC 1918, loopback, link-local, CGNAT,
    #: multicast, reserved, unspecified). Off by default: internal addresses
    #: are not external indicators.
    include_private_ipv4: bool = False
    #: Keep documentation/benchmark ranges (RFC 5737 / RFC 2544). On by
    #: default because the synthetic sample corpus is built from them.
    include_documentation_ipv4: bool = True
    #: Scan ``source_event.full_log`` as free text. Off by default
    #: (ARCHITECTURE.md §7.1). Provenance still records offsets when enabled.
    include_full_log: bool = False
    #: Scan ``source_event.location`` (a source descriptor, not evidence).
    include_location: bool = False
    #: Scan unrecognized string leaves under ``data`` / ``syscheck`` with
    #: auto-detection (typed fields below are always read).
    include_unknown_data_fields: bool = True
    #: Hard cap on indicators per alert (bounded responses, bounded quota).
    max_iocs: int = Field(default=200, ge=1)

    def ipv4_allowed(self, address: IPv4Address) -> bool:
        """Whether ``address`` counts as an indicator under this policy."""
        if any(address in network for network in DOCUMENTATION_IPV4_NETWORKS):
            return self.include_documentation_ipv4
        if address.is_global:
            return True
        # is_global is False for RFC 1918, loopback, link-local (169.254/16),
        # shared/CGNAT (100.64/10), multicast, reserved and 0.0.0.0/8.
        return self.include_private_ipv4


#: The project default: frozen, shareable, safe to use as a default argument.
DEFAULT_IOC_POLICY = IOCExtractionPolicy()


__all__ = [
    "DEFAULT_IOC_POLICY",
    "DOCUMENTATION_IPV4_NETWORKS",
    "IOCExtractionPolicy",
]
