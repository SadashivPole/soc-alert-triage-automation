"""Static IOC allowlist policy and local enrichment provider (Phase 2.2).

The allowlist is an operator-controlled, versioned local policy. It performs
no network I/O and plugs into the existing EnrichmentProvider contract.

Important:
- Provider name is exactly ``allowlist`` because ``ioc_is_allowlisted()``
  consumes that enrichment key.
- Provider status is always ``skipped`` because local policy matching is not
  external threat-intelligence corroboration and must not add enrichment
  scoring points.
- Configuration is validated fail-loud at application startup.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, PrivateAttr

from ..models.ioc import IOC, IOCType
from .normalize import (
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_url,
)
from .providers import EnrichmentContext, EnrichmentStatus, ProviderEnrichment

MAX_ALLOWLIST_ENTRIES = 10_000
_ALLOWLIST_VERSION = "allowlist.v1"
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

_ALLOWED_TOP_LEVEL_KEYS = frozenset({"version", "entries"})

_DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "allowlists.yaml"
DEFAULT_ALLOWLIST_PATH = _DEFAULT_CONFIG_PATH


class AllowlistConfigError(ValueError):
    """Raised when static allowlist configuration is invalid."""


class AllowlistEntry(BaseModel):
    """One normalized allowlist entry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    type: IOCType
    value: str
    reason: str = ""
    network: IPv4Network | None = None


class Allowlist(BaseModel):
    """Validated allowlist with deterministic lookup indexes."""

    model_config = ConfigDict(frozen=True)

    version: str
    entries: tuple[AllowlistEntry, ...]
    duplicates_collapsed: int = 0

    _by_key: dict[str, AllowlistEntry] = PrivateAttr(default_factory=dict)
    _networks: tuple[tuple[IPv4Network, AllowlistEntry], ...] = PrivateAttr(default=())

    def model_post_init(self, __context: Any) -> None:
        by_key: dict[str, AllowlistEntry] = {}
        networks: list[tuple[IPv4Network, AllowlistEntry]] = []

        for entry in self.entries:
            if entry.network is not None:
                networks.append((entry.network, entry))
            else:
                by_key[f"{entry.type.value}:{entry.value}"] = entry

        networks.sort(
            key=lambda item: (
                int(item[0].network_address),
                item[0].prefixlen,
                item[1].id,
            )
        )

        object.__setattr__(self, "_by_key", by_key)
        object.__setattr__(self, "_networks", tuple(networks))

    def __len__(self) -> int:
        return len(self.entries)

    def match(self, ioc: IOC) -> AllowlistEntry | None:
        """Return the deterministic first matching entry, if any."""
        exact = self._by_key.get(ioc.key)
        if exact is not None:
            return exact

        if ioc.type is not IOCType.IPV4:
            return None

        try:
            address = ipaddress.IPv4Address(ioc.value)
        except ValueError:
            return None

        for network, entry in self._networks:
            if address in network:
                return entry

        return None


def _error(message: str) -> AllowlistConfigError:
    return AllowlistConfigError(f"allowlist configuration error: {message}")


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise _error(f"file does not exist: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise _error(f"failed to read {path}: {type(exc).__name__}") from exc

    if not isinstance(raw, dict):
        raise _error("top level must be a YAML mapping")

    return raw


def _normalize_value(
    value: str,
    indicator_type: IOCType,
) -> tuple[str, IPv4Network | None]:
    raw = value.strip()

    if not raw:
        raise _error("value must be a non-empty string")

    if indicator_type is IOCType.IPV4:
        if "/" in raw:
            try:
                network = ipaddress.IPv4Network(raw, strict=False)
            except ValueError as exc:
                raise _error(f"invalid IPv4 CIDR {value!r}") from exc

            if network.prefixlen == 0:
                raise _error("IPv4 /0 allowlist entries are forbidden")

            return str(network), network

        try:
            address = ipaddress.IPv4Address(raw)
        except ValueError as exc:
            raise _error(f"invalid IPv4 address {value!r}") from exc

        return str(address), None

    if indicator_type is IOCType.DOMAIN:
        normalized = normalize_domain(raw)
    elif indicator_type is IOCType.URL:
        normalized = normalize_url(raw)
    elif indicator_type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
        normalized = normalize_hash(raw, expected=indicator_type)
    elif indicator_type is IOCType.EMAIL:
        normalized = normalize_email(raw)
    else:
        normalized = None

    if normalized is None:
        raise _error(f"value {value!r} is invalid for IOC type {indicator_type.value}")

    return normalized, None


def _parse_entry(raw: Any, index: int) -> AllowlistEntry:
    if not isinstance(raw, dict):
        raise _error(f"entry {index} must be a mapping")

    entry_id = raw.get("id")
    if not isinstance(entry_id, str) or not _ID_RE.fullmatch(entry_id):
        raise _error(
            f"entry {index} has invalid id {entry_id!r}; "
            "expected lowercase letters, digits, '_' or '-'; max 64 chars"
        )

    raw_type = raw.get("type")
    if not isinstance(raw_type, str):
        raise _error(f"entry {entry_id}: invalid IOC type {raw_type!r}")

    try:
        indicator_type = IOCType(raw_type)
    except ValueError as exc:
        raise _error(f"entry {entry_id}: invalid IOC type {raw_type!r}") from exc

    raw_value = raw.get("value")
    if not isinstance(raw_value, str):
        raise _error(f"entry {entry_id}: value must be a string")

    reason = raw.get("reason", "")
    if not isinstance(reason, str):
        raise _error(f"entry {entry_id}: reason must be a string")
    if len(reason) > 200:
        raise _error(f"entry {entry_id}: reason exceeds 200 characters")

    try:
        normalized_value, network = _normalize_value(raw_value, indicator_type)
    except AllowlistConfigError as exc:
        raise _error(f"entry {entry_id}: {exc}") from exc

    return AllowlistEntry(
        id=entry_id,
        type=indicator_type,
        value=normalized_value,
        reason=reason,
        network=network,
    )


def allowlist_from_mapping(raw: dict[str, Any]) -> Allowlist:
    """Validate and construct an allowlist from an in-memory mapping."""
    if not isinstance(raw, dict):
        raise _error("top level must be a YAML mapping")

    unexpected_keys = set(raw) - _ALLOWED_TOP_LEVEL_KEYS
    if unexpected_keys:
        unexpected = ", ".join(sorted(str(key) for key in unexpected_keys))
        raise _error(f"unsupported top-level field(s): {unexpected}")

    if "version" not in raw:
        raise _error("version is required")

    if "entries" not in raw:
        raise _error("entries is required")

    version = raw["version"]
    if version != _ALLOWLIST_VERSION:
        raise _error(f"version must be {_ALLOWLIST_VERSION!r}, got {version!r}")

    entries_raw = raw["entries"]
    if not isinstance(entries_raw, list):
        raise _error("entries must be a list")

    if len(entries_raw) > MAX_ALLOWLIST_ENTRIES:
        raise _error(f"entries exceeds maximum of {MAX_ALLOWLIST_ENTRIES}")

    parsed: list[AllowlistEntry] = []
    seen_ids: dict[str, AllowlistEntry] = {}
    seen_keys: dict[str, AllowlistEntry] = {}
    duplicates_collapsed = 0

    for index, item in enumerate(entries_raw):
        entry = _parse_entry(item, index)

        existing_id = seen_ids.get(entry.id)
        if existing_id is not None:
            if existing_id == entry:
                duplicates_collapsed += 1
                continue
            raise _error(f"duplicate id {entry.id!r} contains conflicting entries")

        key = f"{entry.type.value}:{entry.value}"

        existing_key = seen_keys.get(key)
        if existing_key is not None:
            if existing_key == entry:
                duplicates_collapsed += 1
                seen_ids[entry.id] = existing_key
                continue
            raise _error(
                f"entries {existing_key.id!r} and {entry.id!r} "
                f"claim the same normalized IOC key {key!r}"
            )

        seen_ids[entry.id] = entry
        seen_keys[key] = entry
        parsed.append(entry)

    return Allowlist(
        version=version,
        entries=tuple(parsed),
        duplicates_collapsed=duplicates_collapsed,
    )


def load_allowlist(path: Path) -> Allowlist:
    """Load and validate one allowlist YAML file."""
    return allowlist_from_mapping(_load_yaml(path))


class AllowlistProvider:
    """Local allowlist enrichment provider."""

    @property
    def name(self) -> str:
        return "allowlist"

    def __init__(self, allowlist: Allowlist) -> None:
        self._allowlist = allowlist

    @property
    def enabled(self) -> bool:
        return bool(self._allowlist)

    def enrich(
        self,
        iocs: Sequence[IOC],
        *,
        context: EnrichmentContext,  # noqa: ARG002 - contract
    ) -> ProviderEnrichment:
        """Annotate every IOC with a deterministic local-policy result."""
        matched = 0
        results: dict[str, dict[str, Any]] = {}

        for ioc in iocs:
            entry = self._allowlist.match(ioc)

            if entry is None:
                results[ioc.key] = {"matched": False}
                continue

            matched += 1
            results[ioc.key] = {
                "matched": True,
                "entry_id": entry.id,
                "reason": entry.reason,
            }

        return ProviderEnrichment(
            provider=self.name,
            # Local policy is deliberately excluded from enrichment scoring
            # aggregation. It only supplies the existing allowlist signal.
            status=EnrichmentStatus.SKIPPED,
            results=results,
            notes=[
                f"allowlist: local policy lookup, "
                f"{matched} matched of {len(iocs)} indicator(s); "
                "not an external intel source"
            ],
        )


__all__ = [
    "DEFAULT_ALLOWLIST_PATH",
    "MAX_ALLOWLIST_ENTRIES",
    "Allowlist",
    "AllowlistConfigError",
    "AllowlistEntry",
    "AllowlistProvider",
    "allowlist_from_mapping",
    "load_allowlist",
]
