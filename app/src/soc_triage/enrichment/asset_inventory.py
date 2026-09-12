"""Static asset inventory policy and canonical-asset enrichment (Phase 2.2).

The asset inventory is a local, versioned policy that fills missing
canonical asset metadata. It is deliberately NOT an enrichment provider:
asset identity belongs to the normalized alert, not to IOC enrichment.

Rules:
- lookup precedence is agent_id -> IP -> name;
- source-provided alert fields always win;
- only missing/blank asset fields are filled;
- no network I/O;
- malformed configuration fails loudly at load time;
- lookup behavior is deterministic and file-order independent.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, PrivateAttr

from ..models.canonical import CanonicalAlert

MAX_ASSETS = 10_000
_ASSET_INVENTORY_VERSION = "asset_inventory.v1"
_MAX_NAME_LENGTH = 253
_MAX_TIER_LENGTH = 64
_MAX_OWNER_LENGTH = 128

_ALLOWED_TOP_LEVEL_KEYS = frozenset({"version", "assets"})
_ALLOWED_ASSET_KEYS = frozenset({"name", "tier", "owner", "agent_ids", "ips"})


class AssetInventoryConfigError(ValueError):
    """Raised when static asset-inventory configuration is invalid."""


class AssetRecord(BaseModel):
    """One validated asset-inventory record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    tier: str
    owner: str | None = None
    agent_ids: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()


class AssetInventory(BaseModel):
    """Validated asset inventory with deterministic indexes."""

    model_config = ConfigDict(frozen=True)

    version: str
    assets: tuple[AssetRecord, ...]
    duplicates_collapsed: int = 0

    _by_agent_id: dict[str, AssetRecord] = PrivateAttr(default_factory=dict)
    _by_ip: dict[str, AssetRecord] = PrivateAttr(default_factory=dict)
    _by_name: dict[str, AssetRecord] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        by_agent_id: dict[str, AssetRecord] = {}
        by_ip: dict[str, AssetRecord] = {}
        by_name: dict[str, AssetRecord] = {}

        for asset in self.assets:
            by_name[asset.name.casefold()] = asset

            for agent_id in asset.agent_ids:
                by_agent_id[agent_id] = asset

            for ip in asset.ips:
                by_ip[ip] = asset

        object.__setattr__(self, "_by_agent_id", by_agent_id)
        object.__setattr__(self, "_by_ip", by_ip)
        object.__setattr__(self, "_by_name", by_name)

    def __len__(self) -> int:
        return len(self.assets)

    def lookup(
        self,
        *,
        agent_id: str | None,
        ip: str | None,
        name: str | None,
    ) -> AssetRecord | None:
        """Resolve one asset using fixed precedence: agent -> IP -> name."""

        if agent_id:
            record = self._by_agent_id.get(agent_id.strip())
            if record is not None:
                return record

        if ip:
            try:
                normalized_ip = str(ipaddress.IPv4Address(ip.strip()))
            except ValueError:
                normalized_ip = None

            if normalized_ip is not None:
                record = self._by_ip.get(normalized_ip)
                if record is not None:
                    return record

        if name:
            record = self._by_name.get(name.strip().casefold())
            if record is not None:
                return record

        return None


def _error(message: str) -> AssetInventoryConfigError:
    return AssetInventoryConfigError(f"asset inventory configuration error: {message}")


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


def _normalize_name(
    value: Any,
    *,
    field: str,
    asset_name: str,
) -> str:
    if not isinstance(value, str):
        raise _error(f"asset {asset_name!r}: {field} must be a string")

    normalized = value.strip()

    if not normalized:
        raise _error(f"asset {asset_name!r}: {field} must not be empty")

    if len(normalized) > _MAX_NAME_LENGTH:
        raise _error(f"asset {asset_name!r}: {field} exceeds {_MAX_NAME_LENGTH} characters")

    return normalized


def _normalize_tier(
    value: Any,
    *,
    asset_name: str,
) -> str:
    if not isinstance(value, str):
        raise _error(f"asset {asset_name!r}: tier must be a string")

    normalized = value.strip()

    if not normalized:
        raise _error(f"asset {asset_name!r}: tier must not be empty")

    if len(normalized) > _MAX_TIER_LENGTH:
        raise _error(f"asset {asset_name!r}: tier exceeds {_MAX_TIER_LENGTH} characters")

    return normalized


def _normalize_owner(
    value: Any,
    *,
    asset_name: str,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise _error(f"asset {asset_name!r}: owner must be a string")

    normalized = value.strip()

    if len(normalized) > _MAX_OWNER_LENGTH:
        raise _error(f"asset {asset_name!r}: owner exceeds {_MAX_OWNER_LENGTH} characters")

    return normalized or None


def _normalize_agent_ids(
    value: Any,
    *,
    asset_name: str,
) -> tuple[str, ...]:
    if value is None:
        return ()

    if not isinstance(value, list):
        raise _error(f"asset {asset_name!r}: agent_ids must be a list")

    normalized: list[str] = []
    seen: set[str] = set()

    for agent_id in value:
        if not isinstance(agent_id, str):
            raise _error(f"asset {asset_name!r}: every agent_id must be a string")

        item = agent_id.strip()

        if not item:
            raise _error(f"asset {asset_name!r}: agent_ids cannot contain empty values")

        if item in seen:
            raise _error(f"asset {asset_name!r}: duplicate agent_id {item!r}")

        seen.add(item)
        normalized.append(item)

    return tuple(normalized)


def _normalize_ips(
    value: Any,
    *,
    asset_name: str,
) -> tuple[str, ...]:
    if value is None:
        return ()

    if not isinstance(value, list):
        raise _error(f"asset {asset_name!r}: ips must be a list")

    normalized: list[str] = []
    seen: set[str] = set()

    for raw_ip in value:
        if not isinstance(raw_ip, str):
            raise _error(f"asset {asset_name!r}: every ip must be a string")

        try:
            ip = str(ipaddress.IPv4Address(raw_ip.strip()))
        except ValueError as exc:
            raise _error(f"asset {asset_name!r}: invalid IPv4 address {raw_ip!r}") from exc

        if ip in seen:
            raise _error(f"asset {asset_name!r}: duplicate ip {ip!r}")

        seen.add(ip)
        normalized.append(ip)

    return tuple(normalized)


def _parse_asset(raw: Any, index: int) -> AssetRecord:
    if not isinstance(raw, dict):
        raise _error(f"asset {index} must be a mapping")

    unexpected_keys = set(raw) - _ALLOWED_ASSET_KEYS
    if unexpected_keys:
        unexpected = ", ".join(sorted(str(key) for key in unexpected_keys))
        raise _error(f"asset {index}: unsupported field(s): {unexpected}")

    raw_name = raw.get("name")

    if not isinstance(raw_name, str):
        raise _error(f"asset {index}: name must be a string")

    name = raw_name.strip()

    if not name:
        raise _error(f"asset {index}: name must not be empty")

    name = _normalize_name(
        name,
        field="name",
        asset_name=name,
    )

    tier = _normalize_tier(
        raw.get("tier"),
        asset_name=name,
    )

    owner = _normalize_owner(
        raw.get("owner"),
        asset_name=name,
    )

    agent_ids = _normalize_agent_ids(
        raw.get("agent_ids"),
        asset_name=name,
    )

    ips = _normalize_ips(
        raw.get("ips"),
        asset_name=name,
    )

    return AssetRecord(
        name=name,
        tier=tier,
        owner=owner,
        agent_ids=agent_ids,
        ips=ips,
    )


def asset_inventory_from_mapping(
    raw: Mapping[str, Any],
) -> AssetInventory:
    """Validate and construct an asset inventory from an in-memory mapping."""

    if not isinstance(raw, dict):
        raise _error("top level must be a YAML mapping")

    unexpected_keys = set(raw) - _ALLOWED_TOP_LEVEL_KEYS
    if unexpected_keys:
        unexpected = ", ".join(sorted(str(key) for key in unexpected_keys))
        raise _error(f"unsupported top-level field(s): {unexpected}")

    if "version" not in raw:
        raise _error("version is required")

    if "assets" not in raw:
        raise _error("assets is required")

    version = raw["version"]

    if version != _ASSET_INVENTORY_VERSION:
        raise _error(f"version must be {_ASSET_INVENTORY_VERSION!r}, got {version!r}")

    assets_raw = raw["assets"]

    if not isinstance(assets_raw, list):
        raise _error("assets must be a list")

    if len(assets_raw) > MAX_ASSETS:
        raise _error(f"assets exceeds maximum of {MAX_ASSETS}")

    parsed: list[AssetRecord] = []
    duplicates_collapsed = 0

    seen_names: dict[str, AssetRecord] = {}
    seen_agents: dict[str, str] = {}
    seen_ips: dict[str, str] = {}

    for index, raw_asset in enumerate(assets_raw):
        asset = _parse_asset(raw_asset, index)
        name_key = asset.name.casefold()

        existing = seen_names.get(name_key)

        if existing is not None:
            same_content = (
                existing.tier == asset.tier
                and existing.owner == asset.owner
                and existing.agent_ids == asset.agent_ids
                and existing.ips == asset.ips
            )

            if same_content:
                duplicates_collapsed += 1
                continue

            raise _error(f"duplicate asset name {asset.name!r} contains conflicting records")

        for agent_id in asset.agent_ids:
            owner = seen_agents.get(agent_id)

            if owner is not None:
                raise _error(
                    f"agent_id {agent_id!r} is claimed by assets {owner!r} and {asset.name!r}"
                )

        for ip in asset.ips:
            owner = seen_ips.get(ip)

            if owner is not None:
                raise _error(f"IP {ip!r} is claimed by assets {owner!r} and {asset.name!r}")

        seen_names[name_key] = asset

        for agent_id in asset.agent_ids:
            seen_agents[agent_id] = asset.name

        for ip in asset.ips:
            seen_ips[ip] = asset.name

        parsed.append(asset)

    return AssetInventory(
        version=version,
        assets=tuple(parsed),
        duplicates_collapsed=duplicates_collapsed,
    )


def load_asset_inventory(path: Path) -> AssetInventory:
    """Load and validate one asset-inventory YAML file."""

    return asset_inventory_from_mapping(_load_yaml(path))


def apply_asset_inventory(
    alert: CanonicalAlert,
    inventory: AssetInventory | None,
) -> CanonicalAlert:
    """Fill missing canonical asset fields from the static inventory.

    Alert-provided values always win. The original alert object is never
    mutated. The exact same object is returned when the inventory is disabled,
    no matching record exists, or no fields need filling.
    """

    if inventory is None:
        return alert

    asset = alert.asset

    if asset is None:
        return alert

    source_agent = alert.source_event.agent

    record = inventory.lookup(
        agent_id=source_agent.id,
        ip=source_agent.ip,
        name=asset.name,
    )

    if record is None:
        return alert

    updates: dict[str, Any] = {}

    if not asset.name and record.name:
        updates["name"] = record.name

    if not asset.tier and record.tier:
        updates["tier"] = record.tier

    if not asset.owner and record.owner:
        updates["owner"] = record.owner

    if not updates:
        return alert

    updated_asset = asset.model_copy(update=updates)

    return alert.model_copy(update={"asset": updated_asset})


__all__ = [
    "MAX_ASSETS",
    "AssetInventory",
    "AssetInventoryConfigError",
    "AssetRecord",
    "apply_asset_inventory",
    "asset_inventory_from_mapping",
    "load_asset_inventory",
]
