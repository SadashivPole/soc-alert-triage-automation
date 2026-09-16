from __future__ import annotations

import pytest

from soc_triage.enrichment.asset_inventory import (
    AssetInventoryConfigError,
    apply_asset_inventory,
    asset_inventory_from_mapping,
)
from soc_triage.models.canonical import (
    CanonicalAgent,
    CanonicalAlert,
    CanonicalAsset,
    CanonicalRule,
    CanonicalSourceEvent,
)


def inventory_payload() -> dict:
    return {
        "version": "asset_inventory.v1",
        "assets": [
            {
                "name": "web-prod-01",
                "tier": "tier-1",
                "owner": "platform-team",
                "agent_ids": ["001"],
                "ips": ["10.0.1.10"],
            }
        ],
    }


def make_alert(
    *,
    agent_id: str = "001",
    agent_ip: str | None = "10.0.1.10",
    asset_name: str | None = None,
    tier: str | None = None,
    owner: str | None = None,
) -> CanonicalAlert:
    from datetime import UTC, datetime
    from uuid import uuid4

    return CanonicalAlert(
        alert_id=uuid4(),
        received_at=datetime.now(UTC),
        source_event=CanonicalSourceEvent(
            rule=CanonicalRule(
                id="100001",
                level=5,
                description="test alert",
            ),
            agent=CanonicalAgent(
                id=agent_id,
                name="test-agent",
                ip=agent_ip,
            ),
        ),
        asset=CanonicalAsset(
            name=asset_name,
            tier=tier,
            owner=owner,
        ),
    )


def test_lookup_by_agent_id() -> None:
    inventory = asset_inventory_from_mapping(inventory_payload())

    result = inventory.lookup(
        agent_id="001",
        ip=None,
        name=None,
    )

    assert result is not None
    assert result.name == "web-prod-01"


def test_lookup_by_ip() -> None:
    inventory = asset_inventory_from_mapping(inventory_payload())

    result = inventory.lookup(
        agent_id=None,
        ip="10.0.1.10",
        name=None,
    )

    assert result is not None
    assert result.name == "web-prod-01"


def test_lookup_by_name_is_case_insensitive() -> None:
    inventory = asset_inventory_from_mapping(
        {
            "version": "asset_inventory.v1",
            "assets": [
                {
                    "name": "web-prod-01",
                    "tier": "tier-1",
                }
            ],
        }
    )

    result = inventory.lookup(
        agent_id=None,
        ip=None,
        name="WEB-PROD-01",
    )

    assert result is not None
    assert result.name == "web-prod-01"


def test_lookup_precedence_agent_then_ip_then_name() -> None:
    inventory = asset_inventory_from_mapping(
        {
            "version": "asset_inventory.v1",
            "assets": [
                {
                    "name": "agent-match",
                    "tier": "tier-1",
                    "agent_ids": ["001"],
                },
                {
                    "name": "ip-match",
                    "tier": "tier-2",
                    "ips": ["10.0.1.10"],
                },
                {
                    "name": "name-match",
                    "tier": "tier-3",
                },
            ],
        }
    )

    result = inventory.lookup(
        agent_id="001",
        ip="10.0.1.10",
        name="name-match",
    )

    assert result is not None
    assert result.name == "agent-match"


def test_apply_inventory_fills_missing_fields() -> None:
    inventory = asset_inventory_from_mapping(inventory_payload())
    alert = make_alert()

    result = apply_asset_inventory(alert, inventory)

    assert result.asset is not None
    assert result.asset.name == "web-prod-01"
    assert result.asset.tier == "tier-1"
    assert result.asset.owner == "platform-team"


def test_apply_inventory_preserves_source_fields() -> None:
    inventory = asset_inventory_from_mapping(inventory_payload())
    alert = make_alert(
        asset_name="source-name",
        tier="critical",
        owner="source-owner",
    )

    result = apply_asset_inventory(alert, inventory)

    assert result.asset is not None
    assert result.asset.name == "source-name"
    assert result.asset.tier == "critical"
    assert result.asset.owner == "source-owner"


def test_apply_inventory_returns_same_object_when_disabled() -> None:
    alert = make_alert()

    result = apply_asset_inventory(alert, None)

    assert result is alert


def test_conflicting_duplicate_asset_names_are_rejected() -> None:
    with pytest.raises(AssetInventoryConfigError):
        asset_inventory_from_mapping(
            {
                "version": "asset_inventory.v1",
                "assets": [
                    {
                        "name": "web-prod-01",
                        "tier": "tier-1",
                    },
                    {
                        "name": "WEB-PROD-01",
                        "tier": "tier-2",
                    },
                ],
            }
        )


def test_duplicate_agent_ids_are_rejected() -> None:
    with pytest.raises(AssetInventoryConfigError):
        asset_inventory_from_mapping(
            {
                "version": "asset_inventory.v1",
                "assets": [
                    {
                        "name": "web-01",
                        "tier": "tier-1",
                        "agent_ids": ["001"],
                    },
                    {
                        "name": "web-02",
                        "tier": "tier-2",
                        "agent_ids": ["001"],
                    },
                ],
            }
        )


def test_duplicate_ips_are_rejected() -> None:
    with pytest.raises(AssetInventoryConfigError):
        asset_inventory_from_mapping(
            {
                "version": "asset_inventory.v1",
                "assets": [
                    {
                        "name": "web-01",
                        "tier": "tier-1",
                        "ips": ["10.0.1.10"],
                    },
                    {
                        "name": "web-02",
                        "tier": "tier-2",
                        "ips": ["10.0.1.10"],
                    },
                ],
            }
        )


def test_invalid_version_is_rejected() -> None:
    with pytest.raises(AssetInventoryConfigError):
        asset_inventory_from_mapping(
            {
                "version": "wrong.version",
                "assets": [],
            }
        )


def test_unknown_top_level_key_is_rejected() -> None:
    with pytest.raises(AssetInventoryConfigError):
        asset_inventory_from_mapping(
            {
                "version": "asset_inventory.v1",
                "assets": [],
                "unexpected": True,
            }
        )


def test_unknown_asset_key_is_rejected() -> None:
    with pytest.raises(AssetInventoryConfigError):
        asset_inventory_from_mapping(
            {
                "version": "asset_inventory.v1",
                "assets": [
                    {
                        "name": "web-01",
                        "tier": "tier-1",
                        "unexpected": True,
                    }
                ],
            }
        )


def test_invalid_ip_is_rejected() -> None:
    with pytest.raises(AssetInventoryConfigError):
        asset_inventory_from_mapping(
            {
                "version": "asset_inventory.v1",
                "assets": [
                    {
                        "name": "web-01",
                        "tier": "tier-1",
                        "ips": ["not-an-ip"],
                    }
                ],
            }
        )


def test_identical_duplicate_assets_are_collapsed() -> None:
    inventory = asset_inventory_from_mapping(
        {
            "version": "asset_inventory.v1",
            "assets": [
                {
                    "name": "web-01",
                    "tier": "tier-1",
                    "owner": "platform",
                },
                {
                    "name": "WEB-01",
                    "tier": "tier-1",
                    "owner": "platform",
                },
            ],
        }
    )

    assert len(inventory) == 1
    assert inventory.duplicates_collapsed == 1


def test_no_matching_inventory_returns_same_alert() -> None:
    inventory = asset_inventory_from_mapping(
        {
            "version": "asset_inventory.v1",
            "assets": [
                {
                    "name": "other-host",
                    "tier": "tier-1",
                }
            ],
        }
    )
    alert = make_alert(
        agent_id="999",
        agent_ip="10.0.9.9",
        asset_name="unknown-host",
    )

    result = apply_asset_inventory(alert, inventory)

    assert result is alert
