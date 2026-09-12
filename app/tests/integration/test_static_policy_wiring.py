"""Integration tests for Phase 2.2 static policy wiring."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from soc_triage.enrichment.allowlist import AllowlistProvider
from soc_triage.enrichment.asset_inventory import apply_asset_inventory
from soc_triage.models.ioc import IOC, IOCType


def _write_allowlist(path: Path) -> None:
    path.write_text(
        """version: allowlist.v1
entries:
  - id: approved-scanner
    type: ipv4
    value: 203.0.113.20
    reason: Approved vulnerability scanner
""",
        encoding="utf-8",
    )


def _write_asset_inventory(path: Path) -> None:
    path.write_text(
        """version: asset_inventory.v1
assets:
  - name: web-prod-01
    tier: tier-1
    owner: platform-team
    agent_ids:
      - "001"
    ips:
      - "10.0.1.10"
""",
        encoding="utf-8",
    )


def test_default_static_policies_are_disabled(client) -> None:
    """Empty policy paths preserve the existing provider set."""
    app = client.app

    assert app.state.asset_inventory is None

    providers = app.state.enrichment_chain.providers
    assert [provider.name for provider in providers] == [
        "noop",
        "virustotal",
        "misp",
    ]


def test_allowlist_registers_only_when_configured(settings, tmp_path: Path) -> None:
    """Configured allowlist adds exactly one local provider."""
    allowlist_path = tmp_path / "allowlist.yaml"
    _write_allowlist(allowlist_path)

    settings.triage_allowlist_path = str(allowlist_path)
    settings.triage_asset_inventory_path = ""

    from soc_triage.main import create_app

    app = create_app(settings=settings)

    with TestClient(app):
        providers = app.state.enrichment_chain.providers

        assert [provider.name for provider in providers] == [
            "allowlist",
            "noop",
            "virustotal",
            "misp",
        ]

        allowlist_provider = providers[0]
        assert isinstance(allowlist_provider, AllowlistProvider)
        assert allowlist_provider.enabled is True

        ioc = IOC(type=IOCType.IPV4, value="203.0.113.20")
        outcome = allowlist_provider.enrich(
            [ioc],
            context=None,
        )

        assert outcome.status.value == "skipped"

        result = outcome.results["ipv4:203.0.113.20"]
        assert result["matched"] is True
        assert result["reason"] == "Approved vulnerability scanner"


def test_asset_inventory_is_loaded_when_configured(
    settings,
    tmp_path: Path,
) -> None:
    """Configured asset inventory is loaded into application state."""
    inventory_path = tmp_path / "asset_inventory.yaml"
    _write_asset_inventory(inventory_path)

    settings.triage_allowlist_path = ""
    settings.triage_asset_inventory_path = str(inventory_path)

    from soc_triage.main import create_app

    app = create_app(settings=settings)

    with TestClient(app):
        inventory = app.state.asset_inventory

        assert inventory is not None
        assert len(inventory) == 1


def test_asset_inventory_fill_only_preserves_source_values(
    settings,
    tmp_path: Path,
) -> None:
    """Inventory fills missing asset metadata without overwriting source data."""
    inventory_path = tmp_path / "asset_inventory.yaml"
    _write_asset_inventory(inventory_path)

    settings.triage_allowlist_path = ""
    settings.triage_asset_inventory_path = str(inventory_path)

    from tests.conftest import make_canonical_alert

    from soc_triage.main import create_app

    app = create_app(settings=settings)

    with TestClient(app):
        inventory = app.state.asset_inventory

        assert inventory is not None

        source_alert = make_canonical_alert(
            asset_tier=None,
            asset_owner=None,
        )
        enriched = apply_asset_inventory(source_alert, inventory)

        assert enriched.asset is not None
        assert enriched.asset.name == "host-001"
        assert enriched.asset.tier == "tier-1"
        assert enriched.asset.owner == "platform-team"

        source_authoritative = make_canonical_alert(
            asset_tier="tier-0",
            asset_owner="source-owner",
        )
        preserved = apply_asset_inventory(
            source_authoritative,
            inventory,
        )

        assert preserved.asset is not None
        assert preserved.asset.name == "host-001"
        assert preserved.asset.tier == "tier-0"
        assert preserved.asset.owner == "source-owner"


def test_both_static_policies_can_be_enabled_together(
    settings,
    tmp_path: Path,
) -> None:
    """Allowlist and asset inventory can be configured together."""
    allowlist_path = tmp_path / "allowlist.yaml"
    inventory_path = tmp_path / "asset_inventory.yaml"

    _write_allowlist(allowlist_path)
    _write_asset_inventory(inventory_path)

    settings.triage_allowlist_path = str(allowlist_path)
    settings.triage_asset_inventory_path = str(inventory_path)

    from soc_triage.main import create_app

    app = create_app(settings=settings)

    with TestClient(app):
        assert app.state.asset_inventory is not None

        providers = app.state.enrichment_chain.providers
        assert [provider.name for provider in providers] == [
            "allowlist",
            "noop",
            "virustotal",
            "misp",
        ]
