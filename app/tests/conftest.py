"""Shared pytest fixtures for the test suite.

Phase 1D: every test gets an isolated SQLite database (per-test temp file).
The application factory runs its normal startup path — engine creation plus
Alembic migrations — against that file, so integration tests exercise the
same bootstrap the service uses.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from soc_triage.core.config import Settings
from soc_triage.main import create_app
from soc_triage.models.canonical import (
    CanonicalAgent,
    CanonicalAlert,
    CanonicalAsset,
    CanonicalDedupe,
    CanonicalRule,
    CanonicalSourceEvent,
)
from soc_triage.models.ioc import IOC, IOCType

TEST_INGEST_KEY = "test-ingest-key-not-a-real-secret"
TEST_CALLBACK_TOKEN = "test-callback-token-not-a-real-secret"

#: The pre-Phase-2.5 factor set (``scoring.v1``). Policies that do not
#: configure ``threat_intel`` must keep emitting exactly these, in this order —
#: the backward-compatibility contract of the 2.5 change.
LEGACY_FACTOR_NAMES: tuple[str, ...] = (
    "rule_severity",
    "rule_groups_mitre",
    "asset_criticality",
    "recurrence_velocity",
    "ioc_evidence",
    "enrichment_status",
    "allowlist_modifier",
)

#: The ``scoring.v2`` factor order: the legacy set with the intel factor
#: inserted before the subtractive allowlist modifier (ARCHITECTURE.md §8.2).
V2_FACTOR_NAMES: tuple[str, ...] = (
    *LEGACY_FACTOR_NAMES[:6],
    "threat_intel",
    "allowlist_modifier",
)


def make_canonical_alert(
    *,
    level: int = 5,
    rule_id: str = "5710",
    groups: tuple[str, ...] = (),
    mitre: dict | None = None,
    asset_tier: str | None = None,
    asset_owner: str | None = None,
    occurrences: int = 1,
    span_seconds: float = 0.0,
    iocs: list[IOC] | None = None,
    enrichment_status: str = "skipped",
    with_asset: bool = True,
    with_dedupe: bool = True,
    alert_id: UUID | None = None,
    received_at: datetime | None = None,
) -> CanonicalAlert:
    """Build a fully-populated canonical alert for scoring/decision tests.

    All inputs default to the "neutral" case so individual factors can be
    exercised in isolation; ``with_asset`` / ``with_dedupe`` drop optional
    blocks for the "missing optional fields" contract.
    """
    now = received_at or datetime(2026, 8, 29, 10, 15, 0, tzinfo=UTC)

    dedupe = None
    if with_dedupe:
        dedupe = CanonicalDedupe(
            group_key=f"wazuh:{rule_id}:001",
            occurrences=occurrences,
            first_seen=now,
            last_seen=now + timedelta(seconds=span_seconds),
            event_identity=f"wazuh:test:{rule_id}:001",
        )

    asset = None
    if with_asset:
        asset = CanonicalAsset(
            name="host-001",
            tier=asset_tier,
            owner=asset_owner,
        )

    return CanonicalAlert(
        alert_id=alert_id or uuid4(),
        source="wazuh",
        received_at=now,
        source_event=CanonicalSourceEvent(
            rule=CanonicalRule(
                id=rule_id,
                level=level,
                description="synthetic test alert",
                groups=list(groups),
                mitre=mitre or {},
            ),
            agent=CanonicalAgent(
                id="001",
                name="host-001",
                ip="10.0.1.10",
            ),
            location="/var/log/auth.log",
        ),
        dedupe=dedupe,
        asset=asset,
        enrichment_status=enrichment_status,
        iocs=iocs or [],
    )


def make_ioc(
    value: str,
    *,
    type: IOCType = IOCType.IPV4,
    allowlisted: bool = False,
    enrichment: dict | None = None,
) -> IOC:
    """Build an indicator, optionally marked allowlisted.

    ``enrichment`` merges provider payloads (Phase 2.5 scoring consumes the
    ``virustotal`` / ``misp`` entries) on top of the allowlist marker, so a
    test can attach intel verdicts without touching provider internals.
    """
    payload: dict = {}

    if allowlisted:
        payload = {"allowlist": {"matched": True}}
    if enrichment:
        payload = {**payload, **enrichment}

    return IOC(
        type=type,
        value=value,
        enrichment=payload,
    )


def make_vt_payload(
    *,
    malicious: int = 0,
    suspicious: int = 0,
    harmless: int = 0,
    undetected: int = 0,
    lookup_status: str = "found",
) -> dict:
    """A VirusTotal lookup record shaped exactly like the provider's output.

    Mirrors ``enrichment/threat_intel.py``'s :class:`LookupRecord` JSON dump
    (provider / indicator_type / lookup_status / timestamp / sanitized
    ``result``) so scoring tests exercise the real payload contract.
    """
    return {
        "provider": "virustotal",
        "indicator_type": "sha256",
        "lookup_status": lookup_status,
        "timestamp": "2026-08-29T10:15:00+00:00",
        "result": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": -1 if malicious else 0,
        },
    }


def make_misp_payload(
    *,
    match_count: int = 1,
    event_ids: list[str] | None = None,
    tags: list[str] | None = None,
    lookup_status: str = "found",
) -> dict:
    """A MISP lookup record shaped exactly like the provider's output."""
    return {
        "provider": "misp",
        "indicator_type": "ipv4",
        "lookup_status": lookup_status,
        "timestamp": "2026-08-29T10:15:00+00:00",
        "result": {
            "match_count": match_count,
            "event_ids": sorted(event_ids or [])[:5],
            "tags": sorted(set(tags or []))[:5],
        },
    }


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    """A fresh, isolated SQLite database URL per test."""
    return f"sqlite:///{tmp_path / 'soc_triage_test.db'}"


@pytest.fixture
def settings(db_url: str) -> Settings:
    """Return a non-placeholder test configuration."""
    return Settings(
        soc_env="test",
        soc_log_level="INFO",
        soc_instance_name="soc-test",
        triage_cors_origins="http://localhost:8080",
        triage_db_url=db_url,
        triage_ingest_api_key=TEST_INGEST_KEY,
        n8n_callback_token=TEST_CALLBACK_TOKEN,
        n8n_webhook_token="",
        n8n_webhook_url="",
        triage_allowlist_path="",
        triage_asset_inventory_path="",
    )


@pytest.fixture
def app(settings: Settings):
    """Return a configured FastAPI application instance."""
    return create_app(settings=settings)


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    """Return a TestClient that runs the application lifespan."""
    with TestClient(app) as test_client:
        yield test_client
