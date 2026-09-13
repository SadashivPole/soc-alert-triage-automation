"""Phase 2.3 integration tests: enrichment response TTL cache wiring.

Exercises the real application factory, real Alembic migrations and the real
ingest pipeline against a temporary SQLite database. VirusTotal behavior is
faked with ``httpx.MockTransport`` (no network access — ARCHITECTURE.md §17);
the fake transport is attached to the provider the application itself
constructed, so the test exercises the *wired* cache, not a parallel one.

Pinned behavior:

* the cache is **disabled by default** — no cache object, providers keep the
  uncached path, and repeated lookups all go outbound;
* when enabled, the cache policy reflects the settings and the same cache
  object is shared by the VirusTotal and MISP providers;
* the ``enrichment_cache`` table schema is migrated on every startup
  (feature flag gates *use*, not schema);
* end-to-end: two distinct alerts sharing indicators — the second alert's
  shared verdicts are served from the cache with zero additional outbound
  requests and byte-identical payloads;
* the migration is idempotent, recovers from a partially-applied state,
  rejects an incompatible pre-existing table, and downgrades cleanly.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import inspect, text
from tests.conftest import TEST_INGEST_KEY

from soc_triage.core.config import Settings
from soc_triage.db.engine import ALEMBIC_SCRIPT_LOCATION, create_app_engine, run_migrations
from soc_triage.enrichment.cache import PersistentEnrichmentCache
from soc_triage.enrichment.virustotal import VT_BASE_URL, VirusTotalProvider
from soc_triage.main import create_app

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
AUTH_HEADERS = {"X-API-Key": TEST_INGEST_KEY}

#: Phase 2.3 migration (enrichment response cache) and its predecessor.
CACHE_REVISION = "c7d8e9f0a1b2"
PRIOR_REVISION = "f9a0b1c2d3e4"

FAKE_VT_KEY = "vt-fake-key-0123456789abcdef"

#: The two malware fixtures share md5/sha1/sha256 + the VT permalink URL but
#: come from different agents — two *distinct* alerts sharing indicators.
FIRST_ALERT = "04_wazuh_malware_hash_virustotal.json"
SECOND_ALERT = "09_wazuh_malware_hash_critical_server.json"

EXPECTED_CACHE_COLUMNS = {
    "id",
    "provider",
    "indicator_type",
    "indicator_value",
    "lookup_status",
    "payload",
    "looked_at",
    "expires_at",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enable_cache(settings: Settings) -> Settings:
    """Turn the Phase 2.3 cache on (mirrors the Phase 2.2 wiring-test style)."""
    settings.triage_enrichment_cache_enabled = True
    return settings


def _enable_virustotal(settings: Settings) -> Settings:
    # Assignment bypasses pydantic validation, so wrap explicitly.
    settings.virustotal_api_key = SecretStr(FAKE_VT_KEY)
    return settings


class CountingTransport:
    """MockTransport handler: 'found' for files/IPs, 'not found' for URLs."""

    def __init__(self) -> None:
        self.requests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request.url.path)
        if request.url.path.startswith("/api/v3/urls/"):
            return httpx.Response(200, json={"data": None})
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 0,
                            "harmless": 50,
                            "undetected": 5,
                        },
                        "reputation": -42,
                    }
                }
            },
        )


def _swap_vt_transport(app: Any, transport: CountingTransport) -> VirusTotalProvider:
    """Attach the fake transport to the app's own VirusTotal provider.

    Test-only hook: the provider builds a real client in ``main.py``; the
    swap keeps every other wiring decision (cache, rate limiter, settings)
    exactly as the application made it.
    """
    provider = next(p for p in app.state.enrichment_chain.providers if p.name == "virustotal")
    assert isinstance(provider, VirusTotalProvider)
    provider._client = httpx.Client(base_url=VT_BASE_URL, transport=httpx.MockTransport(transport))
    return provider


def _ingest(client: TestClient, fixture_name: str) -> dict[str, Any]:
    payload = json.loads((FIXTURES_DIR / fixture_name).read_text())
    response = client.post("/api/v1/alerts/ingest", json=payload, headers=AUTH_HEADERS)
    assert response.status_code in {200, 202}, response.text
    return response.json()


def _vt_enrichment_by_type(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map indicator type → its ``virustotal`` enrichment payload."""
    return {
        ioc["type"]: ioc["enrichment"]["virustotal"]
        for ioc in body["iocs"]
        if "virustotal" in ioc["enrichment"]
    }


def _cache_rows(client: TestClient) -> list[Any]:
    factory = client.app.state.session_factory
    with factory() as session:
        return session.execute(
            text("SELECT provider, indicator_type, lookup_status FROM enrichment_cache")
        ).fetchall()


def _alembic_version(engine: Any) -> str | None:
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _table_names(engine: Any) -> set[str]:
    with engine.connect() as conn:
        return {
            row[0]
            for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        }


def _index_names(engine: Any, table: str) -> set[str]:
    with engine.connect() as conn:
        return {
            row[0]
            for row in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=:t"),
                {"t": table},
            )
        }


# ---------------------------------------------------------------------------
# 1. Default wiring: disabled by default
# ---------------------------------------------------------------------------


def test_cache_is_disabled_by_default(client: TestClient) -> None:
    app = client.app
    assert app.state.enrichment_cache is None

    providers = app.state.enrichment_chain.providers
    vt = next(p for p in providers if p.name == "virustotal")
    misp = next(p for p in providers if p.name == "misp")
    assert vt._cache is None
    assert misp._cache is None


def test_cache_schema_migrates_even_when_feature_disabled(client: TestClient) -> None:
    """The table is schema-level; the flag gates *use*, not migrations."""
    inspector = inspect(client.app.state.db_engine)
    assert "enrichment_cache" in inspector.get_table_names()
    columns = {column["name"] for column in inspector.get_columns("enrichment_cache")}
    assert columns == EXPECTED_CACHE_COLUMNS


def test_disabled_cache_preserves_pre_2_3_quota_burn(settings: Settings) -> None:
    """Baseline pinned for contrast: without the cache, repeat indicators burn
    the VT token bucket — the first alert's four lookups exhaust the public
    quota (4 req/min), so the second alert's identical indicators all come
    back ``rate_limited`` (status ``failed``) even though the verdicts were
    just fetched. This is exactly the waste Phase 2.3 removes."""
    _enable_virustotal(settings)
    settings.triage_enrichment_cache_enabled = False
    transport = CountingTransport()

    with TestClient(create_app(settings=settings)) as client:
        _swap_vt_transport(client.app, transport)
        first = _ingest(client, FIRST_ALERT)
        second = _ingest(client, SECOND_ALERT)

        assert first["enrichment_status"] == "complete"
        assert len(transport.requests) == 4  # the quota is now exhausted
        # Second alert: every shared indicator is rate-limited before HTTP.
        assert second["enrichment_status"] == "failed"
        assert {ioc["enrichment"]["virustotal"]["lookup_status"] for ioc in second["iocs"]} == {
            "rate_limited"
        }
        assert len(transport.requests) == 4  # no additional outbound requests
        assert _cache_rows(client) == []


# ---------------------------------------------------------------------------
# 2. Enabled wiring: policy + shared provider cache
# ---------------------------------------------------------------------------


def test_enabled_cache_wires_policy_and_shared_providers(settings: Settings) -> None:
    _enable_cache(settings)
    settings.triage_enrichment_cache_max_entries = 128
    settings.triage_enrichment_cache_hash_ttl_seconds = 7200
    settings.triage_enrichment_cache_ipv4_ttl_seconds = 1800
    settings.triage_enrichment_cache_default_ttl_seconds = 900

    with TestClient(create_app(settings=settings)) as client:
        app = client.app
        cache = app.state.enrichment_cache
        assert isinstance(cache, PersistentEnrichmentCache)
        assert cache.policy.max_entries == 128
        assert cache.policy.hash_ttl_seconds == 7200
        assert cache.policy.ipv4_ttl_seconds == 1800
        assert cache.policy.default_ttl_seconds == 900

        providers = app.state.enrichment_chain.providers
        vt = next(p for p in providers if p.name == "virustotal")
        misp = next(p for p in providers if p.name == "misp")
        assert vt._cache is cache
        assert misp._cache is cache


# ---------------------------------------------------------------------------
# 3. End-to-end: second alert served from the cache
# ---------------------------------------------------------------------------


def test_second_alert_shared_indicators_served_from_cache(settings: Settings) -> None:
    _enable_cache(settings)
    _enable_virustotal(settings)
    transport = CountingTransport()

    with TestClient(create_app(settings=settings)) as client:
        _swap_vt_transport(client.app, transport)

        first = _ingest(client, FIRST_ALERT)
        assert first["enrichment_status"] == "complete"
        first_verdicts = _vt_enrichment_by_type(first)
        assert set(first_verdicts) == {"md5", "sha1", "sha256", "url"}
        outbound_after_first = len(transport.requests)
        assert outbound_after_first == 4  # one lookup per distinct indicator

        second = _ingest(client, SECOND_ALERT)
        assert second["enrichment_status"] == "complete"

        # Zero additional outbound requests: every shared indicator was a hit.
        assert len(transport.requests) == outbound_after_first

        # Byte-identical verdicts — including the original timestamps.
        second_verdicts = _vt_enrichment_by_type(second)
        assert second_verdicts == first_verdicts

        # Only definitive verdicts stored: 3 found + 1 not_found (the URL).
        rows = _cache_rows(client)
        assert len(rows) == 4
        statuses = {(row[1], row[2]) for row in rows}
        assert statuses == {
            ("md5", "found"),
            ("sha1", "found"),
            ("sha256", "found"),
            ("url", "not_found"),
        }
        assert all(row[0] == "virustotal" for row in rows)

        cache: PersistentEnrichmentCache = client.app.state.enrichment_cache
        assert cache.stats.hits == 4
        assert cache.stats.stores == 4


@pytest.fixture
def _cache_enabled_client(settings: Settings) -> Iterator[TestClient]:
    """A cache-enabled app with a fake VirusTotal transport, for reuse."""
    _enable_cache(settings)
    _enable_virustotal(settings)
    with TestClient(create_app(settings=settings)) as client:
        _swap_vt_transport(client.app, CountingTransport())
        yield client


def test_cache_hit_does_not_duplicate_rows_on_repeat_alerts(
    _cache_enabled_client: TestClient,
) -> None:
    client = _cache_enabled_client
    _ingest(client, FIRST_ALERT)
    _ingest(client, SECOND_ALERT)
    _ingest(client, FIRST_ALERT)  # idempotent duplicate delivery (200)

    # The duplicate is absorbed by dedupe; the cache still holds exactly 4.
    assert len(_cache_rows(client)) == 4


# ---------------------------------------------------------------------------
# 4. Migration contract: fresh, idempotent, recovery, rejection, downgrade
# ---------------------------------------------------------------------------


def _assert_cache_schema(engine: Any) -> None:
    inspector = inspect(engine)
    assert "enrichment_cache" in inspector.get_table_names()
    columns = {column["name"] for column in inspector.get_columns("enrichment_cache")}
    assert columns == EXPECTED_CACHE_COLUMNS
    indexes = {index["name"]: index for index in inspector.get_indexes("enrichment_cache")}
    assert indexes["ix_enrichment_cache_lookup"]["unique"]  # SQLite reports 1/0
    assert indexes["ix_enrichment_cache_lookup"]["column_names"] == [
        "provider",
        "indicator_type",
        "indicator_value",
    ]
    assert indexes["ix_enrichment_cache_expires_at"]["column_names"] == ["expires_at"]


def test_fresh_database_migrates_to_cache_revision(db_url: str) -> None:
    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == CACHE_REVISION
    _assert_cache_schema(engine)
    engine.dispose()


def test_migration_is_idempotent(db_url: str) -> None:
    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == CACHE_REVISION
    _assert_cache_schema(engine)
    engine.dispose()


def _stamp(engine: Any, revision: str) -> None:
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = :rev"), {"rev": revision})


def test_migration_recovers_partially_created_cache_table(db_url: str) -> None:
    """Interrupted run: table committed, indexes missing, revision unstamped."""
    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    # Simulate the crash: indexes dropped, revision back at the predecessor.
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX ix_enrichment_cache_lookup"))
        conn.execute(text("DROP INDEX ix_enrichment_cache_expires_at"))
    _stamp(engine, PRIOR_REVISION)
    assert _index_names(engine, "enrichment_cache") == set()

    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    assert _alembic_version(engine) == CACHE_REVISION
    _assert_cache_schema(engine)  # the missing indexes were completed
    engine.dispose()


def test_migration_rejects_incompatible_existing_table(db_url: str) -> None:
    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)

    # Simulate a hostile pre-existing table: drop and recreate without payload.
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE enrichment_cache"))
        conn.execute(
            text(
                """
                CREATE TABLE enrichment_cache (
                    id INTEGER PRIMARY KEY,
                    provider VARCHAR(32) NOT NULL
                )
                """
            )
        )
    _stamp(engine, PRIOR_REVISION)

    with pytest.raises(RuntimeError, match="incompatible existing 'enrichment_cache'"):
        run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    # The revision was NOT stamped on failure.
    assert _alembic_version(engine) == PRIOR_REVISION
    assert "enrichment_cache" in _table_names(engine)
    engine.dispose()


def test_downgrade_removes_the_cache_table(db_url: str) -> None:
    from alembic import command as alembic_command
    from alembic.config import Config

    engine = create_app_engine(db_url)
    run_migrations(engine, ALEMBIC_SCRIPT_LOCATION)
    assert "enrichment_cache" in _table_names(engine)

    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_SCRIPT_LOCATION))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        alembic_command.downgrade(config, PRIOR_REVISION)

    assert _alembic_version(engine) == PRIOR_REVISION
    assert "enrichment_cache" not in _table_names(engine)
    engine.dispose()


# ---------------------------------------------------------------------------
# 5. No behavior change for the zero-intel fallback
# ---------------------------------------------------------------------------


def test_zero_intel_fallback_unchanged_with_cache_enabled(settings: Settings) -> None:
    """Cache enabled but no VT/MISP keys: ingestion stays 'skipped' offline."""
    _enable_cache(settings)

    with TestClient(create_app(settings=settings)) as client:
        body = _ingest(client, FIRST_ALERT)

        assert body["enrichment_status"] == "skipped"
        assert _cache_rows(client) == []
        cache: PersistentEnrichmentCache = client.app.state.enrichment_cache
        assert cache.stats.hits == 0
        assert cache.stats.stores == 0
