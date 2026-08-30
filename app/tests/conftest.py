"""Shared pytest fixtures for the test suite.

Phase 1D: every test gets an isolated SQLite database (per-test temp file).
The application factory runs its normal startup path — engine creation plus
Alembic migrations — against that file, so integration tests exercise the
same bootstrap the service uses.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soc_triage.core.config import Settings
from soc_triage.main import create_app

TEST_INGEST_KEY = "test-ingest-key-not-a-real-secret"
TEST_CALLBACK_TOKEN = "test-callback-token-not-a-real-secret"


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
