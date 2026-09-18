"""Phase 2.7A unit tests: the late-enrichment sweep mechanics.

Covers the sweep contract in isolation (real temp SQLite, mocked
:class:`~soc_triage.services.late_enrichment.LateEnrichmentService`):

* lookback window (inclusive boundary, oldest-first ordering);
* per-pass batch bound (``_BATCH_LIMIT``);
* summary counters (``reassessed`` / ``unchanged`` / ``errors``) and
  per-alert error isolation (one bad row never kills the pass);
* ``decided_at`` pass-through of the pass timestamp;
* disabled-by-default: ``start_late_enrichment_task`` returns ``None``;
* the async loop runs passes and stops cleanly on cancellation.

The end-to-end behavior (real chain / scorer / decider / persistence) is
covered by ``tests/integration/test_late_enrichment_trigger.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tests.conftest import make_canonical_alert

from soc_triage.core.config import Settings
from soc_triage.db.session import session_scope
from soc_triage.models.orm import Alert, Base
from soc_triage.services import late_enrichment_sweep as sweep_mod

NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def factory(tmp_path: Path) -> sessionmaker:
    """A fresh SQLite database with the full schema (one per test)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'late_enrichment_sweep.db'}")
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    engine.dispose()


def _persist_alert(factory: sessionmaker, *, received_at: datetime, rule_id: str) -> UUID:
    """Persist a minimal alert row (no assessment) at ``received_at``."""
    canonical = make_canonical_alert(rule_id=rule_id, received_at=received_at)
    with session_scope(factory) as session:
        session.add(
            Alert(
                alert_id=canonical.alert_id,
                source=canonical.source,
                received_at=canonical.received_at,
                dedupe_group_key=(
                    canonical.dedupe.group_key if canonical.dedupe is not None else "g"
                ),
                event_identity=(
                    canonical.dedupe.event_identity
                    if canonical.dedupe is not None
                    else "wazuh:test:x:001"
                ),
                rule_id=canonical.source_event.rule.id,
                rule_level=canonical.source_event.rule.level,
                agent_id=canonical.source_event.agent.id,
                agent_name=canonical.source_event.agent.name,
                normalized_payload=canonical.model_dump(mode="json"),
                created_at=canonical.received_at,
            )
        )
    return canonical.alert_id


def _settings(*, enabled: bool, interval: int, lookback: int) -> Settings:
    return Settings(
        soc_env="test",
        triage_ingest_api_key="test-ingest-key-not-a-real-secret",
        n8n_callback_token="test-callback-token-not-a-real-secret",
        late_enrichment_sweep_enabled=enabled,
        late_enrichment_sweep_interval_seconds=interval,
        late_enrichment_lookback_seconds=lookback,
    )


def _requested_alerts(service: Mock) -> list[UUID]:
    return [
        call.kwargs["alert_id"] for call in service.reassess_persisted_if_changed.call_args_list
    ]


def test_sweep_once_scans_only_the_lookback_window_oldest_first(factory: sessionmaker) -> None:
    """Inclusive lower bound; oldest candidates are processed first."""
    inside_edge = _persist_alert(factory, received_at=NOW - timedelta(seconds=3600), rule_id="5710")
    inside_newer = _persist_alert(
        factory, received_at=NOW - timedelta(seconds=3500), rule_id="5711"
    )
    outside = _persist_alert(factory, received_at=NOW - timedelta(seconds=3601), rule_id="5712")

    service = Mock()
    service.reassess_persisted_if_changed.return_value = None

    stats = sweep_mod.sweep_once(
        factory,
        service=service,
        lookback_seconds=3600,
        as_of=NOW,
    )

    assert stats == {"candidates": 2, "reassessed": 0, "unchanged": 2, "errors": 0}
    # Oldest first: the edge alert (exactly at the boundary) precedes the
    # newer in-window alert; the out-of-window alert is never requested.
    assert _requested_alerts(service) == [inside_edge, inside_newer]
    assert outside not in _requested_alerts(service)
    # The pass timestamp is handed to the service as decided_at.
    for call in service.reassess_persisted_if_changed.call_args_list:
        assert call.kwargs["decided_at"] == NOW


def test_sweep_once_bounds_the_batch_oldest_first(
    factory: sessionmaker, monkeypatch: pytest.MonkeyPatch
) -> None:
    # i = 4 is the oldest (NOW - 4s), i = 1 the newest (NOW - 1s).
    ids = {
        i: _persist_alert(factory, received_at=NOW - timedelta(seconds=i), rule_id=f"57{10 + i}")
        for i in range(1, 5)
    }
    monkeypatch.setattr(sweep_mod, "_BATCH_LIMIT", 2)
    service = Mock()
    service.reassess_persisted_if_changed.return_value = None

    stats = sweep_mod.sweep_once(factory, service=service, lookback_seconds=86400, as_of=NOW)

    assert stats["candidates"] == 2
    assert _requested_alerts(service) == [ids[4], ids[3]]


def test_sweep_once_counts_outcomes_and_isolates_per_alert_errors(factory: sessionmaker) -> None:
    ok = _persist_alert(factory, received_at=NOW - timedelta(seconds=3), rule_id="6001")
    no_change = _persist_alert(factory, received_at=NOW - timedelta(seconds=2), rule_id="6002")
    broken = _persist_alert(factory, received_at=NOW - timedelta(seconds=1), rule_id="6003")

    good_outcome = (Mock(), Mock())

    def side_effect(session_factory, *, alert_id, decided_at):  # noqa: ARG001
        if alert_id == ok:
            return good_outcome
        if alert_id == no_change:
            return None
        raise RuntimeError("boom")

    service = Mock()
    service.reassess_persisted_if_changed.side_effect = side_effect

    stats = sweep_mod.sweep_once(factory, service=service, lookback_seconds=86400, as_of=NOW)

    assert stats == {"candidates": 3, "reassessed": 1, "unchanged": 1, "errors": 1}
    # All three candidates were visited despite the mid-batch failure.
    assert sorted(_requested_alerts(service)) == sorted([ok, no_change, broken])


def test_sweep_once_rejects_invalid_lookback(factory: sessionmaker) -> None:
    with pytest.raises(ValueError):
        sweep_mod.sweep_once(factory, service=Mock(), lookback_seconds=0, as_of=NOW)


def test_start_late_enrichment_task_returns_none_when_disabled() -> None:
    app = SimpleNamespace(
        state=SimpleNamespace(settings=_settings(enabled=False, interval=300, lookback=604800))
    )
    assert sweep_mod.start_late_enrichment_task(app) is None


def test_run_late_enrichment_loop_runs_passes_and_stops_on_cancellation(
    factory: sessionmaker,
) -> None:
    # The loop uses the real UTC clock, so the candidate must be recent
    # relative to the current test run rather than the fixed NOW constant
    # used by the deterministic sweep_once tests.
    current_time = datetime.now(UTC)

    _persist_alert(
        factory,
        received_at=current_time - timedelta(seconds=10),
        rule_id="5720",
    )

    service = Mock()
    service.reassess_persisted_if_changed.return_value = None

    app = SimpleNamespace(
        state=SimpleNamespace(
            settings=_settings(enabled=True, interval=1, lookback=3600),
            session_factory=factory,
            late_enrichment_service=service,
        )
    )

    async def scenario() -> None:
        task = asyncio.create_task(sweep_mod.run_late_enrichment_loop(app))

        # The first pass must run immediately, before the configured
        # one-second interval sleep.
        await asyncio.sleep(0.05)

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(scenario())

    assert service.reassess_persisted_if_changed.call_count >= 1
    assert service.reassess_persisted_if_changed.call_args.kwargs["decided_at"] is not None


def test_stop_late_enrichment_task_is_a_noop_for_none_or_done() -> None:
    sweep_mod.stop_late_enrichment_task(None)
    done: asyncio.Task[None] | None = None

    async def finished() -> None:
        nonlocal done
        done = asyncio.create_task(asyncio.sleep(0.01))
        await done

    asyncio.run(finished())
    assert done is not None and done.done()
    sweep_mod.stop_late_enrichment_task(done)  # must not raise
