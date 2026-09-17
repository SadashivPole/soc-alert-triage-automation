"""Automatic late-enrichment trigger (Phase 2.7A).

A restart-safe, idempotent background loop that periodically re-runs the
deterministic enrichment chain over recently persisted alerts and re-assesses
(re-score, re-decide, persist) exactly those whose enrichment has changed
since the persisted assessment — a late threat-intel verdict, a retried
failed lookup, or a newly enabled provider.

Design (Phase 2.7A architecture investigation):

* **Trigger, not pipeline** — the ingest request path is untouched. The
  sweep is its own asyncio task started from the FastAPI lifespan (Phase 3.4
  sweeper pattern; ADR-4: no Celery/Redis/queue), with all blocking work
  (provider HTTP, SQLite) in a worker thread via ``asyncio.to_thread``.
* **Idempotent** — each candidate goes through
  :meth:`LateEnrichmentService.reassess_persisted_if_changed`, whose
  timestamp-insensitive enrichment fingerprint makes the same enrichment a
  strict no-op (no score, no write, no audit rows). The persisted alert
  payload *is* the state, so a crash mid-pass is safe: the post-restart
  window scan re-derives candidates and completed work no-ops.
* **Bounded** — one pass scans at most ``_BATCH_LIMIT`` alerts (oldest
  first) within the ``LATE_ENRICHMENT_LOOKBACK_SECONDS`` window, so a pass
  always completes; provider calls are additionally bounded by the chain's
  own 3 s timeouts and non-blocking token buckets.
* **Fail-open, error-isolated** — a per-alert failure is logged (exception
  *type* only, SECURITY.md §7) and the pass continues; a pass-level
  (transaction/DB) failure is logged and retried on the next tick; enriched
  failures produce failure records the fingerprint treats as "no change", so
  a permanently failing lookup never re-scores its alert on every pass.
* **No new notifications** — persistence + audit flow through the existing
  ``persist_assessment`` path (``alert.scored`` / ``alert.decided`` with
  before/after snapshots; incident create/attach on escalation). Escalation
  re-notification is deliberately Phase 2.7B.

Disabled by default (``LATE_ENRICHMENT_SWEEP_ENABLED=false``), matching the
Phase 2.2/2.3 convention: with no providers configured the pipeline performs
zero external calls (ARCHITECTURE.md §7.3), and the sweep is the one
component that would otherwise run providers outside the ingest path.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from ..core.config import Settings
from ..core.logging import get_logger
from ..db.session import session_scope
from ..models.repositories import AlertRepository
from .late_enrichment import LateEnrichmentService

#: How many alerts to process in a single sweep pass (bounds one DB scan).
_BATCH_LIMIT = 200


def _utc_now() -> datetime:
    """UTC ``now`` — isolated so tests can inject a deterministic clock."""
    return datetime.now(UTC)


def sweep_once(
    session_factory: Any,
    *,
    service: LateEnrichmentService,
    lookback_seconds: int,
    as_of: datetime | None = None,
    logger: structlog.stdlib.BoundLogger | None = None,
) -> dict[str, int]:
    """Run a single idempotent late-enrichment sweep pass.

    Scans at most ``_BATCH_LIMIT`` alerts received within the lookback
    window (oldest first) and re-assesses exactly those whose freshly
    produced enrichment differs from the persisted one.

    Returns a small integer summary (``candidates``, ``reassessed``,
    ``unchanged``, ``errors``) suitable for structured logging. Safe to call
    from tests or from a management hook: it does not schedule anything and
    does not swallow exceptions raised at the transaction boundary (those
    indicate DB problems, not per-alert errors, and must surface to the
    loop, which logs and retries on the next tick).

    Per-alert errors are isolated: a failure on one alert is counted in
    ``errors`` and logged (exception type only) and the pass continues — a
    single bad row can never kill the periodic task.
    """
    log = logger or get_logger("soc_triage.late_enrichment_sweep")
    if lookback_seconds < 1:
        raise ValueError("lookback_seconds must be >= 1")

    timestamp = as_of if as_of is not None else _utc_now()
    since = timestamp - timedelta(seconds=lookback_seconds)
    stats = {"candidates": 0, "reassessed": 0, "unchanged": 0, "errors": 0}

    with session_scope(session_factory) as session:
        candidates = AlertRepository(session).list_alerts_received_since(
            since,
            limit=_BATCH_LIMIT,
        )
    stats["candidates"] = len(candidates)

    for candidate in candidates:
        # Each alert is processed in its own short transaction (inside the
        # service's persist_assessment) so a failure on one row cannot
        # poison the rest of the batch.
        try:
            outcome = service.reassess_persisted_if_changed(
                session_factory,
                alert_id=candidate.alert_id,
                decided_at=timestamp,
            )
            if outcome is None:
                # Fingerprint guard: no new information — strict no-op.
                stats["unchanged"] += 1
                log.debug(
                    "late_enrichment_unchanged",
                    component="late_enrichment",
                    alert_id=str(candidate.alert_id),
                )
                continue
            result, persistence = outcome
            stats["reassessed"] += 1
            log.info(
                "late_enrichment_reassessed",
                component="late_enrichment",
                alert_id=str(candidate.alert_id),
                previous_score=result.previous_risk.score
                if result.previous_risk is not None
                else None,
                score=result.canonical.risk.score if result.canonical.risk is not None else None,
                previous_decision=(
                    result.previous_decision.action.value
                    if result.previous_decision is not None
                    else None
                ),
                decision=(
                    result.canonical.decision.action.value
                    if result.canonical.decision is not None
                    else None
                ),
                incident_id=persistence.incident_id,
                persisted=persistence.persisted,
            )
        except Exception as exc:  # pragma: no cover - defensive error isolation
            # Per-alert error isolation: log + continue. Never crash the pass.
            stats["errors"] += 1
            log.error(
                "late_enrichment_alert_failed",
                component="late_enrichment",
                alert_id=str(candidate.alert_id),
                error_type=type(exc).__name__,
            )
    return stats


async def run_late_enrichment_loop(
    app: Any,
    *,
    logger: structlog.stdlib.BoundLogger | None = None,
) -> None:
    """Periodic late-enrichment loop, intended to be started from the lifespan.

    Runs :func:`sweep_once` every ``LATE_ENRICHMENT_SWEEP_INTERVAL_SECONDS``
    until cancelled (application shutdown). The first pass runs immediately
    so backlogged alerts left behind after a restart are re-assessed without
    waiting a full interval. Blocking work runs in a worker thread
    (``asyncio.to_thread``) so the event loop — and with it the ingest path
    — is never blocked by provider HTTP or SQLite.

    ``app.state.session_factory`` and ``app.state.late_enrichment_service``
    are resolved per pass (mirroring the per-request dependency resolution)
    so the bound service can be rebound without a restart; settings are read
    once, like the Phase 3.4 sweeper.
    """
    log = logger or get_logger("soc_triage.late_enrichment_sweep")
    settings: Settings = app.state.settings
    interval = settings.late_enrichment_sweep_interval_seconds
    lookback = settings.late_enrichment_lookback_seconds
    log.info(
        "late_enrichment_sweep_started",
        component="late_enrichment",
        interval_seconds=interval,
        lookback_seconds=lookback,
    )
    try:
        while True:
            started = _utc_now()
            try:
                stats = await asyncio.to_thread(
                    sweep_once,
                    app.state.session_factory,
                    service=app.state.late_enrichment_service,
                    lookback_seconds=lookback,
                    logger=log,
                )
                log.info(
                    "late_enrichment_pass_completed",
                    component="late_enrichment",
                    candidates=stats["candidates"],
                    reassessed=stats["reassessed"],
                    unchanged=stats["unchanged"],
                    errors=stats["errors"],
                    duration_ms=round((_utc_now() - started).total_seconds() * 1000),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                # A failure at the transaction-batch level (e.g. DB down)
                # must not kill the loop: log and sleep until the next tick.
                log.error(
                    "late_enrichment_pass_failed",
                    component="late_enrichment",
                    error_type=type(exc).__name__,
                )
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        log.info("late_enrichment_sweep_stopped", component="late_enrichment")
        raise


def start_late_enrichment_task(app: Any) -> asyncio.Task[None] | None:
    """Start the late-enrichment sweep as an asyncio Task, attached to the app.

    Returns the task (so the lifespan can cancel it on shutdown) or ``None``
    when the sweep is disabled by ``LATE_ENRICHMENT_SWEEP_ENABLED=false``
    (the default). Requires ``app.state.late_enrichment_service`` to be bound
    (see the FastAPI lifespan).
    """
    settings: Settings = app.state.settings
    if not settings.late_enrichment_sweep_enabled:
        return None
    loop = asyncio.get_event_loop()
    task: asyncio.Task[None] = loop.create_task(
        run_late_enrichment_loop(app, logger=get_logger("soc_triage.late_enrichment_sweep")),
        name="soc-triage-late-enrichment-sweep",
    )
    return task


def stop_late_enrichment_task(task: asyncio.Task[None] | None) -> None:
    """Cancel the sweep task (the async caller is responsible for awaiting it,
    swallowing ``CancelledError`` — normal shutdown)."""
    if task is None or task.done():
        return
    task.cancel()


__all__ = [
    "run_late_enrichment_loop",
    "start_late_enrichment_task",
    "stop_late_enrichment_task",
    "sweep_once",
]
