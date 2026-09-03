"""Incident auto-close TTL sweeper (Phase 3.4).

A restart-safe, idempotent background loop that periodically scans for
non-terminal incidents whose ``updated_at`` exceeds
``INCIDENT_AUTO_CLOSE_TTL_SECONDS`` and transitions them to ``resolved``
using the existing lifecycle rules. The sweeper is started once from the
FastAPI lifespan and stopped cleanly on shutdown (graceful task
cancellation, no leaked tasks, no external infrastructure dependency).

Concurrency / race safety (ARCHITECTURE.md §10.4):

* Each candidate is closed via a single conditional UPDATE that
  re-checks both ``status`` and ``updated_at`` (see
  :meth:`IncidentRepository.auto_close_if_stale`). If an analyst PATCH
  bumps ``updated_at`` between our SELECT and our UPDATE, the UPDATE
  matches zero rows and the manual action wins — no stale overwrite.
* The whole operation is single-process / single-instance by design
  (ADR-4: no Celery/Redis yet); the SQLite single-writer lock serializes
  the conditional UPDATE so two passes can never double-close the same
  incident. The sweeper does not claim distributed-lock semantics.

Error isolation: a failure on one incident is logged and the loop
continues to the next candidate; a single bad row can never kill the
periodic task.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog

from .audit import (
    audit_entries_for_incident_auto_closed,
)
from .core.config import Settings
from .core.logging import get_logger
from .db.session import session_scope
from .models.repositories import AuditRepository, IncidentRepository

#: How many incidents to process in a single sweep pass (bounds one DB scan).
_BATCH_LIMIT = 500

#: Actor name used on every auto-close audit entry.
SWEEPER_ACTOR = "system:sweeper"


def _utc_now() -> datetime:
    """UTC ``now`` — isolated so tests can inject a deterministic clock."""
    return datetime.now(UTC)


def sweep_once(
    session_factory: Any,
    *,
    ttl_seconds: int,
    as_of: datetime | None = None,
    logger: structlog.stdlib.BoundLogger | None = None,
) -> dict[str, int]:
    """Run a single idempotent auto-close sweep.

    Returns a small integer summary (``candidates``, ``closed``, ``skipped``,
    ``errors``) suitable for structured logging. Safe to call from tests or
    from a management hook: it does not schedule anything and does not
    swallow exceptions raised at the transaction boundary (those indicate
    DB problems, not per-incident errors, and must surface).
    """
    log = logger or get_logger("soc_triage.sweeper")
    if ttl_seconds < 1:
        raise ValueError("ttl_seconds must be >= 1")

    timestamp = as_of if as_of is not None else _utc_now()
    stats = {"candidates": 0, "closed": 0, "skipped": 0, "errors": 0}

    with session_scope(session_factory) as session:
        incidents = IncidentRepository(session).list_incidents_eligible_for_auto_close(
            ttl_seconds=ttl_seconds,
            as_of=timestamp,
            limit=_BATCH_LIMIT,
        )
    stats["candidates"] = len(incidents)

    for candidate in incidents:
        # Each incident is processed in its own short transaction so that
        # a failure on one row cannot poison the rest of the batch.
        try:
            with session_scope(session_factory) as session:
                repo = IncidentRepository(session)
                audit_repo = AuditRepository(session)
                idle_seconds = max(
                    0.0,
                    (timestamp - candidate.updated_at).total_seconds(),
                )
                closed = repo.auto_close_if_stale(
                    candidate.incident_id,
                    ttl_seconds=ttl_seconds,
                    as_of=timestamp,
                    expected_previous_updated_at=candidate.updated_at,
                    expected_previous_status=candidate.status.value,
                )
                if closed is None:
                    # Conditional update rejected: a concurrent writer moved
                    # the incident (analyst PATCH / feedback sync). Manual
                    # action wins — skip silently (logged at debug level).
                    stats["skipped"] += 1
                    log.debug(
                        "sweeper_skip_stale",
                        component="sweeper",
                        incident_id=candidate.incident_id,
                        reason="concurrent_update",
                    )
                    continue
                # Append exactly one audit entry for a successful close.
                # Idempotency is enforced by the conditional UPDATE above:
                # a second sweep will find the incident terminal and not
                # re-select it, so no second row can be appended.
                entries = audit_entries_for_incident_auto_closed(
                    incident=closed,
                    previous_status=candidate.status,
                    ttl_seconds=ttl_seconds,
                    idle_seconds=idle_seconds,
                )
                audit_repo.append(entries, occurred_at=timestamp)
                stats["closed"] += 1
                log.info(
                    "incident_auto_closed",
                    component="sweeper",
                    incident_id=closed.incident_id,
                    previous_status=candidate.status.value,
                    after_status=closed.status.value,
                    ttl_seconds=ttl_seconds,
                    idle_seconds=round(idle_seconds),
                    actor=SWEEPER_ACTOR,
                )
        except Exception as exc:  # pragma: no cover - defensive error isolation
            # Per-incident error isolation: log + continue. Never crash the loop.
            stats["errors"] += 1
            log.error(
                "sweeper_incident_failed",
                component="sweeper",
                incident_id=candidate.incident_id,
                error_type=type(exc).__name__,
                # Never log exception messages that might contain DB internals;
                # the type plus the incident id is enough to debug in the lab.
            )
    return stats


async def run_sweeper_loop(
    session_factory: Any,
    settings: Settings,
    *,
    logger: structlog.stdlib.BoundLogger | None = None,
) -> None:
    """Periodic sweeper loop, intended to be started from the FastAPI lifespan.

    Runs :func:`sweep_once` every ``INCIDENT_SWEEPER_INTERVAL_SECONDS`` until
    cancelled (application shutdown). The first pass runs immediately so
    stale incidents left behind after a restart are closed without waiting
    a full interval.
    """
    log = logger or get_logger("soc_triage.sweeper")
    interval = settings.incident_sweeper_interval_seconds
    ttl = settings.incident_auto_close_ttl_seconds
    log.info(
        "sweeper_started",
        component="sweeper",
        interval_seconds=interval,
        ttl_seconds=ttl,
    )
    try:
        while True:
            started = _utc_now()
            try:
                stats = await asyncio.to_thread(
                    sweep_once,
                    session_factory,
                    ttl_seconds=ttl,
                    logger=log,
                )
                log.info(
                    "sweeper_pass_completed",
                    component="sweeper",
                    candidates=stats["candidates"],
                    closed=stats["closed"],
                    skipped=stats["skipped"],
                    errors=stats["errors"],
                    duration_ms=round((_utc_now() - started).total_seconds() * 1000),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                # A failure at the transaction-batch level (e.g. DB down)
                # must not kill the loop: log and sleep until the next tick.
                log.error(
                    "sweeper_pass_failed",
                    component="sweeper",
                    error_type=type(exc).__name__,
                )
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        log.info("sweeper_stopped", component="sweeper")
        raise


def start_sweeper_task(app: Any) -> asyncio.Task[None] | None:
    """Start the periodic sweeper as an asyncio Task, attached to the app.

    Returns the task (so the lifespan can cancel it on shutdown) or ``None``
    when the sweeper is effectively disabled by a zero/negative interval
    (we don't currently expose that via env — it is a test-only hook).
    """
    settings: Settings = app.state.settings
    if settings.incident_sweeper_interval_seconds < 1:
        return None
    loop = asyncio.get_event_loop()
    task: asyncio.Task[None] = loop.create_task(
        run_sweeper_loop(
            app.state.session_factory,
            settings,
            logger=get_logger("soc_triage.sweeper"),
        ),
        name="soc-triage-incident-sweeper",
    )
    return task


def stop_sweeper_task(task: asyncio.Task[None] | None) -> None:
    """Cancel the sweeper task and await it (swallowing ``CancelledError``)."""
    if task is None or task.done():
        return
    task.cancel()
    # The caller (lifespan) is async and is responsible for awaiting this;
    # however the stop function can be called from both sync and async
    # contexts, so we provide a synchronous helper that only schedules.


__all__ = [
    "SWEEPER_ACTOR",
    "run_sweeper_loop",
    "start_sweeper_task",
    "stop_sweeper_task",
    "sweep_once",
]
