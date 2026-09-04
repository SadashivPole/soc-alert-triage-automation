"""HTTP request metrics middleware (Phase 3.7, Task D5).

A thin **pure ASGI** middleware that records ``soc_triage_http_requests``
(counter) and ``soc_triage_http_request_duration_seconds`` (histogram) for
every HTTP request handled by the Triage API.

Design rules (ARCHITECTURE.md §15, ADR-9):

* Labels come only from the ASGI scope: method, the **FastAPI route
  template** (``scope["route"].path``, e.g. ``/api/v1/alerts/{alert_id}``),
  and the response status. The raw URL path, query string, headers, body and
  hostname are never read — cardinality stays bounded because a template is
  shared by every concrete request to that route.
* The middleware passes method/route/status through the
  :class:`~soc_triage.core.metrics.MetricsRegistry` bounded-label
  sanitizers (D2), so a concrete identifier path or exotic method collapses
  to ``unmatched`` / ``unknown``; an unmatched request has no route and is
  labeled ``unmatched``.
* Duration uses ``time.perf_counter`` (monotonic; never wall clock).
* Recording is **non-load-bearing**: failures are swallowed (log by error
  *type* only) in a ``finally`` after the inner app returns, so a metrics
  bug can never change the response status, headers, body, or any pipeline
  behavior, and no database write or network call is ever made.
* The middleware is installed only when ``METRICS_ENABLED=true``. It
  resolves the app-scoped registry from ``scope["app"].state.metrics`` (the
  Starlette application object, set before the middleware stack runs), so a
  missing/disposed registry simply skips instrumentation.

Why pure ASGI instead of ``BaseHTTPMiddleware``: no request-body buffering,
no streaming/background-task pitfalls, minimal per-request overhead.
"""

from __future__ import annotations

import time
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..core.logging import get_logger
from ..core.metrics import UNMATCHED_ROUTE, MetricsRegistry

logger = get_logger("soc_triage.api.middleware")

#: Fallback status recorded when the inner app raised an unhandled error
#: before sending a response status (ServerErrorMiddleware responds 500).
_DEFAULT_STATUS_CODE = 500


def _route_template(scope: Scope) -> str | None:
    """Return the matched FastAPI route template, or None for unmatchable.

    FastAPI/Starlette merge ``scope["route"]`` (set by ``APIRoute.matches``)
    into this same scope dict before the endpoint runs, so after the inner
    app returns the template is available. Returns None when no route
    matched (404), a plain ``Mount`` without a path, or a sub-app request —
    the registry sanitizer then labels the series ``unmatched``.
    """
    route = scope.get("route")
    path = getattr(route, "path", None) if route is not None else None
    if isinstance(path, str) and path.startswith("/"):
        return path
    return None


def collect_route_paths(routes: Any) -> set[str]:
    """Collect every absolute path template in a FastAPI/Starlette router tree.

    The application's static routes (e.g. ``/health``, ``/ready``,
    ``/api/v1/alerts/ingest``) must be allowlisted by
    :class:`~soc_triage.core.metrics.MetricsRegistry` before the bounded
    sanitizer will accept them as request labels. Newer FastAPI versions keep
    included routers behind lazy ``_IncludedRouter`` wrappers at the top
    level of ``app.routes``, so a flat scan misses them; this walks nested
    ``.routes`` / ``.original_router`` containers generically.

    Templates (paths containing ``{...}``) are also returned — the registry
    accepts them by the template rule — but the call site only needs the
    static subset for the allowlist; deduplication keeps the set small.
    """
    collected: set[str] = set()

    def walk(container: Any) -> None:
        child_routes = getattr(container, "routes", None)
        if child_routes is None:
            return
        for route in child_routes:
            path = getattr(route, "path", None)
            if isinstance(path, str) and path.startswith("/"):
                collected.add(path)
            # FastAPI lazy include wrappers hold the real router.
            inner = getattr(route, "original_router", None)
            if inner is not None and inner is not container:
                walk(inner)
            elif getattr(route, "routes", None) is not None:
                walk(route)

    walk(routes)
    return collected


class MetricsMiddleware:
    """Record bounded HTTP request counters and latency histograms.

    Wraps the ASGI ``send`` callable to capture the response status without
    touching the response body, and records in a ``finally`` so handled
    exceptions still report their real status while unhandled errors report
    a 500 fallback (matching ServerErrorMiddleware's outward response).
    """

    def __init__(self, app: ASGIApp) -> None:
        """Wrap the inner ASGI application."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Instrument one ASGI message cycle (HTTP only; others pass through)."""
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        metrics = self._metrics_registry(scope)
        if metrics is None:
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", ""))
        started = time.perf_counter()
        status_holder: dict[str, int] = {}

        async def send_wrapper(message: Message) -> None:
            """Forward the ASGI message unchanged, capturing the status."""
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # scope["route"] was merged by the router while the inner app ran.
            status_code = status_holder.get("status", _DEFAULT_STATUS_CODE)
            try:
                self._record(
                    metrics,
                    method=method,
                    route=_route_template(scope) or UNMATCHED_ROUTE,
                    status_code=status_code,
                    duration_seconds=time.perf_counter() - started,
                )
            except Exception as exc:  # pragma: no cover - defensive, ADR-9
                logger.warning(
                    "http_metrics_record_failed",
                    component="metrics",
                    error_type=type(exc).__name__,
                )

    @staticmethod
    def _metrics_registry(scope: Scope) -> MetricsRegistry | None:
        """Resolve the app-scoped registry via ``scope["app"].state``.

        ``scope["app"]`` is the Starlette/FastAPI application object (set by
        Starlette before the middleware stack runs); its ``state.metrics``
        holds the Phase 3.7 registry created in the lifespan when metrics
        are enabled. A missing registry means instrumentation is skipped.
        """
        app = scope.get("app")
        state = getattr(app, "state", None)
        metrics = getattr(state, "metrics", None)
        return metrics if isinstance(metrics, MetricsRegistry) else None

    @staticmethod
    def _record(
        metrics: MetricsRegistry,
        *,
        method: str,
        route: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        """Record one request through the registry's bounded sanitizers.

        Registry record helpers are themselves non-raising (D2); this call is
        additionally guarded by the caller so even a registry-level defect
        cannot escape into the request cycle.
        """
        metrics.record_http_request(
            method=method,
            route=route,
            status_code=status_code,
        )
        metrics.observe_http_duration(
            method=method,
            route=route,
            seconds=duration_seconds,
        )


__all__ = ["MetricsMiddleware", "_route_template"]
