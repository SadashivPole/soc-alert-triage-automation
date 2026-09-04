"""Application-scoped Prometheus metrics (Phase 3.7, Task D2).

Defines the bounded ``soc_triage_`` metric catalog for the Triage API and a
lightweight recording surface that the API layer will wire into existing
decision points (Tasks D4-D9). This module is deliberately small, pure of
framework imports (no FastAPI/Starlette), and self-contained:

* Every registry is **app-scoped** — metrics are created on a
  :class:`prometheus_client.CollectorRegistry` owned by one
  :class:`MetricsRegistry` instance, never on the process-global default
  registry, so state can never leak between application instances or tests.
* Every label is drawn from a **documented finite vocabulary** (or sanitized
  to a fixed fallback). Label values are never sourced from alert content,
  identifiers, hosts, URLs, or free text — recording therefore cannot
  introduce unbounded cardinality or secrets (ARCHITECTURE.md §15).
* Recording is **non-load-bearing**: helpers swallow failures (log by error
  *type* only) so metric instrumentation can never raise into the
  application pipeline, write to the database, or change any outcome,
  response, or audit row (ADR-9).

Layering: domain packages must never import FastAPI (ARCHITECTURE.md §12);
this module imports only ``prometheus_client`` + repo logging.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from contextlib import suppress
from typing import Any, Final

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
from prometheus_client.exposition import generate_latest

from .logging import get_logger

logger = get_logger("soc_triage.metrics")

#: Fallback label value for any value outside a metric's bounded vocabulary.
UNKNOWN: Final = "unknown"
#: Fallback for request routes that are not matched route templates.
UNMATCHED_ROUTE: Final = "unmatched"

# ---------------------------------------------------------------------------
# Bounded label vocabularies (mirror the domain enums; ARCHITECTURE.md §15).
# These are the *only* label values the registry may ever emit; every value
# comes from an enum/registry in the application, never from alert content.
# ---------------------------------------------------------------------------

DEDUPE_OUTCOMES: Final[frozenset[str]] = frozenset(
    {"new_generation", "exact_duplicate", "repeated"}
)
INGEST_REJECT_REASONS: Final[frozenset[str]] = frozenset(
    {
        "malformed_json",
        "schema_invalid",
        "identity_invalid",
        "payload_too_large",
        "auth_failed",
        "storage_unavailable",
    }
)
ENRICHMENT_STATUSES: Final[frozenset[str]] = frozenset({"skipped", "complete", "partial", "failed"})
RISK_TIERS: Final[frozenset[str]] = frozenset(
    {"informational", "low", "medium", "high", "critical"}
)
DECISION_ACTIONS: Final[frozenset[str]] = frozenset(
    {"suppress", "monitor", "queue_l1", "open_incident"}
)
N8N_OUTCOMES: Final[frozenset[str]] = frozenset(
    {"delivered", "failed", "skipped", "duplicate_suppressed"}
)
FEEDBACK_VERDICTS: Final[frozenset[str]] = frozenset(
    {
        "true_positive",
        "false_positive",
        "benign",
        "escalate",
        "acknowledged",
        "resolved",
        "contain_requested",
    }
)
INCIDENT_STATUSES: Final[frozenset[str]] = frozenset(
    {"open", "investigating", "acknowledged", "escalated", "resolved", "false_positive"}
)
AUTO_CLOSE_OUTCOMES: Final[frozenset[str]] = frozenset({"closed", "skipped", "error"})
SWEEPER_RESULTS: Final[frozenset[str]] = frozenset({"completed", "failed"})
DEGRADED_VALUES: Final[frozenset[str]] = frozenset({"0", "1"})
HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"}
)

#: Sanity limits for free-form label inputs before they hit a vocabulary.
_ROUTE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^/[A-Za-z0-9_\-./{}:]*$")
_ROUTE_PLACEHOLDER: Final[re.Pattern[str]] = re.compile(r"\{[^{}]+\}")
_PROVIDER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_LABEL_LENGTH: Final = 200


def _vocab(value: str, allowed: frozenset[str]) -> str:
    """Return ``value`` when it is inside ``allowed``, else ``unknown``.

    Values are coerced to ``str`` first and length-capped so a hostile or
    non-string input can never produce an unbounded or huge label.
    """
    text = str(value)
    if len(text) > _MAX_LABEL_LENGTH or text not in allowed:
        return UNKNOWN
    return text


def _method_label(method: str) -> str:
    """Normalize an HTTP method to the bounded vocabulary (``unknown`` else)."""
    return _vocab(str(method).upper(), HTTP_METHODS)


def _route_label(route: str, *, static_routes: frozenset[str] = frozenset()) -> str:
    """Normalize a route template label.

    Only route templates are allowed: a path that contains ``{placeholder}``
    segments (e.g. ``/api/v1/alerts/{alert_id}``) or that is explicitly
    listed in ``static_routes`` (e.g. ``/health``). Concrete request paths —
    including paths that embed identifiers — always collapse to
    ``unmatched``, so metric cardinality and secrets stay bounded.
    """
    text = str(route)
    if len(text) > _MAX_LABEL_LENGTH or not _ROUTE_PATTERN.match(text):
        return UNMATCHED_ROUTE
    if text in static_routes or _ROUTE_PLACEHOLDER.search(text):
        return text
    return UNMATCHED_ROUTE


def _status_label(status_code: Any) -> str:
    """Normalize an HTTP status code to ``100..599`` (``unknown`` else)."""
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return UNKNOWN
    if 100 <= code <= 599:
        return str(code)
    return UNKNOWN


def _bool_label(value: Any) -> str:
    """Normalize a boolean-ish value to the ``0``/``1`` vocabulary."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if value in (0, 1):
        return str(value)
    return _vocab(str(value), DEGRADED_VALUES)


def _duration(value: Any) -> float:
    """Sanitize an observation: non-finite or negative becomes ``0.0``."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(number) or number < 0.0:
        return 0.0
    return number


def resolve_metrics(app: Any) -> MetricsRegistry | None:
    """Return the app-scoped metrics registry from a FastAPI/ASGI application.

    Framework-free helper used by API wiring: returns ``None`` when metrics
    are disabled (``app.state.metrics`` is not set) so callers can skip
    instrumentation without depending on the metrics surface existing.
    """
    state = getattr(app, "state", None)
    metrics = getattr(state, "metrics", None)
    return metrics if isinstance(metrics, MetricsRegistry) else None


class MetricsRegistry:
    """An application-scoped set of ``soc_triage_`` Prometheus metrics.

    One instance exists per running application (owned by ``app.state``,
    wired in Tasks D4+). Each instance owns its own
    :class:`~prometheus_client.CollectorRegistry` and its own metric
    objects, so counters can never leak between app instances or tests and
    the process-global ``REGISTRY`` is never touched.
    """

    def __init__(
        self,
        *,
        provider_names: Sequence[str] = (),
        static_routes: Sequence[str] = (),
    ) -> None:
        """Create the app-scoped registry (no metrics are exposed globally).

        ``static_routes`` lists the app's parameter-less route templates
        (e.g. ``/health``, ``/ready``); any other route label must contain
        a ``{placeholder}`` to be accepted. The wiring layer (Task D5)
        passes the FastAPI route templates it knows about; passing raw
        request paths is never allowed (they collapse to ``unmatched``).
        """
        self._registry = CollectorRegistry(auto_describe=False)
        self._provider_names: frozenset[str] | None = (
            frozenset(provider_names) if provider_names else None
        )
        self._static_routes: frozenset[str] = frozenset(static_routes)

        # --- HTTP request / pipeline latency --------------------------------
        self._http_requests = Counter(
            "soc_triage_http_requests",
            "HTTP requests handled by the Triage API, by method, route template and status code.",
            labelnames=("method", "route", "status"),
            registry=self._registry,
        )
        self._http_duration = Histogram(
            "soc_triage_http_request_duration_seconds",
            "Wall-clock duration of HTTP requests in seconds.",
            labelnames=("method", "route"),
            registry=self._registry,
        )
        self._ingest_duration = Histogram(
            "soc_triage_alert_processing_duration_seconds",
            "End-to-end alert processing latency (normalize through persist).",
            registry=self._registry,
        )

        # --- Ingest / processing --------------------------------------------
        self._ingest_rejections = Counter(
            "soc_triage_ingest_rejections",
            "Ingest requests rejected before processing, by reason.",
            labelnames=("reason",),
            registry=self._registry,
        )
        self._alerts_processed = Counter(
            "soc_triage_alerts_processed",
            "Alerts processed through the deduplication state machine, by outcome.",
            labelnames=("outcome",),
            registry=self._registry,
        )
        self._alerts_scored = Counter(
            "soc_triage_alerts_scored",
            "Alerts scored and decided, by risk tier, decision and degraded flag.",
            labelnames=("tier", "decision", "degraded"),
            registry=self._registry,
        )

        # --- Enrichment ------------------------------------------------------
        self._enrichment_status = Counter(
            "soc_triage_enrichment_status",
            "Enrichment runs by aggregate status (never IOC values).",
            labelnames=("status",),
            registry=self._registry,
        )
        self._enrichment_provider_outcomes = Counter(
            "soc_triage_enrichment_provider_outcomes",
            "Per-provider enrichment outcomes (registered provider names only).",
            labelnames=("provider", "status"),
            registry=self._registry,
        )

        # --- Notifications ----------------------------------------------------
        self._n8n_notifications = Counter(
            "soc_triage_n8n_notifications",
            "Outbound n8n notifications attempted, by outcome.",
            labelnames=("outcome",),
            registry=self._registry,
        )
        self._n8n_duration = Histogram(
            "soc_triage_n8n_notification_duration_seconds",
            "Wall-clock duration of outbound n8n notification attempts.",
            registry=self._registry,
        )

        # --- Feedback / incidents / sweeper -----------------------------------
        self._feedback = Counter(
            "soc_triage_feedback",
            "Analyst feedback submissions by verdict.",
            labelnames=("verdict",),
            registry=self._registry,
        )
        self._incident_transitions = Counter(
            "soc_triage_incident_transitions",
            "Incident lifecycle transitions, by from/to status.",
            labelnames=("from_status", "to_status"),
            registry=self._registry,
        )
        self._incident_auto_close = Counter(
            "soc_triage_incident_auto_close",
            "Auto-close sweeper outcomes per incident.",
            labelnames=("outcome",),
            registry=self._registry,
        )
        self._sweeper_passes = Counter(
            "soc_triage_sweeper_passes",
            "Auto-close sweeper passes by result.",
            labelnames=("result",),
            registry=self._registry,
        )

        # --- Health gauges -----------------------------------------------------
        self._up = Gauge(
            "soc_triage_up",
            "1 while the process is serving (always 1 while scraped).",
            registry=self._registry,
        )
        self._up.set(1)
        self._database_up = Gauge(
            "soc_triage_database_up",
            "1 when the database liveness ping succeeds, else 0.",
            registry=self._registry,
        )
        self._migrations_applied = Gauge(
            "soc_triage_migrations_applied",
            "1 when an Alembic revision is present, else 0.",
            registry=self._registry,
        )

    # -- introspection --------------------------------------------------------
    @property
    def registry(self) -> CollectorRegistry:
        """The owned, app-scoped CollectorRegistry (never process-global)."""
        return self._registry

    def render_text(self) -> str:
        """Render the registry in Prometheus text exposition, never raising.

        Returns an empty string only if rendering itself fails (defensive:
        scraping must not break the service).
        """
        try:
            return generate_latest(self._registry).decode("utf-8")
        except Exception as exc:  # non-load-bearing by design (ADR-9)
            self._log_metric_error("metrics_render", exc)
            return ""

    # -- HTTP ------------------------------------------------------------------
    def record_http_request(self, *, method: str, route: str, status_code: Any) -> None:
        """Count one HTTP response (labels are sanitized to fixed vocabularies)."""
        labels = {
            "method": _method_label(method),
            "route": _route_label(route, static_routes=self._static_routes),
            "status": _status_label(status_code),
        }
        self._record_counter("soc_triage_http_requests", self._http_requests, labels)

    def observe_http_duration(self, *, method: str, route: str, seconds: Any) -> None:
        """Observe one HTTP request duration (monotonic clock is caller-owned)."""
        labels = {
            "method": _method_label(method),
            "route": _route_label(route, static_routes=self._static_routes),
        }
        self._record_histogram(
            "soc_triage_http_request_duration_seconds",
            self._http_duration,
            _duration(seconds),
            labels,
        )

    # -- Alert processing ---------------------------------------------------------
    def record_ingest_rejection(self, reason: str) -> None:
        """Count an ingest rejection by bounded reason."""
        self._record_counter(
            "soc_triage_ingest_rejections",
            self._ingest_rejections,
            {"reason": _vocab(reason, INGEST_REJECT_REASONS)},
        )

    def record_alerts_processed(self, outcome: str) -> None:
        """Count one deduplication outcome (new / repeated / exact duplicate)."""
        self._record_counter(
            "soc_triage_alerts_processed",
            self._alerts_processed,
            {"outcome": _vocab(outcome, DEDUPE_OUTCOMES)},
        )

    def observe_alert_processing(self, seconds: Any) -> None:
        """Observe one end-to-end alert processing duration."""
        self._record_histogram(
            "soc_triage_alert_processing_duration_seconds",
            self._ingest_duration,
            _duration(seconds),
            {},
        )

    def record_alert_scored(self, *, tier: str, decision: str, degraded: bool) -> None:
        """Count one scored/decided alert (bounded tier/decision labels)."""
        labels = {
            "tier": _vocab(tier, RISK_TIERS),
            "decision": _vocab(decision, DECISION_ACTIONS),
            "degraded": _bool_label(degraded),
        }
        self._record_counter("soc_triage_alerts_scored", self._alerts_scored, labels)

    # -- Enrichment ---------------------------------------------------------------
    def record_enrichment_status(self, status: str) -> None:
        """Count one enrichment run by aggregate status."""
        self._record_counter(
            "soc_triage_enrichment_status",
            self._enrichment_status,
            {"status": _vocab(status, ENRICHMENT_STATUSES)},
        )

    def record_enrichment_provider_outcome(self, *, provider: str, status: str) -> None:
        """Count one provider outcome (names are validated, never free text)."""
        self._record_counter(
            "soc_triage_enrichment_provider_outcomes",
            self._enrichment_provider_outcomes,
            {
                "provider": self._provider_label(provider),
                "status": _vocab(status, ENRICHMENT_STATUSES),
            },
        )

    # -- Notifications ---------------------------------------------------------------
    def record_n8n_notification(self, outcome: str) -> None:
        """Count one outbound n8n notification attempt by outcome."""
        self._record_counter(
            "soc_triage_n8n_notifications",
            self._n8n_notifications,
            {"outcome": _vocab(outcome, N8N_OUTCOMES)},
        )

    def observe_n8n_notification(self, seconds: Any) -> None:
        """Observe one outbound n8n notification duration."""
        self._record_histogram(
            "soc_triage_n8n_notification_duration_seconds",
            self._n8n_duration,
            _duration(seconds),
            {},
        )

    # -- Feedback / incidents / sweeper ------------------------------------------------
    def record_feedback(self, verdict: str) -> None:
        """Count one analyst feedback submission by bounded verdict."""
        self._record_counter(
            "soc_triage_feedback",
            self._feedback,
            {"verdict": _vocab(verdict, FEEDBACK_VERDICTS)},
        )

    def record_incident_transition(self, *, from_status: str, to_status: str) -> None:
        """Count one incident lifecycle transition (bounded status labels)."""
        labels = {
            "from_status": _vocab(from_status, INCIDENT_STATUSES),
            "to_status": _vocab(to_status, INCIDENT_STATUSES),
        }
        self._record_counter("soc_triage_incident_transitions", self._incident_transitions, labels)

    def record_incident_auto_close(self, outcome: str) -> None:
        """Count one sweeper auto-close attempt by outcome."""
        self._record_counter(
            "soc_triage_incident_auto_close",
            self._incident_auto_close,
            {"outcome": _vocab(outcome, AUTO_CLOSE_OUTCOMES)},
        )

    def record_sweeper_pass(self, result: str) -> None:
        """Count one completed/failed sweeper pass."""
        self._record_counter(
            "soc_triage_sweeper_passes",
            self._sweeper_passes,
            {"result": _vocab(result, SWEEPER_RESULTS)},
        )

    # -- Health gauges -------------------------------------------------------------------
    def set_up(self, value: bool) -> None:
        """Set the process-up gauge (``1``/``0``)."""
        self._record_gauge("soc_triage_up", self._up, _bool_label(value))

    def set_database_up(self, value: bool) -> None:
        """Set the database liveness gauge (``1``/``0``; one ping per scrape)."""
        self._record_gauge("soc_triage_database_up", self._database_up, _bool_label(value))

    def set_migrations_applied(self, value: bool) -> None:
        """Set the migrations-applied gauge (``1``/``0``; one read per scrape)."""
        self._record_gauge(
            "soc_triage_migrations_applied", self._migrations_applied, _bool_label(value)
        )

    # -- internals --------------------------------------------------------------------------
    def _record_counter(self, name: str, counter: Counter, labels: Mapping[str, str]) -> None:
        """Increment a counter; instrumentation failures are swallowed."""
        try:
            self._increment(counter, labels)
        except Exception as exc:  # non-load-bearing by design (ADR-9)
            self._log_metric_error(name, exc)

    def _record_histogram(
        self, name: str, histogram: Histogram, value: float, labels: Mapping[str, str]
    ) -> None:
        """Observe a histogram; instrumentation failures are swallowed."""
        try:
            self._observe(histogram, value, labels)
        except Exception as exc:  # non-load-bearing by design (ADR-9)
            self._log_metric_error(name, exc)

    def _record_gauge(self, name: str, gauge: Gauge, value: str) -> None:
        """Set a gauge; instrumentation failures are swallowed."""
        try:
            self._apply_gauge(gauge, value)
        except Exception as exc:  # non-load-bearing by design (ADR-9)
            self._log_metric_error(name, exc)

    def _increment(self, counter: Counter, labels: Mapping[str, str]) -> None:
        """Apply one counter increment (separated for failure injection tests)."""
        if labels:
            counter.labels(**labels).inc()
        else:
            counter.inc()

    def _observe(self, histogram: Histogram, value: float, labels: Mapping[str, str]) -> None:
        """Apply one histogram observation (separated for failure injection tests)."""
        if labels:
            histogram.labels(**labels).observe(value)
        else:
            histogram.observe(value)

    def _apply_gauge(self, gauge: Gauge, value: str) -> None:
        """Apply one gauge set (separated for failure injection tests)."""
        gauge.set(float(value))

    def _provider_label(self, provider: str) -> str:
        """Validate a provider name against the registered-name vocabulary."""
        text = str(provider)
        if not _PROVIDER_PATTERN.match(text) or len(text) > _MAX_LABEL_LENGTH:
            return UNKNOWN
        if self._provider_names is not None and text not in self._provider_names:
            return UNKNOWN
        return text

    def _log_metric_error(self, metric: str, exc: Exception) -> None:
        """Log a swallowed instrumentation failure by type only (never message)."""
        with suppress(Exception):  # pragma: no cover - logging must never raise either
            logger.warning(
                "metrics_record_failed",
                component="metrics",
                metric=metric,
                error_type=type(exc).__name__,
            )


__all__ = [
    "AUTO_CLOSE_OUTCOMES",
    "DECISION_ACTIONS",
    "DEDUPE_OUTCOMES",
    "DEGRADED_VALUES",
    "ENRICHMENT_STATUSES",
    "FEEDBACK_VERDICTS",
    "HTTP_METHODS",
    "INCIDENT_STATUSES",
    "INGEST_REJECT_REASONS",
    "N8N_OUTCOMES",
    "RISK_TIERS",
    "SWEEPER_RESULTS",
    "UNKNOWN",
    "UNMATCHED_ROUTE",
    "MetricsRegistry",
    "resolve_metrics",
]
