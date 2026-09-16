"""Alert ingest + read APIs.

Ingest: POST /api/v1/alerts/ingest.
Read (Phase 3.3): GET /api/v1/alerts, GET /api/v1/alerts/{alert_id}.

Accepts Wazuh-shaped alert JSON, validates the schema, normalizes to the
canonical format, extracts IOCs and runs the enrichment chain (Phase 1E),
then deduplicates (Phase 1C), scores (Phase 1F), decides (Phase 1F) and
notifies n8n (Phase 2B).

This module is routing/orchestration only — deduplication lives in
:mod:`soc_triage.ingest.deduplication` and extraction/enrichment in
:mod:`soc_triage.enrichment` (ARCHITECTURE.md §12: domain packages never
import FastAPI).

IOC provenance is returned (canonical field path, source location, offset);
``full_log`` is never an extraction source by default and is never echoed by
this endpoint beyond the pre-existing ``normalized`` payload
(SECURITY.md §5, §7).

Response contract (ARCHITECTURE.md §6, §16):

* New/recurring alert  → ``202`` ``{"status": "accepted", "duplicate": false, ...}``
* Exact duplicate      → ``200`` ``{"status": "duplicate", "duplicate": true, ...}``
  carrying the *original* ``alert_id`` and preserved canonical alert, so
  re-delivery is idempotent. Nothing is discarded: the duplicate delivery is
  counted (``dedupe.duplicate_deliveries``) and logged.

Phase 2B: after scoring, the alert is notified to n8n via a structured
payload (no full_log, no secrets). n8n failure never corrupts or loses the
alert (fail-open, ARCHITECTURE.md §16).

Based on ARCHITECTURE.md §6 and SECURITY.md §3.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Annotated, Any, NamedTuple
from uuid import UUID

from fastapi import APIRouter, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from ..audit import (
    audit_entries_for_assessment,
    audit_entries_for_incident,
    audit_entries_for_notification,
)
from ..core.errors import error_response
from ..core.logging import get_logger
from ..core.metrics import MetricsRegistry, resolve_metrics
from ..db.errors import StorageError
from ..db.session import session_scope
from ..enrichment import EnrichmentContext, extract_iocs
from ..enrichment.asset_inventory import apply_asset_inventory
from ..ingest.auth import RequireApiKey
from ..ingest.deduplication import DedupeStatus, InvalidDedupeInputError
from ..ingest.normalizer import normalize_wazuh_alert
from ..ingest.schemas import WazuhAlert
from ..models.assessment import Decision, DecisionAction, RiskAssessment
from ..models.canonical import CanonicalAlert
from ..models.records import DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT
from ..models.repositories import (
    AlertRepository,
    AuditRepository,
    CorrelationRepository,
    IncidentRepository,
    NotificationRepository,
)
from ..notifications import build_n8n_payload
from .dependencies import (
    AssetInventoryDependency,
    CorrelatorDependency,
    DeciderDependency,
    DeduplicatorDependency,
    EnrichmentChainDependency,
    N8NClientDependency,
    ScorerDependency,
    SessionFactoryDependency,
    SettingsDependency,
)
from .n8n_auth import RequireN8NToken
from .schemas import (
    AlertDetail,
    AlertListResponse,
    CorrelationContextDetailRead,
    alert_detail_from_record,
    alert_summary_from_record,
    correlation_detail_from_records,
    make_pagination,
)

logger = get_logger("soc_triage.ingest")

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

# Maximum request body size: 256 KiB (ARCHITECTURE.md §6, SECURITY.md §6)
MAX_BODY_SIZE = 256 * 1024


def _utc_now() -> datetime:
    """Reception clock; patched in tests to exercise window expiry."""
    return datetime.now(UTC)


def _monotonic() -> float:
    """Monotonic clock for ingest processing timing (Phase 3.7, D6).

    Isolated like :func:`_utc_now` so tests can inject a deterministic,
    non-wall-clock timeline without affecting the HTTP middleware's own
    clock or any other ``time`` consumer.
    """
    return time.perf_counter()


class _AssessmentPersistResult(NamedTuple):
    """Outcome of one assessment persistence attempt (Phase 3.7, D7).

    ``persisted`` is True only when the score/decision/audit/incident writes
    committed atomically; ``incident_id`` is the durable incident id when an
    incident applies (``None`` otherwise — including a failed persistence).
    """

    incident_id: str | None
    persisted: bool


@router.post(
    "/ingest",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a Wazuh alert",
    description=(
        "Accept a Wazuh-shaped alert JSON payload, validate its schema, "
        "normalize it to the canonical alert format, and deduplicate it. "
        "Exact duplicate deliveries are idempotent: they respond 200 with the "
        "original alert_id and duplicate=true. Requires X-API-Key authentication."
    ),
)
async def ingest_alert(
    request: Request,
    deduplicator: DeduplicatorDependency,
    enrichment_chain: EnrichmentChainDependency,
    asset_inventory: AssetInventoryDependency,
    scorer: ScorerDependency,
    decider: DeciderDependency,
    correlator: CorrelatorDependency,
    session_factory: SessionFactoryDependency,
    settings: SettingsDependency,
    n8n_client: N8NClientDependency,
    _: None = RequireApiKey,
) -> JSONResponse:
    """Ingest, validate, extract IOCs, deduplicate, score, decide and notify n8n.

    Returns:
        202 with the canonical alert (new or recurring within the window),
        including its deterministic risk score and routing decision.
        200 with the preserved original alert when the delivery is an exact
        duplicate (idempotent response, ``duplicate: true``).
        401 if the API key is missing or invalid.
        413 if the request body exceeds 256 KiB.
        422 if the payload fails schema validation or identity validation.
    """
    # Phase 3.7 (D6): app-scoped ingest metrics. resolve_metrics returns None
    # when METRICS_ENABLED=false, so all instrumentation below is skipped
    # without touching pipeline behavior (ADR-9).
    ingest_metrics = resolve_metrics(request.app)

    # --- Body size guard ---
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_SIZE:
                if ingest_metrics is not None:
                    ingest_metrics.record_ingest_rejection("payload_too_large")
                return error_response(
                    status.HTTP_413_CONTENT_TOO_LARGE,
                    "payload_too_large",
                    f"request body exceeds {MAX_BODY_SIZE} bytes",
                )
        except ValueError:
            pass

    # Read the raw body with a size cap
    body = await _read_body_with_limit(request, MAX_BODY_SIZE)
    if body is None:
        if ingest_metrics is not None:
            ingest_metrics.record_ingest_rejection("payload_too_large")
        return error_response(
            status.HTTP_413_CONTENT_TOO_LARGE,
            "payload_too_large",
            f"request body exceeds {MAX_BODY_SIZE} bytes",
        )

    # --- Parse JSON ---
    try:
        raw_payload: Any = await _parse_json(body)
    except Exception:
        if ingest_metrics is not None:
            ingest_metrics.record_ingest_rejection("malformed_json")
        return error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "request body is not valid JSON",
        )

    # --- Schema validation ---
    try:
        wazuh_alert = WazuhAlert.model_validate(raw_payload)
    except ValidationError as exc:
        logger.info(
            "alert_validation_failed",
            component="ingest",
            error_count=len(exc.errors()),
        )
        if ingest_metrics is not None:
            ingest_metrics.record_ingest_rejection("schema_invalid")
        return error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "alert schema validation failed",
            details=exc.errors(),
        )

    # --- Ingest metrics: accepted boundary (Phase 3.7, D6) ---
    # The measured processing path starts after the body-size / JSON / schema
    # guards pass, spans normalize → extract → enrich → dedupe → assess
    # (score/decide/persist for new/repeated; incident lookup for exact
    # duplicates), and stops BEFORE the fail-open n8n notification step
    # (tracked separately). Rejected requests never produce a processing
    # observation. Monotonic clock only (see _monotonic).
    processing_started = _monotonic()

    # --- Normalize → extract IOCs → enrich → deduplicate ---
    received_at = _utc_now()
    try:
        canonical = normalize_wazuh_alert(
            wazuh_alert,
            received_at=received_at,
        )

        # Phase 2.2: optional static asset inventory is applied after
        # normalization and before IOC extraction/enrichment. It is
        # fill-only: source-derived canonical values always win.
        canonical = apply_asset_inventory(canonical, asset_inventory)

        iocs = extract_iocs(canonical)
        enrichment = enrichment_chain.enrich(
            iocs,
            context=EnrichmentContext(
                alert_id=canonical.alert_id,
                source=canonical.source,
                received_at=received_at,
            ),
        )
        # --- Phase 3.7 (D8): enrichment metrics at the chain's semantic
        # outcome boundary ---
        # Exactly one alert-level status per returned EnrichmentOutcome and
        # exactly one provider outcome per ProviderOutcome the chain returned
        # (one per registered provider, including disabled/skipped ones; the
        # chain never raises — provider failures are folded into the outcome).
        # Provider labels pass through the D2 registered-name allowlist, so
        # unknown names collapse to the fixed fallback and never create new
        # series. Helpers are non-raising (ADR-9) and never read back.
        if ingest_metrics is not None:
            ingest_metrics.record_enrichment_status(enrichment.status.value)
            for provider_outcome in enrichment.providers:
                ingest_metrics.record_enrichment_provider_outcome(
                    provider=provider_outcome.provider,
                    status=provider_outcome.status.value,
                )
        canonical = canonical.model_copy(
            update={
                "iocs": list(enrichment.iocs),
                "enrichment_status": enrichment.status.value,
            }
        )
        outcome = deduplicator.process(wazuh_alert, canonical, received_at)
    except InvalidDedupeInputError as exc:
        if ingest_metrics is not None:
            ingest_metrics.record_ingest_rejection("identity_invalid")
        logger.info(
            "alert_identity_validation_failed",
            component="ingest",
            reason=str(exc),
        )
        return error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "alert identity validation failed",
            details={"reason": str(exc)},
        )
    except StorageError:
        if ingest_metrics is not None:
            ingest_metrics.record_ingest_rejection("storage_unavailable")
        logger.warning(
            "ingest_storage_unavailable",
            component="ingest",
            rule_id=wazuh_alert.rule.id,
            agent_id=wazuh_alert.agent.id,
        )
        return error_response(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "service_unavailable",
            "ingest temporarily unavailable; retry",
        )

    is_duplicate = outcome.status is DedupeStatus.EXACT_DUPLICATE
    recorded_iocs = outcome.canonical_alert.iocs

    # --- Score & decide (Phase 1F) ---
    incident_id: str | None = None
    correlation_context_id: str | None = None
    if is_duplicate:
        assessed = outcome.canonical_alert
        # Exact duplicates never re-score or create incidents; echo the
        # incident the original alert belongs to (if any).
        incident_id = _incident_for_alert(session_factory, outcome.alert_id)
        # Same idempotent echo for the correlation context: the original
        # alert's membership is surfaced, never re-created or extended.
        correlation_context_id = _correlation_context_for_alert(session_factory, outcome.alert_id)
    else:
        risk = scorer.score(outcome.canonical_alert)
        decision = decider.decide(risk, alert=outcome.canonical_alert, decided_at=received_at)
        assessed = outcome.canonical_alert.model_copy(update={"risk": risk, "decision": decision})
        persist_result = _persist_assessment(
            session_factory,
            alert_id=outcome.alert_id,
            canonical=assessed,
            risk=risk,
            decision=decision,
            dedupe_group_key=outcome.group_key,
            occurred_at=received_at,
        )
        incident_id = persist_result.incident_id
        # --- Cross-alert correlation (Phase 6.4) — fail-open, read-only
        # w.r.t. the alert of record: groups this distinct alert with
        # window-bounded peers that share deterministic evidence into one
        # investigation context. Never runs for exact duplicates, never
        # touches dedupe/incident state, and can never fail the ingest.
        correlation_context_id = _correlate_alert(
            correlator, alert_id=outcome.alert_id, received_at=received_at
        )
        logger.info(
            "alert_scored",
            component="scoring",
            alert_id=str(outcome.alert_id),
            score=risk.score,
            tier=risk.tier.value,
            decision=decision.action.value,
            degraded=risk.degraded,
        )
        # --- Phase 3.7 (D7): scoring/decision metric ---
        # Recorded exactly once per newly scored+decided alert, only after the
        # score/decision are final AND the assessment transaction committed
        # (persist_result.persisted). Labels are the domain enum values;
        # degraded is the existing RiskAssessment.degraded flag — the
        # rule-severity-only engine fallback (ARCHITECTURE.md §16), never a
        # re-interpretation of enrichment status. Exact duplicates never reach
        # this branch, so they can never create a phantom scored event. The
        # D2 helper is non-raising (ADR-9) and never read back into the
        # pipeline.
        if ingest_metrics is not None and persist_result.persisted:
            ingest_metrics.record_alert_scored(
                tier=risk.tier.value,
                decision=decision.action.value,
                degraded=risk.degraded,
            )

    # --- Ingest metrics: outcome + duration once per accepted attempt ---
    # Exactly one alerts_processed increment with the dedupe outcome value
    # (new_generation / repeated / exact_duplicate) and exactly one processing
    # duration observation; recorded only after the outcome is known and the
    # assess step completed, before the fail-open notification. The D2 record
    # helpers are non-raising (ADR-9) and never read back into the pipeline.
    if ingest_metrics is not None:
        ingest_metrics.observe_alert_processing(_monotonic() - processing_started)
        ingest_metrics.record_alerts_processed(outcome.status.value)

    logger.info(
        "iocs_extracted",
        component="enrichment",
        alert_id=str(outcome.alert_id),
        ioc_count=len(recorded_iocs),
        ioc_types=sorted({ioc.type.value for ioc in recorded_iocs}),
        enrichment_status=enrichment.status.value,
    )
    logger.info(
        "alert_ingested",
        component="ingest",
        alert_id=str(outcome.alert_id),
        rule_id=wazuh_alert.rule.id,
        rule_level=wazuh_alert.rule.level,
        agent_id=wazuh_alert.agent.id,
        agent_name=wazuh_alert.agent.name,
        dedupe_group=outcome.group_key,
        dedupe_status=outcome.status.value,
        duplicate=is_duplicate,
        occurrences=outcome.dedupe.occurrences,
        duplicate_deliveries=outcome.dedupe.duplicate_deliveries,
    )

    # --- n8n notification (Phase 2B) — fail-open, never blocks ingest ---
    notification_result = None
    if not is_duplicate:
        try:
            # Build investigation base URL from settings when possible (host/port)
            # 0.0.0.0 is replaced with localhost for link generation
            host = settings.triage_api_host
            if host == "0.0.0.0":
                host = "localhost"
            base_url = f"http://{host}:{settings.triage_api_port}"
            notification_result = _notify_n8n(
                session_factory=session_factory,
                n8n_client=n8n_client,
                alert=assessed,
                dedupe_status=outcome.status.value,
                received_at=received_at,
                investigation_base_url=base_url,
                metrics=ingest_metrics,
            )
        except Exception as exc:  # defensive: notification must never crash ingest
            logger.error(
                "n8n_notification_unexpected_error",
                component="notifications",
                alert_id=str(outcome.alert_id),
                error_type=type(exc).__name__,
            )
            notification_result = None
    else:
        logger.info(
            "n8n_notification_skipped_duplicate",
            component="notifications",
            alert_id=str(outcome.alert_id),
            reason="exact_duplicate",
        )

    return JSONResponse(
        status_code=(status.HTTP_200_OK if is_duplicate else status.HTTP_202_ACCEPTED),
        content={
            "status": "duplicate" if is_duplicate else "accepted",
            "duplicate": is_duplicate,
            "dedupe_status": outcome.status.value,
            "alert_id": str(outcome.alert_id),
            "received_at": received_at.isoformat(),
            "dedupe": outcome.dedupe.model_dump(mode="json"),
            "iocs": [ioc.model_dump(mode="json") for ioc in recorded_iocs],
            "enrichment_status": enrichment.status.value,
            "risk": assessed.risk.model_dump(mode="json") if assessed.risk else None,
            "decision": assessed.decision.model_dump(mode="json") if assessed.decision else None,
            "incident_id": incident_id,
            "correlation_context_id": correlation_context_id,
            "normalized": assessed.model_dump(mode="json"),
            "notification": (
                {
                    "attempted": notification_result.attempted,
                    "delivered": notification_result.delivered,
                    "skipped": notification_result.skipped,
                    "status_code": notification_result.status_code,
                    "attempts": notification_result.attempts,
                }
                if notification_result
                else None
            ),
        },
    )


def _notify_n8n(
    *,
    session_factory: sessionmaker,
    n8n_client: Any,
    alert: CanonicalAlert,
    dedupe_status: str,
    received_at: datetime,
    investigation_base_url: str | None = None,
    metrics: MetricsRegistry | None = None,
) -> Any:
    """Notify n8n with duplicate prevention, persistence and audit (fail-open).

    Returns the :class:`NotificationResult` or None if notification is disabled.
    Never raises — failures are logged and audited, but the alert itself is
    already durable.

    Phase 3.7 (D9): the notification outcome metric is recorded at the exact
    points where the business outcome is already final — the explicit
    duplicate-suppression decision and the client's aggregated send result
    (retries are folded into one result by the client, so one attempt yields
    one outcome). The duration histogram observes only actual send attempts
    (``result.attempted``), using the client's monotonic elapsed milliseconds.
    Helpers are non-raising (ADR-9) and never read back into the pipeline.
    """
    from ..notifications.client import NotificationResult

    # Duplicate prevention: if this alert_id already delivered, skip
    suppressed_result: NotificationResult | None = None
    try:
        with session_scope(session_factory) as session:
            notif_repo = NotificationRepository(session)
            if notif_repo.has_delivered(alert.alert_id):
                logger.info(
                    "n8n_notification_duplicate_suppressed",
                    component="notifications",
                    alert_id=str(alert.alert_id),
                )
                # Audit duplicate suppression
                audit_repo = AuditRepository(session)

                result = NotificationResult(
                    alert_id=str(alert.alert_id),
                    attempted=False,
                    delivered=False,
                    skipped=True,
                    status_code=None,
                    error_type=None,
                    attempts=0,
                    duration_ms=0,
                    webhook_host=None,
                    payload_hash="duplicate",
                )
                audit_repo.append(
                    audit_entries_for_notification(
                        alert.alert_id,
                        status="skipped",
                        payload_hash="duplicate",
                        duplicate_suppressed=True,
                    ),
                    occurred_at=received_at,
                )
                suppressed_result = result
    except Exception as exc:
        # If duplicate check fails, proceed to attempt notification anyway
        # (fail-open for the check itself)
        logger.warning(
            "n8n_duplicate_check_failed",
            component="notifications",
            alert_id=str(alert.alert_id),
            error_type=type(exc).__name__,
        )
    else:
        # The suppression transaction committed above, so the decision is
        # final — record exactly once at this boundary. A commit failure
        # lands in the except branch and proceeds to send instead (fail-open).
        if suppressed_result is not None:
            if metrics is not None:
                metrics.record_n8n_notification("duplicate_suppressed")
            return suppressed_result

    # Build payload (pure, no I/O) — investigation base from settings if available
    try:
        payload = build_n8n_payload(
            alert,
            dedupe_status=dedupe_status,
            investigation_base_url=investigation_base_url,
        )
    except Exception as exc:
        logger.warning(
            "n8n_payload_build_failed",
            component="notifications",
            alert_id=str(alert.alert_id),
            error_type=type(exc).__name__,
        )
        return None

    # Send (with retry, timeout — client handles fail-open). The client
    # aggregates all retries into one NotificationResult, so this is exactly
    # one semantic notification attempt.
    result = n8n_client.send(payload)
    if metrics is not None:
        if result.delivered:
            metrics.record_n8n_notification("delivered")
        elif result.skipped:
            metrics.record_n8n_notification("skipped")
        else:
            metrics.record_n8n_notification("failed")
        if result.attempted:
            # The client measures the whole attempt (incl. retries) with a
            # monotonic clock; convert the integer milliseconds to seconds.
            metrics.observe_n8n_notification(result.duration_ms / 1000.0)

    # Persist attempt + audit (best-effort, never crash ingest)
    try:
        with session_scope(session_factory) as session:
            NotificationRepository(session).record(result, occurred_at=received_at)
            AuditRepository(session).append(
                audit_entries_for_notification(
                    alert.alert_id,
                    status="delivered"
                    if result.delivered
                    else ("skipped" if result.skipped else "failed"),
                    http_status=result.status_code,
                    error_type=result.error_type,
                    attempts=result.attempts,
                    payload_hash=result.payload_hash,
                    webhook_host=result.webhook_host,
                    duration_ms=result.duration_ms,
                ),
                occurred_at=received_at,
            )
    except SQLAlchemyError as exc:
        logger.error(
            "n8n_notification_persistence_failed",
            component="notifications",
            alert_id=str(alert.alert_id),
            error_type=type(exc).__name__,
        )
    except Exception as exc:
        logger.error(
            "n8n_notification_audit_failed",
            component="notifications",
            alert_id=str(alert.alert_id),
            error_type=type(exc).__name__,
        )

    return result


def _persist_assessment(
    session_factory: sessionmaker,
    *,
    alert_id: UUID,
    canonical: CanonicalAlert,
    risk: RiskAssessment,
    decision: Decision,
    dedupe_group_key: str,
    occurred_at: datetime,
) -> _AssessmentPersistResult:
    """Persist a scored alert's assessment + audit entries (best-effort).

    Phase 3.1 — incident handling: when the decision is ``open_incident`` the
    alert is linked to an incident *in the same transaction* as the
    assessment/audit writes:

    * no open incident for the dedupe group ⇒ create one (SEV1 for critical /
      SEV2 for high, ``status=open``, ``INC-YYYY-MM-DD-NNNN``) and append an
      ``incident.created`` audit entry;
    * an open incident already exists for the group (recurring/deduplicated
      alert) ⇒ attach this alert to it, no second incident, no duplicate.

    Returns an :class:`_AssessmentPersistResult` carrying the durable
    incident id (``None`` when no incident applies) and a ``persisted`` flag
    that is True only when the transaction committed. A persistence failure is
    logged and reported as ``persisted=False`` (the transaction is rolled
    back atomically; the caller stays fail-open, ARCHITECTURE.md §16).
    """
    incident_id: str | None = None
    incident_action: str | None = None
    severity: str | None = None
    try:
        with session_scope(session_factory) as session:
            AlertRepository(session).update_normalized_payload(alert_id, canonical)
            AuditRepository(session).append(
                audit_entries_for_assessment(alert_id, risk=risk, decision=decision),
                occurred_at=occurred_at,
            )
            if decision.action is DecisionAction.OPEN_INCIDENT:
                incident_repo = IncidentRepository(session)
                existing = incident_repo.open_for_group(dedupe_group_key)
                if existing is None:
                    # Policy validation guarantees a severity for open_incident.
                    if decision.severity is None:  # pragma: no cover - defensive
                        raise ValueError("open_incident decision is missing a severity")
                    incident = incident_repo.create(
                        alert_id=alert_id,
                        severity=decision.severity,
                        dedupe_group_key=dedupe_group_key,
                        occurred_at=occurred_at,
                    )
                    incident_id = incident.incident_id
                    severity = incident.severity.value
                    incident_action = "created"
                    AuditRepository(session).append(
                        audit_entries_for_incident(incident), occurred_at=occurred_at
                    )
                else:
                    incident_repo.attach(alert_id=alert_id, incident_id=existing.incident_id)
                    incident_id = existing.incident_id
                    severity = existing.severity.value
                    incident_action = "attached_existing"
        # Only report the incident once the transaction committed: a rollback
        # must never leak a not-yet-durable incident id into the response.
        if incident_id is not None:
            logger.info(
                "incident_created"
                if incident_action == "created"
                else "incident_attached_existing",
                component="incidents",
                incident_id=incident_id,
                alert_id=str(alert_id),
                severity=severity,
                dedupe_group_key=dedupe_group_key,
            )
    except SQLAlchemyError as exc:
        logger.error(
            "assessment_persistence_failed",
            component="scoring",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return _AssessmentPersistResult(incident_id=None, persisted=False)
    return _AssessmentPersistResult(incident_id=incident_id, persisted=True)


def _incident_for_alert(session_factory: sessionmaker, alert_id: UUID) -> str | None:
    """Best-effort lookup of the incident an alert is attached to (Phase 3.1)."""
    try:
        with session_scope(session_factory) as session:
            incident = IncidentRepository(session).for_alert(alert_id)
            return incident.incident_id if incident is not None else None
    except SQLAlchemyError as exc:
        logger.warning(
            "incident_lookup_failed",
            component="incidents",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return None


def _correlation_context_for_alert(session_factory: sessionmaker, alert_id: UUID) -> str | None:
    """Best-effort lookup of the correlation context an alert belongs to.

    Used on the idempotent exact-duplicate path (mirroring
    :func:`_incident_for_alert`): the original alert's membership is echoed,
    never re-created.
    """
    try:
        with session_scope(session_factory) as session:
            context = CorrelationRepository(session).context_for_alert(alert_id)
            return context.context_id if context is not None else None
    except SQLAlchemyError as exc:
        logger.warning(
            "correlation_lookup_failed",
            component="correlation",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return None


def _correlate_alert(correlator: Any, *, alert_id: UUID, received_at: datetime) -> str | None:
    """Correlate a newly recorded alert (Phase 6.4, strictly fail-open).

    Returns the investigation context id the alert joined, or ``None`` when
    no qualifying evidence exists (the normal case). A correlation failure
    is logged with the exception type only and swallowed — the alert itself
    is already durable and dedupe/incident state is untouched, so
    correlation can never reject or corrupt an ingest
    (ARCHITECTURE.md §16).
    """
    try:
        result = correlator.correlate(alert_id=alert_id, received_at=received_at)
    except Exception as exc:  # defensive: correlation must never crash ingest
        logger.error(
            "correlation_failed",
            component="correlation",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return None
    return result.context_id if result is not None else None


async def _read_body_with_limit(request: Request, max_size: int) -> bytes | None:
    """Read the request body, returning None if it exceeds the size limit."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_size:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def _parse_json(body: bytes) -> Any:
    """Parse a JSON body from raw bytes."""
    return json.loads(body)


# ---------------------------------------------------------------------------
# Phase 3.3 — read APIs (GET is strictly read-only: no audit writes, no
# incident transitions, no n8n/Wazuh/intel/LLM calls).
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=AlertListResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
@router.get(
    "",
    response_model=AlertListResponse,
    status_code=status.HTTP_200_OK,
    summary="List persisted alerts",
    description=(
        "Return a newest-first page of analyst-safe alert summaries. "
        "Filters are simple equality matches on fields already stored "
        "(source, incident_id, rule_id, agent_id, risk tier, decision "
        "severity, dedupe_group_key, duplicate-absorbed). Requires the "
        "shared N8N token (same analyst channel as feedback). "
        "A dedicated analyst/read token is deferred to the console milestone."
    ),
)
async def list_alerts(
    session_factory: SessionFactoryDependency,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_LIMIT)] = DEFAULT_PAGE_LIMIT,
    offset: Annotated[int, Query(ge=0)] = 0,
    source: Annotated[str | None, Query()] = None,
    incident_id: Annotated[str | None, Query()] = None,
    rule_id: Annotated[str | None, Query()] = None,
    agent_id: Annotated[str | None, Query()] = None,
    tier: Annotated[str | None, Query(description="Risk tier")] = None,
    severity: Annotated[str | None, Query(description="Decision severity (SEV1/SEV2)")] = None,
    dedupe_group_key: Annotated[str | None, Query()] = None,
    duplicate: Annotated[bool | None, Query()] = None,
    _: None = RequireN8NToken,
) -> AlertListResponse | JSONResponse:
    """List persisted alerts (paginated, filtered, no raw logs)."""
    try:
        with session_scope(session_factory) as session:
            items, total = AlertRepository(session).list_alerts(
                source=source,
                incident_id=incident_id,
                rule_id=rule_id,
                agent_id=agent_id,
                tier=tier,
                severity=severity,
                dedupe_group_key=dedupe_group_key,
                duplicate=duplicate,
                limit=limit,
                offset=offset,
            )
            response = AlertListResponse(
                items=[alert_summary_from_record(item) for item in items],
                pagination=make_pagination(limit=limit, offset=offset, total=total),
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "alert_list_failed",
            component="alerts",
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list alerts",
        )
    logger.info(
        "alerts_listed",
        component="alerts",
        count=len(response.items),
        total=total,
        limit=limit,
        offset=offset,
    )
    return response


@router.get(
    "/{alert_id}",
    response_model=AlertDetail,
    status_code=status.HTTP_200_OK,
    summary="Get a persisted alert",
    description=(
        "Return an analyst-safe alert representation (identity, rule/agent, "
        "risk/decision, dedupe, incident linkage, IOC summaries). Never "
        "includes full_log, credentials, or tokens. Unknown ids return a "
        "structured 404. Requires the shared N8N token."
    ),
)
async def get_alert(
    session_factory: SessionFactoryDependency,
    alert_id: Annotated[UUID, Path(description="Alert ID")],
    _: None = RequireN8NToken,
) -> AlertDetail | JSONResponse:
    """Return one persisted alert, or a structured 404."""
    try:
        with session_scope(session_factory) as session:
            record = AlertRepository(session).get_alert(alert_id)
            if record is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"alert {alert_id} not found",
                )
            detail = alert_detail_from_record(record)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "alert_get_failed",
            component="alerts",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load alert",
        )
    logger.info("alert_read", component="alerts", alert_id=str(alert_id))
    return detail


@router.get(
    "/{alert_id}/correlation",
    response_model=CorrelationContextDetailRead,
    status_code=status.HTTP_200_OK,
    summary="Get the correlation context an alert belongs to",
    description=(
        "Return the cross-alert investigation context this alert is a member "
        "of (member summaries, pairwise + aggregated evidence, time span). "
        "An uncorrelated alert returns a structured 404. Read-only — never "
        "includes full_log, credentials, or tokens, and never mutates "
        "incident or dedupe state. Requires the shared N8N token."
    ),
)
async def get_alert_correlation(
    session_factory: SessionFactoryDependency,
    alert_id: Annotated[UUID, Path(description="Alert ID")],
    _: None = RequireN8NToken,
) -> CorrelationContextDetailRead | JSONResponse:
    """Return the alert's correlation context, or a structured 404."""
    try:
        with session_scope(session_factory) as session:
            repo = CorrelationRepository(session)
            context = repo.context_for_alert(alert_id)
            if context is None:
                return error_response(
                    status.HTTP_404_NOT_FOUND,
                    "not_found",
                    f"alert {alert_id} is not part of a correlation context",
                )
            members = repo.members(context.context_id)
            detail = correlation_detail_from_records(context, members)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "alert_correlation_get_failed",
            component="correlations",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )
        return error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to load alert correlation context",
        )
    logger.info(
        "alert_correlation_read",
        component="correlations",
        alert_id=str(alert_id),
        context_id=detail.context_id,
    )
    return detail


__all__ = ["MAX_BODY_SIZE", "router"]
