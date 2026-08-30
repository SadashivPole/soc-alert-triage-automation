"""Alert ingestion endpoint: POST /api/v1/alerts/ingest.

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
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from ..audit import audit_entries_for_assessment, audit_entries_for_notification
from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.errors import StorageError
from ..db.session import session_scope
from ..enrichment import EnrichmentContext, extract_iocs
from ..ingest.auth import RequireApiKey
from ..ingest.deduplication import DedupeStatus, InvalidDedupeInputError
from ..ingest.normalizer import normalize_wazuh_alert
from ..ingest.schemas import WazuhAlert
from ..models.assessment import Decision, RiskAssessment
from ..models.canonical import CanonicalAlert
from ..models.repositories import (
    AlertRepository,
    AuditRepository,
    NotificationRepository,
)
from ..notifications import build_n8n_payload
from .dependencies import (
    DeciderDependency,
    DeduplicatorDependency,
    EnrichmentChainDependency,
    N8NClientDependency,
    ScorerDependency,
    SessionFactoryDependency,
    SettingsDependency,
)

logger = get_logger("soc_triage.ingest")

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

# Maximum request body size: 256 KiB (ARCHITECTURE.md §6, SECURITY.md §6)
MAX_BODY_SIZE = 256 * 1024


def _utc_now() -> datetime:
    """Reception clock; patched in tests to exercise window expiry."""
    return datetime.now(UTC)


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
    scorer: ScorerDependency,
    decider: DeciderDependency,
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
    # --- Body size guard ---
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_SIZE:
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
        return error_response(
            status.HTTP_413_CONTENT_TOO_LARGE,
            "payload_too_large",
            f"request body exceeds {MAX_BODY_SIZE} bytes",
        )

    # --- Parse JSON ---
    try:
        raw_payload: Any = await _parse_json(body)
    except Exception:
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
        return error_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "alert schema validation failed",
            details=exc.errors(),
        )

    # --- Normalize → extract IOCs → enrich → deduplicate ---
    received_at = _utc_now()
    try:
        canonical = normalize_wazuh_alert(wazuh_alert, received_at=received_at)
        iocs = extract_iocs(canonical)
        enrichment = enrichment_chain.enrich(
            iocs,
            context=EnrichmentContext(
                alert_id=canonical.alert_id,
                source=canonical.source,
                received_at=received_at,
            ),
        )
        canonical = canonical.model_copy(
            update={
                "iocs": list(enrichment.iocs),
                "enrichment_status": enrichment.status.value,
            }
        )
        outcome = deduplicator.process(wazuh_alert, canonical, received_at)
    except InvalidDedupeInputError as exc:
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
    if is_duplicate:
        assessed = outcome.canonical_alert
    else:
        risk = scorer.score(outcome.canonical_alert)
        decision = decider.decide(risk, alert=outcome.canonical_alert, decided_at=received_at)
        assessed = outcome.canonical_alert.model_copy(update={"risk": risk, "decision": decision})
        _persist_assessment(
            session_factory,
            alert_id=outcome.alert_id,
            canonical=assessed,
            risk=risk,
            decision=decision,
            occurred_at=received_at,
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
) -> Any:
    """Notify n8n with duplicate prevention, persistence and audit (fail-open).

    Returns the :class:`NotificationResult` or None if notification is disabled.
    Never raises — failures are logged and audited, but the alert itself is
    already durable.
    """
    from ..notifications.client import NotificationResult

    # Duplicate prevention: if this alert_id already delivered, skip
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
                return result
    except Exception as exc:
        # If duplicate check fails, proceed to attempt notification anyway
        # (fail-open for the check itself)
        logger.warning(
            "n8n_duplicate_check_failed",
            component="notifications",
            alert_id=str(alert.alert_id),
            error_type=type(exc).__name__,
        )

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

    # Send (with retry, timeout — client handles fail-open)
    result = n8n_client.send(payload)

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
    occurred_at: datetime,
) -> None:
    """Persist a scored alert's assessment + audit entries (best-effort)."""
    try:
        with session_scope(session_factory) as session:
            AlertRepository(session).update_normalized_payload(alert_id, canonical)
            AuditRepository(session).append(
                audit_entries_for_assessment(alert_id, risk=risk, decision=decision),
                occurred_at=occurred_at,
            )
    except SQLAlchemyError as exc:
        logger.error(
            "assessment_persistence_failed",
            component="scoring",
            alert_id=str(alert_id),
            error_type=type(exc).__name__,
        )


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


__all__ = ["MAX_BODY_SIZE", "router"]
