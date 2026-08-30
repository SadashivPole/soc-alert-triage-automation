"""Alert ingestion endpoint: POST /api/v1/alerts/ingest.

Accepts Wazuh-shaped alert JSON, validates the schema, normalizes to the
canonical format, runs it through the deduplicator (Phase 1C), and returns the
canonical alert of record. This module is routing/orchestration only — all
deduplication logic lives in :mod:`soc_triage.ingest.deduplication`
(ARCHITECTURE.md §12: domain packages never import FastAPI).

Response contract (ARCHITECTURE.md §6, §16):

* New/recurring alert  → ``202`` ``{"status": "accepted", "duplicate": false, ...}``
* Exact duplicate      → ``200`` ``{"status": "duplicate", "duplicate": true, ...}``
  carrying the *original* ``alert_id`` and preserved canonical alert, so
  re-delivery is idempotent. Nothing is discarded: the duplicate delivery is
  counted (``dedupe.duplicate_deliveries``) and logged.

Based on ARCHITECTURE.md §6 and SECURITY.md §3.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ..core.errors import error_response
from ..core.logging import get_logger
from ..db.errors import StorageError
from ..ingest.auth import RequireApiKey
from ..ingest.deduplication import DedupeStatus, InvalidDedupeInputError
from ..ingest.normalizer import normalize_wazuh_alert
from ..ingest.schemas import WazuhAlert
from .dependencies import DeduplicatorDependency

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
    _: None = RequireApiKey,
) -> JSONResponse:
    """Ingest, validate, deduplicate, and normalize a single Wazuh alert.

    Returns:
        202 with the canonical alert (new or recurring within the window).
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

    # --- Normalize + deduplicate ---
    received_at = _utc_now()
    try:
        canonical = normalize_wazuh_alert(wazuh_alert, received_at=received_at)
        outcome = deduplicator.process(wazuh_alert, canonical, received_at)
    except InvalidDedupeInputError as exc:
        # Invalid identity inputs (e.g. blank rule/agent id): surface as a
        # validation error instead of guessing an identity.
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
        # The persistence layer failed (already rolled back, already logged
        # with context by the deduplicator). Per ARCHITECTURE.md §16, ingest
        # answers a *retryable* 503 — the Wazuh integrator buffers and
        # retries. No database internals are ever included in the response.
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

    return JSONResponse(
        status_code=(status.HTTP_200_OK if is_duplicate else status.HTTP_202_ACCEPTED),
        content={
            "status": "duplicate" if is_duplicate else "accepted",
            "duplicate": is_duplicate,
            "dedupe_status": outcome.status.value,
            "alert_id": str(outcome.alert_id),
            "received_at": received_at.isoformat(),
            "dedupe": outcome.dedupe.model_dump(mode="json"),
            "normalized": outcome.canonical_alert.model_dump(mode="json"),
        },
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
