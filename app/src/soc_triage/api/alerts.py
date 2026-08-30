"""Alert ingestion endpoint: POST /api/v1/alerts/ingest.

Accepts Wazuh-shaped alert JSON, validates the schema, normalizes to the
canonical format, and returns the normalized alert. Phase 1B implements
ingestion and validation only — persistence, deduplication, scoring, and
decision routing come in later phases.

Based on ARCHITECTURE.md §6 and SECURITY.md §3.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ..core.errors import error_response
from ..core.logging import get_logger
from ..ingest.auth import RequireApiKey
from ..ingest.normalizer import normalize_wazuh_alert
from ..ingest.schemas import WazuhAlert

logger = get_logger("soc_triage.ingest")

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

# Maximum request body size: 256 KiB (ARCHITECTURE.md §6, SECURITY.md §6)
MAX_BODY_SIZE = 256 * 1024


@router.post(
    "/ingest",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a Wazuh alert",
    description=(
        "Accept a Wazuh-shaped alert JSON payload, validate its schema, "
        "and normalize it to the canonical alert format. Requires X-API-Key "
        "authentication."
    ),
)
async def ingest_alert(
    request: Request,
    _: None = RequireApiKey,
) -> JSONResponse:
    """Ingest and validate a single Wazuh alert.

    Returns:
        202 with the normalized canonical alert (Phase 1B: no persistence yet).
        401 if the API key is missing or invalid.
        413 if the request body exceeds 256 KiB.
        422 if the payload fails schema validation.
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

    # --- Normalize ---
    received_at = datetime.now(UTC)
    canonical = normalize_wazuh_alert(wazuh_alert, received_at=received_at)

    logger.info(
        "alert_ingested",
        component="ingest",
        alert_id=str(canonical.alert_id),
        rule_id=canonical.source_event.rule.id,
        rule_level=canonical.source_event.rule.level,
        agent_name=canonical.source_event.agent.name,
    )

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "accepted",
            "alert_id": str(canonical.alert_id),
            "received_at": canonical.received_at.isoformat(),
            "normalized": canonical.model_dump(mode="json"),
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
    import json

    return json.loads(body)


__all__ = ["MAX_BODY_SIZE", "router"]
