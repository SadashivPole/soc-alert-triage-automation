"""X-API-Key authentication for the ingest endpoint.

Uses constant-time comparison to prevent timing attacks. The API key is
read from the ``X-API-Key`` header and compared against the configured
``TRIAGE_INGEST_API_KEY`` secret.

Based on ARCHITECTURE.md §6 and SECURITY.md §3.
"""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from ..core.config import Settings
from ..core.logging import get_logger
from ..core.metrics import resolve_metrics

logger = get_logger("soc_triage.auth")


def _constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def verify_api_key(
    request: Request,
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    """Verify the X-API-Key header against the configured ingest key.

    Raises:
        HTTPException: 401 if the key is missing or invalid.
    """
    settings: Settings = request.app.state.settings
    # Phase 3.7 (D6): exactly one auth_failed rejection per rejected request,
    # recorded at the actual rejection boundary (not in exception handlers —
    # no double counting through layers). Metrics stay non-load-bearing.
    metrics = resolve_metrics(request.app)

    if not x_api_key:
        if metrics is not None:
            metrics.record_ingest_rejection("auth_failed")
        logger.warning(
            "auth_failed",
            component="auth",
            reason="missing_api_key",
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing API key",
        )

    expected_key = settings.triage_ingest_api_key.get_secret_value()

    if not _constant_time_compare(x_api_key, expected_key):
        if metrics is not None:
            metrics.record_ingest_rejection("auth_failed")
        logger.warning(
            "auth_failed",
            component="auth",
            reason="invalid_api_key",
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid API key",
        )


# FastAPI dependency alias for cleaner route signatures
RequireApiKey = Depends(verify_api_key)


__all__ = ["RequireApiKey", "verify_api_key"]
