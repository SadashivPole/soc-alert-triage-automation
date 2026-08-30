"""Authentication for n8n callbacks (Phase 2B).

n8n workflows call back into the triage API (feedback, ack) using a shared
token. The token is verified with constant-time comparison to prevent timing
attacks. The same token is used for outbound notifications (service → n8n)
and inbound callbacks (n8n → service) — shared authentication token per
Phase 2B spec.

Accepted headers (in order):
* X-N8N-Token
* X-Callback-Token
* Authorization: Bearer <token>

Empty token configuration means the endpoint is disabled? No — for
defense-in-depth, if no token is configured, the endpoint returns 401 for
every request (fail-closed for callbacks, SECURITY.md §6).
"""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from ..core.config import Settings
from ..core.logging import get_logger

logger = get_logger("soc_triage.n8n_auth")


def _constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _extract_token(
    x_n8n_token: str | None,
    x_callback_token: str | None,
    authorization: str | None,
) -> str | None:
    """Extract token from one of the supported headers."""
    if x_n8n_token:
        return x_n8n_token.strip()
    if x_callback_token:
        return x_callback_token.strip()
    if authorization:
        # Bearer <token>
        auth = authorization.strip()
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return auth.strip()
    return None


def verify_n8n_token(
    request: Request,
    x_n8n_token: Annotated[str | None, Header(alias="X-N8N-Token")] = None,
    x_callback_token: Annotated[str | None, Header(alias="X-Callback-Token")] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> None:
    """Verify the shared n8n token for callback endpoints.

    Raises:
        HTTPException: 401 if missing or invalid, 503 if not configured.
    """
    settings: Settings = request.app.state.settings
    effective = settings.effective_n8n_token

    # If no token is configured, fail closed (callback auth required)
    if not effective:
        logger.warning(
            "n8n_auth_not_configured",
            component="n8n_auth",
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="n8n callback authentication not configured",
        )

    supplied = _extract_token(x_n8n_token, x_callback_token, authorization)

    if not supplied:
        logger.warning(
            "n8n_auth_failed",
            component="n8n_auth",
            reason="missing_token",
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing n8n token",
        )

    if not _constant_time_compare(supplied, effective):
        logger.warning(
            "n8n_auth_failed",
            component="n8n_auth",
            reason="invalid_token",
            path=request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid n8n token",
        )


RequireN8NToken = Depends(verify_n8n_token)

__all__ = ["RequireN8NToken", "verify_n8n_token"]
