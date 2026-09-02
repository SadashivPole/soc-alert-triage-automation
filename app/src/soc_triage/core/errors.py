"""Error-handling foundation: a consistent JSON error envelope.

Handlers translate framework exceptions into a stable shape:

.. code-block:: json

    {"error": {"code": "not_found", "message": "Not Found"}}
"""

from __future__ import annotations

from typing import Any, cast

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

logger = structlog.get_logger("soc_triage.errors")

_STATUS_CODES = {
    status.HTTP_400_BAD_REQUEST: "bad_request",
    status.HTTP_401_UNAUTHORIZED: "unauthorized",
    status.HTTP_403_FORBIDDEN: "forbidden",
    status.HTTP_404_NOT_FOUND: "not_found",
    status.HTTP_405_METHOD_NOT_ALLOWED: "method_not_allowed",
    status.HTTP_409_CONFLICT: "conflict",
    status.HTTP_413_CONTENT_TOO_LARGE: "payload_too_large",
    status.HTTP_422_UNPROCESSABLE_CONTENT: "validation_error",
    status.HTTP_429_TOO_MANY_REQUESTS: "rate_limited",
    status.HTTP_500_INTERNAL_SERVER_ERROR: "internal_error",
    status.HTTP_503_SERVICE_UNAVAILABLE: "service_unavailable",
}


def _code_for_status(status_code: int) -> str:
    """Map an HTTP status to a stable, machine-readable error code."""
    return _STATUS_CODES.get(status_code, "http_error")


def error_response(
    status_code: int,
    code: str,
    message: str,
    *,
    details: Any | None = None,
) -> JSONResponse:
    """Build a JSON error envelope with no stack traces or internal details."""
    payload: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details is not None:
        payload["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=payload)


async def http_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Render every HTTP exception through the shared error envelope."""
    http_exc = cast(HTTPException, exc)
    return error_response(
        http_exc.status_code, _code_for_status(http_exc.status_code), str(http_exc.detail)
    )


async def validation_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Render request validation failures as 422 with field-level detail."""
    validation_exc = cast(RequestValidationError, exc)
    return error_response(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        "validation_error",
        "request validation failed",
        details=validation_exc.errors(),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler: log the failure, return a generic 500 without details."""
    logger.exception(
        "unhandled_exception",
        component="errors",
        path=request.url.path,
        error_type=type(exc).__name__,
    )
    return error_response(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "internal_error",
        "internal server error",
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Install the application's exception handlers on a FastAPI instance."""
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)


__all__ = ["error_response", "register_exception_handlers"]
