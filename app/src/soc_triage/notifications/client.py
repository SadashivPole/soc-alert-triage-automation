"""n8n webhook client with timeout, retry, fail-open and audit (Phase 2B).

This module implements the outbound integration from the triage service to
n8n (ARCHITECTURE.md §10, §11). Guarantees:

* **Fail-open** — any failure (timeout, HTTP error, n8n unavailable) is
  captured as a :class:`NotificationResult` with ``delivered=False`` and
  **never raises** into the ingest path. The alert itself is already durable
  and scored; notification is best-effort (ARCHITECTURE.md §16).
* **Timeout & retry** — each attempt has a hard timeout (default 3 s) and
  retries with capped exponential backoff + jitter on transient failures
  (network errors, timeouts, 429, 5xx). 4xx (except 429) is not retried.
* **Shared authentication** — the client sends ``X-N8N-Token`` (and
  ``Authorization: Bearer <token>`` for compatibility) when a token is
  configured. No secrets are ever logged.
* **Duplicate prevention** — the service layer (ingest) checks the
  ``NotificationRepository`` before calling the client for the same
  ``alert_id``; the client itself is stateless but exposes a helper to
  build a payload hash for idempotency.
* **Audit-friendly** — every attempt returns a result object that the caller
  persists and audits; logs use allow-listed fields only.

The client uses ``httpx.Client`` (sync) because ingest is currently sync
via TestClient; an async variant can be added later without changing the
result contract.
"""

from __future__ import annotations

import hashlib
import json
import random
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from ..core.logging import get_logger
from .payload import N8NAlertPayload

logger = get_logger("soc_triage.notifications")

# HTTP statuses that are safe to retry (transient)
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

# Network exceptions safe to retry
_RETRYABLE_EXCEPTIONS: tuple[type[httpx.HTTPError], ...] = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
)


@dataclass(frozen=True, slots=True)
class NotificationResult:
    """Outcome of one notification attempt (or series of retries)."""

    alert_id: str
    attempted: bool
    delivered: bool
    skipped: bool
    status_code: int | None
    error_type: str | None
    attempts: int
    duration_ms: int
    webhook_host: str | None
    payload_hash: str


def _payload_hash(payload: N8NAlertPayload) -> str:
    """Deterministic hash of the payload for deduplication / audit."""
    # Use the sanitized JSON dump — stable keys, no whitespace variance
    data = payload.model_dump(mode="json")
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _webhook_host(webhook_url: str) -> str | None:
    """Extract host from URL for logging (never log full URL with potential token)."""
    try:
        parsed = urlparse(webhook_url)
        return parsed.hostname
    except Exception:
        return None


def _jittered(delay: float) -> float:
    """Full-ish jitter in [delay/2, delay]."""
    return delay * random.uniform(0.5, 1.0)


class N8NWebhookClient:
    """Synchronous n8n webhook client with retry and fail-open semantics."""

    def __init__(
        self,
        webhook_url: str,
        token: str = "",
        *,
        timeout_seconds: float = 3.0,
        max_retries: int = 3,
        retry_backoff_seconds: float = 0.5,
        enabled: bool | None = None,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._webhook_url = webhook_url.strip()
        self._token = token.strip()
        self._timeout = timeout_seconds
        self._max_retries = max(1, max_retries)
        self._backoff = retry_backoff_seconds
        self._sleep = sleep or time.sleep

        # enabled defaults to URL non-empty (disable-by-empty)
        if enabled is None:
            self._enabled = bool(self._webhook_url)
        else:
            self._enabled = bool(enabled) and bool(self._webhook_url)

        # httpx client: if not supplied, create a short-lived one per send
        # (simpler for lifespan). If supplied (tests), reuse it.
        self._client = client
        self._owns_client = client is None

    @property
    def enabled(self) -> bool:
        """Whether notification is enabled (URL configured)."""
        return self._enabled

    @property
    def webhook_url(self) -> str:
        """Configured webhook URL (may be empty when disabled)."""
        return self._webhook_url

    def _headers(self) -> dict[str, str]:
        """Build auth headers (no secret logging)."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._token:
            # Primary header: X-N8N-Token (custom, easy to validate in n8n)
            headers["X-N8N-Token"] = self._token
            # Compatibility: Bearer token
            headers["Authorization"] = f"Bearer {self._token}"
            # Also X-Callback-Token for n8n workflows that check callback token
            headers["X-Callback-Token"] = self._token
        return headers

    def send(self, payload: N8NAlertPayload) -> NotificationResult:
        """Send one notification payload to n8n, with retry and fail-open.

        Never raises for delivery failures — returns a result object instead.
        If disabled, returns a skipped result without network I/O.

        Args:
            payload: The structured alert payload (validated, no full_log).

        Returns:
            :class:`NotificationResult` describing the attempt.
        """
        alert_id = payload.alert_id
        payload_hash = _payload_hash(payload)
        host = _webhook_host(self._webhook_url)
        start = time.monotonic()

        if not self._enabled or not self._webhook_url:
            logger.info(
                "n8n_notification_skipped",
                component="notifications",
                alert_id=alert_id,
                reason="disabled",
                payload_hash=payload_hash,
            )
            return NotificationResult(
                alert_id=alert_id,
                attempted=False,
                delivered=False,
                skipped=True,
                status_code=None,
                error_type=None,
                attempts=0,
                duration_ms=0,
                webhook_host=host,
                payload_hash=payload_hash,
            )

        # Prepare JSON body (sanitized, no full_log)
        try:
            body = payload.model_dump(mode="json")
        except Exception as exc:
            # Payload serialization should never fail (validated), but if it
            # does, treat as failed delivery, not a crash (fail-open).
            elapsed_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "n8n_notification_failed",
                component="notifications",
                alert_id=alert_id,
                error_type=type(exc).__name__,
                attempts=0,
                duration_ms=elapsed_ms,
                payload_hash=payload_hash,
                webhook_host=host,
            )
            return NotificationResult(
                alert_id=alert_id,
                attempted=True,
                delivered=False,
                skipped=False,
                status_code=None,
                error_type=type(exc).__name__,
                attempts=0,
                duration_ms=elapsed_ms,
                webhook_host=host,
                payload_hash=payload_hash,
            )

        last_status: int | None = None
        last_error_type: str | None = None
        attempts = 0

        # Use supplied client or create a temporary one
        client = self._client
        close_after = False
        if client is None:
            client = httpx.Client(timeout=self._timeout)
            close_after = True

        try:
            delay = self._backoff
            for attempt in range(1, self._max_retries + 1):
                attempts = attempt
                try:
                    response = client.post(
                        self._webhook_url,
                        json=body,
                        headers=self._headers(),
                        timeout=self._timeout,
                    )
                    last_status = response.status_code

                    # Success: 2xx
                    if 200 <= response.status_code < 300:
                        elapsed_ms = int((time.monotonic() - start) * 1000)
                        logger.info(
                            "n8n_notification_delivered",
                            component="notifications",
                            alert_id=alert_id,
                            status_code=response.status_code,
                            attempts=attempts,
                            duration_ms=elapsed_ms,
                            payload_hash=payload_hash,
                            webhook_host=host,
                        )
                        return NotificationResult(
                            alert_id=alert_id,
                            attempted=True,
                            delivered=True,
                            skipped=False,
                            status_code=response.status_code,
                            error_type=None,
                            attempts=attempts,
                            duration_ms=elapsed_ms,
                            webhook_host=host,
                            payload_hash=payload_hash,
                        )

                    # Retryable status (429, 5xx)
                    if response.status_code in _RETRYABLE_STATUS and attempt < self._max_retries:
                        # Honour Retry-After if present
                        retry_after = response.headers.get("retry-after")
                        if retry_after:
                            with suppress(ValueError):
                                delay = min(float(int(retry_after)), 8.0)
                        self._sleep(_jittered(delay))
                        delay = min(delay * 2, 8.0)
                        continue

                    # Non-retryable 4xx or final retryable failure
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    logger.warning(
                        "n8n_notification_failed",
                        component="notifications",
                        alert_id=alert_id,
                        status_code=response.status_code,
                        error_type=f"http_{response.status_code}",
                        attempts=attempts,
                        duration_ms=elapsed_ms,
                        payload_hash=payload_hash,
                        webhook_host=host,
                    )
                    return NotificationResult(
                        alert_id=alert_id,
                        attempted=True,
                        delivered=False,
                        skipped=False,
                        status_code=response.status_code,
                        error_type=f"http_{response.status_code}",
                        attempts=attempts,
                        duration_ms=elapsed_ms,
                        webhook_host=host,
                        payload_hash=payload_hash,
                    )

                except _RETRYABLE_EXCEPTIONS as exc:
                    last_error_type = type(exc).__name__
                    if attempt < self._max_retries:
                        self._sleep(_jittered(delay))
                        delay = min(delay * 2, 8.0)
                        continue
                    # Final failure after retries
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    logger.warning(
                        "n8n_notification_failed",
                        component="notifications",
                        alert_id=alert_id,
                        error_type=last_error_type,
                        attempts=attempts,
                        duration_ms=elapsed_ms,
                        payload_hash=payload_hash,
                        webhook_host=host,
                    )
                    return NotificationResult(
                        alert_id=alert_id,
                        attempted=True,
                        delivered=False,
                        skipped=False,
                        status_code=last_status,
                        error_type=last_error_type,
                        attempts=attempts,
                        duration_ms=elapsed_ms,
                        webhook_host=host,
                        payload_hash=payload_hash,
                    )
                except httpx.HTTPError as exc:
                    # Non-retryable HTTP error
                    last_error_type = type(exc).__name__
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    logger.warning(
                        "n8n_notification_failed",
                        component="notifications",
                        alert_id=alert_id,
                        error_type=last_error_type,
                        attempts=attempts,
                        duration_ms=elapsed_ms,
                        payload_hash=payload_hash,
                        webhook_host=host,
                    )
                    return NotificationResult(
                        alert_id=alert_id,
                        attempted=True,
                        delivered=False,
                        skipped=False,
                        status_code=last_status,
                        error_type=last_error_type,
                        attempts=attempts,
                        duration_ms=elapsed_ms,
                        webhook_host=host,
                        payload_hash=payload_hash,
                    )

            # Exhausted retries (should be unreachable due to returns above, but keep)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return NotificationResult(
                alert_id=alert_id,
                attempted=True,
                delivered=False,
                skipped=False,
                status_code=last_status,
                error_type=last_error_type or "max_retries_exceeded",
                attempts=attempts,
                duration_ms=elapsed_ms,
                webhook_host=host,
                payload_hash=payload_hash,
            )
        finally:
            if close_after:
                client.close()

    def close(self) -> None:
        """Close the owned httpx client if we own it."""
        if self._owns_client and self._client is not None:
            with suppress(Exception):
                self._client.close()


__all__ = ["N8NWebhookClient", "NotificationResult"]
