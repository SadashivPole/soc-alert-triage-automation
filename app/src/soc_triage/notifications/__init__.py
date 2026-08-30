"""n8n SOAR notification integration (Phase 2B).

Public surface:
* :class:`N8NAlertPayload` and :func:`build_n8n_payload` — structured,
  security-aware payload builder (no full_log, no secrets).
* :class:`N8NWebhookClient` and :class:`NotificationResult` — outbound
  webhook client with timeout, retry, fail-open, duplicate prevention.
"""

from __future__ import annotations

from .client import N8NWebhookClient, NotificationResult
from .payload import N8NAlertPayload, build_n8n_payload

__all__ = [
    "N8NAlertPayload",
    "N8NWebhookClient",
    "NotificationResult",
    "build_n8n_payload",
]
