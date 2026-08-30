"""Normalize Wazuh alerts into the canonical alert schema.

The normalizer is a pure function: ``(WazuhAlert, received_at) → CanonicalAlert``.
It has no I/O and is fully unit-testable. Based on ARCHITECTURE.md §6.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from ..models.canonical import (
    CanonicalAgent,
    CanonicalAlert,
    CanonicalRule,
    CanonicalSourceEvent,
)
from .schemas import WazuhAlert


def normalize_wazuh_alert(
    alert: WazuhAlert,
    *,
    alert_id: UUID | None = None,
    received_at: datetime | None = None,
    source: str = "wazuh",
) -> CanonicalAlert:
    """Convert a validated Wazuh alert into the canonical schema.

    Args:
        alert: A validated WazuhAlert instance.
        alert_id: Optional pre-assigned UUID; generated if omitted.
        received_at: Optional reception timestamp; defaults to now (UTC).
        source: Source label (``wazuh`` or ``simulator``).

    Returns:
        A frozen CanonicalAlert instance.
    """
    resolved_id = alert_id or uuid4()
    resolved_received_at = received_at or datetime.now(UTC)

    # Build canonical rule
    canonical_rule = CanonicalRule(
        id=alert.rule.id,
        level=alert.rule.level,
        description=alert.rule.description,
        groups=alert.rule.groups,
        mitre=alert.rule.mitre.model_dump() if alert.rule.mitre else {},
    )

    # Build canonical agent
    canonical_agent = CanonicalAgent(
        id=alert.agent.id,
        name=alert.agent.name,
        ip=alert.agent.ip,
    )

    # Build source event (trimmed payload)
    source_event = CanonicalSourceEvent(
        rule=canonical_rule,
        agent=canonical_agent,
        location=alert.location,
        full_log=alert.full_log,
    )

    return CanonicalAlert(
        alert_id=resolved_id,
        source=source,
        received_at=resolved_received_at,
        source_event=source_event,
    )


__all__ = ["normalize_wazuh_alert"]
