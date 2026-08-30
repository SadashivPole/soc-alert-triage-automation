"""Normalize Wazuh alerts into the canonical alert schema.

The normalizer is a pure function: ``(WazuhAlert, received_at) → CanonicalAlert``.
It has no I/O and is fully unit-testable. Based on ARCHITECTURE.md §6.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from ..enrichment.normalize import strip_url_userinfo
from ..models.canonical import (
    CanonicalAgent,
    CanonicalAlert,
    CanonicalAsset,
    CanonicalDedupe,
    CanonicalRule,
    CanonicalSourceEvent,
)
from .schemas import WazuhAlert


def _sanitize_data_block(data: dict) -> dict:
    """Strip URL userinfo from the *typed* URL fields of a Wazuh ``data`` block.

    SECURITY.md §2: credentials must never become part of a stored indicator or
    persisted payload. The typed URL fields (``data.url`` and
    ``data.virustotal.permalink``) are the only structured fields that carry a
    URL; free-text fields and ``full_log`` remain verbatim (SECURITY.md §5).
    """
    url = data.get("url")
    if isinstance(url, str):
        data["url"] = strip_url_userinfo(url)
    virustotal = data.get("virustotal")
    if isinstance(virustotal, dict):
        permalink = virustotal.get("permalink")
        if isinstance(permalink, str):
            virustotal["permalink"] = strip_url_userinfo(permalink)
    return data


def normalize_wazuh_alert(
    alert: WazuhAlert,
    *,
    alert_id: UUID | None = None,
    received_at: datetime | None = None,
    source: str = "wazuh",
    dedupe: CanonicalDedupe | None = None,
) -> CanonicalAlert:
    """Convert a validated Wazuh alert into the canonical schema.

    Args:
        alert: A validated WazuhAlert instance.
        alert_id: Optional pre-assigned UUID; generated if omitted.
        received_at: Optional reception timestamp; defaults to now (UTC).
        source: Source label (``wazuh`` or ``simulator``).
        dedupe: Optional deduplication information.

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

    # Build the asset context from the agent's optional inventory labels
    # (Phase 1F): `asset_tier` and `owner` drive the `asset_criticality`
    # scoring factor. Missing labels yield an asset with no tier, which the
    # scoring engine treats as *unknown* — never an ingestion error.
    labels = alert.agent.labels if isinstance(alert.agent.labels, dict) else {}
    canonical_asset = CanonicalAsset(
        name=canonical_agent.name,
        tier=labels.get("asset_tier") if isinstance(labels.get("asset_tier"), str) else None,
        owner=labels.get("owner") if isinstance(labels.get("owner"), str) else None,
    )

    # Build source event (trimmed payload). The structured `data` /
    # `syscheck` blocks are preserved verbatim: they carry the typed evidence
    # (srcip, file hashes, FIM paths) that IOC extraction reads in Phase 1E
    # (ARCHITECTURE.md §6, §7.1). Typed URL fields are userinfo-stripped so a
    # credential-bearing URL is never persisted (SECURITY.md §2); `full_log`
    # is kept raw but is *not* an extraction source by default (SECURITY.md §5, §7).
    raw_data = alert.data.model_dump(mode="json") if alert.data is not None else {}
    source_event = CanonicalSourceEvent(
        rule=canonical_rule,
        agent=canonical_agent,
        location=alert.location,
        full_log=alert.full_log,
        data=_sanitize_data_block(raw_data),
        syscheck=dict(alert.syscheck) if alert.syscheck is not None else {},
    )

    return CanonicalAlert(
        alert_id=resolved_id,
        source=source,
        received_at=resolved_received_at,
        source_event=source_event,
        dedupe=dedupe,
        asset=canonical_asset,
    )


__all__ = ["normalize_wazuh_alert"]
