"""Structured n8n alert payload builder (Phase 2B).

Builds the outbound webhook payload sent from the triage service to n8n.
The payload is **security-aware**:

* No ``full_log`` forwarding — raw log lines stay in the alert store, not in
  the notification channel (SECURITY.md §5).
* No secrets — only allow-listed, analyst-safe fields.
* Deterministic, JSON-serializable, schema-validated via Pydantic.

The payload contains every field required by the Phase 2B spec:

* alert_id
* severity/risk tier
* score
* decision
* rule information
* recurrence
* IOC summary
* enrichment summary
* investigation links where available

Design: pure function (CanonicalAlert + DedupeStatus → dict), no I/O, no
clock, fully unit-testable.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..models.canonical import CanonicalAlert
from ..models.ioc import IOC


class RuleInfo(BaseModel):
    """Rule metadata for the n8n payload (no raw log)."""

    model_config = {"frozen": True}

    id: str
    level: int
    description: str
    groups: list[str] = Field(default_factory=list)
    mitre: dict[str, Any] = Field(default_factory=dict)


class AgentInfo(BaseModel):
    """Agent context (safe fields only)."""

    model_config = {"frozen": True}

    id: str
    name: str
    ip: str | None = None


class RecurrenceInfo(BaseModel):
    """Deduplication / recurrence summary."""

    model_config = {"frozen": True}

    group_key: str
    occurrences: int
    generation: int
    first_seen: str | None = None
    last_seen: str | None = None
    duplicate_deliveries: int = 0
    dedupe_status: str
    event_identity: str | None = None


class IOCSummary(BaseModel):
    """One indicator summary (value + enrichment, no raw offsets)."""

    model_config = {"frozen": True}

    type: str
    value: str
    enrichment: dict[str, Any] = Field(default_factory=dict)


class EnrichmentSummary(BaseModel):
    """Enrichment run outcome summary."""

    model_config = {"frozen": True}

    status: str
    providers: list[dict[str, Any]] = Field(default_factory=list)
    ioc_count: int = 0


class DecisionInfo(BaseModel):
    """Routing decision summary."""

    model_config = {"frozen": True}

    action: str
    severity: str | None = None
    reasons: list[str] = Field(default_factory=list)
    runbook: str | None = None
    decided_at: str | None = None


class RiskInfo(BaseModel):
    """Risk scoring summary."""

    model_config = {"frozen": True}

    score: int
    tier: str
    engine_version: str
    factors: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""
    degraded: bool = False


class InvestigationLinks(BaseModel):
    """Investigation deep-links (where available)."""

    model_config = {"frozen": True}

    alert_api: str
    alert_console: str | None = None
    runbook: str | None = None
    feedback_url: str | None = None
    ioc_links: dict[str, str] = Field(default_factory=dict)


class N8NAlertPayload(BaseModel):
    """Complete structured payload sent to n8n webhook.

    Validated shape — every field is explicitly allow-listed. The payload
    never contains ``full_log`` or secrets.
    """

    model_config = {"frozen": True}

    alert_id: str
    received_at: str
    source: str
    risk: RiskInfo
    decision: DecisionInfo
    rule: RuleInfo
    agent: AgentInfo
    asset: dict[str, Any] | None = None
    recurrence: RecurrenceInfo
    iocs: list[IOCSummary] = Field(default_factory=list)
    enrichment: EnrichmentSummary
    investigation_links: InvestigationLinks
    # Convenience top-level aliases required by spec:
    severity: str
    score: int
    dedupe_status: str

    def model_dump_sanitized(self) -> dict[str, Any]:
        """Return JSON-serializable dict, guaranteed no full_log."""
        data = self.model_dump(mode="json")
        # Defensive: ensure no full_log slipped through
        dumped_str = str(data).lower()
        assert "full_log" not in dumped_str, "payload must not contain full_log"
        return data


def _sanitize_enrichment(enrichment: dict[str, Any]) -> dict[str, Any]:
    """Return enrichment payload stripped of any unexpected large blobs.

    Only allow-listed top-level keys from providers are kept; raw upstream
    bodies are never stored (ARCHITECTURE.md §7.3). The sanitization here is
    a second defense layer — providers already sanitize, but the payload
    builder must not blindly forward everything.
    """
    # Keep only small, known-safe keys: reputation, tags, counts, status, etc.
    # Drop anything that looks like raw log or large text.
    allowed_keys = {
        "provider",
        "indicator_type",
        "lookup_status",
        "timestamp",
        "result",
        "reputation",
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "matched",
        "matched_event_ids",
        "tags",
        "threat_level",
        "classification",
    }
    sanitized: dict[str, Any] = {}
    for key, value in enrichment.items():
        # provider payloads are dicts like {"vt": {...}, "misp": {...}}
        if isinstance(value, dict):
            inner: dict[str, Any] = {}
            for inner_key, inner_val in value.items():
                if inner_key in allowed_keys or inner_key in {
                    "malicious",
                    "suspicious",
                    "harmless",
                    "undetected",
                    "reputation",
                    "tags",
                    "matched",
                    "matched_event_ids",
                }:
                    # Truncate long strings
                    if isinstance(inner_val, str) and len(inner_val) > 500:
                        inner[inner_key] = inner_val[:500] + "...[truncated]"
                    else:
                        inner[inner_key] = inner_val
                elif isinstance(inner_val, dict):
                    # One more level of sanitization for nested result dicts
                    nested: dict[str, Any] = {}
                    for nk, nv in inner_val.items():
                        if nk in allowed_keys:
                            if isinstance(nv, str) and len(nv) > 500:
                                nested[nk] = nv[:500] + "...[truncated]"
                            else:
                                nested[nk] = nv
                    if nested:
                        inner[inner_key] = nested
            if inner:
                sanitized[key] = inner
        else:
            # Primitive values that are safe and small
            if isinstance(value, (bool, int, float)) or (
                isinstance(value, str) and len(value) <= 200
            ):
                sanitized[key] = value
    return sanitized


def _build_ioc_summary(ioc: IOC) -> IOCSummary:
    """Build a safe IOC summary (no provenance offsets, no raw log)."""
    return IOCSummary(
        type=ioc.type.value,
        value=ioc.value,
        enrichment=_sanitize_enrichment(ioc.enrichment),
    )


def build_n8n_payload(
    alert: CanonicalAlert,
    *,
    dedupe_status: str,
    investigation_base_url: str | None = None,
) -> N8NAlertPayload:
    """Build the structured n8n webhook payload for one alert.

    Args:
        alert: The scored canonical alert (must have risk & decision).
        dedupe_status: The deduplication outcome (new_generation/repeated/etc).
        investigation_base_url: Optional base URL for deep links (e.g.
            ``http://localhost:8000``). If omitted, links use relative paths
            or ``/api/v1/alerts/{id}``.

    Returns:
        A validated :class:`N8NAlertPayload` (never contains full_log).
    """
    if alert.risk is None:
        raise ValueError("alert must be scored before building n8n payload")
    if alert.decision is None:
        raise ValueError("alert must have a decision before building n8n payload")

    risk = alert.risk
    decision = alert.decision

    # Rule info (no full_log)
    rule = RuleInfo(
        id=alert.source_event.rule.id,
        level=alert.source_event.rule.level,
        description=alert.source_event.rule.description,
        groups=list(alert.source_event.rule.groups),
        mitre=dict(alert.source_event.rule.mitre) if alert.source_event.rule.mitre else {},
    )

    agent = AgentInfo(
        id=alert.source_event.agent.id,
        name=alert.source_event.agent.name,
        ip=alert.source_event.agent.ip,
    )

    asset = None
    if alert.asset is not None:
        asset = {
            "name": alert.asset.name,
            "tier": alert.asset.tier,
            "owner": alert.asset.owner,
        }

    # Recurrence
    dedupe = alert.dedupe
    recurrence = RecurrenceInfo(
        group_key=dedupe.group_key if dedupe else "",
        occurrences=dedupe.occurrences if dedupe else 1,
        generation=dedupe.generation if dedupe else 1,
        first_seen=dedupe.first_seen.isoformat() if dedupe and dedupe.first_seen else None,
        last_seen=dedupe.last_seen.isoformat() if dedupe and dedupe.last_seen else None,
        duplicate_deliveries=0,  # populated from group state if available
        dedupe_status=dedupe_status,
        event_identity=dedupe.event_identity if dedupe else None,
    )

    # IOC summary (no provenance offsets, no raw log)
    ioc_summaries = [_build_ioc_summary(ioc) for ioc in alert.iocs]

    # Enrichment summary
    enrichment = EnrichmentSummary(
        status=alert.enrichment_status or "skipped",
        ioc_count=len(ioc_summaries),
        providers=[],  # provider outcomes are logged elsewhere; payload keeps it light
    )

    # Risk info
    risk_info = RiskInfo(
        score=risk.score,
        tier=risk.tier.value,
        engine_version=risk.engine_version,
        factors=[
            {
                "name": factor.name,
                "points": factor.points,
                "max": factor.max,
                "detail": factor.detail,
            }
            for factor in risk.factors
        ],
        summary=risk.summary,
        degraded=risk.degraded,
    )

    decision_info = DecisionInfo(
        action=decision.action.value,
        severity=decision.severity.value if decision.severity else None,
        reasons=list(decision.reasons),
        runbook=decision.runbook,
        decided_at=decision.decided_at.isoformat() if decision.decided_at else None,
    )

    # Investigation links
    base = (investigation_base_url or "").rstrip("/")
    if base:
        alert_api = f"{base}/api/v1/alerts/{alert.alert_id}"
        alert_console = f"{base}/alerts/{alert.alert_id}"
    else:
        alert_api = f"/api/v1/alerts/{alert.alert_id}"
        alert_console = None

    runbook_link = decision.runbook
    if runbook_link and base and not runbook_link.startswith("http"):
        # If runbook is a relative path like docs/runbooks/..., make it absolute for n8n
        runbook_link = f"{base}/{runbook_link.lstrip('/')}"

    # Feedback link used by n8n notification emails (WF2/WF3). Provided by the
    # API rather than reconstructed in workflow JS so the address is always the
    # allow-listed triage endpoint (Phase 2D email-chain fix).
    if base:
        feedback_url = f"{base}/api/v1/alerts/{alert.alert_id}/feedback"
    else:
        feedback_url = f"/api/v1/alerts/{alert.alert_id}/feedback"

    investigation_links = InvestigationLinks(
        alert_api=alert_api,
        alert_console=alert_console,
        runbook=runbook_link,
        feedback_url=feedback_url,
        ioc_links={},
    )

    payload = N8NAlertPayload(
        alert_id=str(alert.alert_id),
        received_at=alert.received_at.isoformat(),
        source=alert.source,
        risk=risk_info,
        decision=decision_info,
        rule=rule,
        agent=agent,
        asset=asset,
        recurrence=recurrence,
        iocs=ioc_summaries,
        enrichment=enrichment,
        investigation_links=investigation_links,
        severity=risk.tier.value,
        score=risk.score,
        dedupe_status=dedupe_status,
    )

    # Final safety check
    payload.model_dump_sanitized()
    return payload


__all__ = [
    "AgentInfo",
    "DecisionInfo",
    "EnrichmentSummary",
    "IOCSummary",
    "InvestigationLinks",
    "N8NAlertPayload",
    "RecurrenceInfo",
    "RiskInfo",
    "RuleInfo",
    "build_n8n_payload",
]
