"""Build safe, deterministic payloads for TheHive case export."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models.assessment import DecisionSeverity


@dataclass(frozen=True)
class TheHiveObservable:
    """Safe observable prepared for TheHive."""

    data_type: str
    data: str
    message: str | None = None


@dataclass(frozen=True)
class TheHiveCaseExport:
    """Complete safe export representation for one incident."""

    incident_id: str
    title: str
    description: str
    severity: int
    tlp: int
    pap: int
    observables: tuple[TheHiveObservable, ...]


def _severity_to_thehive(severity: DecisionSeverity | str) -> int:
    """Map application severity to TheHive's numeric severity."""

    value = (
        severity.value if isinstance(severity, DecisionSeverity) else str(severity).strip().upper()
    )

    mapping = {
        "SEV1": 4,
        "SEV2": 3,
        "SEV3": 2,
        "SEV4": 1,
    }

    return mapping.get(value, 1)


def _safe_value(value: Any) -> str | None:
    """Return a bounded scalar string, rejecting complex/raw structures."""

    if value is None:
        return None

    if isinstance(value, (dict, list, tuple, set)):
        return None

    text = str(value).strip()

    if not text:
        return None

    return text[:1000]


def _extract_ioc_observables(
    iocs: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> tuple[TheHiveObservable, ...]:
    """Convert safe IOC summaries into TheHive observables."""

    results: list[TheHiveObservable] = []

    allowed_types = {
        "ip": "ip",
        "ipv4": "ip",
        "ipv6": "ip",
        "domain": "domain",
        "hostname": "hostname",
        "fqdn": "domain",
        "url": "url",
        "hash": "hash",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "email": "mail",
    }

    for item in iocs:
        if not isinstance(item, dict):
            continue

        raw_type = _safe_value(item.get("type") or item.get("ioc_type") or item.get("kind") or "")

        value = _safe_value(item.get("value") or item.get("ioc") or item.get("indicator"))

        if not raw_type or not value:
            continue

        normalized_type = allowed_types.get(raw_type.lower())

        if normalized_type is None:
            continue

        message = _safe_value(item.get("source"))

        results.append(
            TheHiveObservable(
                data_type=normalized_type,
                data=value,
                message=message,
            )
        )

    return tuple(results)


def build_thehive_case_export(
    *,
    incident: dict[str, Any],
    alerts: list[dict[str, Any]] | tuple[dict[str, Any], ...] = (),
    iocs: list[dict[str, Any]] | tuple[dict[str, Any], ...] = (),
    assignment: dict[str, Any] | None = None,
    notes: list[dict[str, Any]] | tuple[dict[str, Any], ...] = (),
    timeline: list[dict[str, Any]] | tuple[dict[str, Any], ...] = (),
) -> TheHiveCaseExport:
    """Build a safe TheHive export from already-sanitized domain data.

    The function intentionally accepts dictionaries containing only data
    selected by the caller. It never consumes or forwards ``full_log``.
    """

    incident_id = _safe_value(incident.get("incident_id"))

    if not incident_id:
        raise ValueError("incident_id is required")

    status = _safe_value(incident.get("status")) or "unknown"
    severity_raw = incident.get("severity", "SEV4")

    severity = _severity_to_thehive(severity_raw)

    title = f"SOC Incident {incident_id} [{str(severity_raw).upper()}]"

    description_lines = [
        f"Incident ID: {incident_id}",
        f"Status: {status}",
    ]

    dedupe_group = _safe_value(incident.get("dedupe_group_key"))
    if dedupe_group:
        description_lines.append(f"Dedupe Group: {dedupe_group}")

    primary_alert_id = _safe_value(incident.get("primary_alert_id"))
    if primary_alert_id:
        description_lines.append(f"Primary Alert ID: {primary_alert_id}")

    assignee = None
    if assignment:
        assignee = _safe_value(assignment.get("assignee"))

    if assignee:
        description_lines.append(f"Assignee: {assignee}")

    linked_alert_ids: list[str] = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        alert_id = _safe_value(alert.get("alert_id") or alert.get("id"))

        if alert_id:
            linked_alert_ids.append(alert_id)

    if linked_alert_ids:
        description_lines.append("Linked Alerts: " + ", ".join(linked_alert_ids[:50]))

    safe_notes: list[str] = []

    for note in notes:
        if not isinstance(note, dict):
            continue

        # First non-empty key wins. ``"note"`` is the key the export route emits
        # (api/incident_thehive.py); the others are kept for compatibility.
        text = _safe_value(
            note.get("notes") or note.get("text") or note.get("content") or note.get("note")
        )

        actor = _safe_value(note.get("actor"))

        if not text:
            continue

        if actor:
            safe_notes.append(f"{actor}: {text}")
        else:
            safe_notes.append(text)

    if safe_notes:
        description_lines.append("Investigation Notes:")
        description_lines.extend(f"- {item}" for item in safe_notes[:50])

    timeline_summary: list[str] = []

    for event in timeline:
        if not isinstance(event, dict):
            continue

        action = _safe_value(event.get("action") or event.get("event") or event.get("type"))

        occurred_at = _safe_value(event.get("occurred_at") or event.get("timestamp"))

        if not action:
            continue

        if occurred_at:
            timeline_summary.append(f"{occurred_at} - {action}")
        else:
            timeline_summary.append(action)

    if timeline_summary:
        description_lines.append("Timeline Summary:")
        description_lines.extend(f"- {item}" for item in timeline_summary[:100])

    observables = _extract_ioc_observables(list(iocs))

    return TheHiveCaseExport(
        incident_id=incident_id,
        title=title[:250],
        description="\n".join(description_lines)[:12000],
        severity=severity,
        tlp=2,
        pap=2,
        observables=observables,
    )


__all__ = [
    "TheHiveCaseExport",
    "TheHiveObservable",
    "build_thehive_case_export",
]
