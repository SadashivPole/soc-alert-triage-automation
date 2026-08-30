"""Models: canonical (Pydantic) schemas, SQLAlchemy ORM objects, repositories.

* :mod:`soc_triage.models.canonical` — the Pydantic canonical alert schema
  (domain representation, frozen).
* :mod:`soc_triage.models.orm` — SQLAlchemy ORM models (``alerts``,
  ``alert_dedupe_groups``, ``alert_events``, ``audit_log``); Alembic's target
  metadata.
* :mod:`soc_triage.models.repositories` — the only code that touches ORM
  objects; everything else works in domain models (ARCHITECTURE.md §12).
"""

from .orm import (
    Alert,
    AlertDedupeGroup,
    AlertEvent,
    AuditEvent,
    Base,
)

__all__ = [
    "Alert",
    "AlertDedupeGroup",
    "AlertEvent",
    "AuditEvent",
    "Base",
]
