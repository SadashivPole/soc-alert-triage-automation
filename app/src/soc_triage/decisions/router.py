"""Decision & routing engine (Phase 1F).

:func:`decide` is the **pure** decision function:
``(RiskAssessment, CanonicalAlert, DecisionPolicy, decided_at) → Decision``.
It maps the alert's risk tier onto a routing action and, when the source is
allowlisted, overrides to ``suppress`` regardless of score (ARCHITECTURE.md
§9: "Allowlisted → suppressed regardless of score").

Outcomes (ARCHITECTURE.md §9):

* ``open_incident`` — critical (SEV1) / high (SEV2); requires analyst
  handling; **no** autonomous response action is taken here (SECURITY.md §1,
  ADR-8);
* ``queue_l1`` — medium; await L1 triage;
* ``monitor`` — low / informational; dashboard/digest visibility only;
* ``suppress`` — allowlisted source, regardless of score.

Like the scoring engine, the decision engine performs no I/O and contacts no
external service. ``decided_at`` is injected (the ingest reception clock) so
the function stays pure and deterministic in tests.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..models.assessment import Decision, RiskAssessment
from ..models.canonical import CanonicalAlert
from ..models.ioc import ioc_is_allowlisted
from .policy import DecisionPolicy


def _is_allowlisted(alert: CanonicalAlert) -> bool:
    return any(ioc_is_allowlisted(ioc) for ioc in alert.iocs)


def decide(
    risk: RiskAssessment,
    *,
    alert: CanonicalAlert,
    policy: DecisionPolicy,
    decided_at: datetime | None = None,
) -> Decision:
    """Choose a routing decision for a scored alert.

    Args:
        risk: The deterministic risk assessment (score + tier).
        alert: The canonical alert (for allowlist context).
        policy: The validated decision policy.
        decided_at: Decision timestamp (defaults to now UTC).

    Returns:
        A :class:`Decision` carrying the action, optional severity, and
        human-readable reasons.
    """
    decided = decided_at or datetime.now(UTC)

    if _is_allowlisted(alert):
        return Decision(
            action=policy.allowlisted_action,
            reasons=("allowlisted indicator present; suppressed regardless of score",),
            decided_at=decided,
        )

    tier_decision = policy.tier_actions[risk.tier]
    reasons = [f"score={risk.score} tier={risk.tier.value}"]
    if tier_decision.severity is not None:
        reasons.append(f"severity={tier_decision.severity.value}")

    return Decision(
        action=tier_decision.action,
        severity=tier_decision.severity,
        reasons=tuple(reasons),
        decided_at=decided,
    )


class DecisionEngine:
    """Thin holder for a validated :class:`DecisionPolicy`.

    Exists so ingest depends on an injected engine object (with a stable
    ``policy`` attribute) rather than a bare dict/function, matching the
    scoring engine and easing future extension (runbook lookup, Phase 3).
    """

    def __init__(self, policy: DecisionPolicy) -> None:
        self._policy = policy

    @property
    def policy(self) -> DecisionPolicy:
        """The engine's validated policy."""
        return self._policy

    def decide(
        self,
        risk: RiskAssessment,
        *,
        alert: CanonicalAlert,
        decided_at: datetime | None = None,
    ) -> Decision:
        """Choose a routing decision (delegates to :func:`decide`)."""
        return decide(risk, alert=alert, policy=self._policy, decided_at=decided_at)


__all__ = ["DecisionEngine", "decide"]
