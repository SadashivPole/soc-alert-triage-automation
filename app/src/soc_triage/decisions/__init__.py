"""Decision & routing engine (Phase 1F).

Public surface (ARCHITECTURE.md §9, §12 — pure, zero-I/O):

* :mod:`.router` — the pure :func:`~.router.decide` function and the
  :class:`~.router.DecisionEngine` wrapper;
* :mod:`.policy` — the validated, immutable :class:`~.policy.DecisionPolicy`;
* :mod:`.config` — the YAML loader (:func:`~.config.load_decision_policy`) and
  its :class:`~.config.DecisionConfigError`.

No decision path here performs a response action: ``open_incident`` only
*proposes* escalation and always requires analyst handling (SECURITY.md §1,
ADR-8).
"""

from __future__ import annotations

from .config import (
    DEFAULT_DECISION_POLICY_PATH,
    DecisionConfigError,
    decision_policy_from_mapping,
    default_decision_policy,
    load_decision_policy,
)
from .policy import DecisionPolicy, TierDecision
from .router import DecisionEngine, decide

__all__ = [
    "DEFAULT_DECISION_POLICY_PATH",
    "DecisionConfigError",
    "DecisionEngine",
    "DecisionPolicy",
    "TierDecision",
    "decide",
    "decision_policy_from_mapping",
    "default_decision_policy",
    "load_decision_policy",
]
