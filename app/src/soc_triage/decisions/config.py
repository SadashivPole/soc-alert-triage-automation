"""Decision policy loader (Phase 1F).

Mirrors :mod:`soc_triage.scoring.config`: loads and schema-validates the
versioned, non-secret decision policy YAML (``app/config/decisions.yaml``)
into an immutable :class:`DecisionPolicy`, fail-loud on any problem.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .policy import DecisionPolicy

#: Bundled policy location: ``app/config/decisions.yaml``.
DEFAULT_DECISION_POLICY_PATH = Path(__file__).resolve().parents[3] / "config" / "decisions.yaml"


class DecisionConfigError(ValueError):
    """The decision policy could not be loaded or validated."""


def load_decision_policy(path: Path | None = None) -> DecisionPolicy:
    """Load and validate the decision policy from YAML.

    Raises:
        DecisionConfigError: if the file is unreadable, not valid YAML, not a
            mapping, or fails schema validation.
    """
    policy_path = path or DEFAULT_DECISION_POLICY_PATH
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DecisionConfigError(f"cannot read decision policy {policy_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise DecisionConfigError(f"invalid YAML in decision policy {policy_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise DecisionConfigError(
            f"decision policy {policy_path} must be a mapping, got {type(raw).__name__}"
        )

    try:
        return DecisionPolicy.model_validate(raw)
    except ValidationError as exc:
        raise DecisionConfigError(f"invalid decision policy {policy_path}: {exc}") from exc


@lru_cache
def default_decision_policy() -> DecisionPolicy:
    """Return the process-cached bundled decision policy."""
    return load_decision_policy()


def decision_policy_from_mapping(raw: dict[str, Any]) -> DecisionPolicy:
    """Validate a decision policy from an in-memory mapping (tests)."""
    try:
        return DecisionPolicy.model_validate(raw)
    except ValidationError as exc:
        raise DecisionConfigError(f"invalid decision policy: {exc}") from exc


__all__ = [
    "DEFAULT_DECISION_POLICY_PATH",
    "DecisionConfigError",
    "decision_policy_from_mapping",
    "default_decision_policy",
    "load_decision_policy",
]
