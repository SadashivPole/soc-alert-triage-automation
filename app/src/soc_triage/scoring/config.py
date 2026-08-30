"""Scoring policy loader (Phase 1F).

Loads and schema-validates the versioned, non-secret scoring policy YAML
(``app/config/scoring.yaml``) into an immutable :class:`ScoringPolicy`. The
bundled file is the default; tests inject dicts through
:class:`ScoringPolicy` directly (no file I/O), and :func:`load_scoring_policy`
also accepts an explicit path for deployment overrides.

Configuration is **fail-loud**: a missing, unreadable, malformed, or
schema-invalid policy raises :class:`ScoringConfigError` rather than silently
falling back to guessed weights (ARCHITECTURE.md §14, §16 — fail closed for
configuration, fail loud for the pipeline). No secrets ever live in this file
(SECURITY.md §2); the error messages therefore never redact anything.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .policy import ScoringPolicy

#: Bundled policy location: ``app/config/scoring.yaml`` (this module lives at
#: ``app/src/soc_triage/scoring/config.py``).
DEFAULT_SCORING_POLICY_PATH = Path(__file__).resolve().parents[3] / "config" / "scoring.yaml"


class ScoringConfigError(ValueError):
    """The scoring policy could not be loaded or validated.

    Carries no secrets (the policy is non-secret by design); the message is
    safe to log and surface in a readiness endpoint.
    """


def load_scoring_policy(path: Path | None = None) -> ScoringPolicy:
    """Load and validate the scoring policy from YAML.

    Args:
        path: Policy file to read; defaults to the bundled
            ``app/config/scoring.yaml``.

    Returns:
        A validated, immutable :class:`ScoringPolicy`.

    Raises:
        ScoringConfigError: if the file is unreadable, not valid YAML, not a
            mapping, or fails schema validation.
    """
    policy_path = path or DEFAULT_SCORING_POLICY_PATH
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScoringConfigError(f"cannot read scoring policy {policy_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ScoringConfigError(f"invalid YAML in scoring policy {policy_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ScoringConfigError(
            f"scoring policy {policy_path} must be a mapping, got {type(raw).__name__}"
        )

    try:
        return ScoringPolicy.model_validate(raw)
    except ValidationError as exc:
        raise ScoringConfigError(f"invalid scoring policy {policy_path}: {exc}") from exc


@lru_cache
def default_scoring_policy() -> ScoringPolicy:
    """Return the process-cached bundled scoring policy."""
    return load_scoring_policy()


def scoring_policy_from_mapping(raw: dict[str, Any]) -> ScoringPolicy:
    """Validate a scoring policy from an in-memory mapping (tests).

    Raises:
        ScoringConfigError: on schema validation failure.
    """
    try:
        return ScoringPolicy.model_validate(raw)
    except ValidationError as exc:
        raise ScoringConfigError(f"invalid scoring policy: {exc}") from exc


__all__ = [
    "DEFAULT_SCORING_POLICY_PATH",
    "ScoringConfigError",
    "default_scoring_policy",
    "load_scoring_policy",
    "scoring_policy_from_mapping",
]
