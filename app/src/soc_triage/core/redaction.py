"""Shared secret-redaction helper for every analyst-facing projection.

Read-side surfaces (alert/incident read APIs, correlation reads, the Phase
6.5 explanation layer) must never emit secret-bearing keys or raw logs
(SECURITY.md §5, §7). This module is the single implementation of that rule:
it lives in ``core`` (a cross-cutting concern) so domain-level projections
can apply it without importing the API layer (ARCHITECTURE.md §12).

The redaction is *conservative and deterministic*: any mapping key whose
name contains a sensitive fragment is dropped entirely (its value is never
inspected or echoed), lists are redacted element-wise, and primitives pass
through unchanged. No randomness, no I/O, no clock.
"""

from __future__ import annotations

from typing import Any

#: Keys / substrings that must never appear in a read-API payload.
_SENSITIVE_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "full_log",
)


def redact_mapping(value: Any) -> Any:
    """Recursively drop secret-bearing keys and ``full_log``.

    Applied to nested ``data`` / ``syscheck`` / enrichment blobs before they
    leave the process. Primitive values are returned unchanged.
    """
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, inner in value.items():
            lowered = str(key).lower()
            if any(fragment in lowered for fragment in _SENSITIVE_FRAGMENTS):
                continue
            redacted[key] = redact_mapping(inner)
        return redacted
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    return value


__all__ = ["redact_mapping"]
