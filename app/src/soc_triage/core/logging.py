"""Structured JSON logging built on structlog.

Logs are emitted as one JSON object per line to stdout, which is Docker- and
log-collector friendly. Fields are allow-listed: callers are encouraged to pass
only scalar/JSON-serializable values and never secret values.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from .config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure stdlib logging and structlog to write JSON lines to stdout."""
    level_value = getattr(logging, settings.soc_log_level.upper(), logging.INFO)
    level = int(level_value) if isinstance(level_value, int) else logging.INFO

    logging.basicConfig(stream=sys.stdout, level=level, format="%(message)s", force=True)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a named structlog logger for a component."""
    return structlog.get_logger(name)


__all__ = ["Any", "Settings", "configure_logging", "get_logger"]
