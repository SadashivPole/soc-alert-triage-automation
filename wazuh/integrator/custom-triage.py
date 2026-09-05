#!/usr/bin/env python3
"""Wazuh ``integrator`` script — forwards Wazuh alerts to the Triage API.

Phase 4.2 (DEVELOPMENT_PLAN.md §Phase 4, ARCHITECTURE.md §13 / ADR-6).

Wazuh's ``integrator`` daemon writes each matching alert to a temporary JSON
file and executes this script as::

    /var/ossec/integrations/custom-triage <alert_file> <api_key> <hook_url> [options]

This implementation deliberately **ignores** the positional ``api_key`` /
``hook_url`` arguments as a secret source and reads *all* configuration from
environment variables instead (ARCHITECTURE.md §14, SECURITY.md §3): the
``ossec.conf`` file is world-readable inside the manager container, so a key
placed there would be a committed/at-rest secret. The positional arguments are
accepted only so the standard Wazuh invocation contract still works.

Design constraints honoured here:

* **Standard library only.** It runs inside the ``wazuh/wazuh-manager`` image,
  which has no project dependencies installed (no ``httpx``/``pydantic``).
* **Never blocks or crashes the manager.** Any transient failure buffers the
  alert on local disk and exits ``0``; ``integratord`` never retries for us.
* **Local buffering + retry.** Every invocation first tries to drain the spool
  directory (oldest first, bounded), then delivers the current alert. The spool
  is size- and age-bounded so a long API outage cannot fill the manager disk.
* **Existing auth contract preserved.** Delivery is a plain
  ``POST {base}/api/v1/alerts/ingest`` with the ``X-API-Key`` header — exactly
  what :mod:`soc_triage.ingest.auth` expects. Nothing here weakens it.
* **Defensive only.** This script forwards detections and nothing else. It has
  no containment capability, spawns no processes, and runs no commands
  (SECURITY.md 1).
* **No sensitive data in logs.** Logs are structured stderr lines carrying
  allow-listed metadata (rule id/level, agent id, status code, attempt count).
  API keys, URLs with credentials, and alert bodies are never logged.
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urlunparse

__all__ = [
    "ConfigError",
    "DeliveryOutcome",
    "IntegratorConfig",
    "Spool",
    "UrllibSender",
    "build_request_headers",
    "deliver",
    "load_config",
    "main",
    "run",
    "sanitize_url",
    "should_forward",
]

#: Exit code used for every non-fatal outcome (delivered *or* buffered).
EXIT_OK = 0
#: Exit code for configuration/usage errors that an operator must fix.
EXIT_CONFIG_ERROR = 2

#: HTTP statuses worth retrying/buffering (transient), mirroring the n8n client.
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})

#: Hard cap on a single alert file we are willing to read (bytes).
MAX_ALERT_BYTES = 1_048_576

_INGEST_PATH = "/api/v1/alerts/ingest"

#: Process-local counter breaking same-millisecond ties in spool file names.
_SEQUENCE = 0


class ConfigError(ValueError):
    """Raised when the environment configuration is missing or invalid."""


# ---------------------------------------------------------------------------
# Logging (structured, secret-free)
# ---------------------------------------------------------------------------

#: Keys that must never reach a log line even if a caller passes them.
_FORBIDDEN_LOG_KEYS = frozenset({"api_key", "apikey", "key", "token", "password", "secret"})

#: Default log sink, matching the convention used by the integrations Wazuh
#: ships (slack.py, virustotal.py, ...): ``<ossec>/logs/integrations.log``.
#:
#: This is NOT cosmetic. ``wazuh-integratord`` appends ``> /dev/null 2>&1`` to
#: the command unless the manager runs at debug level (src/os_integrator/
#: integrator.c), so anything written to stdout/stderr is discarded in a normal
#: deployment. Writing to the log file directly is the only way these events
#: are observable in production.
_DEFAULT_LOG_FILE = "/var/ossec/logs/integrations.log"


#: Resolved log destination for this invocation. ``run()`` sets it from the
#: environment it was handed so tests (and any embedded caller) do not have to
#: mutate the real ``os.environ``.
_LOG_FILE: str = ""


def _log_path() -> str:
    if _LOG_FILE:
        return _LOG_FILE
    return (
        os.environ.get("WAZUH_INTEGRATOR_LOG_FILE") or _DEFAULT_LOG_FILE
    ).strip() or _DEFAULT_LOG_FILE


def _set_log_path(env: Mapping[str, str]) -> None:
    """Pin the log destination for this invocation."""
    global _LOG_FILE
    _LOG_FILE = (env.get("WAZUH_INTEGRATOR_LOG_FILE") or _DEFAULT_LOG_FILE).strip()


def log(event: str, **fields: object) -> None:
    """Emit one structured JSON log line.

    Only allow-listed, non-sensitive metadata should be passed. Any key that
    looks like a credential is dropped defensively rather than redacted, so a
    future caller mistake cannot leak a value.

    The line is appended to ``integrations.log`` (see :data:`_DEFAULT_LOG_FILE`)
    and also mirrored to stderr, which the manager surfaces when running at
    debug level. Logging never raises: an unwritable log file must not cost us
    an alert.
    """
    payload: dict[str, object] = {"component": "wazuh_integrator", "event": event}
    for name, value in fields.items():
        if name.lower() in _FORBIDDEN_LOG_KEYS:
            continue
        payload[name] = value

    try:
        line = json.dumps(payload, sort_keys=True, default=str)
    except Exception:  # pragma: no cover - logging must never raise
        return

    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:  # pragma: no cover - logging must never raise
        pass

    try:
        with open(_log_path(), "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        # No log file (e.g. running outside the manager) is not fatal.
        pass


def sanitize_url(url: str) -> str:
    """Return ``url`` without any embedded userinfo credentials.

    Mirrors the existing URL-credential sanitization contract used elsewhere in
    the project (``test_url_credential_sanitization``): a URL is only ever
    logged after stripping ``user:pass@``.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return "<unparseable-url>"
    if not parsed.hostname:
        return "<unparseable-url>"
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path, "", parsed.query, ""))


# ---------------------------------------------------------------------------
# Configuration (12-factor: environment only, no secrets on disk or in argv)
# ---------------------------------------------------------------------------


def _env_int(env: Mapping[str, str], name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_float(
    env: Mapping[str, str], name: str, default: float, *, minimum: float, maximum: float
) -> float:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = (env.get(name) or "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean (1/0, true/false)")


def _env_csv(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    raw = (env.get(name) or "").strip()
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class IntegratorConfig:
    """Validated integrator configuration, sourced entirely from the environment."""

    ingest_url: str
    api_key: str = field(repr=False)
    min_rule_level: int = 5
    excluded_rule_ids: tuple[str, ...] = ()
    excluded_groups: tuple[str, ...] = ()
    timeout_seconds: float = 5.0
    max_attempts: int = 3
    backoff_seconds: float = 0.5
    spool_dir: Path = Path("/var/ossec/logs/triage-spool")
    spool_max_entries: int = 1000
    spool_max_age_seconds: int = 604_800  # 7 days
    spool_flush_batch: int = 25
    verify_tls: bool = True

    def __repr__(self) -> str:  # pragma: no cover - trivial, secret-safe repr
        return (
            f"IntegratorConfig(ingest_url={sanitize_url(self.ingest_url)!r}, "
            f"min_rule_level={self.min_rule_level}, api_key='***')"
        )


def load_config(env: Mapping[str, str] | None = None) -> IntegratorConfig:
    """Build an :class:`IntegratorConfig` from environment variables.

    Raises:
        ConfigError: if a required variable is missing, a placeholder value is
            still in place, or a numeric/boolean value is malformed.
    """
    env = os.environ if env is None else env

    base_url = (env.get("TRIAGE_API_BASE_URL") or env.get("TRIAGE_API_URL") or "").strip()
    if not base_url:
        raise ConfigError("TRIAGE_API_BASE_URL is required")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigError("TRIAGE_API_BASE_URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ConfigError(
            "TRIAGE_API_BASE_URL must not embed credentials; use TRIAGE_INGEST_API_KEY"
        )

    ingest_path = (env.get("TRIAGE_INGEST_PATH") or _INGEST_PATH).strip() or _INGEST_PATH
    if not ingest_path.startswith("/"):
        raise ConfigError("TRIAGE_INGEST_PATH must start with '/'")
    ingest_url = base_url.rstrip("/") + ingest_path

    api_key = (env.get("TRIAGE_INGEST_API_KEY") or "").strip()
    if not api_key:
        raise ConfigError("TRIAGE_INGEST_API_KEY is required (never hardcode it in ossec.conf)")
    if api_key.lower().startswith("change-me"):
        raise ConfigError("TRIAGE_INGEST_API_KEY is still a placeholder value")

    return IntegratorConfig(
        ingest_url=ingest_url,
        api_key=api_key,
        min_rule_level=_env_int(env, "WAZUH_INTEGRATOR_MIN_LEVEL", 5, minimum=0, maximum=15),
        excluded_rule_ids=_env_csv(env, "WAZUH_INTEGRATOR_EXCLUDED_RULE_IDS"),
        excluded_groups=_env_csv(env, "WAZUH_INTEGRATOR_EXCLUDED_GROUPS"),
        timeout_seconds=_env_float(
            env, "WAZUH_INTEGRATOR_TIMEOUT_SECONDS", 5.0, minimum=0.1, maximum=60.0
        ),
        max_attempts=_env_int(env, "WAZUH_INTEGRATOR_MAX_ATTEMPTS", 3, minimum=1, maximum=10),
        backoff_seconds=_env_float(
            env, "WAZUH_INTEGRATOR_BACKOFF_SECONDS", 0.5, minimum=0.0, maximum=10.0
        ),
        spool_dir=Path(
            (env.get("WAZUH_INTEGRATOR_SPOOL_DIR") or "/var/ossec/logs/triage-spool").strip()
        ),
        spool_max_entries=_env_int(
            env, "WAZUH_INTEGRATOR_SPOOL_MAX_ENTRIES", 1000, minimum=1, maximum=100_000
        ),
        spool_max_age_seconds=_env_int(
            env, "WAZUH_INTEGRATOR_SPOOL_MAX_AGE_SECONDS", 604_800, minimum=60, maximum=2_592_000
        ),
        spool_flush_batch=_env_int(
            env, "WAZUH_INTEGRATOR_SPOOL_FLUSH_BATCH", 25, minimum=1, maximum=1000
        ),
        verify_tls=_env_bool(env, "WAZUH_INTEGRATOR_VERIFY_TLS", True),
    )


# ---------------------------------------------------------------------------
# Forwarding filter
# ---------------------------------------------------------------------------


def should_forward(alert: Mapping[str, object], config: IntegratorConfig) -> tuple[bool, str]:
    """Decide whether ``alert`` should be forwarded.

    Returns a ``(forward, reason)`` pair; ``reason`` is a short, non-sensitive
    token suitable for logging.
    """
    rule = alert.get("rule")
    if not isinstance(rule, Mapping):
        return False, "missing_rule"

    raw_level = rule.get("level")
    try:
        level = int(raw_level)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False, "invalid_level"
    if level < config.min_rule_level:
        return False, "below_min_level"

    rule_id = str(rule.get("id", "")).strip()
    if rule_id and rule_id in config.excluded_rule_ids:
        return False, "excluded_rule_id"

    groups = rule.get("groups")
    if isinstance(groups, list | tuple):
        group_names = {str(group) for group in groups}
        if group_names.intersection(config.excluded_groups):
            return False, "excluded_group"

    return True, "forward"


# ---------------------------------------------------------------------------
# Local spool (buffering + retry across invocations)
# ---------------------------------------------------------------------------


class Spool:
    """A bounded, on-disk FIFO buffer of undelivered alerts.

    Files are named ``<epoch_ms>-<uuid4hex>.json`` so lexical ordering is
    chronological. The spool is bounded by entry count *and* age: enqueueing
    past the cap drops the **oldest** entries (the newest detection is the most
    actionable), and stale entries are pruned on every pass.
    """

    _SUFFIX = ".json"

    def __init__(
        self,
        directory: Path,
        *,
        max_entries: int = 1000,
        max_age_seconds: int = 604_800,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._dir = Path(directory)
        self._max_entries = max(1, max_entries)
        self._max_age = max(1, max_age_seconds)
        self._now = now

    @property
    def directory(self) -> Path:
        return self._dir

    def _ensure_dir(self) -> None:
        # 0700: the spool holds alert bodies; only the ossec user may read it.
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def entries(self) -> list[Path]:
        """Return spooled files, oldest first."""
        if not self._dir.is_dir():
            return []
        return sorted(p for p in self._dir.iterdir() if p.is_file() and p.suffix == self._SUFFIX)

    def prune(self) -> int:
        """Drop entries older than ``max_age_seconds``. Returns the count removed."""
        cutoff = self._now() - self._max_age
        removed = 0
        for path in self.entries():
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except OSError:
                continue
        if removed:
            log("spool_pruned_expired", dropped=removed)
        return removed

    def enqueue(self, raw_body: bytes) -> bool:
        """Persist ``raw_body`` for a later attempt. Returns ``True`` on success."""
        try:
            self._ensure_dir()
            self.prune()
            self._enforce_capacity(incoming=1)
            # Timestamp + monotonic sequence keeps lexical order chronological
            # even for entries written within the same millisecond.
            global _SEQUENCE
            _SEQUENCE += 1
            name = (
                f"{int(self._now() * 1000):015d}-{_SEQUENCE:09d}-{uuid.uuid4().hex}{self._SUFFIX}"
            )
            target = self._dir / name
            tmp = target.with_suffix(".tmp")
            # Write-then-rename so a crashed write never yields a partial entry.
            with open(tmp, "wb") as handle:
                handle.write(raw_body)
            os.chmod(tmp, 0o600)
            tmp.replace(target)
            return True
        except OSError as exc:
            log("spool_write_failed", error_type=type(exc).__name__)
            return False

    def _enforce_capacity(self, *, incoming: int) -> None:
        entries = self.entries()
        overflow = len(entries) + incoming - self._max_entries
        dropped = 0
        for path in entries[: max(0, overflow)]:
            try:
                path.unlink()
                dropped += 1
            except OSError:
                continue
        if dropped:
            log("spool_overflow_dropped_oldest", dropped=dropped)

    def read(self, path: Path) -> bytes | None:
        try:
            return path.read_bytes()
        except OSError as exc:
            log("spool_read_failed", error_type=type(exc).__name__)
            return None

    def discard(self, path: Path) -> None:
        with suppress(OSError):
            path.unlink()

    def pending(self) -> int:
        return len(self.entries())


# ---------------------------------------------------------------------------
# HTTP delivery
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SenderResponse:
    """Minimal transport-level response used by :func:`deliver`."""

    status: int
    error_type: str | None = None


class UrllibSender:
    """Default transport: ``urllib`` POST with an explicit timeout.

    Kept behind a tiny interface so tests inject a fake and never touch the
    network (DEVELOPMENT_PLAN.md testing strategy: fakes only).
    """

    def __call__(
        self, url: str, body: bytes, headers: Mapping[str, str], timeout: float, verify_tls: bool
    ) -> SenderResponse:
        request = urllib.request.Request(  # scheme validated in load_config
            url, data=body, headers=dict(headers), method="POST"
        )
        context = None
        if url.lower().startswith("https://") and not verify_tls:
            import ssl

            context = ssl._create_unverified_context()  # opt-in lab-only escape hatch
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return SenderResponse(status=int(response.status))
        except urllib.error.HTTPError as exc:
            return SenderResponse(status=int(exc.code))
        except urllib.error.URLError as exc:
            return SenderResponse(status=0, error_type=type(exc.reason).__name__)
        except (TimeoutError, OSError) as exc:
            return SenderResponse(status=0, error_type=type(exc).__name__)


Sender = Callable[[str, bytes, Mapping[str, str], float, bool], SenderResponse]


@dataclass(frozen=True)
class DeliveryOutcome:
    """Result of attempting to deliver one alert body."""

    delivered: bool
    retryable: bool
    status: int
    attempts: int
    error_type: str | None = None


def build_request_headers(config: IntegratorConfig) -> dict[str, str]:
    """Headers for the ingest call — the existing ``X-API-Key`` contract."""
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "wazuh-integrator-custom-triage/1.0",
        "X-API-Key": config.api_key,
    }


def _jittered(delay: float, rng: random.Random) -> float:
    return delay * rng.uniform(0.5, 1.0)


def deliver(
    body: bytes,
    config: IntegratorConfig,
    *,
    sender: Sender,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> DeliveryOutcome:
    """POST ``body`` to the ingest endpoint with bounded retries.

    Retries transient failures (network errors and
    :data:`RETRYABLE_STATUS`) with capped exponential backoff + jitter. A
    non-retryable HTTP status (e.g. 401 auth failure, 422 validation) fails
    immediately and is **not** buffered — buffering an alert the API will never
    accept would only grow the spool forever.
    """
    rng = rng or random.Random()
    headers = build_request_headers(config)
    last = SenderResponse(status=0, error_type="not_attempted")

    for attempt in range(1, config.max_attempts + 1):
        try:
            last = sender(
                config.ingest_url, body, headers, config.timeout_seconds, config.verify_tls
            )
        except Exception as exc:  # defensive: a transport must never crash the manager
            last = SenderResponse(status=0, error_type=type(exc).__name__)

        if 200 <= last.status < 300:
            return DeliveryOutcome(
                delivered=True, retryable=False, status=last.status, attempts=attempt
            )

        transient = last.status == 0 or last.status in RETRYABLE_STATUS
        if not transient:
            return DeliveryOutcome(
                delivered=False,
                retryable=False,
                status=last.status,
                attempts=attempt,
                error_type=last.error_type,
            )

        if attempt < config.max_attempts and config.backoff_seconds > 0:
            sleep(_jittered(config.backoff_seconds * (2 ** (attempt - 1)), rng))

    return DeliveryOutcome(
        delivered=False,
        retryable=True,
        status=last.status,
        attempts=config.max_attempts,
        error_type=last.error_type,
    )


def flush_spool(
    spool: Spool,
    config: IntegratorConfig,
    *,
    sender: Sender,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> tuple[int, int]:
    """Attempt to deliver buffered alerts, oldest first.

    Returns ``(delivered, remaining)``. Stops at the first transient failure so
    a still-down API is not hammered, and drops entries the API permanently
    rejects (they can never succeed).
    """
    spool.prune()
    delivered = 0
    for path in spool.entries()[: config.spool_flush_batch]:
        body = spool.read(path)
        if body is None:
            spool.discard(path)
            continue
        outcome = deliver(body, config, sender=sender, sleep=sleep, rng=rng)
        if outcome.delivered:
            spool.discard(path)
            delivered += 1
            continue
        if not outcome.retryable:
            spool.discard(path)
            log("spool_entry_permanently_rejected", status=outcome.status)
            continue
        break

    remaining = spool.pending()
    if delivered or remaining:
        log("spool_flush", delivered=delivered, remaining=remaining)
    return delivered, remaining


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def _read_alert_file(path: Path) -> tuple[dict[str, object] | None, bytes | None, str | None]:
    try:
        if path.stat().st_size > MAX_ALERT_BYTES:
            return None, None, "alert_too_large"
        raw = path.read_bytes()
    except OSError as exc:
        return None, None, f"unreadable:{type(exc).__name__}"

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, None, "invalid_json"
    if not isinstance(parsed, dict):
        return None, None, "not_an_object"
    return parsed, raw, None


def run(
    argv: list[str],
    env: Mapping[str, str] | None = None,
    *,
    sender: Sender | None = None,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> int:
    """Execute one integrator invocation. Always returns an exit code."""
    _set_log_path(os.environ if env is None else env)

    if len(argv) < 2:
        log("usage_error", reason="missing_alert_file_argument")
        return EXIT_CONFIG_ERROR

    try:
        config = load_config(env)
    except ConfigError as exc:
        # The message is authored above and never interpolates a secret value.
        log("config_error", reason=str(exc))
        return EXIT_CONFIG_ERROR

    sender = sender or UrllibSender()
    spool = Spool(
        config.spool_dir,
        max_entries=config.spool_max_entries,
        max_age_seconds=config.spool_max_age_seconds,
    )

    # 1. Drain anything buffered by earlier invocations (best effort).
    flush_spool(spool, config, sender=sender, sleep=sleep, rng=rng)

    # 2. Handle the alert we were invoked for.
    alert, raw, read_error = _read_alert_file(Path(argv[1]))
    if alert is None or raw is None:
        log("alert_unreadable", reason=read_error)
        return EXIT_OK

    forward, reason = should_forward(alert, config)
    rule = alert.get("rule") if isinstance(alert.get("rule"), Mapping) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), Mapping) else {}
    rule_id = str(rule.get("id", "")) if isinstance(rule, Mapping) else ""
    rule_level = rule.get("level") if isinstance(rule, Mapping) else None
    agent_id = str(agent.get("id", "")) if isinstance(agent, Mapping) else ""

    if not forward:
        log("alert_filtered", reason=reason, rule_id=rule_id, rule_level=rule_level)
        return EXIT_OK

    outcome = deliver(raw, config, sender=sender, sleep=sleep, rng=rng)
    if outcome.delivered:
        log(
            "alert_forwarded",
            status=outcome.status,
            attempts=outcome.attempts,
            rule_id=rule_id,
            rule_level=rule_level,
            agent_id=agent_id,
            endpoint=sanitize_url(config.ingest_url),
        )
        return EXIT_OK

    if outcome.retryable:
        buffered = spool.enqueue(raw)
        log(
            "alert_buffered" if buffered else "alert_dropped_spool_unavailable",
            status=outcome.status,
            attempts=outcome.attempts,
            error_type=outcome.error_type,
            rule_id=rule_id,
            pending=spool.pending(),
            endpoint=sanitize_url(config.ingest_url),
        )
        return EXIT_OK

    log(
        "alert_rejected",
        status=outcome.status,
        attempts=outcome.attempts,
        rule_id=rule_id,
        endpoint=sanitize_url(config.ingest_url),
    )
    return EXIT_OK


def main() -> int:  # pragma: no cover - thin CLI wrapper
    return run(sys.argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
