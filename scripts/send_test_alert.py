"""Replay a synthetic alert fixture into the Triage API ingest endpoint.

Minimal demo/lab utility (Phase 1 backlog item ``scripts/send_test_alert``):

* reads one Wazuh-shaped JSON fixture (see ``docs/sample-alerts/``),
* POSTs it unchanged to ``POST /api/v1/alerts/ingest`` with ``X-API-Key`` auth,
* prints one allow-listed summary line per delivery.

Standard library only — no third-party dependencies, Windows + Linux portable.
The API key is read from ``--api-key`` or the ``TRIAGE_INGEST_API_KEY``
environment variable and is never printed (not even in error output).

Response contract (``app/src/soc_triage/api/alerts.py``):

* new/recurring alert → HTTP 202 ``{"status": "accepted", ...}``
* exact re-delivery   → HTTP 200 ``{"status": "duplicate", "duplicate": true,
  ...}`` with the *original* ``alert_id`` (idempotent)

So ``--repeat N`` replays identical bytes N times: the first delivery returns
202 and every further delivery returns 200 with ``duplicate: true``. That is
the dedupe/idempotency demo, not a recurrence demo — recurrence needs distinct
event ids (see ``scripts/phase47_soak.py`` for the id-varying shape).

Exit codes: 0 when every delivery returned 202/200, 1 when any delivery
failed, 2 for usage/config errors (missing fixture, bad JSON, missing key).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
INGEST_PATH = "/api/v1/alerts/ingest"
API_KEY_ENV_VAR = "TRIAGE_INGEST_API_KEY"
DEFAULT_TIMEOUT_SECONDS = 30.0

#: Deliveries with either status count as success (ARCHITECTURE.md §6).
SUCCESS_STATUSES = frozenset({200, 202})


class SendTestAlertError(Exception):
    """Usage/config error (missing fixture, bad JSON, missing API key)."""


class TransportError(Exception):
    """The request could not be completed (connection/timeout/DNS, …)."""


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser (mirrors the phase47 flag names where shared)."""
    parser = argparse.ArgumentParser(
        description="Replay a synthetic alert fixture into POST /api/v1/alerts/ingest.",
    )
    parser.add_argument(
        "fixture",
        help="Path to a Wazuh-shaped JSON fixture "
        "(e.g. docs/sample-alerts/01_wazuh_ssh_brute_force.json)",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Triage API base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help=f"X-API-Key value; falls back to ${API_KEY_ENV_VAR} (never printed)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Replay the identical fixture N times "
        "(first: 202; rest: 200 duplicate:true). Default: 1",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
    )
    return parser


def build_ingest_url(base_url: str) -> str:
    """Join a base URL with the ingest route (tolerates a trailing slash)."""
    return base_url.rstrip("/") + INGEST_PATH


def load_fixture(path: str | Path) -> dict[str, Any]:
    """Load a fixture file; it must contain one JSON object.

    Raises:
        FileNotFoundError: when the path does not exist or is not a file.
        SendTestAlertError: when the content is not valid JSON or not an object.
    """
    fixture_path = Path(path)
    if not fixture_path.is_file():
        raise FileNotFoundError(f"Fixture not found: {fixture_path}")
    try:
        payload = json.loads(fixture_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SendTestAlertError(f"Fixture is not valid JSON: {fixture_path} ({exc})") from exc
    if not isinstance(payload, dict):
        raise SendTestAlertError(f"Fixture must contain a JSON object: {fixture_path}")
    return payload


def resolve_api_key(cli_value: str | None) -> str:
    """Resolve the ingest key from ``--api-key`` or the environment.

    Raises:
        SendTestAlertError: when no usable key is available.
    """
    if cli_value and cli_value.strip():
        return cli_value.strip()
    env_value = os.environ.get(API_KEY_ENV_VAR, "")
    if env_value and env_value.strip():
        return env_value.strip()
    raise SendTestAlertError(
        f"No API key: pass --api-key or set ${API_KEY_ENV_VAR} "
        "(see .env.example: TRIAGE_INGEST_API_KEY)"
    )


def post_json(
    url: str,
    payload: dict[str, Any],
    api_key: str,
    timeout: float,
) -> tuple[int, Any]:
    """POST one JSON payload; return ``(status_code, parsed_body)``.

    HTTP error statuses (401/422/…) are returned, not raised, so the caller
    can report the API's error envelope. Transport failures raise
    :class:`TransportError`. The body is parsed as JSON when possible and
    returned raw otherwise.

    Raises:
        TransportError: on connection errors, timeouts, and DNS failures.
    """
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except OSError:
            raw = ""
    except (urllib.error.URLError, OSError) as exc:
        raise TransportError(f"{type(exc).__name__}: {exc}") from exc
    try:
        parsed: Any = json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError:
        parsed = raw
    return status, parsed


def _nested(body: Any, *keys: str) -> Any:
    """Read nested dict keys defensively (None when absent/not a dict)."""
    current = body
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def summarize_response(status: int, body: Any) -> str:
    """Render one allow-listed summary line for a delivery.

    Only stable contract fields are shown (never ``normalized``, which
    carries ``full_log``). Missing fields are omitted, never invented.
    """
    parts = [f"HTTP {status}"]
    if not isinstance(body, dict):
        text = "" if body is None else str(body)
        if text:
            parts.append(f"body={text[:160]!r}")
        return " ".join(parts)
    for key in ("status", "duplicate", "dedupe_status", "alert_id"):
        value = body.get(key)
        if value is None:
            continue
        if isinstance(value, bool):
            value = str(value).lower()
        parts.append(f"{key}={value}")
    score = _nested(body, "risk", "score")
    tier = _nested(body, "risk", "tier")
    if score is not None or tier is not None:
        parts.append(f"score={score} tier={tier}")
    action = _nested(body, "decision", "action")
    severity = _nested(body, "decision", "severity")
    if action is not None:
        parts.append(f"action={action}" + (f" severity={severity}" if severity else ""))
    occurrences = _nested(body, "dedupe", "occurrences")
    if occurrences is not None:
        parts.append(f"occurrences={occurrences}")
    error = body.get("error")
    if isinstance(error, dict):  # shared envelope: {"error": {"code", "message"}}
        parts.append(f"error={error.get('code')}: {error.get('message')}")
    elif body.get("code") is not None or body.get("message") is not None:
        parts.append(f"error={body.get('code')}: {body.get('message')}")
    return " ".join(parts)


def deliver(
    *,
    fixture_path: str | Path,
    base_url: str,
    api_key: str,
    repeat: int,
    timeout: float,
) -> int:
    """Replay the fixture ``repeat`` times; return the process exit code.

    Prints one summary line per delivery plus a final result line. Returns 0
    when every delivery returned 202/200, else 1. Never prints the API key.
    """
    payload = load_fixture(fixture_path)
    url = build_ingest_url(base_url)
    failures = 0
    for sequence in range(1, repeat + 1):
        try:
            status, body = post_json(url, payload, api_key, timeout)
        except TransportError as exc:
            failures += 1
            print(f"[{sequence}/{repeat}] transport_error: {exc}")
            continue
        print(f"[{sequence}/{repeat}] {summarize_response(status, body)}")
        if status not in SUCCESS_STATUSES:
            failures += 1
    if failures:
        print(f"FAIL: {failures}/{repeat} deliveries did not return 202/200.")
        return 1
    print(f"OK: all {repeat} deliveries returned 202/200.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code (2 on usage errors)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    try:
        api_key = resolve_api_key(args.api_key)
    except SendTestAlertError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        return deliver(
            fixture_path=args.fixture,
            base_url=args.base_url,
            api_key=api_key,
            repeat=args.repeat,
            timeout=args.timeout,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except SendTestAlertError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
