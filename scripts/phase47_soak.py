"""Phase 4.7 performance soak harness for the SOC triage ingest API."""

from __future__ import annotations

import argparse
import copy
import json
import socket
import statistics
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_COUNT = 100
DEFAULT_TIMEOUT = 30.0

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
FIXTURE_PATH = (
    REPO_ROOT / "app" / "tests" / "fixtures" / "01_wazuh_ssh_brute_force.json"
)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    rank = (len(ordered) - 1) * pct
    lower = int(rank)
    upper = min(lower + 1, len(ordered))
    fraction = rank - lower

    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def load_fixture() -> dict[str, Any]:
    with FIXTURE_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise TypeError(f"Fixture must contain a JSON object: {FIXTURE_PATH}")

    return payload


def make_payload(
    template: dict[str, Any],
    sequence: int,
    run_id: str,
) -> dict[str, Any]:
    """Create a unique synthetic alert for this soak run."""
    payload = copy.deepcopy(template)

    payload["id"] = f"phase47-{run_id}-{sequence:08d}"

    return payload


def post_json(
    url: str,
    payload: dict[str, Any],
    api_key: str,
    timeout: float,
) -> tuple[int, float, str]:
    """POST one request with urllib and measure the wall-clock round-trip."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
    )

    started = time.perf_counter()

    try:
        with urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            response_body = response.read().decode("utf-8", errors="replace")
    except HTTPError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        detail = error.read().decode("utf-8", errors="replace")
        return error.code, elapsed_ms, detail
    except TimeoutError:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return 0, elapsed_ms, "transport_error: timeout"
    except URLError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        reason = error.reason

        if isinstance(reason, (socket.timeout, TimeoutError)):
            return 0, elapsed_ms, "transport_error: timeout"

        return 0, elapsed_ms, f"transport_error: {reason}"[:300]
    except OSError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return 0, elapsed_ms, f"transport_error: {error}"[:300]

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return status, elapsed_ms, response_body


def run(args: argparse.Namespace) -> int:
    template = load_fixture()
    run_id = uuid.uuid4().hex[:12]

    url = f"{args.base_url.rstrip('/')}/api/v1/alerts/ingest"

    print()
    print("=== Phase 4.7 Performance Soak ===")
    print(f"Run ID   : {run_id}")
    print(f"Endpoint : {url}")
    print(f"Alerts   : {args.count}")
    print(f"Timeout  : {args.timeout}s")
    print(f"Fixture  : {FIXTURE_PATH}")
    print()

    latencies: list[float] = []
    status_counts: dict[int, int] = {}
    errors: list[str] = []

    started = time.perf_counter()

    for sequence in range(1, args.count + 1):
        payload = make_payload(template, sequence, run_id)

        status, elapsed_ms, response_body = post_json(
            url=url,
            payload=payload,
            api_key=args.api_key,
            timeout=args.timeout,
        )

        latencies.append(elapsed_ms)
        status_counts[status] = status_counts.get(status, 0) + 1

        if status != 202:
            errors.append(
                f"#{sequence}: HTTP {status} after {elapsed_ms:.2f} ms: "
                f"{response_body[:300]}"
            )

        if args.progress and (
            sequence == 1 or sequence == args.count or sequence % args.progress == 0
        ):
            print(
                f"[{sequence:>6}/{args.count}] "
                f"status={status:<3} latency={elapsed_ms:>9.2f} ms"
            )

    total_seconds = time.perf_counter() - started
    successful = status_counts.get(202, 0)

    print()
    print("=== Results ===")

    if not latencies:
        print("No requests were completed.")
        return 1

    print(f"Total requests : {len(latencies)}")
    print(f"Successful 202 : {successful}")
    print(f"Errors         : {len(errors)}")
    print(f"Total time     : {total_seconds:.3f} s")
    print(f"Throughput     : {len(latencies) / total_seconds:.2f} alerts/s")
    print(f"Mean latency   : {statistics.mean(latencies):.2f} ms")
    print(f"Median (p50)   : {percentile(latencies, 0.50):.2f} ms")
    print(f"p95 latency    : {percentile(latencies, 0.95):.2f} ms")
    print(f"p99 latency    : {percentile(latencies, 0.99):.2f} ms")
    print(f"Max latency    : {max(latencies):.2f} ms")

    print()
    print("Status counts:")
    for status in sorted(status_counts):
        label = "transport error" if status == 0 else str(status)
        print(f"  {label}: {status_counts[status]}")

    expected_rate = 10_000 / 86_400
    print()
    print(f"10k alerts/day average arrival rate: {expected_rate:.3f} alerts/s")

    if errors:
        print()
        print("First failures:")
        for error in errors[:10]:
            print(f"  {error}")
        return 1

    print()
    print("PASS: all replayed alerts returned HTTP 202.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
    )
    parser.add_argument(
        "--api-key",
        required=True,
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_COUNT,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
    )
    parser.add_argument(
        "--progress",
        type=int,
        default=25,
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    if args.progress < 1:
        parser.error("--progress must be at least 1")

    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
