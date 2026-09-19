"""Unit tests for the ``scripts/send_test_alert.py`` replay utility.

The script is loaded from its file location (it is not an installed
package). All HTTP is faked — no test here touches the network.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "send_test_alert.py"
FIXTURE_PATH = REPO_ROOT / "app" / "tests" / "fixtures" / "01_wazuh_ssh_brute_force.json"


@pytest.fixture(scope="module")
def script() -> Any:
    """Import the replay script from ``scripts/`` (stdlib-only module)."""
    assert SCRIPT_PATH.is_file(), f"missing replay script: {SCRIPT_PATH}"
    spec = importlib.util.spec_from_file_location("send_test_alert", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _accepted_body() -> dict[str, Any]:
    """A 202 ingest response shaped like the real contract (fixture 01 pins)."""
    return {
        "status": "accepted",
        "duplicate": False,
        "dedupe_status": "new_generation",
        "alert_id": "01234567-89ab-cdef-0123-456789abcdef",
        "risk": {"score": 43, "tier": "low"},
        "decision": {"action": "monitor", "severity": None},
        "dedupe": {"occurrences": 1, "duplicate_deliveries": 0},
        "normalized": {"source_event": {"full_log": "Failed password for root"}},
    }


# --- Script-level constraints ------------------------------------------------


def test_script_is_stdlib_only() -> None:
    """The replay utility must not add dependencies (repo-root scripts duty)."""
    tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= stdlib, f"non-stdlib imports: {sorted(imported - stdlib)}"


# --- Argument parsing --------------------------------------------------------


def test_parser_defaults(script: Any) -> None:
    """Positional fixture; documented defaults for every flag."""
    args = script.build_parser().parse_args(["fixture.json"])
    assert args.fixture == "fixture.json"
    assert args.base_url == "http://127.0.0.1:8000"
    assert args.api_key is None
    assert args.repeat == 1
    assert args.timeout == 30.0


def test_parser_accepts_all_options(script: Any) -> None:
    """Every documented flag parses with the right type."""
    args = script.build_parser().parse_args(
        [
            "docs/sample-alerts/01_wazuh_ssh_brute_force.json",
            "--base-url",
            "http://localhost:9000/",
            "--api-key",
            "secret-key",
            "--repeat",
            "3",
            "--timeout",
            "5",
        ]
    )
    assert args.fixture.endswith("01_wazuh_ssh_brute_force.json")
    assert args.base_url == "http://localhost:9000/"
    assert args.api_key == "secret-key"
    assert args.repeat == 3
    assert args.timeout == 5.0


def test_main_rejects_bad_repeat_and_timeout(script: Any) -> None:
    """argparse usage errors exit 2 (nothing is sent)."""
    with pytest.raises(SystemExit) as exc:
        script.main(["fixture.json", "--repeat", "0"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        script.main(["fixture.json", "--timeout", "0"])
    assert exc.value.code == 2


# --- URL construction --------------------------------------------------------


def test_build_ingest_url(script: Any) -> None:
    """The ingest route is appended exactly once, slash-tolerant."""
    assert (
        script.build_ingest_url("http://127.0.0.1:8000")
        == "http://127.0.0.1:8000/api/v1/alerts/ingest"
    )
    assert (
        script.build_ingest_url("http://127.0.0.1:8000/")
        == "http://127.0.0.1:8000/api/v1/alerts/ingest"
    )


# --- Fixture loading ---------------------------------------------------------


def test_load_fixture_real_sample(script: Any) -> None:
    """The shipped fixture loads as the object the API expects."""
    payload = script.load_fixture(FIXTURE_PATH)
    assert payload["rule"]["id"] == "5710"
    assert payload["agent"]["id"] == "001"


def test_load_fixture_missing_file(script: Any, tmp_path: Path) -> None:
    """A missing path is a clean FileNotFoundError (exit 2 upstream)."""
    with pytest.raises(FileNotFoundError):
        script.load_fixture(tmp_path / "nope.json")


def test_load_fixture_invalid_json(script: Any, tmp_path: Path) -> None:
    """Malformed JSON is a clean config error, never a traceback leak."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(script.SendTestAlertError, match="not valid JSON"):
        script.load_fixture(bad)


def test_load_fixture_non_object(script: Any, tmp_path: Path) -> None:
    """The ingest body must be one JSON object, not a list/scalar."""
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(script.SendTestAlertError, match="JSON object"):
        script.load_fixture(bad)


# --- API key handling --------------------------------------------------------


def test_resolve_api_key_cli_wins(script: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit --api-key beats the environment."""
    monkeypatch.setenv("TRIAGE_INGEST_API_KEY", "env-key")
    assert script.resolve_api_key("cli-key") == "cli-key"


def test_resolve_api_key_env_fallback(script: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --api-key the documented env var is used."""
    monkeypatch.setenv("TRIAGE_INGEST_API_KEY", "env-key")
    assert script.resolve_api_key(None) == "env-key"


def test_resolve_api_key_missing(script: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """No key anywhere is a clean error naming the env var (not a traceback)."""
    monkeypatch.delenv("TRIAGE_INGEST_API_KEY", raising=False)
    with pytest.raises(script.SendTestAlertError, match="TRIAGE_INGEST_API_KEY"):
        script.resolve_api_key(None)
    with pytest.raises(script.SendTestAlertError, match="TRIAGE_INGEST_API_KEY"):
        script.resolve_api_key("   ")


# --- HTTP layer (faked urlopen — no real network) ----------------------------


class _FakeResponse:
    """Minimal urlopen context manager returning canned bytes + status."""

    def __init__(self, *, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


def test_post_json_sends_ingest_contract(script: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """POST + JSON body + X-API-Key header to the exact ingest URL."""
    seen: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: float | None = None) -> _FakeResponse:
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        seen["content_type"] = request.get_header("Content-type")
        seen["api_key"] = request.get_header("X-api-key")
        seen["data"] = request.data
        seen["timeout"] = timeout
        return _FakeResponse(status=202, body=b'{"status":"accepted"}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    status, body = script.post_json(
        "http://127.0.0.1:8000/api/v1/alerts/ingest",
        {"id": "x"},
        "test-key",
        30.0,
    )
    assert status == 202
    assert body == {"status": "accepted"}
    assert seen["url"] == "http://127.0.0.1:8000/api/v1/alerts/ingest"
    assert seen["method"] == "POST"
    assert seen["content_type"] == "application/json"
    assert seen["api_key"] == "test-key"
    assert json.loads(seen["data"].decode("utf-8")) == {"id": "x"}
    assert seen["timeout"] == 30.0


def test_post_json_http_error_returns_status_and_envelope(
    script: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """API rejections (401/422/…) are returned for reporting, not raised."""

    def fake_urlopen(
        request: Any,
        timeout: float | None = None,  # noqa: ARG001 - urlopen kwarg
    ) -> Any:
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            {},
            io.BytesIO(b'{"error":{"code":"unauthorized","message":"invalid API key"}}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    status, body = script.post_json("http://x/ingest", {"id": "x"}, "bad", 5.0)
    assert status == 401
    assert body == {"error": {"code": "unauthorized", "message": "invalid API key"}}


def test_post_json_transport_failure_raises(script: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Connection/timeout failures become TransportError (exit 1 upstream)."""

    def fake_urlopen(
        _request: Any,
        timeout: float | None = None,  # noqa: ARG001 - urlopen kwarg
    ) -> Any:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(script.TransportError, match="connection refused"):
        script.post_json("http://x/ingest", {"id": "x"}, "k", 5.0)


def test_post_json_non_json_body_is_returned_raw(
    script: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-JSON body (proxy/gateway) never crashes the reporter."""
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *_args, **_kwargs: _FakeResponse(status=502, body=b"Bad Gateway"),
    )
    status, body = script.post_json("http://x/ingest", {"id": "x"}, "k", 5.0)
    assert status == 502
    assert body == "Bad Gateway"


# --- Response summaries ------------------------------------------------------


def test_summarize_accepted_response(script: Any) -> None:
    """The 202 line carries the demo fields — and never full_log."""
    line = script.summarize_response(202, _accepted_body())
    assert "HTTP 202" in line
    assert "status=accepted" in line
    assert "duplicate=false" in line
    assert "alert_id=01234567-89ab-cdef-0123-456789abcdef" in line
    assert "score=43" in line
    assert "tier=low" in line
    assert "action=monitor" in line
    assert "dedupe_status=new_generation" in line
    assert "Failed password" not in line
    assert "normalized" not in line


def test_summarize_duplicate_response(script: Any) -> None:
    """The idempotent 200 line shows duplicate=true + the same alert id."""
    body = {
        "status": "duplicate",
        "duplicate": True,
        "dedupe_status": "exact_duplicate",
        "alert_id": "01234567-89ab-cdef-0123-456789abcdef",
        "risk": None,
        "decision": None,
    }
    line = script.summarize_response(200, body)
    assert "HTTP 200" in line
    assert "duplicate=true" in line
    assert "dedupe_status=exact_duplicate" in line
    assert "score=" not in line  # absent fields are omitted, never invented


def test_summarize_error_envelope(script: Any) -> None:
    """API error envelopes surface code + message for troubleshooting."""
    line = script.summarize_response(
        422,
        {"error": {"code": "validation_error", "message": "alert schema validation failed"}},
    )
    assert "HTTP 422" in line
    assert "validation_error" in line
    assert "alert schema validation failed" in line
    flat = script.summarize_response(
        422, {"code": "validation_error", "message": "alert schema validation failed"}
    )
    assert "validation_error" in flat


def test_summarize_tolerates_missing_and_raw_bodies(script: Any) -> None:
    """Partial dicts and non-JSON bodies never raise."""
    assert "HTTP 202" in script.summarize_response(202, {})
    assert "HTTP 502" in script.summarize_response(502, "Bad Gateway")
    assert "HTTP 200" in script.summarize_response(200, None)


# --- Delivery loop -----------------------------------------------------------


def test_deliver_repeat_reports_each_delivery(
    script: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """--repeat 2 against the real fixture shape: 202 then idempotent 200."""
    calls = {"count": 0}

    def fake_post(url: str, payload: dict[str, Any], key: str, _timeout: float) -> Any:
        calls["count"] += 1
        assert url.endswith("/api/v1/alerts/ingest")
        assert payload["rule"]["id"] == "5710"
        assert key == "k"
        if calls["count"] == 1:
            return 202, _accepted_body()
        return 200, {
            "status": "duplicate",
            "duplicate": True,
            "dedupe_status": "exact_duplicate",
            "alert_id": "01234567-89ab-cdef-0123-456789abcdef",
        }

    monkeypatch.setattr(script, "post_json", fake_post)
    exit_code = script.deliver(
        fixture_path=FIXTURE_PATH,
        base_url="http://127.0.0.1:8000",
        api_key="k",
        repeat=2,
        timeout=5.0,
    )
    assert exit_code == 0
    assert calls["count"] == 2
    out = capsys.readouterr().out
    assert "[1/2] HTTP 202" in out
    assert "[2/2] HTTP 200" in out
    assert "duplicate=true" in out
    assert "OK: all 2 deliveries" in out


def test_deliver_api_rejection_exits_1(
    script: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A non-202/200 status fails the run and names the envelope."""
    monkeypatch.setattr(script, "post_json", lambda *_a, **_k: (422, {"code": "validation_error"}))
    exit_code = script.deliver(
        fixture_path=FIXTURE_PATH,
        base_url="http://127.0.0.1:8000",
        api_key="k",
        repeat=1,
        timeout=5.0,
    )
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "HTTP 422" in out
    assert "FAIL:" in out


def test_deliver_transport_error_exits_1(
    script: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unreachable API is a reported failure, not a traceback."""
    monkeypatch.setattr(
        script,
        "post_json",
        lambda *_a, **_k: (_ for _ in ()).throw(
            script.TransportError("URLError: connection refused")
        ),
    )
    exit_code = script.deliver(
        fixture_path=FIXTURE_PATH,
        base_url="http://127.0.0.1:8000",
        api_key="k",
        repeat=1,
        timeout=5.0,
    )
    assert exit_code == 1
    assert "transport_error" in capsys.readouterr().out


# --- main() wiring -----------------------------------------------------------


def test_main_success(
    script: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Config → key → deliver chain returns 0 on an accepted alert."""
    monkeypatch.setenv("TRIAGE_INGEST_API_KEY", "env-key")
    monkeypatch.setattr(script, "post_json", lambda *_a, **_k: (202, _accepted_body()))
    assert script.main([str(FIXTURE_PATH)]) == 0
    assert "HTTP 202" in capsys.readouterr().out


def test_main_missing_key_exits_2(
    script: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No --api-key and no env var: clean exit-2 error on stderr."""
    monkeypatch.delenv("TRIAGE_INGEST_API_KEY", raising=False)
    assert script.main([str(FIXTURE_PATH)]) == 2
    assert "TRIAGE_INGEST_API_KEY" in capsys.readouterr().err


def test_main_missing_fixture_exits_2(
    script: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A bad fixture path is a clean exit-2 error on stderr."""
    monkeypatch.setenv("TRIAGE_INGEST_API_KEY", "env-key")
    assert script.main(["does-not-exist.json"]) == 2
    assert "Fixture not found" in capsys.readouterr().err


def test_main_never_prints_api_key(
    script: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The key (flag or env) must not appear on stdout or stderr, ever."""
    sentinel = "sentinel-key-4f8c2a9e"
    monkeypatch.setattr(
        script,
        "post_json",
        lambda *_a, **_k: (_ for _ in ()).throw(script.TransportError("down")),
    )
    assert script.main([str(FIXTURE_PATH), "--api-key", sentinel]) == 1
    captured = capsys.readouterr()
    assert sentinel not in captured.out
    assert sentinel not in captured.err
