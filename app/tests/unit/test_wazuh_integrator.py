"""Unit tests for the Wazuh integrator script (Phase 4.2).

The script under test lives outside the Python package (it is deployed into
the Wazuh manager image at ``/var/ossec/integrations/``), so it is imported
here by path. Every test uses fakes: **no live Wazuh manager, no network I/O,
no real API** is required (DEVELOPMENT_PLAN.md testing strategy).

Coverage:

* environment-only configuration (no secrets in argv/ossec.conf, placeholder
  rejection, validation of every tunable)
* the existing ``X-API-Key`` auth contract is sent unchanged
* rule-level / rule-id / group forwarding filters
* retry semantics: transient vs permanent failures
* local buffering, bounded spool, ordered flush, replay after recovery
* no secrets or alert bodies in logs
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
INTEGRATOR_DIR = REPO_ROOT / "wazuh" / "integrator"
INTEGRATOR_PY = INTEGRATOR_DIR / "custom-triage.py"
INTEGRATOR_SH = INTEGRATOR_DIR / "custom-triage"
OSSEC_CONF = REPO_ROOT / "wazuh" / "config" / "ossec.conf"
INSTALL_SCRIPT = REPO_ROOT / "wazuh" / "entrypoint-scripts" / "10-install-triage-integration.sh"
SAMPLE_ALERTS = REPO_ROOT / "docs" / "sample-alerts"

TEST_API_KEY = "integrator-test-key-not-a-real-secret"


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("wazuh_custom_triage", INTEGRATOR_PY)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


integrator = _load_module()


BASE_ENV: dict[str, str] = {
    "TRIAGE_API_BASE_URL": "http://triage-api:8000",
    "TRIAGE_INGEST_API_KEY": TEST_API_KEY,
}


def make_env(**overrides: str) -> dict[str, str]:
    env = dict(BASE_ENV)
    env.update(overrides)
    return env


def make_alert(
    level: int = 10,
    rule_id: str = "5710",
    groups: list[str] | None = None,
) -> dict:
    return {
        "timestamp": "2026-08-29T10:15:29.000+0000",
        "rule": {
            "id": rule_id,
            "level": level,
            "description": "sshd: brute force trying to get access to the system.",
            "groups": groups if groups is not None else ["syslog", "sshd", "authentication_failed"],
        },
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "data": {"srcip": "203.0.113.42"},
    }


class FakeSender:
    """Scripted transport: no sockets are ever opened."""

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
        verify_tls: bool,
    ) -> Any:
        self.calls.append(
            {
                "url": url,
                "body": body,
                "headers": dict(headers),
                "timeout": timeout,
                "verify_tls": verify_tls,
            }
        )

        response = self._responses[min(len(self.calls) - 1, len(self._responses) - 1)]
        if isinstance(response, Exception):
            raise response
        return response


def ok(status: int = 202) -> Any:
    return integrator.SenderResponse(status=status)


def transient(status: int = 503) -> Any:
    return integrator.SenderResponse(status=status)


def network_error() -> Any:
    return integrator.SenderResponse(status=0, error_type="ConnectionRefusedError")


def write_alert(tmp_path: Path, alert: dict, name: str = "alert.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(alert), encoding="utf-8")
    return path


def make_config(tmp_path: Path, **overrides: str) -> Any:
    env = make_env(
        WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"),
        **overrides,
    )
    return integrator.load_config(env)


# ---------------------------------------------------------------------------
# Configuration: environment only, never argv / ossec.conf
# ---------------------------------------------------------------------------


def test_config_is_built_from_environment_only() -> None:
    config = integrator.load_config(make_env())
    assert config.ingest_url == "http://triage-api:8000/api/v1/alerts/ingest"
    assert config.api_key == TEST_API_KEY
    assert config.min_rule_level == 5
    assert config.verify_tls is True


def test_config_accepts_the_triage_api_url_compatibility_alias() -> None:
    env = {
        "TRIAGE_API_URL": "http://triage-api:8000",
        "TRIAGE_INGEST_API_KEY": TEST_API_KEY,
    }
    assert integrator.load_config(env).ingest_url.endswith("/api/v1/alerts/ingest")


@pytest.mark.parametrize(
    "env",
    [
        {"TRIAGE_INGEST_API_KEY": TEST_API_KEY},  # no base URL
        {"TRIAGE_API_BASE_URL": "http://triage-api:8000"},  # no key
        {
            "TRIAGE_API_BASE_URL": "not-a-url",
            "TRIAGE_INGEST_API_KEY": TEST_API_KEY,
        },
        {
            "TRIAGE_API_BASE_URL": "ftp://x/y",
            "TRIAGE_INGEST_API_KEY": TEST_API_KEY,
        },
        {
            "TRIAGE_API_BASE_URL": "http://triage-api:8000",
            "TRIAGE_INGEST_API_KEY": "   ",
        },
    ],
)
def test_config_rejects_missing_or_malformed_values(env: dict[str, str]) -> None:
    with pytest.raises(integrator.ConfigError):
        integrator.load_config(env)


def test_config_rejects_placeholder_api_key() -> None:
    with pytest.raises(integrator.ConfigError):
        integrator.load_config(make_env(TRIAGE_INGEST_API_KEY="change-me-generate-a-value"))


def test_config_rejects_credentials_embedded_in_the_base_url() -> None:
    with pytest.raises(integrator.ConfigError):
        integrator.load_config(make_env(TRIAGE_API_BASE_URL="http://user:pw@triage-api:8000"))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("WAZUH_INTEGRATOR_MIN_LEVEL", "16"),
        ("WAZUH_INTEGRATOR_MIN_LEVEL", "abc"),
        ("WAZUH_INTEGRATOR_MAX_ATTEMPTS", "0"),
        ("WAZUH_INTEGRATOR_TIMEOUT_SECONDS", "0"),
        ("WAZUH_INTEGRATOR_SPOOL_MAX_ENTRIES", "0"),
        ("WAZUH_INTEGRATOR_VERIFY_TLS", "maybe"),
        ("TRIAGE_INGEST_PATH", "api/v1/alerts/ingest"),
    ],
)
def test_config_validates_tunables(name: str, value: str) -> None:
    with pytest.raises(integrator.ConfigError):
        integrator.load_config(make_env(**{name: value}))


def test_config_repr_never_exposes_the_api_key() -> None:
    config = integrator.load_config(make_env())
    assert TEST_API_KEY not in repr(config)
    assert TEST_API_KEY not in str(config)


def test_sanitize_url_strips_userinfo() -> None:
    assert integrator.sanitize_url("http://user:pw@triage-api:8000/x") == "http://triage-api:8000/x"
    assert "pw" not in integrator.sanitize_url("https://a:pw@h/p?q=1")


# ---------------------------------------------------------------------------
# Auth contract
# ---------------------------------------------------------------------------


def test_request_uses_the_existing_x_api_key_contract() -> None:
    headers = integrator.build_request_headers(integrator.load_config(make_env()))
    assert headers["X-API-Key"] == TEST_API_KEY
    assert headers["Content-Type"] == "application/json"
    # The ingest endpoint authenticates on X-API-Key only; no alternative
    # auth scheme is introduced here.
    assert "Authorization" not in headers


def test_delivery_targets_the_documented_ingest_path(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    sender = FakeSender([ok()])
    integrator.deliver(b"{}", config, sender=sender, sleep=lambda _: None)
    assert sender.calls[0]["url"] == ("http://triage-api:8000/api/v1/alerts/ingest")
    assert sender.calls[0]["headers"]["X-API-Key"] == TEST_API_KEY


# ---------------------------------------------------------------------------
# Forwarding filter
# ---------------------------------------------------------------------------


def test_forwarding_filter_respects_min_level() -> None:
    config = integrator.load_config(make_env(WAZUH_INTEGRATOR_MIN_LEVEL="7"))
    assert integrator.should_forward(make_alert(level=10), config)[0] is True
    forward, reason = integrator.should_forward(make_alert(level=3), config)
    assert forward is False
    assert reason == "below_min_level"


def test_forwarding_filter_excludes_rule_ids_and_groups() -> None:
    config = integrator.load_config(
        make_env(
            WAZUH_INTEGRATOR_EXCLUDED_RULE_IDS="5710,1002",
            WAZUH_INTEGRATOR_EXCLUDED_GROUPS="noisy",
        )
    )
    assert integrator.should_forward(make_alert(rule_id="5710"), config)[1] == "excluded_rule_id"
    assert (
        integrator.should_forward(
            make_alert(rule_id="9999", groups=["noisy"]),
            config,
        )[1]
        == "excluded_group"
    )
    assert integrator.should_forward(make_alert(rule_id="9999"), config)[0] is True


@pytest.mark.parametrize(
    "alert",
    [{}, {"rule": "nope"}, {"rule": {"id": "1", "level": "high"}}],
)
def test_forwarding_filter_rejects_malformed_alert(alert: dict) -> None:
    config = integrator.load_config(make_env())
    assert integrator.should_forward(alert, config)[0] is False


def test_default_filter_matches_the_repository_sample_corpus() -> None:
    """Every sample alert is classified deterministically by rule level.

    The default threshold is level >= 5, which forwards the eight actionable
    samples and filters the two level-3 samples
    (``02_wazuh_ssh_brute_force_success``, ``08_wazuh_ssh_session_opened``)
    as noise. Phase 6.3 added the level-3 benign baseline fixture 08, so the
    filtered golden grew by exactly that sample.
    """
    config = integrator.load_config(make_env())
    samples = sorted(SAMPLE_ALERTS.glob("*.json"))
    assert samples, "sample alert corpus is missing"
    forwarded, filtered = [], []
    for sample in samples:
        alert = json.loads(sample.read_text(encoding="utf-8"))
        decision, reason = integrator.should_forward(alert, config)
        (forwarded if decision else filtered).append(sample.name)
        expected = alert["rule"]["level"] >= config.min_rule_level
        assert decision is expected, (sample.name, reason)
    assert filtered == [
        "02_wazuh_ssh_brute_force_success.json",
        "08_wazuh_ssh_session_opened.json",
    ]
    assert len(forwarded) == len(samples) - 2


# ---------------------------------------------------------------------------
# Retry semantics
# ---------------------------------------------------------------------------


def test_successful_delivery_stops_after_one_attempt(tmp_path: Path) -> None:
    sender = FakeSender([ok(202)])
    outcome = integrator.deliver(
        b"{}",
        make_config(tmp_path),
        sender=sender,
        sleep=lambda _: None,
    )
    assert outcome.delivered is True
    assert outcome.attempts == 1


def test_transient_failure_then_success_is_retried(tmp_path: Path) -> None:
    sender = FakeSender([transient(503), network_error(), ok(202)])
    outcome = integrator.deliver(
        b"{}",
        make_config(tmp_path),
        sender=sender,
        sleep=lambda _: None,
        rng=random.Random(7),
    )
    assert outcome.delivered is True
    assert outcome.attempts == 3


def test_permanent_failure_is_not_retried(tmp_path: Path) -> None:
    """401/422 can never succeed on replay — fail fast, do not buffer."""
    for status in (400, 401, 403, 413, 422):
        sender = FakeSender([integrator.SenderResponse(status=status)])
        outcome = integrator.deliver(
            b"{}",
            make_config(tmp_path),
            sender=sender,
            sleep=lambda _: None,
        )
        assert outcome.delivered is False
        assert outcome.retryable is False
        assert len(sender.calls) == 1, status


def test_retry_budget_is_bounded(tmp_path: Path) -> None:
    sender = FakeSender([transient(503)])
    config = make_config(tmp_path, WAZUH_INTEGRATOR_MAX_ATTEMPTS="4")
    outcome = integrator.deliver(
        b"{}",
        config,
        sender=sender,
        sleep=lambda _: None,
        rng=random.Random(1),
    )
    assert outcome.delivered is False
    assert outcome.retryable is True
    assert len(sender.calls) == 4


def test_transport_exception_never_escapes(tmp_path: Path) -> None:
    sender = FakeSender([RuntimeError("boom")])
    outcome = integrator.deliver(
        b"{}",
        make_config(tmp_path, WAZUH_INTEGRATOR_MAX_ATTEMPTS="1"),
        sender=sender,
    )
    assert outcome.delivered is False
    assert outcome.retryable is True
    assert outcome.error_type == "RuntimeError"


def test_backoff_is_bounded_and_increasing(tmp_path: Path) -> None:
    delays: list[float] = []
    sender = FakeSender([transient(503)])
    config = make_config(
        tmp_path,
        WAZUH_INTEGRATOR_MAX_ATTEMPTS="4",
        WAZUH_INTEGRATOR_BACKOFF_SECONDS="1",
    )
    integrator.deliver(
        b"{}",
        config,
        sender=sender,
        sleep=delays.append,
        rng=random.Random(11),
    )
    assert len(delays) == 3
    assert all(0 < d <= 4.0 for d in delays)


# ---------------------------------------------------------------------------
# Local buffering / spool
# ---------------------------------------------------------------------------


def test_alert_is_buffered_when_the_api_is_unreachable(tmp_path: Path) -> None:
    alert_file = write_alert(tmp_path, make_alert())
    sender = FakeSender([network_error()])
    env = make_env(
        WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"),
        WAZUH_INTEGRATOR_MAX_ATTEMPTS="2",
    )
    code = integrator.run(
        ["custom-triage", str(alert_file)],
        env,
        sender=sender,
        sleep=lambda _: None,
    )
    assert code == 0  # never fails the manager
    spooled = list((tmp_path / "spool").glob("*.json"))
    assert len(spooled) == 1
    assert json.loads(spooled[0].read_text())["rule"]["id"] == "5710"


def test_buffered_alerts_are_replayed_on_the_next_invocation(tmp_path: Path) -> None:
    env = make_env(
        WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"),
        WAZUH_INTEGRATOR_MAX_ATTEMPTS="1",
    )
    first = write_alert(tmp_path, make_alert(rule_id="1111"), "a.json")
    integrator.run(
        ["custom-triage", str(first)],
        env,
        sender=FakeSender([network_error()]),
        sleep=lambda _: None,
    )
    assert len(list((tmp_path / "spool").glob("*.json"))) == 1

    # API recovered: the buffered alert flushes before the new one.
    second = write_alert(tmp_path, make_alert(rule_id="2222"), "b.json")
    sender = FakeSender([ok(202)])
    integrator.run(
        ["custom-triage", str(second)],
        env,
        sender=sender,
        sleep=lambda _: None,
    )

    sent = [json.loads(call["body"])["rule"]["id"] for call in sender.calls]
    assert sent == ["1111", "2222"]
    assert list((tmp_path / "spool").glob("*.json")) == []


def test_spool_flush_preserves_chronological_order(tmp_path: Path) -> None:
    config = make_config(tmp_path, WAZUH_INTEGRATOR_MAX_ATTEMPTS="1")
    spool = integrator.Spool(config.spool_dir)
    for index in range(5):
        spool.enqueue(json.dumps({"n": index}).encode())
    sender = FakeSender([ok(202)])
    delivered, remaining = integrator.flush_spool(
        spool,
        config,
        sender=sender,
        sleep=lambda _: None,
    )
    assert delivered == 5
    assert remaining == 0
    assert [json.loads(c["body"])["n"] for c in sender.calls] == [0, 1, 2, 3, 4]


def test_spool_flush_stops_at_the_first_transient_failure(tmp_path: Path) -> None:
    """A still-down API must not be hammered with the whole backlog."""
    config = make_config(tmp_path, WAZUH_INTEGRATOR_MAX_ATTEMPTS="1")
    spool = integrator.Spool(config.spool_dir)
    for index in range(4):
        spool.enqueue(json.dumps({"n": index}).encode())
    sender = FakeSender([ok(202), transient(503)])
    delivered, remaining = integrator.flush_spool(
        spool,
        config,
        sender=sender,
        sleep=lambda _: None,
    )
    assert delivered == 1
    assert remaining == 3
    assert len(sender.calls) == 2


def test_spool_flush_discards_permanently_rejected_entries(tmp_path: Path) -> None:
    config = make_config(tmp_path, WAZUH_INTEGRATOR_MAX_ATTEMPTS="1")
    spool = integrator.Spool(config.spool_dir)
    spool.enqueue(b'{"bad": true}')
    sender = FakeSender([integrator.SenderResponse(status=422)])
    delivered, remaining = integrator.flush_spool(
        spool,
        config,
        sender=sender,
        sleep=lambda _: None,
    )
    assert (delivered, remaining) == (0, 0)


def test_spool_is_bounded_and_drops_oldest_entries(tmp_path: Path) -> None:
    spool = integrator.Spool(tmp_path / "spool", max_entries=3)
    for index in range(6):
        spool.enqueue(json.dumps({"n": index}).encode())
    remaining = [json.loads(p.read_text())["n"] for p in spool.entries()]
    assert len(remaining) == 3
    assert remaining == [3, 4, 5]


def test_spool_prunes_entries_past_the_age_limit(tmp_path: Path) -> None:
    clock = {"now": 1_000_000.0}
    spool = integrator.Spool(
        tmp_path / "spool",
        max_entries=10,
        max_age_seconds=60,
        now=lambda: clock["now"],
    )
    spool.enqueue(b"{}")
    old = spool.entries()[0]
    os.utime(old, (clock["now"] - 600, clock["now"] - 600))
    assert spool.prune() == 1
    assert spool.entries() == []


@pytest.mark.skipif(sys.platform == "win32", reason="Unix permission bits are POSIX-specific")
def test_spool_directory_and_files_are_owner_only(tmp_path: Path) -> None:
    """Spooled alert bodies must not be world-readable."""
    spool = integrator.Spool(tmp_path / "spool")
    spool.enqueue(b"{}")
    assert (tmp_path / "spool").stat().st_mode & 0o077 == 0
    assert spool.entries()[0].stat().st_mode & 0o077 == 0


def test_spool_write_failure_is_survivable(tmp_path: Path) -> None:
    """A broken spool path degrades to a dropped alert, never a crash."""
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    spool = integrator.Spool(blocker / "spool")
    assert spool.enqueue(b"{}") is False
    assert spool.pending() == 0


# ---------------------------------------------------------------------------
# Entrypoint behaviour
# ---------------------------------------------------------------------------


def test_run_forwards_a_real_sample_alert(tmp_path: Path) -> None:
    sample = json.loads((SAMPLE_ALERTS / "01_wazuh_ssh_brute_force.json").read_text())
    alert_file = write_alert(tmp_path, sample)
    sender = FakeSender([ok(202)])
    env = make_env(WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"))
    assert (
        integrator.run(
            ["custom-triage", str(alert_file)],
            env,
            sender=sender,
        )
        == 0
    )
    assert json.loads(sender.calls[0]["body"]) == sample


def test_run_ignores_positional_key_and_url_arguments(tmp_path: Path) -> None:
    """Wazuh passes $2/$3; they must never override the env-sourced config."""
    alert_file = write_alert(tmp_path, make_alert())
    sender = FakeSender([ok(202)])
    env = make_env(WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"))
    integrator.run(
        [
            "custom-triage",
            str(alert_file),
            "argv-key-should-be-ignored",
            "http://evil.invalid/x",
        ],
        env,
        sender=sender,
    )
    assert sender.calls[0]["url"].startswith("http://triage-api:8000/")
    assert sender.calls[0]["headers"]["X-API-Key"] == TEST_API_KEY


def test_run_returns_config_error_code_without_sending(tmp_path: Path) -> None:
    alert_file = write_alert(tmp_path, make_alert())
    sender = FakeSender([ok(202)])
    code = integrator.run(
        ["custom-triage", str(alert_file)],
        {},
        sender=sender,
    )
    assert code == integrator.EXIT_CONFIG_ERROR
    assert sender.calls == []


def test_run_requires_an_alert_file_argument() -> None:
    assert integrator.run(["custom-triage"], make_env()) == integrator.EXIT_CONFIG_ERROR


@pytest.mark.parametrize("content", ["not json", "[1,2,3]", ""])
def test_run_survives_unreadable_alert_payloads(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    sender = FakeSender([ok(202)])
    env = make_env(WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"))
    assert (
        integrator.run(
            ["custom-triage", str(path)],
            env,
            sender=sender,
        )
        == 0
    )
    assert sender.calls == []


def test_run_rejects_oversized_alert_files(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b"{" + b"a" * (integrator.MAX_ALERT_BYTES + 10) + b"}")
    sender = FakeSender([ok(202)])
    env = make_env(WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"))
    assert (
        integrator.run(
            ["custom-triage", str(path)],
            env,
            sender=sender,
        )
        == 0
    )
    assert sender.calls == []


def test_run_does_not_forward_filtered_alerts(tmp_path: Path) -> None:
    alert_file = write_alert(tmp_path, make_alert(level=2))
    sender = FakeSender([ok(202)])
    env = make_env(WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"))
    assert (
        integrator.run(
            ["custom-triage", str(alert_file)],
            env,
            sender=sender,
        )
        == 0
    )
    assert sender.calls == []
    assert list((tmp_path / "spool").glob("*.json")) == []


def test_run_always_exits_zero_on_permanent_rejection(tmp_path: Path) -> None:
    """A 401 must be visible in logs but must never break the manager."""
    alert_file = write_alert(tmp_path, make_alert())
    sender = FakeSender([integrator.SenderResponse(status=401)])
    env = make_env(WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"))
    assert (
        integrator.run(
            ["custom-triage", str(alert_file)],
            env,
            sender=sender,
        )
        == 0
    )
    assert list((tmp_path / "spool").glob("*.json")) == []


# ---------------------------------------------------------------------------
# Logging hygiene
# ---------------------------------------------------------------------------


def test_logs_never_contain_the_api_key_or_alert_body(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alert = make_alert()
    alert["full_log"] = "Failed password for root from 203.0.113.42 port 4444 ssh2"
    alert_file = write_alert(tmp_path, alert)
    env = make_env(WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"))

    integrator.run(
        ["custom-triage", str(alert_file)],
        env,
        sender=FakeSender([ok(202)]),
    )

    integrator.run(
        ["custom-triage", str(alert_file)],
        env,
        sender=FakeSender([network_error()]),
        sleep=lambda _: None,
    )

    err = capsys.readouterr().err
    assert err.strip(), "expected structured log output"
    assert TEST_API_KEY not in err
    assert "Failed password" not in err
    assert "203.0.113.42" not in err
    for line in err.strip().splitlines():
        record = json.loads(line)
        assert record["component"] == "wazuh_integrator"
        assert not {"api_key", "token", "password", "secret"} & set(record)


def test_logs_are_written_to_the_integrations_log_file(tmp_path: Path) -> None:
    """integratord discards stdout/stderr unless the manager runs in debug.

    ``> /dev/null 2>&1`` is appended to the command (src/os_integrator/
    integrator.c), so writing only to stderr loses every event in a normal
    deployment. The log file is the real observability channel.
    """
    log_file = tmp_path / "integrations.log"
    alert_file = write_alert(tmp_path, make_alert())
    env = make_env(
        WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"),
        WAZUH_INTEGRATOR_LOG_FILE=str(log_file),
    )
    integrator.run(
        ["custom-triage", str(alert_file)],
        env,
        sender=FakeSender([ok(202)]),
    )

    assert log_file.exists(), "integrator must log to integrations.log"
    records = [json.loads(line) for line in log_file.read_text().strip().splitlines()]
    assert any(r["event"] == "alert_forwarded" for r in records)
    assert TEST_API_KEY not in log_file.read_text()


def test_unwritable_log_file_never_costs_an_alert(tmp_path: Path) -> None:
    """A broken log path must degrade to silence, not a lost detection."""
    sender = FakeSender([ok(202)])
    env = make_env(
        WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"),
        WAZUH_INTEGRATOR_LOG_FILE=str(tmp_path / "nonexistent-dir" / "x.log"),
    )
    alert_file = write_alert(tmp_path, make_alert())
    assert (
        integrator.run(
            ["custom-triage", str(alert_file)],
            env,
            sender=sender,
        )
        == 0
    )
    assert len(sender.calls) == 1


def test_log_helper_drops_credential_shaped_fields(
    capsys: pytest.CaptureFixture[str],
) -> None:
    integrator.log(
        "t",
        api_key="s3cret",
        token="s3cret",
        password="s3cret",
        rule_id="5710",
    )
    record = json.loads(capsys.readouterr().err.strip())
    assert record == {
        "component": "wazuh_integrator",
        "event": "t",
        "rule_id": "5710",
    }


def test_logged_endpoint_is_sanitized(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alert_file = write_alert(tmp_path, make_alert())
    env = make_env(WAZUH_INTEGRATOR_SPOOL_DIR=str(tmp_path / "spool"))
    integrator.run(
        ["custom-triage", str(alert_file)],
        env,
        sender=FakeSender([ok(202)]),
    )
    err = capsys.readouterr().err
    assert "http://triage-api:8000/api/v1/alerts/ingest" in err
    assert "@" not in err


# ---------------------------------------------------------------------------
# Deployment artifacts (static, defensive-scope guards)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="Unix permission bits are POSIX-specific")
def test_integrator_files_exist_and_wrapper_is_executable() -> None:
    assert INTEGRATOR_PY.is_file()
    assert INTEGRATOR_SH.is_file()
    assert INTEGRATOR_SH.stat().st_mode & 0o111, "custom-triage wrapper must be executable"
    assert INTEGRATOR_SH.read_text(encoding="utf-8").startswith("#!/bin/sh")


def test_integrator_uses_only_the_standard_library() -> None:
    """The Wazuh image has no project dependencies installed."""
    source = INTEGRATOR_PY.read_text(encoding="utf-8")
    for banned in (
        "import httpx",
        "import requests",
        "import pydantic",
        "from soc_triage",
    ):
        assert banned not in source


def test_integrator_sources_contain_no_hardcoded_secrets() -> None:
    for path in (INTEGRATOR_PY, INTEGRATOR_SH, OSSEC_CONF, INSTALL_SCRIPT):
        text = path.read_text(encoding="utf-8")
        assert "change-me-generate" not in text
        # No `KEY = "value"` style literal assignments of credentials.
        assert not any(
            marker in text.lower()
            for marker in (
                'api_key = "',
                "api_key = '",
                'password = "',
                'token = "',
            )
        )


def test_integrator_has_no_containment_or_response_capability() -> None:
    """Defensive-only charter: no execution, no active response (SECURITY.md §1)."""
    source = INTEGRATOR_PY.read_text(encoding="utf-8")
    for banned in (
        "subprocess",
        "os.system",
        "os.popen",
        "active-response",
        "active_response",
        "iptables",
        "firewall-drop",
        "eval(",
        "exec(",
    ):
        assert banned not in source, banned


def test_ossec_conf_is_a_complete_config_with_the_integration() -> None:
    """Wazuh has NO ossec.conf.d include mechanism.

    The manager image copies ``/wazuh-config-mount/etc/ossec.conf`` over
    ``/var/ossec/etc/ossec.conf`` wholesale, so a partial fragment would
    silently never load. This asserts we ship a complete configuration whose
    integration block matches the deployed script name.
    """
    import xml.etree.ElementTree as ET

    text = OSSEC_CONF.read_text(encoding="utf-8")
    # Multiple <ossec_config> roots are valid Wazuh config; wrap to parse.
    root = ET.fromstring(f"<wrapper>{text[text.index('-->') + 3 :]}</wrapper>")

    sections = root.findall("ossec_config")
    assert sections, "expected at least one <ossec_config> section"

    # A complete config, not a fragment.
    tags = {child.tag for section in sections for child in section}
    for required in ("global", "remote", "ruleset", "auth", "syscheck"):
        assert required in tags, f"ossec.conf is missing <{required}> — is it a fragment?"

    integrations = [
        integration for section in sections for integration in section.findall("integration")
    ]
    assert len(integrations) == 1
    integration = integrations[0]
    # Wazuh requires custom integrations to be named custom-*, matching a file
    # in /var/ossec/integrations/.
    name = integration.findtext("name")
    assert name == "custom-triage"
    assert name.startswith("custom-")
    assert name == INTEGRATOR_SH.name, "config name must match the installed script"
    assert integration.findtext("alert_format") == "json"
    # The api_key element carries an env reference marker, never a value.
    assert integration.findtext("api_key") == "env:TRIAGE_INGEST_API_KEY"


def test_ossec_conf_defines_no_active_response() -> None:
    """Defensive-only charter (SECURITY.md §1)."""
    import xml.etree.ElementTree as ET

    text = OSSEC_CONF.read_text(encoding="utf-8")
    root = ET.fromstring(f"<wrapper>{text[text.index('-->') + 3 :]}</wrapper>")
    active = [
        action
        for section in root.findall("ossec_config")
        for action in section.findall("active-response")
    ]
    assert active == [], "no active-response may be enabled"


def test_ossec_conf_disables_the_indexer_we_do_not_run() -> None:
    """The lab stack has no wazuh-indexer; leaving it enabled spams errors."""
    import xml.etree.ElementTree as ET

    text = OSSEC_CONF.read_text(encoding="utf-8")
    root = ET.fromstring(f"<wrapper>{text[text.index('-->') + 3 :]}</wrapper>")
    sections = root.findall("ossec_config")
    for tag in ("indexer", "vulnerability-detection"):
        blocks = [block for section in sections for block in section.findall(tag)]
        assert blocks, tag
        for block in blocks:
            assert block.findtext("enabled") == "no", tag


def test_ossec_conf_carries_no_hardcoded_cluster_key() -> None:
    """Upstream's template ships a literal key; ours uses the substitution marker."""
    text = OSSEC_CONF.read_text(encoding="utf-8")
    assert "to_be_replaced_by_cluster_key" in text
    assert not re.search(r"<key>[0-9a-f]{16,}</key>", text)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix permission bits are POSIX-specific")
def test_install_script_places_integrator_where_integratord_looks() -> None:
    """integratord resolves `integrations/<name>` relative to /var/ossec.

    The script must therefore land at /var/ossec/integrations/custom-triage
    with Wazuh's required root:wazuh 750 ownership — not in a subdirectory
    and not with host-derived ownership from a bind mount.
    """
    script = INSTALL_SCRIPT.read_text(encoding="utf-8")
    assert INSTALL_SCRIPT.stat().st_mode & 0o111, "install hook must be executable"
    assert "DEST_DIR=/var/ossec/integrations" in script
    assert "-m 750 -o root -g wazuh" in script
    assert "custom-triage.py" in script
    # Log file must be writable by the wazuh user integratord runs as.
    assert "integrations.log" in script
    # Spool stays owner-only.
    assert "-d -m 700 -o wazuh -g wazuh" in script
    # Parent integrations directory must be root:wazuh 0750 explicitly.
    assert 'chown root:wazuh "$DEST_DIR"' in script
    assert 'chmod 0750 "$DEST_DIR"' in script
    # Startup must never be blocked by an integration problem.
    assert "exit 0" in script


def test_wazuh_scripts_have_no_crlf() -> None:
    """Integratord cannot execute scripts with CRLF line endings.

    Wazuh integratord resolves integrations/<name> relative to /var/ossec
    and runs scripts as the `wazuh` user. CRLF scripts cause silent
    failures (the ^M character breaks #! line parsing and command
    execution). This test asserts all checked-in executable Wazuh scripts
    contain LF only.
    """
    scripts = [
        REPO_ROOT / "wazuh" / "integrator" / "custom-triage",
        REPO_ROOT / "wazuh" / "integrator" / "custom-triage.py",
        REPO_ROOT / "wazuh" / "entrypoint-scripts" / "10-install-triage-integration.sh",
    ]

    for script_path in scripts:
        data = script_path.read_bytes()
        assert b"\r\n" not in data, f"{script_path} contains CRLF"
        assert b"\r" not in data, f"{script_path} contains lone CR"


def test_install_script_has_no_containment_capability() -> None:
    script = INSTALL_SCRIPT.read_text(encoding="utf-8")
    for banned in ("active-response", "iptables", "firewall-drop", "curl ", "wget "):
        assert banned not in script, banned
