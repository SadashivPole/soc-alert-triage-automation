"""Unit tests for the Wazuh alert normalizer."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from soc_triage.ingest.normalizer import normalize_wazuh_alert
from soc_triage.ingest.schemas import WazuhAlert
from soc_triage.models.canonical import CanonicalAlert

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def sample_alerts() -> list[tuple[str, dict]]:
    """Load all sample alert fixtures with filenames."""
    alerts = []
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        with path.open() as f:
            alerts.append((path.name, json.load(f)))
    return alerts


def test_normalize_ssh_brute_force() -> None:
    """Normalize the SSH brute-force sample alert."""
    raw = json.loads((FIXTURES_DIR / "01_wazuh_ssh_brute_force.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh)

    assert isinstance(canonical, CanonicalAlert)
    assert isinstance(canonical.alert_id, UUID)
    assert canonical.source == "wazuh"
    assert canonical.source_event.rule.id == "5710"
    assert canonical.source_event.rule.level == 5
    assert "authentication_failed" in canonical.source_event.rule.groups
    assert canonical.source_event.rule.mitre["id"] == ["T1110"]
    assert canonical.source_event.agent.id == "001"
    assert canonical.source_event.agent.name == "web-prod-01"
    assert canonical.source_event.location == "/var/log/auth.log"
    assert canonical.source_event.full_log is not None


def test_normalize_fim_alert() -> None:
    """Normalize the FIM /etc/passwd change sample alert."""
    raw = json.loads((FIXTURES_DIR / "03_wazuh_fim_etc_passwd_change.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh)

    assert canonical.source_event.rule.id == "550"
    assert canonical.source_event.rule.level == 7
    assert "syscheck_file_modified" in canonical.source_event.rule.groups
    assert len(canonical.source_event.rule.mitre["tactic"]) == 2
    assert canonical.source_event.agent.name == "db-prod-01"


def test_normalize_malware_hash_alert() -> None:
    """Normalize the VirusTotal malware hash sample alert."""
    raw = json.loads((FIXTURES_DIR / "04_wazuh_malware_hash_virustotal.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh)

    assert canonical.source_event.rule.id == "87105"
    assert canonical.source_event.rule.level == 12
    assert "malware" in canonical.source_event.rule.groups


def test_normalize_sql_injection_alert() -> None:
    """Normalize the SQL injection sample alert."""
    raw = json.loads((FIXTURES_DIR / "05_wazuh_web_sql_injection.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh)

    assert canonical.source_event.rule.id == "31103"
    assert canonical.source_event.rule.level == 10
    assert "attack" in canonical.source_event.rule.groups
    assert "sql_injection" in canonical.source_event.rule.groups


def test_normalize_windows_account_alert() -> None:
    """Normalize the Windows user-created sample alert."""
    raw = json.loads((FIXTURES_DIR / "06_wazuh_windows_user_created.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh)

    assert canonical.source_event.rule.id == "60180"
    assert canonical.source_event.rule.level == 5
    assert "account_management" in canonical.source_event.rule.groups
    assert canonical.source_event.agent.name == "fin-srv-02"


def test_normalize_all_sample_fixtures(sample_alerts: list[tuple[str, dict]]) -> None:
    """Every sample alert must normalize without error."""
    assert len(sample_alerts) >= 6
    for name, raw in sample_alerts:
        wazuh = WazuhAlert.model_validate(raw)
        canonical = normalize_wazuh_alert(wazuh)
        assert isinstance(canonical.alert_id, UUID), f"{name}: missing alert_id"
        assert canonical.source_event.rule.id, f"{name}: missing rule id"
        assert canonical.source_event.agent.name, f"{name}: missing agent name"


def test_normalize_with_custom_alert_id() -> None:
    """A pre-assigned alert_id should be used."""
    custom_id = uuid4()
    raw = json.loads((FIXTURES_DIR / "01_wazuh_ssh_brute_force.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh, alert_id=custom_id)
    assert canonical.alert_id == custom_id


def test_normalize_with_custom_received_at() -> None:
    """A custom received_at timestamp should be used."""
    custom_time = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    raw = json.loads((FIXTURES_DIR / "01_wazuh_ssh_brute_force.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh, received_at=custom_time)
    assert canonical.received_at == custom_time


def test_normalize_with_simulator_source() -> None:
    """Source label should be configurable (e.g., 'simulator')."""
    raw = json.loads((FIXTURES_DIR / "01_wazuh_ssh_brute_force.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh, source="simulator")
    assert canonical.source == "simulator"


def test_canonical_alert_is_frozen() -> None:
    """Canonical alerts should be immutable."""
    from pydantic import ValidationError as PydanticValidationError

    raw = json.loads((FIXTURES_DIR / "01_wazuh_ssh_brute_force.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh)
    with pytest.raises((PydanticValidationError, AttributeError, TypeError)):
        canonical.source = "changed"  # type: ignore[misc]


def test_normalize_preserves_mitre_empty_when_absent() -> None:
    """Alerts without MITRE data should have an empty mitre dict."""
    raw = json.loads((FIXTURES_DIR / "02_wazuh_ssh_brute_force_success.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh)
    assert canonical.source_event.rule.mitre == {}


def test_normalize_serializes_to_json() -> None:
    """Canonical alert should be JSON-serializable."""
    raw = json.loads((FIXTURES_DIR / "01_wazuh_ssh_brute_force.json").read_text())
    wazuh = WazuhAlert.model_validate(raw)
    canonical = normalize_wazuh_alert(wazuh)
    dumped = canonical.model_dump(mode="json")
    # Should round-trip through JSON without error
    serialized = json.dumps(dumped)
    deserialized = json.loads(serialized)
    assert deserialized["alert_id"] == str(canonical.alert_id)
    assert deserialized["source"] == "wazuh"
