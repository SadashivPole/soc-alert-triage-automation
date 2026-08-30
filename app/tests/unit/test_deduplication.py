from datetime import UTC, datetime, timedelta

import pytest

from soc_triage.ingest.deduplication import DedupeStatus, MemoryDeduplicator, compute_event_identity
from soc_triage.ingest.schemas import WazuhAlert


@pytest.fixture
def sample_wazuh_alert() -> WazuhAlert:
    return WazuhAlert.model_validate(
        {
            "id": "1770000000.100001",
            "timestamp": "2026-08-29T10:15:29.000+0000",
            "rule": {
                "level": 5,
                "description": "sshd: Attempt to login using a non-existent user",
                "id": "5710",
            },
            "agent": {
                "id": "001",
                "name": "web-prod-01",
            },
            "full_log": "Failed password for admin",
        }
    )


def test_deduplicator_new_generation(sample_wazuh_alert: WazuhAlert):
    deduplicator = MemoryDeduplicator(window_seconds=900)
    now = datetime.now(UTC)

    result = deduplicator.process_alert(sample_wazuh_alert, now)

    assert result.status == DedupeStatus.NEW_GENERATION
    assert result.dedupe_info.occurrences == 1
    assert result.dedupe_info.group_key == "5710:001"


def test_deduplicator_exact_duplicate(sample_wazuh_alert: WazuhAlert):
    deduplicator = MemoryDeduplicator(window_seconds=900)
    now = datetime.now(UTC)

    result1 = deduplicator.process_alert(sample_wazuh_alert, now)
    assert result1.status == DedupeStatus.NEW_GENERATION

    # Exact duplicate delivery of the SAME event
    result2 = deduplicator.process_alert(sample_wazuh_alert, now + timedelta(seconds=10))

    assert result2.status == DedupeStatus.EXACT_DUPLICATE
    assert result2.dedupe_info.occurrences == 1
    # Check that last_seen did not update
    assert result2.dedupe_info.last_seen == now


def test_deduplicator_repeated_within_window(sample_wazuh_alert: WazuhAlert):
    deduplicator = MemoryDeduplicator(window_seconds=900)
    now = datetime.now(UTC)

    deduplicator.process_alert(sample_wazuh_alert, now)

    # Different event, same rule/agent
    alert2 = sample_wazuh_alert.model_copy(deep=True)
    alert2.id = "1770000000.100002"

    later = now + timedelta(seconds=60)
    result2 = deduplicator.process_alert(alert2, later)

    assert result2.status == DedupeStatus.REPEATED
    assert result2.dedupe_info.occurrences == 2
    assert result2.dedupe_info.last_seen == later
    assert result2.dedupe_info.first_seen == now


def test_deduplicator_new_alert_after_window_expires(sample_wazuh_alert: WazuhAlert):
    deduplicator = MemoryDeduplicator(window_seconds=900)
    now = datetime.now(UTC)

    deduplicator.process_alert(sample_wazuh_alert, now)

    alert2 = sample_wazuh_alert.model_copy(deep=True)
    alert2.id = "1770000000.100002"

    way_later = now + timedelta(seconds=1000)
    result2 = deduplicator.process_alert(alert2, way_later)

    assert result2.status == DedupeStatus.NEW_GENERATION
    assert result2.dedupe_info.occurrences == 1
    assert result2.dedupe_info.first_seen == way_later
    assert result2.dedupe_info.last_seen == way_later


def test_different_agents_do_not_collide(sample_wazuh_alert: WazuhAlert):
    deduplicator = MemoryDeduplicator(window_seconds=900)
    now = datetime.now(UTC)

    deduplicator.process_alert(sample_wazuh_alert, now)

    alert2 = sample_wazuh_alert.model_copy(deep=True)
    alert2.id = "1770000000.100002"
    alert2.agent.id = "002"

    result2 = deduplicator.process_alert(alert2, now)

    assert result2.status == DedupeStatus.NEW_GENERATION
    assert result2.dedupe_info.occurrences == 1
    assert result2.dedupe_info.group_key == "5710:002"


def test_compute_event_identity_fallback():
    # If no ID is present, it uses hash
    alert = WazuhAlert.model_validate(
        {
            "timestamp": "2026-08-29T10:15:29.000+0000",
            "rule": {"level": 5, "description": "test", "id": "5710"},
            "agent": {"id": "001", "name": "test"},
            "full_log": "Failed log",
        }
    )
    identity = compute_event_identity(alert)
    assert identity.startswith("wazuh:hash:")
