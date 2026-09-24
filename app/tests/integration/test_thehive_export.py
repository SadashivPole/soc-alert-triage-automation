from soc_triage.thehive.export import build_thehive_case_export


def test_builds_safe_case_export():
    result = build_thehive_case_export(
        incident={
            "incident_id": "INC-2026-0001",
            "status": "investigating",
            "severity": "SEV2",
            "primary_alert_id": "ALERT-001",
            "dedupe_group_key": "group-001",
        },
        alerts=[
            {"alert_id": "ALERT-001"},
            {"alert_id": "ALERT-002"},
        ],
        iocs=[
            {"type": "ip", "value": "10.10.10.10", "source": "test"},
            {"type": "sha256", "value": "a" * 64, "source": "test"},
        ],
        assignment={"assignee": "analyst@example.com"},
        notes=[
            {"actor": "analyst", "text": "Investigated suspicious activity"},
        ],
        timeline=[
            {
                "event": "incident.created",
                "timestamp": "2026-09-14T10:00:00Z",
            },
        ],
    )

    assert result.incident_id == "INC-2026-0001"
    assert result.severity == 3
    assert result.tlp == 2
    assert result.pap == 2
    assert len(result.observables) == 2

    assert "INC-2026-0001" in result.title
    assert "ALERT-001" in result.description
    assert "ALERT-002" in result.description
    assert "analyst@example.com" in result.description
    assert "Investigated suspicious activity" in result.description
    assert "incident.created" in result.description


def test_raw_full_log_is_not_exported():
    result = build_thehive_case_export(
        incident={
            "incident_id": "INC-2026-0002",
            "status": "open",
            "severity": "SEV1",
            "full_log": "SECRET_RAW_LOG_SHOULD_NEVER_BE_EXPORTED",
        },
        alerts=[
            {
                "alert_id": "ALERT-002",
                "full_log": "ANOTHER_SECRET_RAW_LOG",
            }
        ],
        iocs=[],
    )

    assert "SECRET_RAW_LOG_SHOULD_NEVER_BE_EXPORTED" not in result.description
    assert "ANOTHER_SECRET_RAW_LOG" not in result.description
    assert "full_log" not in result.description


def test_route_style_note_key_is_exported():
    """Regression: the route emits ``{"note": ...}`` and it must be exported.

    Covers (1) route-style ``"note"`` key, (2) legacy ``"text"`` key still works,
    (3) ``full_log``/secrets stay excluded from the description.
    """
    result = build_thehive_case_export(
        incident={
            "incident_id": "INC-2026-0004",
            "status": "investigating",
            "severity": "SEV2",
            "full_log": "SECRET_RAW_LOG_SHOULD_NEVER_BE_EXPORTED",
        },
        alerts=[
            {
                "alert_id": "ALERT-004",
                "full_log": "ANOTHER_SECRET_RAW_LOG",
            }
        ],
        notes=[
            # Exact shape api/incident_thehive.py builds for note_added rows.
            {
                "actor": "analyst",
                "note": "Route-style investigation note",
                "created_at": "2026-09-20T10:00:00Z",
            },
            # Legacy shape must keep working.
            {"actor": "analyst", "text": "Legacy-style investigation note"},
        ],
    )

    # 1. route-style "note" is exported (silently dropped before the fix)
    assert "analyst: Route-style investigation note" in result.description
    # 2. existing "text" behavior is preserved
    assert "analyst: Legacy-style investigation note" in result.description
    assert "Investigation Notes:" in result.description

    # 3. full_log/secrets remain excluded
    assert "SECRET_RAW_LOG_SHOULD_NEVER_BE_EXPORTED" not in result.description
    assert "ANOTHER_SECRET_RAW_LOG" not in result.description
    assert "full_log" not in result.description


def test_unsupported_ioc_types_are_ignored():
    result = build_thehive_case_export(
        incident={
            "incident_id": "INC-2026-0003",
            "status": "open",
            "severity": "SEV3",
        },
        iocs=[
            {"type": "ip", "value": "192.168.1.10"},
            {"type": "password", "value": "do-not-export"},
            {"type": "api_key", "value": "do-not-export"},
            {"type": "token", "value": "do-not-export"},
        ],
    )

    assert len(result.observables) == 1
    assert result.observables[0].data_type == "ip"
    assert result.observables[0].data == "192.168.1.10"

    exported_values = {observable.data for observable in result.observables}

    assert "do-not-export" not in exported_values


def test_missing_incident_id_is_rejected():
    try:
        build_thehive_case_export(
            incident={
                "status": "open",
                "severity": "SEV2",
            }
        )
    except ValueError as exc:
        assert str(exc) == "incident_id is required"
    else:
        raise AssertionError("Expected ValueError")
