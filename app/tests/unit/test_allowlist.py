from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from soc_triage.enrichment.allowlist import (
    AllowlistConfigError,
    AllowlistProvider,
    allowlist_from_mapping,
)
from soc_triage.enrichment.providers import EnrichmentContext, EnrichmentStatus
from soc_triage.models.ioc import IOC, IOCType


def make_ioc(ioc_type: IOCType, value: str) -> IOC:
    return IOC(type=ioc_type, value=value)


def make_context() -> EnrichmentContext:
    return EnrichmentContext(
        alert_id=uuid4(),
        source="wazuh",
        received_at=datetime.now(UTC),
        dedupe_group="test-group",
    )


def make_allowlist(entries: list[dict[str, str]]):
    return allowlist_from_mapping(
        {
            "version": "allowlist.v1",
            "entries": entries,
        }
    )


def test_ipv4_exact_match() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "approved-scanner",
                "type": "ipv4",
                "value": "10.10.10.10",
                "reason": "Approved scanner",
            }
        ]
    )

    match = allowlist.match(make_ioc(IOCType.IPV4, "10.10.10.10"))

    assert match is not None
    assert match.id == "approved-scanner"
    assert match.reason == "Approved scanner"


def test_ipv4_non_match() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "approved-scanner",
                "type": "ipv4",
                "value": "10.10.10.10",
            }
        ]
    )

    assert allowlist.match(make_ioc(IOCType.IPV4, "10.10.10.11")) is None


def test_ipv4_cidr_match() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "trusted-subnet",
                "type": "ipv4",
                "value": "10.20.30.0/24",
            }
        ]
    )

    match = allowlist.match(make_ioc(IOCType.IPV4, "10.20.30.55"))

    assert match is not None
    assert match.id == "trusted-subnet"


def test_ipv4_cidr_host_bits_are_normalized() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "trusted-subnet",
                "type": "ipv4",
                "value": "10.20.30.55/24",
            }
        ]
    )

    match = allowlist.match(make_ioc(IOCType.IPV4, "10.20.30.10"))

    assert match is not None
    assert match.value == "10.20.30.0/24"


def test_ipv4_cidr_overlap_is_deterministic() -> None:
    entries = [
        {
            "id": "broad-network",
            "type": "ipv4",
            "value": "10.30.0.0/16",
        },
        {
            "id": "specific-network",
            "type": "ipv4",
            "value": "10.30.20.0/24",
        },
    ]

    allowlist_a = make_allowlist(entries)
    allowlist_b = make_allowlist(list(reversed(entries)))

    match_a = allowlist_a.match(make_ioc(IOCType.IPV4, "10.30.20.15"))
    match_b = allowlist_b.match(make_ioc(IOCType.IPV4, "10.30.20.15"))

    assert match_a is not None
    assert match_b is not None
    assert match_a.id == match_b.id


def test_domain_normalization_and_match() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "trusted-domain",
                "type": "domain",
                "value": "Example.COM.",
            }
        ]
    )

    match = allowlist.match(make_ioc(IOCType.DOMAIN, "example.com"))

    assert match is not None
    assert match.id == "trusted-domain"


def test_url_normalization_and_match() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "trusted-url",
                "type": "url",
                "value": "HTTPS://Example.COM/path/",
            }
        ]
    )

    match = allowlist.match(
        make_ioc(
            IOCType.URL,
            "https://example.com/path/",
        )
    )

    assert match is not None
    assert match.id == "trusted-url"


def test_md5_normalization_and_match() -> None:
    value = "D41D8CD98F00B204E9800998ECF8427E"

    allowlist = make_allowlist(
        [
            {
                "id": "known-md5",
                "type": "md5",
                "value": value,
            }
        ]
    )

    match = allowlist.match(
        make_ioc(
            IOCType.MD5,
            value.lower(),
        )
    )

    assert match is not None
    assert match.id == "known-md5"


def test_sha1_normalization_and_match() -> None:
    value = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"

    allowlist = make_allowlist(
        [
            {
                "id": "known-sha1",
                "type": "sha1",
                "value": value,
            }
        ]
    )

    match = allowlist.match(
        make_ioc(
            IOCType.SHA1,
            value.lower(),
        )
    )

    assert match is not None
    assert match.id == "known-sha1"


def test_sha256_normalization_and_match() -> None:
    value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    allowlist = make_allowlist(
        [
            {
                "id": "known-sha256",
                "type": "sha256",
                "value": value.upper(),
            }
        ]
    )

    match = allowlist.match(
        make_ioc(
            IOCType.SHA256,
            value,
        )
    )

    assert match is not None
    assert match.id == "known-sha256"


def test_email_normalization_and_match() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "trusted-mailbox",
                "type": "email",
                "value": "Admin@Example.COM",
            }
        ]
    )

    match = allowlist.match(
        make_ioc(
            IOCType.EMAIL,
            "Admin@example.com",
        )
    )

    assert match is not None
    assert match.id == "trusted-mailbox"


def test_provider_returns_all_input_iocs() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "approved-ip",
                "type": "ipv4",
                "value": "10.0.0.10",
            }
        ]
    )

    provider = AllowlistProvider(allowlist)

    iocs = [
        make_ioc(IOCType.IPV4, "10.0.0.10"),
        make_ioc(IOCType.DOMAIN, "example.com"),
    ]

    result = provider.enrich(
        iocs,
        context=make_context(),
    )

    assert set(result.results) == {
        "ipv4:10.0.0.10",
        "domain:example.com",
    }

    assert result.results["ipv4:10.0.0.10"]["matched"] is True
    assert result.results["domain:example.com"]["matched"] is False


def test_provider_status_is_skipped() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "approved-ip",
                "type": "ipv4",
                "value": "10.0.0.10",
            }
        ]
    )

    provider = AllowlistProvider(allowlist)

    result = provider.enrich(
        [make_ioc(IOCType.IPV4, "10.0.0.10")],
        context=make_context(),
    )

    assert result.provider == "allowlist"
    assert result.status is EnrichmentStatus.SKIPPED


def test_provider_reports_match_metadata() -> None:
    allowlist = make_allowlist(
        [
            {
                "id": "approved-ip",
                "type": "ipv4",
                "value": "10.0.0.10",
                "reason": "Approved scanner",
            }
        ]
    )

    provider = AllowlistProvider(allowlist)

    result = provider.enrich(
        [make_ioc(IOCType.IPV4, "10.0.0.10")],
        context=make_context(),
    )

    payload = result.results["ipv4:10.0.0.10"]

    assert payload == {
        "matched": True,
        "entry_id": "approved-ip",
        "reason": "Approved scanner",
    }


def test_provider_does_not_mutate_iocs() -> None:
    ioc = make_ioc(IOCType.IPV4, "10.0.0.10")

    allowlist = make_allowlist(
        [
            {
                "id": "approved-ip",
                "type": "ipv4",
                "value": "10.0.0.10",
            }
        ]
    )

    provider = AllowlistProvider(allowlist)

    before = ioc.model_dump()

    provider.enrich(
        [ioc],
        context=make_context(),
    )

    assert ioc.model_dump() == before


def test_empty_allowlist_provider_is_disabled() -> None:
    allowlist = make_allowlist([])

    provider = AllowlistProvider(allowlist)

    assert provider.enabled is False


def test_invalid_version_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "wrong.version",
                "entries": [],
            }
        )


def test_unknown_top_level_key_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "allowlist.v1",
                "entries": [],
                "unexpected": True,
            }
        )


def test_missing_entries_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "allowlist.v1",
            }
        )


def test_invalid_ioc_type_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "allowlist.v1",
                "entries": [
                    {
                        "id": "bad-type",
                        "type": "not-a-real-type",
                        "value": "example.com",
                    }
                ],
            }
        )


def test_invalid_entry_id_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "allowlist.v1",
                "entries": [
                    {
                        "id": "Bad-ID",
                        "type": "domain",
                        "value": "example.com",
                    }
                ],
            }
        )


def test_reason_over_200_characters_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "allowlist.v1",
                "entries": [
                    {
                        "id": "too-long-reason",
                        "type": "domain",
                        "value": "example.com",
                        "reason": "x" * 201,
                    }
                ],
            }
        )


def test_ipv4_zero_prefix_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "allowlist.v1",
                "entries": [
                    {
                        "id": "everything",
                        "type": "ipv4",
                        "value": "0.0.0.0/0",
                    }
                ],
            }
        )


def test_duplicate_id_with_conflicting_entries_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "allowlist.v1",
                "entries": [
                    {
                        "id": "scanner",
                        "type": "ipv4",
                        "value": "10.0.0.1",
                    },
                    {
                        "id": "scanner",
                        "type": "ipv4",
                        "value": "10.0.0.2",
                    },
                ],
            }
        )


def test_duplicate_normalized_ioc_key_with_conflict_is_rejected() -> None:
    with pytest.raises(AllowlistConfigError):
        allowlist_from_mapping(
            {
                "version": "allowlist.v1",
                "entries": [
                    {
                        "id": "first",
                        "type": "domain",
                        "value": "Example.COM",
                    },
                    {
                        "id": "second",
                        "type": "domain",
                        "value": "example.com",
                    },
                ],
            }
        )


def test_identical_duplicate_entries_are_collapsed() -> None:
    allowlist = allowlist_from_mapping(
        {
            "version": "allowlist.v1",
            "entries": [
                {
                    "id": "scanner",
                    "type": "ipv4",
                    "value": "10.0.0.1",
                    "reason": "approved",
                },
                {
                    "id": "scanner",
                    "type": "ipv4",
                    "value": "10.0.0.1",
                    "reason": "approved",
                },
            ],
        }
    )

    assert len(allowlist) == 1
    assert allowlist.duplicates_collapsed == 1
