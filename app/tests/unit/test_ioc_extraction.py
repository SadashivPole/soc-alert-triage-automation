"""Phase 1E unit tests: IOC extraction (types, normalization, provenance).

Covers the extraction contract from ARCHITECTURE.md §7.1 and the false-positive
policy in SECURITY.md §5:

* every supported indicator type (ipv4, domain, url, md5, sha1, sha256, email);
* mixed input (one alert, several types);
* normalized duplicates collapse into one indicator with merged provenance;
* invalid IPs / hashes / domains are dropped rather than guessed at;
* false-positive handling (private ranges, version-like strings, file paths);
* provenance (canonical field path, alert location, offset, raw value);
* determinism (repeated extraction is byte-identical);
* the synthetic sample corpus (contract test over ``docs/sample-alerts``).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from soc_triage.enrichment import (
    DEFAULT_IOC_POLICY,
    IOCExtractionPolicy,
    extract_iocs,
    extract_iocs_from_text,
)
from soc_triage.enrichment.normalize import (
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ipv4,
    normalize_url,
)
from soc_triage.ingest.normalizer import normalize_wazuh_alert
from soc_triage.ingest.schemas import WazuhAlert
from soc_triage.models.canonical import (
    CanonicalAgent,
    CanonicalAlert,
    CanonicalRule,
    CanonicalSourceEvent,
)
from soc_triage.models.ioc import (
    EXTRACTOR_TEXT_SCAN,
    EXTRACTOR_TYPED_FIELD,
    IOCType,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
RECEIVED = datetime(2026, 8, 29, 10, 15, 30, tzinfo=UTC)
ALERT_ID = UUID("3f9d2b1e-5c7a-4a1e-9a2f-0b6d8e4c1a11")

# Synthetic, documentation-range test data only (SECURITY.md §5).
DOC_IP = "203.0.113.50"
DOC_IP_2 = "198.51.100.77"
PRIVATE_IP = "10.0.1.10"
MD5 = "bc478d7a48bfab117da4b9bdcb5aee36"
SHA1 = "87c151c211facd64c46da2004bccfc31f52128bd"
SHA256 = "23b3c5642480341d8bb98c40b6edb136f59088a7ae4e57ef6518789908769f0f"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_alert(
    *,
    data: dict[str, Any] | None = None,
    syscheck: dict[str, Any] | None = None,
    agent_ip: str | None = None,
    location: str | None = "/var/log/auth.log",
    full_log: str | None = None,
) -> CanonicalAlert:
    """Build a canonical alert with only the fields under test populated."""
    return CanonicalAlert(
        alert_id=ALERT_ID,
        source="wazuh",
        received_at=RECEIVED,
        source_event=CanonicalSourceEvent(
            rule=CanonicalRule(id="5710", level=5, description="sshd: failed login"),
            agent=CanonicalAgent(id="001", name="web-prod-01", ip=agent_ip),
            location=location,
            full_log=full_log,
            data=data or {},
            syscheck=syscheck or {},
        ),
    )


def values_of_type(iocs: list[Any], kind: IOCType) -> list[str]:
    """Normalized values of one indicator type, in extraction order."""
    return [ioc.value for ioc in iocs if ioc.type is kind]


def as_pairs(iocs: list[Any]) -> list[tuple[str, str]]:
    """``(type, value)`` pairs — stable, order-sensitive comparison helper."""
    return [(ioc.type.value, ioc.value) for ioc in iocs]


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------


def test_extracts_ipv4_from_typed_source_field() -> None:
    """``data.srcip`` yields one ipv4 indicator with typed provenance."""
    iocs = extract_iocs(make_alert(data={"srcip": DOC_IP}))

    assert as_pairs(iocs) == [("ipv4", DOC_IP)]
    provenance = iocs[0].provenance[0]
    assert provenance.field == "source_event.data.srcip"
    assert provenance.extractor == EXTRACTOR_TYPED_FIELD
    assert provenance.raw_value == DOC_IP
    assert provenance.offset is None  # typed fields match the whole value


def test_extracts_ipv4_from_agent_and_destination_fields() -> None:
    """Every typed IPv4 field is an extraction source."""
    iocs = extract_iocs(make_alert(data={"dstip": DOC_IP_2}, agent_ip="192.0.2.9"))

    assert values_of_type(iocs, IOCType.IPV4) == ["192.0.2.9", DOC_IP_2]
    assert {p.field for ioc in iocs for p in ioc.provenance} == {
        "source_event.agent.ip",
        "source_event.data.dstip",
    }


def test_private_ipv4_is_dropped_by_default_policy() -> None:
    """RFC 1918 / loopback / link-local addresses are not indicators."""
    iocs = extract_iocs(
        make_alert(
            data={"srcip": PRIVATE_IP, "dstip": "127.0.0.1"},
            agent_ip="169.254.1.1",
        )
    )
    assert iocs == []


@pytest.mark.parametrize(
    "address",
    [
        "999.1.1.1",  # octet out of range
        "1.2.3",  # too short
        "1.2.3.4.5",  # version-like string
        "010.1.1.1",  # leading zeros
        "1.2.3.256",  # octet out of range
        "not-an-ip",
        "",
    ],
)
def test_invalid_ipv4_values_are_rejected(address: str) -> None:
    """Malformed dotted quads are dropped, never partially guessed."""
    assert normalize_ipv4(address) is None
    assert extract_iocs(make_alert(data={"srcip": address})) == []


def test_documentation_ranges_are_kept_by_default_and_can_be_dropped() -> None:
    """The lab corpus lives in RFC 5737 ranges (SECURITY.md §5)."""
    policy = IOCExtractionPolicy(include_documentation_ipv4=False)

    assert values_of_type(extract_iocs(make_alert(data={"srcip": DOC_IP})), IOCType.IPV4) == [
        DOC_IP
    ]
    assert extract_iocs(make_alert(data={"srcip": DOC_IP}), policy=policy) == []


def test_private_ipv4_can_be_enabled_by_policy() -> None:
    """A deployment may opt into internal addresses explicitly."""
    policy = IOCExtractionPolicy(include_private_ipv4=True)

    assert values_of_type(
        extract_iocs(make_alert(data={"srcip": PRIVATE_IP}), policy=policy), IOCType.IPV4
    ) == [PRIVATE_IP]


def test_public_ipv4_outside_documentation_ranges_is_kept() -> None:
    """A global address is evidence in every policy configuration."""
    assert normalize_ipv4("8.8.8.8") == "8.8.8.8"
    assert normalize_ipv4("8.8.8.8", policy=IOCExtractionPolicy()) == "8.8.8.8"


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------


def test_domain_normalization_lower_cases_and_strips_trailing_dot() -> None:
    """Domains are normalized to lowercase FQDN form."""
    assert normalize_domain("WWW.Example.COM.") == "www.example.com"
    assert normalize_domain("Evil.Example.COM") == "evil.example.com"
    assert normalize_domain("<evil.example.com>") == "evil.example.com"


def test_defanged_domain_is_normalized() -> None:
    """``evil[.]example[.]com`` is one indicator, not three fragments."""
    assert normalize_domain("evil[.]example[.]com") == "evil.example.com"


@pytest.mark.parametrize(
    "candidate",
    [
        "localhost",  # no TLD / not an FQDN
        "etc/passwd",  # file path
        "invoice_tracker.exe",  # filename with underscore
        "1.2.3.4",  # IPv4 literal, not a domain
        "-evil.example.com",  # leading hyphen in label
        "evil..example.com",  # empty label
        "a" * 300 + ".com",  # too long
    ],
)
def test_invalid_domains_are_rejected(candidate: str) -> None:
    """Syntactically invalid domains never become indicators."""
    assert normalize_domain(candidate) is None


def test_domain_extraction_from_free_text() -> None:
    """Text scanning returns domains with their offsets."""
    iocs = extract_iocs_from_text(
        "beacon to CDN-EDGE.Evil-Example.COM. then stop",
        field="source_event.full_log",
        location="/var/log/agent.log",
    )

    assert as_pairs(iocs) == [("domain", "cdn-edge.evil-example.com")]
    assert iocs[0].provenance[0].offset == 10
    assert iocs[0].provenance[0].raw_value == "CDN-EDGE.Evil-Example.COM"
    assert iocs[0].provenance[0].location == "/var/log/agent.log"


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------


def test_url_normalization_drops_default_port_fragment_and_userinfo() -> None:
    """Canonical URLs: no credentials, no default port, no fragment."""
    assert normalize_url("https://user:hunter2@Evil.Example.COM:443/a?b=1#frag") == (
        "https://evil.example.com/a?b=1"
    )
    assert normalize_url("HTTPS://WWW.Example.COM") == "https://www.example.com/"
    assert normalize_url("http://192.0.2.1:8080/x") == "http://192.0.2.1:8080/x"


def test_url_extraction_from_typed_field() -> None:
    """``data.url`` is validated as a whole value."""
    iocs = extract_iocs(make_alert(data={"url": "http://evil.example.com/a.exe?x=1"}))

    assert as_pairs(iocs) == [("url", "http://evil.example.com/a.exe?x=1")]
    assert iocs[0].provenance[0].field == "source_event.data.url"
    assert iocs[0].provenance[0].extractor == EXTRACTOR_TYPED_FIELD


def test_url_extraction_from_free_text() -> None:
    """A URL in text yields a url indicator (and its host as a domain)."""
    iocs = extract_iocs_from_text(
        "fetched https://cdn.evil.example.com:443/dl/payload.exe from cache",
        field="source_event.data.message",
    )

    assert ("url", "https://cdn.evil.example.com/dl/payload.exe") in as_pairs(iocs)
    assert ("domain", "cdn.evil.example.com") in as_pairs(iocs)


@pytest.mark.parametrize(
    "candidate",
    [
        "/products.php?id=1",  # relative path, no scheme/host
        "javascript:alert(1)",  # unsupported scheme
        "ftp://",  # no host
        "http://",  # no host
        "not a url",
    ],
)
def test_invalid_urls_are_rejected(candidate: str) -> None:
    """URLs are validated by scheme + host, never guessed from fragments."""
    assert normalize_url(candidate) is None


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


def test_hash_extraction_from_virustotal_and_fim_fields() -> None:
    """Typed hash fields yield md5 / sha1 / sha256 indicators."""
    alert = make_alert(
        data={"virustotal": {"md5": MD5.upper(), "sha1": SHA1, "sha256": SHA256}},
        syscheck={"md5_after": MD5, "sha256_after": SHA256},
    )

    iocs = extract_iocs(alert)

    assert as_pairs(iocs) == [
        ("md5", MD5),  # upper-case input normalized, deduplicated
        ("sha1", SHA1),
        ("sha256", SHA256),
    ]
    md5 = next(ioc for ioc in iocs if ioc.type is IOCType.MD5)
    assert {p.field for p in md5.provenance} == {
        "source_event.data.virustotal.md5",
        "source_event.syscheck.md5_after",
    }


@pytest.mark.parametrize(
    "candidate",
    [
        "",  # empty
        "bc478d7a48bfab117da4b9bdcb5aee3",  # 31 chars
        "bc478d7a48bfab117da4b9bdcb5aee369",  # 33 chars
        "zz478d7a48bfab117da4b9bdcb5aee36",  # non-hex characters
        "bc478d7a48bfab117da4b9bdcb5aee3 ",  # short after strip
    ],
)
def test_invalid_hashes_are_rejected(candidate: str) -> None:
    """Hashes are validated by length and character set only."""
    assert normalize_hash(candidate) is None


def test_hash_type_is_pinned_for_typed_fields() -> None:
    """A SHA-256 inside an ``md5`` field is not evidence."""
    assert normalize_hash(SHA256, expected=IOCType.MD5) is None
    assert normalize_hash(MD5, expected=IOCType.MD5) == MD5
    assert extract_iocs(make_alert(data={"virustotal": {"md5": SHA256}})) == []


def test_hash_scan_does_not_split_longer_hashes() -> None:
    """A SHA-256 is never also reported as an MD5/SHA-1 prefix."""
    iocs = extract_iocs_from_text(f"file hash {SHA256} seen", field="source_event.data.file")

    assert as_pairs(iocs) == [("sha256", SHA256)]


# ---------------------------------------------------------------------------
# Emails
# ---------------------------------------------------------------------------


def test_email_normalization_keeps_local_case_and_lowers_domain() -> None:
    """The local part is case-sensitive; the domain is not."""
    assert normalize_email("Bob.Smith@Example.ORG") == "Bob.Smith@example.org"
    assert normalize_email("<soc-lab+alerts@example.com>") == "soc-lab+alerts@example.com"


@pytest.mark.parametrize(
    "candidate",
    [
        "bob@localhost",  # not an FQDN
        "bob@@example.com",  # double @
        "bob@example",  # no TLD
        "@example.com",  # no local part
        "bob@-evil.example.com",  # invalid domain label
        "not-an-email",
    ],
)
def test_invalid_emails_are_rejected(candidate: str) -> None:
    """Email candidates must validate as address + routable domain."""
    assert normalize_email(candidate) is None


def test_email_extraction_from_typed_user_field() -> None:
    """A user field carrying an address yields an email indicator."""
    iocs = extract_iocs(make_alert(data={"srcuser": "attacker@evil.example.com"}))

    assert as_pairs(iocs) == [("email", "attacker@evil.example.com")]
    assert iocs[0].provenance[0].field == "source_event.data.srcuser"


# ---------------------------------------------------------------------------
# Mixed input, deduplication, provenance
# ---------------------------------------------------------------------------


def test_mixed_input_yields_every_supported_type() -> None:
    """One alert carrying all indicator types extracts all of them."""
    alert = make_alert(
        data={
            "srcip": DOC_IP,
            "dstip": DOC_IP_2,
            "url": "https://cdn.evil.example.com/dl/invoice.exe",
            "srcuser": "phish@evil.example.com",
            "virustotal": {"md5": MD5, "sha1": SHA1, "sha256": SHA256},
            "message": "beacon to phish.evil.example.com",
            "syscheck_file": "C:\\Users\\jdoe-lab\\invoice_tracker.exe",
        },
        syscheck={"path": "/etc/passwd", "md5_after": MD5},
    )

    iocs = extract_iocs(alert)
    types = {ioc.type for ioc in iocs}

    assert types == {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.EMAIL,
    }
    # Windows paths and FIM paths never turn into domains; the host of the
    # typed URL field is not re-emitted as a domain (see extractor docstring).
    assert values_of_type(iocs, IOCType.DOMAIN) == ["phish.evil.example.com"]
    assert values_of_type(iocs, IOCType.URL) == ["https://cdn.evil.example.com/dl/invoice.exe"]


def test_duplicate_indicators_collapse_with_merged_provenance() -> None:
    """The same normalized value in several fields is one indicator."""
    alert = make_alert(
        data={"srcip": DOC_IP, "dstip": DOC_IP, "virustotal": {"md5": MD5.upper()}},
        syscheck={"md5_after": MD5},
    )

    iocs = extract_iocs(alert)

    assert as_pairs(iocs) == [("ipv4", DOC_IP), ("md5", MD5)]
    ipv4 = next(ioc for ioc in iocs if ioc.type is IOCType.IPV4)
    assert {p.field for p in ipv4.provenance} == {
        "source_event.data.srcip",
        "source_event.data.dstip",
    }
    md5 = next(ioc for ioc in iocs if ioc.type is IOCType.MD5)
    assert len(md5.provenance) == 2  # case/format variants merged, not duplicated


def test_identical_provenance_is_not_duplicated() -> None:
    """Re-running extraction never stacks identical provenance records."""
    alert = make_alert(data={"srcip": DOC_IP})

    first = extract_iocs(alert)
    second = extract_iocs(alert)

    assert len(first[0].provenance) == 1
    assert as_pairs(first) == as_pairs(second)


def test_provenance_records_field_location_and_offset() -> None:
    """Provenance keeps the canonical path, the alert location and the offset."""
    alert = make_alert(
        data={"message": "connected to 203.0.113.50 then exfil"},
        location="/var/log/nginx/error.log",
    )

    iocs = extract_iocs(alert)
    ipv4 = next(ioc for ioc in iocs if ioc.type is IOCType.IPV4)
    provenance = ipv4.provenance[0]

    assert provenance.field == "source_event.data.message"
    assert provenance.location == "/var/log/nginx/error.log"
    assert provenance.offset == 13
    assert provenance.raw_value == DOC_IP
    assert provenance.extractor == EXTRACTOR_TEXT_SCAN


# ---------------------------------------------------------------------------
# False positives & policy switches
# ---------------------------------------------------------------------------


def test_file_paths_are_not_domains() -> None:
    """``/etc/passwd`` and Windows paths must never become domain indicators."""
    alert = make_alert(
        data={"file": "C:\\Users\\jdoe-lab\\Downloads\\invoice_tracker.exe"},
        syscheck={"path": "/etc/passwd"},
    )

    assert extract_iocs(alert) == []


def test_location_is_not_an_extraction_source_by_default() -> None:
    """``location`` is a source descriptor, not evidence (opt-in only)."""
    alert = make_alert(location="/var/log/nginx/error.log", data={"srcip": DOC_IP})
    policy = IOCExtractionPolicy(include_location=True)

    default_fields = {p.field for ioc in extract_iocs(alert) for p in ioc.provenance}
    assert default_fields == {"source_event.data.srcip"}

    # A path-like location stays clean even when scanning is enabled.
    scanned_fields = {p.field for ioc in extract_iocs(alert, policy=policy) for p in ioc.provenance}
    assert scanned_fields == {"source_event.data.srcip"}

    # The switch itself works: a location carrying a host is scanned.
    remote = make_alert(location="dns-evidence cdn.evil.example.com")
    assert extract_iocs(remote) == []
    assert {p.field for ioc in extract_iocs(remote, policy=policy) for p in ioc.provenance} == {
        "source_event.location"
    }


def test_full_log_is_opt_in_per_architecture() -> None:
    """ARCHITECTURE.md §7.1: extraction reads fields, not arbitrary log text."""
    alert = make_alert(full_log=f"Failed password for admin from {DOC_IP} port 41234 ssh2")

    assert extract_iocs(alert) == []

    policy = IOCExtractionPolicy(include_full_log=True)
    iocs = extract_iocs(alert, policy=policy)

    assert as_pairs(iocs) == [("ipv4", DOC_IP)]
    assert iocs[0].provenance[0].field == "source_event.full_log"
    assert iocs[0].provenance[0].offset is not None


def test_version_like_strings_are_not_ipv4() -> None:
    """``1.2.3.4.5`` style strings are rejected by the IPv4 pattern."""
    iocs = extract_iocs_from_text(
        "nginx/1.18.0 upgraded to 1.2.3.4.5 build 9", field="source_event.data.message"
    )
    assert iocs == []


def test_unknown_data_fields_can_be_disabled() -> None:
    """Auto-scanning of unrecognized leaves is a policy decision."""
    alert = make_alert(data={"message": f"beacon {DOC_IP}"})
    policy = IOCExtractionPolicy(include_unknown_data_fields=False)

    assert extract_iocs(alert, policy=policy) == []
    assert as_pairs(extract_iocs(alert)) == [("ipv4", DOC_IP)]


def test_max_iocs_caps_the_indicator_set() -> None:
    """The indicator cap bounds responses and later quota usage."""
    data = {f"ip_{index}": f"198.51.100.{index}" for index in range(1, 20)}
    policy = IOCExtractionPolicy(max_iocs=5)

    iocs = extract_iocs(make_alert(data=data), policy=policy)

    assert len(iocs) == 5
    assert as_pairs(iocs) == sorted(as_pairs(iocs))  # deterministic truncation


# ---------------------------------------------------------------------------
# Determinism & purity
# ---------------------------------------------------------------------------


def test_extraction_is_deterministic_across_repeated_runs() -> None:
    """Same alert + same policy → identical, ordered, byte-equal output."""
    alert = make_alert(
        data={
            "srcip": DOC_IP,
            "url": "https://cdn.evil.example.com/a",
            "srcuser": "phish@evil.example.com",
            "virustotal": {"md5": MD5, "sha256": SHA256},
        },
        syscheck={"md5_after": MD5, "path": "/etc/passwd"},
    )

    runs = [
        json.dumps([ioc.model_dump(mode="json") for ioc in extract_iocs(alert)]) for _ in range(5)
    ]

    assert len(set(runs)) == 1
    assert as_pairs(extract_iocs(alert)) == sorted(as_pairs(extract_iocs(alert)))


def test_extraction_does_not_depend_on_field_insertion_order() -> None:
    """Field iteration is order-independent: dicts are traversed sorted."""
    forward = make_alert(data={"srcip": DOC_IP, "dstip": DOC_IP_2, "message": "beacon 192.0.2.7"})
    backward = make_alert(data={"message": "beacon 192.0.2.7", "dstip": DOC_IP_2, "srcip": DOC_IP})

    assert [ioc.model_dump(mode="json") for ioc in extract_iocs(forward)] == [
        ioc.model_dump(mode="json") for ioc in extract_iocs(backward)
    ]


def test_extraction_is_side_effect_free() -> None:
    """Extraction must not mutate the alert it reads."""
    alert = make_alert(data={"srcip": DOC_IP, "url": "https://evil.example.com/a"})
    before = alert.model_dump(mode="json")

    extract_iocs(alert)

    assert alert.model_dump(mode="json") == before
    assert alert.iocs == []


def test_empty_alert_yields_no_indicators() -> None:
    """An alert without evidence fields extracts nothing (no errors)."""
    assert extract_iocs(make_alert()) == []
    assert extract_iocs_from_text("", field="source_event.full_log") == []


def test_default_policy_is_frozen_and_shared() -> None:
    """The module default is immutable so sharing it is safe."""
    with pytest.raises(ValidationError):
        DEFAULT_IOC_POLICY.max_iocs = 1  # type: ignore[misc]
    assert DEFAULT_IOC_POLICY.max_iocs == 200


# ---------------------------------------------------------------------------
# Contract test: the synthetic sample corpus
# ---------------------------------------------------------------------------


SAMPLE_EXPECTATIONS: dict[str, list[tuple[str, str]]] = {
    "01_wazuh_ssh_brute_force.json": [("ipv4", DOC_IP)],
    "02_wazuh_ssh_brute_force_success.json": [("ipv4", DOC_IP)],
    "03_wazuh_fim_etc_passwd_change.json": [
        ("md5", "bc478d7a48bfab117da4b9bdcb5aee36"),
        ("md5", "cb1e913a5dd676ba1ee0715c0a604b07"),
        ("sha256", "5ac4ad709135aadc306574382fcb94d33c1bb4fcdd8eb2f7b43e6b71dc6d1e95"),
    ],
    "04_wazuh_malware_hash_virustotal.json": [
        ("md5", MD5),
        ("sha1", SHA1),
        (
            "sha256",
            SHA256,
        ),
        (
            "url",
            f"https://www.virustotal.com/gui/file/{SHA256}/detection",
        ),
    ],
    "05_wazuh_web_sql_injection.json": [("ipv4", DOC_IP_2)],
    "06_wazuh_windows_user_created.json": [],
}


@pytest.mark.parametrize("name", sorted(SAMPLE_EXPECTATIONS))
def test_sample_alerts_extract_expected_indicators(name: str) -> None:
    """Every sample fixture normalizes and extracts its documented IOCs."""
    payload = json.loads((FIXTURES_DIR / name).read_text())
    canonical = normalize_wazuh_alert(WazuhAlert.model_validate(payload))

    assert as_pairs(extract_iocs(canonical)) == SAMPLE_EXPECTATIONS[name]


def test_sample_alerts_keep_private_agent_addresses_out() -> None:
    """Sample agents live in 10.0.0.0/8 — they must never be indicators."""
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        payload = json.loads(path.read_text())
        canonical = normalize_wazuh_alert(WazuhAlert.model_validate(payload))
        values = {ioc.value for ioc in extract_iocs(canonical)}

        assert canonical.source_event.agent.ip is None or (
            canonical.source_event.agent.ip not in values
        )


# ---------------------------------------------------------------------------
# Normalization edge cases & defensive paths
# ---------------------------------------------------------------------------


def test_internationalized_domains_are_converted_to_punycode() -> None:
    """Non-ASCII hosts are normalized to their ASCII (punycode) form."""
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"
    assert normalize_domain("xn--bcher-kva.example") == "xn--bcher-kva.example"


def test_unconvertible_internationalized_domain_is_rejected() -> None:
    """An IDN that cannot be encoded is dropped rather than stored raw."""
    assert normalize_domain("bücher" * 20 + ".example") is None


@pytest.mark.parametrize("candidate", ["", "   "])
def test_empty_urls_are_rejected(candidate: str) -> None:
    """Blank values never become indicators."""
    assert normalize_url(candidate) is None


def test_url_with_out_of_range_port_is_rejected() -> None:
    """A malformed port is a parse error, not a truncated URL."""
    assert normalize_url("http://example.com:99999/x") is None


def test_ipv6_hosts_are_out_of_scope() -> None:
    """IPv6-literal hosts are not Phase 1E indicators (IPv4 + domains only)."""
    assert normalize_url("http://[::1]/x") is None


def test_email_with_invalid_local_part_is_rejected() -> None:
    """Spaces and other illegal local-part characters are rejected."""
    assert normalize_email("bo b@example.com") is None


def test_typed_hostname_field_yields_a_domain() -> None:
    """``data.hostname`` is a typed domain field (whole-value validation)."""
    alert = make_alert(data={"hostname": "EVIL.Example.COM"})

    iocs = extract_iocs(alert)

    assert as_pairs(iocs) == [("domain", "evil.example.com")]
    assert iocs[0].provenance[0].field == "source_event.data.hostname"


def test_single_label_hostname_is_not_a_domain() -> None:
    """A bare host name (``FIN-WS-07``) is not an FQDN indicator."""
    assert extract_iocs(make_alert(data={"hostname": "FIN-WS-07"})) == []


def test_typed_field_path_through_a_scalar_is_ignored() -> None:
    """A typed path whose parent is not an object yields nothing (no crash)."""
    alert = make_alert(data={"virustotal": "not-a-dict"})

    assert extract_iocs(alert) == []


def test_email_scanning_in_free_text() -> None:
    """Addresses inside free text are extracted with their offsets."""
    iocs = extract_iocs_from_text(
        "sender: soc-lab+alerts@example.com (lab)", field="source_event.data.message"
    )

    email = next(ioc for ioc in iocs if ioc.type is IOCType.EMAIL)
    assert email.value == "soc-lab+alerts@example.com"
    assert email.provenance[0].offset == 8
    # The address domain is reported as its own indicator (both are useful
    # enrichment keys), but never twice for the same value.
    assert values_of_type(iocs, IOCType.DOMAIN) == ["example.com"]


def test_hash_scan_anchors_hex_runs_to_word_boundaries() -> None:
    """A hex run adjacent to punctuation is extracted with its exact span."""
    iocs = extract_iocs_from_text(f"digest={MD5};", field="source_event.data.message")

    assert as_pairs(iocs) == [("md5", MD5)]
    assert iocs[0].provenance[0].offset == 7
    assert iocs[0].provenance[0].raw_value == MD5


def test_missing_full_log_is_safe_when_scanning_is_enabled() -> None:
    """Enabling ``full_log`` scanning on an alert without one is a no-op."""
    policy = IOCExtractionPolicy(include_full_log=True)

    assert extract_iocs(make_alert(full_log=None), policy=policy) == []
