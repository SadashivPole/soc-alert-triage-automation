"""Phase 2A hardening: URL credential-leak regression tests.

Pin the guarantee that a credential-bearing URL (``https://user:pass@host/…``)
never leaks its userinfo into the IOC set or the persisted canonical payload
(SECURITY.md §2). The canonical value is sanitized by :func:`normalize_url`
(userinfo dropped), and — the previously-broken part — so is the provenance
``raw_value``:

* typed URL fields (``data.url``, ``data.virustotal.permalink``) store the
  sanitized URL as ``raw_value`` instead of the raw field value;
* text-scanned URLs store the sanitized URL as ``raw_value`` instead of the raw
  match;
* the URL's userinfo is never re-extracted as an email or domain indicator
  (``user:pass@host`` → ``pass@host`` is not an email; the host *is* kept).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from soc_triage.enrichment import extract_iocs, extract_iocs_from_text
from soc_triage.enrichment.normalize import normalize_url, strip_url_userinfo
from soc_triage.ingest.normalizer import normalize_wazuh_alert
from soc_triage.ingest.schemas import WazuhAlert
from soc_triage.models.canonical import (
    CanonicalAgent,
    CanonicalAlert,
    CanonicalRule,
    CanonicalSourceEvent,
)
from soc_triage.models.ioc import IOCType

CREDENTIAL_URL = "https://analyst:SuperSecret123@example.com/login"
SECRET = "SuperSecret123"
SANITIZED_URL = "https://example.com/login"


def make_alert(**source_event_fields: Any) -> CanonicalAlert:
    """Build a canonical alert with only the fields under test populated."""
    return CanonicalAlert(
        alert_id=UUID(int=1),
        source="wazuh",
        received_at=datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC),
        source_event=CanonicalSourceEvent(
            rule=CanonicalRule(id="5710", level=5, description="synthetic"),
            agent=CanonicalAgent(id="001", name="host-001"),
            **source_event_fields,
        ),
    )


def every_string(iocs: list[Any]) -> list[str]:
    """All provenance strings (values + raw values) for leak assertions."""
    blobs: list[str] = []
    for ioc in iocs:
        blobs.append(ioc.value)
        for provenance in ioc.provenance:
            blobs.append(provenance.raw_value)
    return blobs


# ---------------------------------------------------------------------------
# Typed URL fields
# ---------------------------------------------------------------------------


def test_typed_url_field_strips_userinfo_from_value_and_raw_value() -> None:
    """``data.url`` yields a sanitized value and a sanitized raw_value."""
    iocs = extract_iocs(make_alert(data={"url": CREDENTIAL_URL}))

    assert [(ioc.type, ioc.value) for ioc in iocs] == [(IOCType.URL, SANITIZED_URL)]
    assert iocs[0].provenance[0].raw_value == SANITIZED_URL
    assert all(SECRET not in blob for blob in every_string(iocs))


def test_typed_permalink_field_strips_userinfo_from_value_and_raw_value() -> None:
    """``data.virustotal.permalink`` is a typed URL field — also sanitized."""
    permalink = f"https://analyst:{SECRET}@example.com/gui/file/abc/detection"
    iocs = extract_iocs(make_alert(data={"virustotal": {"permalink": permalink}}))

    assert [(ioc.type, ioc.value) for ioc in iocs] == [
        (IOCType.URL, "https://example.com/gui/file/abc/detection")
    ]
    assert iocs[0].provenance[0].raw_value == "https://example.com/gui/file/abc/detection"
    assert all(SECRET not in blob for blob in every_string(iocs))


# ---------------------------------------------------------------------------
# Text-scanned URLs
# ---------------------------------------------------------------------------


def test_text_scanned_url_strips_userinfo_from_raw_value() -> None:
    """A credential URL in free text yields a sanitized URL, not its raw match."""
    iocs = extract_iocs_from_text(
        f"beacon GET {CREDENTIAL_URL} then stop", field="source_event.data.message"
    )

    urls = [ioc for ioc in iocs if ioc.type is IOCType.URL]
    assert [(ioc.value, ioc.provenance[0].raw_value) for ioc in urls] == [
        (SANITIZED_URL, SANITIZED_URL)
    ]
    assert all(SECRET not in blob for blob in every_string(iocs))


def test_text_scanned_url_does_not_yield_email_or_domain_from_userinfo() -> None:
    """``user:pass@host`` must not leak ``pass@host`` as an email indicator."""
    iocs = extract_iocs_from_text(
        f"GET {CREDENTIAL_URL} fetched", field="source_event.data.message"
    )

    types = {ioc.type for ioc in iocs}
    assert IOCType.EMAIL not in types  # no "SuperSecret123@example.com"
    # The host is legitimate evidence and is still reported as a domain.
    assert (IOCType.DOMAIN, "example.com") in {(ioc.type, ioc.value) for ioc in iocs}
    assert all(SECRET not in blob for blob in every_string(iocs))


def test_text_scanned_url_with_username_only_does_not_yield_email() -> None:
    """``https://user@host/`` must not produce an ``user@host`` email."""
    iocs = extract_iocs_from_text(
        "GET https://analyst@example.com/path", field="source_event.data.message"
    )

    assert IOCType.EMAIL not in {ioc.type for ioc in iocs}


# ---------------------------------------------------------------------------
# strip_url_userinfo helper
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        (CREDENTIAL_URL, SANITIZED_URL),
        ("https://user@example.com/x", "https://example.com/x"),
        ("http://a:b@192.0.2.1:8080/x", "http://192.0.2.1:8080/x"),
        ("hxxps://analyst[:]SuperSecret123@example.com/login", SANITIZED_URL),
    ],
)
def test_strip_url_userinfo_removes_credentials(raw: str, expected: str) -> None:
    """Userinfo (with and without defang markers) is removed."""
    assert strip_url_userinfo(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "https://example.com/path",  # no userinfo
        "https://EVIL.Example.COM:8443/a?b=1",  # benign, preserved verbatim
        "not a url",
        "",
    ],
)
def test_strip_url_userinfo_leaves_benign_values_unchanged(raw: str) -> None:
    """Non-credential inputs are returned verbatim."""
    assert strip_url_userinfo(raw) == raw


def test_normalize_url_removes_userinfo() -> None:
    """The canonical form is userinfo-free (the value-side guarantee)."""
    assert normalize_url(CREDENTIAL_URL) == SANITIZED_URL


# ---------------------------------------------------------------------------
# Normalizer → persisted canonical payload
# ---------------------------------------------------------------------------


def _wazuh_payload(url: str) -> dict[str, Any]:
    return {
        "id": "1770000000.900001",
        "rule": {"level": 12, "description": "credential URL", "id": "99999"},
        "agent": {"id": "009", "name": "host-009"},
        "data": {"url": url},
    }


def test_normalizer_strips_userinfo_from_typed_url_field() -> None:
    """The canonical alert's ``data.url`` must never persist credentials."""
    payload = _wazuh_payload(CREDENTIAL_URL)
    canonical = normalize_wazuh_alert(WazuhAlert.model_validate(payload))

    assert canonical.source_event.data["url"] == SANITIZED_URL
    assert SECRET not in canonical.model_dump_json()


def test_normalizer_leaves_benign_url_untouched() -> None:
    """A non-credential URL in ``data.url`` is preserved."""
    payload = _wazuh_payload("https://example.com/path?x=1")
    canonical = normalize_wazuh_alert(WazuhAlert.model_validate(payload))

    assert canonical.source_event.data["url"] == "https://example.com/path?x=1"


def test_normalizer_strips_permalink_userinfo() -> None:
    """``data.virustotal.permalink`` is stripped in the canonical payload too."""
    permalink = f"https://analyst:{SECRET}@example.com/gui/file/abc"
    payload = {
        "id": "1770000000.900002",
        "rule": {"level": 12, "description": "x", "id": "99999"},
        "agent": {"id": "009", "name": "host-009"},
        "data": {"virustotal": {"permalink": permalink}},
    }
    canonical = normalize_wazuh_alert(WazuhAlert.model_validate(payload))

    assert canonical.source_event.data["virustotal"]["permalink"] == (
        "https://example.com/gui/file/abc"
    )
    assert SECRET not in canonical.model_dump_json()
