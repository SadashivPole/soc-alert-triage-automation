"""IOC extraction from canonical alerts (Phase 1E).

Pure, deterministic, side-effect free: ``(CanonicalAlert, policy) → [IOC]``.
No I/O, no clock, no logging, no randomness — the same alert always yields the
identical, ordered indicator list, which is what makes the pipeline testable
and re-runnable (ARCHITECTURE.md §17: "no network access in unit/integration
tests", "deterministic").

**Two extraction strategies** (recorded per indicator in
:class:`~soc_triage.models.ioc.IOCProvenance`):

1. *Typed fields* (:data:`TYPED_FIELDS`) — a known canonical path whose **whole
   value** must validate as one indicator type (``data.srcip`` → ``ipv4``,
   ``data.virustotal.sha256`` → ``sha256``, ``syscheck.md5_after`` → ``md5``,
   …). Whole-value validation is the strongest false-positive guard: a field
   that says it holds a source IP either parses as one or yields nothing.
2. *Text scan* — pattern matching inside free-text fields. Enabled by policy
   for ``full_log`` (:data:`include_full_log`, off by default per
   ARCHITECTURE.md §7.1), ``location`` (off) and for unrecognized string
   leaves under ``data`` / ``syscheck``.

False-positive controls beyond validation:

* strict IPv4 octets plus lookaround guards, so ``1.2.3.4.5`` (a version-ish
  string) is never an IP;
* domains must have an alphabetic TLD and LDH labels, so a Windows path or a
  ``*.exe`` filename never becomes a domain;
* a domain match directly preceded by ``/`` or ``\\`` is rejected — file paths
  like ``/etc/passwd`` are not hosts — unless it is the authority of a URL
  (``//host/…``), so URL hosts are still captured;
* non-routable IPv4 is dropped by policy (see :mod:`.policy`);
* a URL's **userinfo** is never evidence: the sanitized URL is stored as both
  the indicator value and the provenance ``raw_value``, and ``user:pass@host``
  is never re-extracted as an email or domain (SECURITY.md §2);
* overlapping matches of *different* types are intentionally kept (a URL and
  its host domain are both useful enrichment keys), while identical
  ``(type, value)`` pairs collapse into one indicator with merged provenance.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from typing import Any, NamedTuple

from pydantic import BaseModel

from ..models.canonical import CanonicalAlert
from ..models.ioc import (
    EXTRACTOR_TEXT_SCAN,
    EXTRACTOR_TYPED_FIELD,
    IOC,
    IOCProvenance,
    IOCType,
    ioc_sort_key,
)
from .normalize import (
    hash_type_for,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ipv4,
    normalize_url,
)
from .policy import DEFAULT_IOC_POLICY, IOCExtractionPolicy

# --- Patterns -------------------------------------------------------------

# ``[.]`` / ``(.)`` / ``{.}`` are accepted as dot separators so a defanged
# indicator is captured as one match; normalization rewrites them afterwards.
_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\})"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"

# Hashes longest-first so a 64-hex string is not read as an MD5 (the
# lookaround would reject the short match anyway; this avoids backtracking).
_HASH_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})"
    r"(?![A-Za-z0-9])"
)
# ``(?![A-Za-z0-9_-]|\.[A-Za-z0-9])`` rejects "1.2.3.4.5" and hostnames such
# as "1.2.3.4.example.com" while allowing a sentence-final "1.2.3.4.".
_IPV4_RE = re.compile(
    rf"(?<![A-Za-z0-9._-]){_OCTET}{_DOT}{_OCTET}{_DOT}{_OCTET}{_DOT}{_OCTET}"
    r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9])"
)
_DOMAIN_RE = re.compile(rf"(?<![A-Za-z0-9._-])(?:{_LABEL}{_DOT})+[A-Za-z]{{2,63}}(?![A-Za-z0-9_])")
_URL_RE = re.compile(
    r"(?<![A-Za-z0-9+.\-])(?:https?|ftp|hxxps?)://[^\s<>\"']+",
    flags=re.IGNORECASE,
)
_EMAIL_LOCAL = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
_EMAIL_RE = re.compile(
    rf"(?<![A-Za-z0-9._%+-]){_EMAIL_LOCAL}@(?:{_LABEL}{_DOT})+[A-Za-z]{{2,63}}"
    r"(?![A-Za-z0-9_])"
)

#: Punctuation trimmed from the edges of a scanned match.
_LEADING_PUNCTUATION = "'\"(<[{"
_TRAILING_PUNCTUATION = "'\".,;:!?)]}>"

# --- Field specifications -------------------------------------------------

#: Known canonical paths → the indicator type their whole value must be.
#: Order is declaration order, which keeps extraction deterministic.
TYPED_FIELDS: tuple[tuple[str, IOCType], ...] = (
    ("source_event.agent.ip", IOCType.IPV4),
    ("source_event.data.srcip", IOCType.IPV4),
    ("source_event.data.dstip", IOCType.IPV4),
    ("source_event.data.srcuser", IOCType.EMAIL),
    ("source_event.data.dstuser", IOCType.EMAIL),
    ("source_event.data.hostname", IOCType.DOMAIN),
    ("source_event.data.url", IOCType.URL),
    ("source_event.data.virustotal.md5", IOCType.MD5),
    ("source_event.data.virustotal.sha1", IOCType.SHA1),
    ("source_event.data.virustotal.sha256", IOCType.SHA256),
    ("source_event.data.virustotal.permalink", IOCType.URL),
    ("source_event.syscheck.md5_before", IOCType.MD5),
    ("source_event.syscheck.md5_after", IOCType.MD5),
    ("source_event.syscheck.sha1_before", IOCType.SHA1),
    ("source_event.syscheck.sha1_after", IOCType.SHA1),
    ("source_event.syscheck.sha256_before", IOCType.SHA256),
    ("source_event.syscheck.sha256_after", IOCType.SHA256),
)

#: Free-text fields scanned only when the policy enables them.
OPTIONAL_SCAN_FIELDS: tuple[tuple[str, str], ...] = (
    ("source_event.full_log", "include_full_log"),
    ("source_event.location", "include_location"),
)

#: Nested blocks whose unrecognized string leaves are auto-scanned.
AUTO_SCAN_ROOTS: tuple[str, ...] = ("source_event.data", "source_event.syscheck")


class _Candidate(NamedTuple):
    """One accepted match before merging."""

    type: IOCType
    value: str
    provenance: IOCProvenance


def _resolve(alert: CanonicalAlert, path: str) -> Any:
    """Read a dotted path from a canonical alert (models and dicts)."""
    node: Any = alert
    for part in path.split("."):
        if isinstance(node, BaseModel):
            node = getattr(node, part, None)
        elif isinstance(node, dict):
            node = node.get(part)
        else:
            return None
        if node is None:
            return None
    return node


def _string_leaves(prefix: str, node: Any) -> Iterator[tuple[str, str]]:
    """Yield ``(dotted_path, value)`` for every string leaf, sorted by path."""
    if isinstance(node, str):
        yield prefix, node
        return
    if not isinstance(node, dict):
        return
    for key in sorted(node):
        yield from _string_leaves(f"{prefix}.{key}", node[key])


def _clean_match(raw: str) -> tuple[str, str]:
    """Return ``(raw, trimmed)`` with edge punctuation removed from ``trimmed``."""
    trimmed = raw.strip().lstrip(_LEADING_PUNCTUATION).rstrip(_TRAILING_PUNCTUATION)
    return raw, trimmed


def _url_authority_spans(text: str) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Return ``(authority_spans, userinfo_spans)`` for the URLs in ``text``.

    Userinfo (``user:pass@``) is **not evidence**: an ``user@host`` / ``pass@host``
    substring inside a URL's authority must never be re-extracted as an email or
    domain — that would leak credentials into the IOC set (SECURITY.md §2).

    * ``authority_spans`` cover each URL's whole netloc (``userinfo@host:port``)
      and are used to suppress *email* matches that overlap it (the email local
      part may legally start with ``/``, so a ``//user@host`` match must be
      dropped, not just ``user@host``);
    * ``userinfo_spans`` cover only the userinfo portion (before the ``@``) and
      are used to suppress *domain* matches that are really the username/
      password, while still allowing the *host* (after the ``@``) as a domain.
    """
    authority_spans: list[tuple[int, int]] = []
    userinfo_spans: list[tuple[int, int]] = []
    for match in _URL_RE.finditer(text):
        raw = match.group(0)
        scheme_idx = raw.find("://")
        if scheme_idx == -1:
            continue
        rest_start = scheme_idx + 3
        rest = raw[rest_start:]
        end = len(rest)
        for sep in ("/", "?", "#"):
            idx = rest.find(sep)
            if idx != -1:
                end = min(end, idx)
        authority_start = match.start() + rest_start
        authority_end = authority_start + end
        authority_spans.append((authority_start, authority_end))
        at = rest[:end].rfind("@")
        if at != -1:
            userinfo_spans.append((authority_start, authority_start + at))
    return authority_spans, userinfo_spans


def _domain_boundary_ok(text: str, start: int, end: int) -> bool:
    """Reject path-like domain matches (``/etc/passwd``), allow URL hosts.

    A match preceded by ``/`` or ``\\`` is treated as part of a path unless it
    is the authority of a URL (``//host/…``). A match followed by ``\\`` is
    likewise part of a Windows path.
    """
    previous = text[start - 1] if start > 0 else ""
    if previous in "/\\" and not (start >= 2 and text[start - 2] == "/"):
        return False
    following = text[end] if end < len(text) else ""
    return following != "\\"


def _scan_text(
    text: str,
    *,
    field: str,
    location: str | None,
    policy: IOCExtractionPolicy,
) -> list[_Candidate]:
    """Extract every indicator from one free-text field value."""
    candidates: list[_Candidate] = []

    def add(kind: IOCType, raw: str, value: str, offset: int) -> None:
        candidates.append(
            _Candidate(
                type=kind,
                value=value,
                provenance=IOCProvenance(
                    field=field,
                    extractor=EXTRACTOR_TEXT_SCAN,
                    raw_value=raw,
                    offset=offset,
                    location=location,
                ),
            )
        )

    authority_spans, userinfo_spans = _url_authority_spans(text)

    def within(spans: list[tuple[int, int]], offset: int) -> bool:
        return any(start <= offset < end for start, end in spans)

    def overlaps(spans: list[tuple[int, int]], start: int, end: int) -> bool:
        return any(s < end and start < e for s, e in spans)

    for match in _URL_RE.finditer(text):
        raw, trimmed = _clean_match(match.group(0))
        value = normalize_url(trimmed)
        if value is not None:
            # SECURITY: store only the sanitized (userinfo-free) URL as the
            # provenance raw value — never the original credential-bearing match.
            add(IOCType.URL, value, value, match.start())

    for match in _EMAIL_RE.finditer(text):
        if overlaps(authority_spans, match.start(), match.end()):
            continue  # a URL's userinfo is not an email (SECURITY.md §2)
        raw, trimmed = _clean_match(match.group(0))
        value = normalize_email(trimmed)
        if value is not None:
            add(IOCType.EMAIL, raw, value, match.start())

    for match in _DOMAIN_RE.finditer(text):
        if within(userinfo_spans, match.start()):
            continue  # a URL's userinfo is not a domain (SECURITY.md §2)
        if not _domain_boundary_ok(text, match.start(), match.end()):
            continue
        raw, trimmed = _clean_match(match.group(0))
        value = normalize_domain(trimmed)
        if value is not None:
            add(IOCType.DOMAIN, raw, value, match.start())

    for match in _IPV4_RE.finditer(text):
        raw, trimmed = _clean_match(match.group(0))
        value = normalize_ipv4(trimmed, policy=policy)
        if value is not None:
            add(IOCType.IPV4, raw, value, match.start())

    for match in _HASH_RE.finditer(text):
        raw, trimmed = _clean_match(match.group(0))
        kind = hash_type_for(trimmed)
        if kind is not None:
            value = normalize_hash(trimmed, expected=kind)
            if value is not None:
                add(kind, raw, value, match.start())

    return candidates


def _scan_typed_field(kind: IOCType, value: str, policy: IOCExtractionPolicy) -> str | None:
    """Normalize a typed field's whole value, or ``None`` if it is not one."""
    text = value.strip()
    if not text:
        return None
    if kind is IOCType.IPV4:
        return normalize_ipv4(text, policy=policy)
    if kind is IOCType.DOMAIN:
        return normalize_domain(text)
    if kind is IOCType.URL:
        return normalize_url(text)
    if kind is IOCType.EMAIL:
        return normalize_email(text)
    return normalize_hash(text, expected=kind)


def _provenance_sort_key(provenance: IOCProvenance) -> tuple[str, int, str, str, str]:
    return (
        provenance.field,
        provenance.offset if provenance.offset is not None else -1,
        provenance.raw_value,
        provenance.extractor,
        provenance.location or "",
    )


def _merge(candidates: Sequence[_Candidate], policy: IOCExtractionPolicy) -> list[IOC]:
    """Collapse candidates by ``(type, value)`` and order them deterministically."""
    merged: dict[tuple[IOCType, str], dict[IOCProvenance, None]] = {}
    for candidate in candidates:
        merged.setdefault((candidate.type, candidate.value), {})[candidate.provenance] = None

    iocs = [
        IOC(
            type=kind,
            value=value,
            provenance=tuple(sorted(provenance, key=_provenance_sort_key)),
        )
        for (kind, value), provenance in merged.items()
    ]
    iocs.sort(key=ioc_sort_key)
    return iocs[: policy.max_iocs]


def extract_iocs_from_text(
    text: str,
    *,
    field: str,
    location: str | None = None,
    policy: IOCExtractionPolicy = DEFAULT_IOC_POLICY,
) -> list[IOC]:
    """Extract indicators from a single free-text value.

    Args:
        text: The field value to scan.
        field: Canonical dotted path recorded as provenance.
        location: Alert source location recorded as provenance.
        policy: Extraction policy (false-positive controls).

    Returns:
        Indicators ordered by ``(type, value)``, deduplicated, provenance-merged.
    """
    if not text:
        return []
    return _merge(_scan_text(text, field=field, location=location, policy=policy), policy)


def extract_iocs(
    alert: CanonicalAlert,
    *,
    policy: IOCExtractionPolicy = DEFAULT_IOC_POLICY,
) -> list[IOC]:
    """Extract every indicator of a canonical alert.

    Pure and deterministic: no I/O, no clock, no logging. Repeated calls with
    the same alert and policy return identical results (including ordering).

    Args:
        alert: The normalized canonical alert.
        policy: Extraction policy (defaults to the project policy).

    Returns:
        Indicators ordered by ``(type, normalized value)``. Each indicator
        carries every provenance record it was found under, so the same value
        seen in two fields appears exactly once.
    """
    candidates: list[_Candidate] = []
    location = alert.source_event.location
    typed_paths = {path for path, _ in TYPED_FIELDS}

    for path, kind in TYPED_FIELDS:
        value = _resolve(alert, path)
        if not isinstance(value, str):
            continue
        normalized = _scan_typed_field(kind, value, policy)
        if normalized is None:
            continue
        # SECURITY: for URLs the provenance raw value is the *sanitized* URL
        # (userinfo removed), never the original credential-bearing field value.
        raw_value = normalized if kind is IOCType.URL else value
        candidates.append(
            _Candidate(
                type=kind,
                value=normalized,
                provenance=IOCProvenance(
                    field=path,
                    extractor=EXTRACTOR_TYPED_FIELD,
                    raw_value=raw_value,
                    location=location,
                ),
            )
        )

    if policy.include_unknown_data_fields:
        for root in AUTO_SCAN_ROOTS:
            node = _resolve(alert, root)
            if not node:
                continue
            for path, value in _string_leaves(root, node):
                if path in typed_paths:
                    continue
                candidates.extend(_scan_text(value, field=path, location=location, policy=policy))

    for path, flag in OPTIONAL_SCAN_FIELDS:
        if not getattr(policy, flag):
            continue
        value = _resolve(alert, path)
        if not isinstance(value, str):
            continue
        candidates.extend(_scan_text(value, field=path, location=location, policy=policy))

    return _merge(candidates, policy)


__all__ = [
    "AUTO_SCAN_ROOTS",
    "OPTIONAL_SCAN_FIELDS",
    "TYPED_FIELDS",
    "extract_iocs",
    "extract_iocs_from_text",
]
