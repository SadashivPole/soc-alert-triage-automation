"""Validation and normalization of raw indicator strings (Phase 1E).

Every function here is pure: ``(raw string) → normalized string | None``.
``None`` means "not an indicator of this type" — callers never raise, they
simply drop the candidate. That is what turns messy log text into a clean,
deduplicable indicator set.

Normalization rules

* **IPv4** — parsed with :mod:`ipaddress` (rejects ``999.1.1.1``, leading
  zeros, short/long forms); range policy applied by the caller-supplied
  :class:`~soc_triage.enrichment.policy.IOCExtractionPolicy`.
* **Domain** — lowercased, trailing dot and wrapping quotes stripped,
  defang markers rewritten, then validated label-by-label (LDH rules,
  alphabetic TLD, ≤253 chars). File paths such as ``/etc/passwd`` may *look*
  like domains; the extractor's boundary rule rejects them.
* **URL** — scheme must be ``http``/``https``/``ftp``; host lowercased (IDNA
  when non-ASCII), default port dropped, **userinfo removed** (credentials
  must never become part of a stored indicator — SECURITY.md §2), fragment
  dropped, path/query preserved verbatim.
* **Hashes** — hex-only, exact length (32/40/64), lowercased. Validated by
  format only; no content is ever fetched or executed.
* **Email** — single ``@``, validated local part, domain normalized as above
  (local part keeps its case: it is case-sensitive by RFC).

Defanging (``hxxp://``, ``evil[.]example[.]com``) is normalized so indicators
survive copy/paste from reports; the *raw* match is still preserved in the
IOC's provenance.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from ..models.ioc import HASH_LENGTHS, IOCType
from .policy import DEFAULT_IOC_POLICY, IOCExtractionPolicy

# --- Defanging ------------------------------------------------------------

_DEFANG_DOT_RE = re.compile(r"[\[({]\.[\])}]")
_DEFANG_COLON_RE = re.compile(r"[\[({]:[\])}]")
_DEFANG_AT_RE = re.compile(r"[\[({]@[\])}]")
_DEFANG_SLASHES_RE = re.compile(r"[\[({]/{2}[\])}]")
_DEFANG_SCHEME_RE = re.compile(r"^hxxp(?P<secure>s?)(?=://)", flags=re.IGNORECASE)

# --- Validation -----------------------------------------------------------

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+[a-z]{{2,63}}$")
_EMAIL_LOCAL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HASH_BY_LENGTH: dict[int, IOCType] = {length: kind for kind, length in HASH_LENGTHS.items()}

_ALLOWED_URL_SCHEMES = frozenset({"http", "https", "ftp"})
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443, "ftp": 21}
_MAX_DOMAIN_LENGTH = 253


def defang_to_plain(value: str) -> str:
    """Rewrite common defang markers back to their plain equivalents.

    ``hxxps://evil[.]example[.]com/x`` → ``https://evil.example.com/x``.
    """
    text = _DEFANG_DOT_RE.sub(".", value)
    text = _DEFANG_COLON_RE.sub(":", text)
    text = _DEFANG_AT_RE.sub("@", text)
    text = _DEFANG_SLASHES_RE.sub("//", text)
    return _DEFANG_SCHEME_RE.sub(lambda match: f"http{match.group('secure')}", text)


def _as_ascii_domain(host: str) -> str | None:
    """Lowercase a host, converting non-ASCII (IDN) labels to punycode."""
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None


def normalize_ipv4(raw: str, *, policy: IOCExtractionPolicy = DEFAULT_IOC_POLICY) -> str | None:
    """Return the dotted-quad form of ``raw`` when it is an allowed IPv4."""
    # A single trailing dot is tolerated so an indicator at the end of a
    # sentence still parses ("connected to 203.0.113.50.").
    text = raw.strip().rstrip(".").strip()
    if not text:
        return None
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return None
    if not policy.ipv4_allowed(address):
        return None
    return str(address)


#: Authority decomposition of a URL: scheme, authority (userinfo@host:port) and
#: the rest of the URL. The authority is delimited by the first ``/``, ``?`` or
#: ``#`` (or end of string).
_URL_AUTHORITY_RE = re.compile(
    r"^(?P<prefix>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<authority>[^/?#]*)(?P<suffix>.*)$"
)


def strip_url_userinfo(raw: str) -> str:
    """Remove URL userinfo (``user:pass@``) from ``raw``, keeping the rest verbatim.

    A credential-bearing URL must never be persisted in a *structured* (typed)
    field, even though the free-text ``full_log`` is preserved raw (SECURITY.md
    §5: the platform keeps what Wazuh already logged). This returns ``raw``
    unchanged when there is no scheme+authority or no userinfo, so benign URLs
    are never rewritten. When userinfo *is* present it is dropped — everything
    from the last ``@`` in the authority back to ``://`` (per RFC 3986 an ``@``
    inside a password must be percent-encoded, so the last raw ``@`` separates
    userinfo from host:port).

    Defanged schemes (``hxxp://``, ``[:]``) are normalized first so a defanged
    credential URL is stripped too.
    """
    text = defang_to_plain(raw.strip()).strip("<>\"'`").strip()
    match = _URL_AUTHORITY_RE.match(text)
    if match is None:
        return raw
    authority = match.group("authority")
    if "@" not in authority:
        return raw
    _, _, hostport = authority.rpartition("@")
    return f"{match.group('prefix')}{hostport}{match.group('suffix')}"


def normalize_domain(raw: str) -> str | None:
    """Return the normalized domain in ``raw``, or ``None`` if invalid."""
    text = defang_to_plain(raw.strip()).strip("<>\"'`").strip().rstrip(".")
    if not text or "." not in text:
        return None
    candidate = _as_ascii_domain(text)
    if candidate is None:
        return None
    candidate = candidate.lower()
    if len(candidate) > _MAX_DOMAIN_LENGTH or not _DOMAIN_RE.match(candidate):
        return None
    return candidate


def normalize_url(raw: str) -> str | None:
    """Return the canonical form of the URL in ``raw``, or ``None``."""
    text = defang_to_plain(raw.strip()).strip("<>\"'`").strip()
    if not text:
        return None
    try:
        parts = urlsplit(text)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:  # malformed port / netloc
        return None

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES or not host:
        return None

    # Accept a DNS host or an IPv4 literal; IPv6-literal hosts are out of
    # Phase 1E scope (and the URL pattern never yields one).
    candidate_host = host.lower().rstrip(".")
    if _DOMAIN_RE.match(candidate_host):
        netloc = candidate_host
    else:
        try:
            netloc = str(ipaddress.IPv4Address(host))
        except ValueError:
            return None

    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{port}"

    # SECURITY: userinfo (``https://user:pass@host/``) is dropped — a stored
    # indicator must never carry credentials (SECURITY.md §2).
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def hash_type_for(raw: str) -> IOCType | None:
    """Return the hash type matching ``raw`` by length/charset, else ``None``."""
    text = raw.strip()
    if not text or not _HEX_RE.match(text):
        return None
    return _HASH_BY_LENGTH.get(len(text))


def normalize_hash(raw: str, *, expected: IOCType | None = None) -> str | None:
    """Return the lowercased hash in ``raw`` when its format is valid.

    ``expected`` pins the type (used for typed fields such as
    ``data.virustotal.md5``, where a SHA-256 in an MD5 field is not evidence).
    """
    text = raw.strip()
    found = hash_type_for(text)
    if found is None or (expected is not None and found is not expected):
        return None
    return text.lower()


def normalize_email(raw: str) -> str | None:
    """Return the normalized email address in ``raw``, or ``None``.

    The domain is lowercased; the local part keeps its original case (it is
    case-sensitive by RFC 5321).
    """
    text = defang_to_plain(raw.strip()).strip("<>\"'`").strip()
    if text.count("@") != 1:
        return None
    local, _, domain = text.partition("@")
    if not local or local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    if not _EMAIL_LOCAL_RE.match(local):
        return None
    normalized_domain = normalize_domain(domain)
    if normalized_domain is None:
        return None
    return f"{local}@{normalized_domain}"


__all__ = [
    "defang_to_plain",
    "hash_type_for",
    "normalize_domain",
    "normalize_email",
    "normalize_hash",
    "normalize_ipv4",
    "normalize_url",
    "strip_url_userinfo",
]
