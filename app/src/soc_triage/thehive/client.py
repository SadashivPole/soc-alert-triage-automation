"""TheHive CE API client for Phase 4.6.

This module contains outbound TheHive communication only.
It does not make incident/scoring decisions and never logs secrets.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from ..core.config import Settings

#: Tag prefix that makes an exported case findable by incident (D2 idempotency).
#: Unlike the case title it is stable: it never varies with severity.
CASE_TAG_PREFIX = "soc-triage:"


class TheHiveError(RuntimeError):
    """Base error for TheHive integration failures."""


class TheHiveNotConfiguredError(TheHiveError):
    """Raised when TheHive integration is disabled by configuration."""


class TheHiveAuthenticationError(TheHiveError):
    """Raised when TheHive rejects the configured credentials."""


class TheHiveUnavailableError(TheHiveError):
    """Raised when TheHive cannot be reached or times out."""


class TheHiveRequestError(TheHiveError):
    """Raised for non-authentication HTTP failures."""


@dataclass(frozen=True)
class TheHiveCaseResult:
    """Minimal result returned after creating a TheHive case."""

    case_id: str
    raw: dict[str, Any]


class TheHiveClient:
    """Small, deterministic wrapper around the TheHive API v1."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._base_url = settings.thehive_url.strip().rstrip("/") + "/"
        self._api_key = settings.thehive_api_key.get_secret_value().strip()
        self._organisation = settings.thehive_organisation.strip()
        self._verify_tls = settings.thehive_verify_tls
        self._timeout = settings.thehive_timeout_seconds
        self._transport = transport

    @property
    def configured(self) -> bool:
        """Return whether outbound TheHive export is enabled."""
        return bool(self._base_url.strip("/") and self._api_key)

    def _require_configured(self) -> None:
        if not self._base_url.strip("/") or not self._api_key:
            raise TheHiveNotConfiguredError("TheHive integration is not configured")

    def _headers(self) -> dict[str, str]:
        self._require_configured()

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self._organisation:
            headers["X-Organisation"] = self._organisation

        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response:
        url = urljoin(self._base_url, path.lstrip("/"))

        try:
            with httpx.Client(
                verify=self._verify_tls,
                timeout=self._timeout,
                transport=self._transport,
            ) as client:
                response = client.request(
                    method,
                    url,
                    headers=self._headers(),
                    json=json,
                )
        except httpx.TimeoutException as exc:
            raise TheHiveUnavailableError("TheHive request timed out") from exc
        except httpx.RequestError as exc:
            raise TheHiveUnavailableError("TheHive server is unavailable") from exc

        if response.status_code in (401, 403):
            raise TheHiveAuthenticationError(
                f"TheHive authentication failed with HTTP {response.status_code}"
            )

        if response.status_code >= 400:
            detail = response.text.strip()

            # Do not expose credentials or authorization headers in errors.
            if len(detail) > 500:
                detail = detail[:500]

            raise TheHiveRequestError(
                f"TheHive API returned HTTP {response.status_code}: {detail}"
            )

        return response

    def create_case(
        self,
        *,
        title: str,
        description: str,
        severity: int,
        pap: int = 2,
        tlp: int = 2,
        tags: Sequence[str] = (),
    ) -> TheHiveCaseResult:
        """Create a TheHive case and return its identifier."""

        if not title.strip():
            raise ValueError("TheHive case title must not be empty")

        if not description.strip():
            raise ValueError("TheHive case description must not be empty")

        payload = {
            "title": title.strip(),
            "description": description,
            "severity": severity,
            "pap": pap,
            "tlp": tlp,
        }

        # D2: the incident tag is the durable key that lets a later export
        # recognise this case before creating another one.
        clean_tags = [tag.strip() for tag in tags if tag and tag.strip()]

        if clean_tags:
            payload["tags"] = clean_tags

        response = self._request(
            "POST",
            "/api/v1/case",
            json=payload,
        )

        try:
            data = response.json()
        except ValueError as exc:
            raise TheHiveRequestError(
                "TheHive returned a non-JSON case response"
            ) from exc

        case_id = data.get("_id") or data.get("id")

        if not isinstance(case_id, str) or not case_id.strip():
            raise TheHiveRequestError(
                "TheHive case response did not contain a case identifier"
            )

        return TheHiveCaseResult(
            case_id=case_id,
            raw=data,
        )

    def create_observable(
        self,
        *,
        case_id: str,
        data_type: str,
        data: str,
        message: str | None = None,
    ) -> dict[str, Any]:
        """Create one observable inside a TheHive case."""

        if not case_id.strip():
            raise ValueError("TheHive case id must not be empty")

        if not data_type.strip():
            raise ValueError("TheHive observable type must not be empty")

        if not data.strip():
            raise ValueError("TheHive observable data must not be empty")

        payload: dict[str, Any] = {
            "dataType": data_type.strip(),
            "data": data.strip(),
        }

        if message:
            payload["message"] = message.strip()

        response = self._request(
            "POST",
            f"/api/v1/case/{case_id}/observable",
            json=payload,
        )

        try:
            result = response.json()
        except ValueError as exc:
            raise TheHiveRequestError(
                "TheHive returned a non-JSON observable response"
            ) from exc

        if not isinstance(result, dict):
            raise TheHiveRequestError(
                "TheHive observable response was not an object"
            )

        return result

    def find_case_by_incident(
        self,
        incident_id: str,
        *,
        case_range: str = "0-200",
    ) -> str | None:
        """Return the id of an existing case for ``incident_id``, else ``None``.

        D2 recovery: the export route writes its idempotency audit row *after*
        the case is created, so a failed export can leave a case in TheHive
        that nothing tracks. Before creating a case the caller asks this
        method whether one already exists. Two identifiers are matched:

        * the durable tag ``soc-triage:<incident_id>`` written on new cases;
        * ``incident_id`` appearing in the case title — this also finds cases
          created before the tag existed (legacy/untracked cases).

        The earliest match wins so repeated lookups agree. Read-only in
        effect; the caller decides whether a lookup failure is fatal.
        """

        marker = f"{CASE_TAG_PREFIX}{incident_id}"

        try:
            range_from, range_to = (
                int(value.strip())
                for value in case_range.split("-", 1)
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid TheHive case range: {case_range!r}"
            ) from exc

        if range_from < 0 or range_to < range_from:
            raise ValueError(
                f"Invalid TheHive case range: {case_range!r}"
            )

        # TheHive 5 Query API uses the `page` query operation rather than
        # the removed `/api/v1/case/_search` endpoint.
        payload = {
            "query": [
                {"_name": "listCase"},
                {
                    "_name": "page",
                    "from": range_from,
                    "to": range_to,
                },
            ]
        }

        response = self._request(
            "POST",
            "/api/v1/query",
            json=payload,
        )

        try:
            cases = response.json()
        except ValueError as exc:
            raise TheHiveRequestError(
                "TheHive returned a non-JSON case query response"
            ) from exc

        if not isinstance(cases, list):
            return None

        matches = [
            case
            for case in cases
            if isinstance(case, dict)
            and (
                marker in (case.get("tags") or [])
                or incident_id in str(case.get("title") or "")
            )
        ]

        matches.sort(
            key=lambda case: (
                case.get("createdAt") or 0,
                str(case.get("_id") or ""),
            )
        )

        for case in matches:
            case_id = case.get("_id") or case.get("id")

            if isinstance(case_id, str) and case_id.strip():
                return case_id.strip()

        return None


__all__ = [
    "CASE_TAG_PREFIX",
    "TheHiveAuthenticationError",
    "TheHiveCaseResult",
    "TheHiveClient",
    "TheHiveError",
    "TheHiveNotConfiguredError",
    "TheHiveRequestError",
    "TheHiveUnavailableError",
]
