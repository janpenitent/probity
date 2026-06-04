# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Live GitHub connector for the CI/CD-security control (C13) via the REST API.

Zero runtime dependencies: the REST calls use the Python standard library
``urllib`` only — no ``PyGithub``. The connector emits the SAME
``pipeline.config`` facts as
:class:`~probity.connectors.mock_pipeline.MockPipelineConnector`, so C13
(pipeline security controls enabled) consumes it unchanged.

Field mapping (GitHub -> fact):

========================  ===================================================
``id`` / ``repo``         repository ``full_name`` (``owner/name``)
``secret_scanning_enabled`` ``security_and_analysis.secret_scanning.status``
                          is ``"enabled"``
``sast_enabled``          the repo has at least one code-scanning analysis
========================  ===================================================

SAST is inferred from code-scanning *results*, not configuration: a repo with
at least one analysis is actively scanned (CodeQL default setup, an Actions
workflow, or a third-party uploader — all count). A ``403``/``404`` on the
code-scanning endpoint means scanning is unavailable or off, which reads as
``sast_enabled = False`` — fail-closed, so C13 surfaces the gap rather than
assuming coverage.

Pagination uses ``?per_page=100&page=N`` and stops on the first short page,
avoiding ``Link``-header parsing. List endpoints return JSON arrays, so the
transport seam returns ``Any`` (list or dict).

Tests inject a fake ``transport`` returning canned REST JSON; the connector
never opens a socket and needs no token under test.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_pipeline import PIPELINE_KIND
from probity.model.fact import Fact

_API_BASE = "https://api.github.com"
_API_VERSION = "2022-11-28"
_PAGE_SIZE = 100
_HTTP_TIMEOUT = 30.0
#: Hard cap on pagination so a misbehaving API that never returns a short page
#: cannot hang an autonomous scan. 1000 pages * _PAGE_SIZE = 100k items.
_MAX_PAGES = 1000

#: Transport seam: ``(method, url, headers) -> parsed JSON (list or dict)``.
#: The default implementation uses urllib; tests inject a fake.
Transport = Callable[[str, str, dict[str, str]], Any]


class GitHubError(RuntimeError):
    """A non-2xx response from the GitHub REST API, carrying the status code."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(f"GitHub API {status}: {message}")


def _urllib_transport(method: str, url: str, headers: dict[str, str]) -> Any:
    """Default HTTPS transport over stdlib urllib, returning parsed JSON."""
    if not url.startswith("https://"):  # never send a token in cleartext
        raise ValueError(f"refusing non-HTTPS request to {url!r}")
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 - https enforced
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise GitHubError(exc.code, exc.reason or "") from exc
    return json.loads(raw) if raw else None


class GitHubConnector(Connector):
    """Reads repositories and their security settings from the GitHub REST API."""

    id = "github"
    title = "GitHub repositories (live REST API)"

    def __init__(
        self,
        token: str,
        org: str | None = None,
        *,
        transport: Transport | None = None,
    ) -> None:
        if not token:
            raise ValueError("GitHubConnector requires a personal-access token")
        self._token = token
        self._org = org
        self._transport = transport or _urllib_transport

    # -- HTTP plumbing ----------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
        }

    def _get(self, path: str) -> Any:
        url = path if path.startswith("http") else f"{_API_BASE}{path}"
        return self._transport("GET", url, self._headers())

    def _list(self, path: str) -> list[dict[str, Any]]:
        """GET a REST collection, paging until the first short page."""
        items: list[dict[str, Any]] = []
        for page in range(1, _MAX_PAGES + 1):
            sep = "&" if "?" in path else "?"
            data = self._get(f"{path}{sep}per_page={_PAGE_SIZE}&page={page}")
            if not isinstance(data, list) or not data:
                break
            items.extend(d for d in data if isinstance(d, dict))
            if len(data) < _PAGE_SIZE:
                break
        else:
            # Loop exhausted without a short page: the API is misbehaving.
            raise GitHubError(0, f"pagination exceeded {_MAX_PAGES} pages for {path}")
        return items

    # -- collection -------------------------------------------------------

    def collect(self) -> Iterable[Fact]:
        for repo in self._list(self._repos_path()):
            full = str(repo.get("full_name", ""))
            if not full:
                continue
            yield Fact(
                kind=PIPELINE_KIND,
                key=full,
                data={
                    "id": full,
                    "repo": full,
                    "sast_enabled": self._has_code_scanning(full),
                    "secret_scanning_enabled": _secret_scanning_enabled(repo),
                },
            )

    def _repos_path(self) -> str:
        """Org repos when an org is given, otherwise the token user's repos."""
        return f"/orgs/{self._org}/repos" if self._org else "/user/repos"

    def _has_code_scanning(self, full_name: str) -> bool:
        """True if the repo has at least one code-scanning analysis.

        Fail-closed: ``403``/``404`` (scanning off, no access, or no advanced
        security) counts as no SAST so C13 surfaces the gap.
        """
        try:
            data = self._get(f"/repos/{full_name}/code-scanning/analyses?per_page=1")
        except GitHubError as exc:
            if exc.status in (403, 404):
                return False
            raise
        return bool(data)


def _secret_scanning_enabled(repo: dict[str, Any]) -> bool:
    """Read ``security_and_analysis.secret_scanning.status == 'enabled'``."""
    analysis = cast("dict[str, Any]", repo.get("security_and_analysis") or {})
    secret_scanning = cast("dict[str, Any]", analysis.get("secret_scanning") or {})
    return secret_scanning.get("status") == "enabled"
