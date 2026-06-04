# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""GitHubConnector tests — fake transport, no network, no token.

The fake routes by URL substring and returns canned GitHub REST JSON (repo
list, per-repo code-scanning analyses), so the connector is exercised end to
end without opening a socket. A repo mapped to ``None`` for analyses simulates a
``404`` (code scanning unavailable), exercising the fail-closed path.
"""

from __future__ import annotations

from typing import Any

import pytest

from probity.connectors import github_connector
from probity.connectors.github_connector import GitHubConnector, GitHubError
from probity.connectors.mock_pipeline import PIPELINE_KIND
from probity.controls.c13_cicd_security import C13CicdSecurity
from probity.model.enums import Status
from probity.model.fact import FactSet

# org/app: secret scanning on + has code-scanning analyses  -> both controls on
# org/legacy: secret scanning off + code scanning 404        -> both off
_REPOS = [
    {
        "full_name": "org/app",
        "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
    },
    {
        "full_name": "org/legacy",
        "security_and_analysis": {"secret_scanning": {"status": "disabled"}},
    },
]
_ANALYSES: dict[str, Any] = {
    "org/app": [{"id": 1, "tool": {"name": "CodeQL"}}],
    "org/legacy": None,  # None -> 404 (code scanning unavailable)
}


def _fake_transport(repos: list[dict[str, Any]], analyses: dict[str, Any]) -> Any:
    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str]) -> Any:
        calls.append(url)
        if "code-scanning/analyses" in url:
            for repo, result in analyses.items():
                if f"/repos/{repo}/" in url:
                    if result is None:
                        raise GitHubError(404, "Not Found")
                    return result
            raise GitHubError(404, "Not Found")
        if "/repos" in url:  # the repo collection (/orgs/.../repos or /user/repos)
            return repos if "page=1" in url else []
        return []

    transport.calls = calls  # type: ignore[attr-defined]
    return transport


def _connector(*, org: str | None = "org", **overrides: Any) -> GitHubConnector:
    repos = overrides.pop("repos", _REPOS)
    analyses = overrides.pop("analyses", _ANALYSES)
    return GitHubConnector(token="t", org=org, transport=_fake_transport(repos, analyses))


def test_requires_token():
    with pytest.raises(ValueError, match="requires a personal-access token"):
        GitHubConnector(token="")


def test_emits_pipeline_config_in_mock_shape():
    facts = list(_connector().collect())
    assert {f.kind for f in facts} == {PIPELINE_KIND}
    app = next(f for f in facts if f.key == "org/app")
    assert set(app.data) == {"id", "repo", "sast_enabled", "secret_scanning_enabled"}
    assert app.data == {
        "id": "org/app",
        "repo": "org/app",
        "sast_enabled": True,
        "secret_scanning_enabled": True,
    }


def test_secret_scanning_status_maps_to_bool():
    facts = {f.key: f for f in _connector().collect()}
    assert facts["org/app"].data["secret_scanning_enabled"] is True
    assert facts["org/legacy"].data["secret_scanning_enabled"] is False


def test_missing_security_block_reads_as_disabled():
    repos = [{"full_name": "org/x"}]
    facts = {f.key: f for f in _connector(repos=repos, analyses={"org/x": []}).collect()}
    assert facts["org/x"].data["secret_scanning_enabled"] is False


def test_code_scanning_analyses_present_means_sast_enabled():
    facts = {f.key: f for f in _connector().collect()}
    assert facts["org/app"].data["sast_enabled"] is True


def test_code_scanning_404_means_sast_disabled_fail_closed():
    facts = {f.key: f for f in _connector().collect()}
    assert facts["org/legacy"].data["sast_enabled"] is False


def test_org_scope_lists_org_repos_user_scope_lists_user_repos():
    org_conn = _connector(org="acme")
    list(org_conn.collect())
    assert any("/orgs/acme/repos" in u for u in org_conn._transport.calls)  # type: ignore[attr-defined]

    user_conn = _connector(org=None)
    list(user_conn.collect())
    assert any("/user/repos" in u for u in user_conn._transport.calls)  # type: ignore[attr-defined]


def test_pagination_pages_until_short_page(monkeypatch):
    monkeypatch.setattr(github_connector, "_PAGE_SIZE", 2)
    sa = {"secret_scanning": {"status": "enabled"}}
    page_full = [
        {"full_name": "org/a", "security_and_analysis": sa},
        {"full_name": "org/b", "security_and_analysis": sa},
    ]
    page_short = [{"full_name": "org/c", "security_and_analysis": sa}]

    def transport(method: str, url: str, headers: dict[str, str]) -> Any:
        if "code-scanning/analyses" in url:
            return [{"id": 1}]
        # Anchor on "&page=" so the per_page=2 query param cannot collide with
        # the page=2 match (substring "page=2" lives inside "per_page=2").
        if "&page=1" in url or "&page=2" in url:
            return page_full  # two full pages -> connector keeps paging
        if "&page=3" in url:
            return page_short  # short page -> stop
        return []

    conn = GitHubConnector(token="t", org="org", transport=transport)
    keys = {f.key for f in conn.collect()}
    assert keys == {"org/a", "org/b", "org/c"}


def test_pagination_raises_when_no_short_page(monkeypatch):
    # A misbehaving API that never returns a short page must not hang the scan:
    # _list is capped at _MAX_PAGES and raises instead of looping forever.
    monkeypatch.setattr(github_connector, "_PAGE_SIZE", 2)
    monkeypatch.setattr(github_connector, "_MAX_PAGES", 3)
    sa = {"secret_scanning": {"status": "enabled"}}
    always_full = [
        {"full_name": "org/a", "security_and_analysis": sa},
        {"full_name": "org/b", "security_and_analysis": sa},
    ]

    def transport(method: str, url: str, headers: dict[str, str]) -> Any:
        if "code-scanning/analyses" in url:
            return [{"id": 1}]
        return always_full  # full page on every page -> short page never arrives

    conn = GitHubConnector(token="t", org="org", transport=transport)
    with pytest.raises(GitHubError, match="exceeded 3 pages"):
        list(conn.collect())


def test_feeds_c13_unchanged():
    facts = FactSet(list(_connector().collect()))
    finding = C13CicdSecurity().evaluate(facts)
    assert finding.status is Status.FAIL  # org/legacy misses both controls
    assert "1 of 2" in finding.summary
