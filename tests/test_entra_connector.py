# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""EntraConnector tests — fake transport, no network, no credentials.

The fake routes by URL substring and returns canned Microsoft Graph JSON, so
the connector is exercised end to end (token -> users -> roles -> MFA) without
opening a socket.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from probity.connectors.entra_connector import ACCOUNT_KIND, EntraConnector
from probity.controls.c19_access import C19Access
from probity.controls.c20_mfa import C20Mfa
from probity.model.enums import Status
from probity.model.fact import FactSet

# A fixed "now" so sign-in staleness is deterministic.
NOW = datetime(2026, 6, 1, tzinfo=UTC)

# Three users: an active MFA-registered admin, an active user without MFA, and
# a privileged account that has not signed in for a year (stale -> orphan).
_USERS = {
    "value": [
        {
            "id": "u-admin",
            "displayName": "Alice Admin",
            "accountEnabled": True,
            "signInActivity": {"lastSuccessfulSignInDateTime": "2026-05-20T10:00:00Z"},
        },
        {
            "id": "u-nomfa",
            "displayName": "Bob NoMfa",
            "accountEnabled": True,
            "signInActivity": {"lastSuccessfulSignInDateTime": "2026-05-25T08:00:00Z"},
        },
        {
            "id": "u-stale",
            "displayName": "Carol Stale",
            "accountEnabled": True,
            "signInActivity": {"lastSuccessfulSignInDateTime": "2025-05-01T08:00:00Z"},
        },
    ]
}
_ROLES = {"value": [{"id": "role-ga", "displayName": "Global Administrator"}]}
_ROLE_MEMBERS = {"value": [{"id": "u-admin"}, {"id": "u-stale"}]}
_MFA = {
    "value": [
        {"id": "u-admin", "isMfaRegistered": True},
        {"id": "u-nomfa", "isMfaRegistered": False},
        {"id": "u-stale", "isMfaRegistered": True},
    ]
}


def _fake_transport(routes: dict[str, Any]) -> Any:
    """Build a transport that returns canned JSON keyed by URL substring."""
    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
        calls.append(url)
        if "oauth2/v2.0/token" in url:
            return {"access_token": "fake-token", "expires_in": 3600}
        for needle, payload in routes.items():
            if needle in url:
                return payload
        return {"value": []}

    transport.calls = calls  # type: ignore[attr-defined]
    return transport


def _connector(**overrides: Any) -> EntraConnector:
    routes = {
        "/directoryRoles/role-ga/members": _ROLE_MEMBERS,
        "/directoryRoles": _ROLES,
        "userRegistrationDetails": _MFA,
        "/users": _USERS,
    }
    routes.update(overrides.pop("routes", {}))
    return EntraConnector(
        tenant_id="t",
        client_id="c",
        client_secret="s",
        transport=_fake_transport(routes),
        now=lambda: NOW,
        **overrides,
    )


def test_requires_all_credentials():
    with pytest.raises(ValueError, match="requires tenant_id"):
        EntraConnector(tenant_id="", client_id="c", client_secret="s")


def test_emits_identity_account_facts_in_mock_shape():
    facts = list(_connector().collect())

    assert {f.kind for f in facts} == {ACCOUNT_KIND}
    admin = next(f for f in facts if f.key == "u-admin")
    assert set(admin.data) == {
        "id",
        "display_name",
        "enabled",
        "privileged",
        "mfa_enabled",
        "hr_active",
    }
    assert admin.data == {
        "id": "u-admin",
        "display_name": "Alice Admin",
        "enabled": True,
        "privileged": True,
        "mfa_enabled": True,
        "hr_active": True,
    }


def test_directory_role_members_are_privileged():
    facts = {f.key: f for f in _connector().collect()}
    assert facts["u-admin"].data["privileged"] is True
    assert facts["u-stale"].data["privileged"] is True
    assert facts["u-nomfa"].data["privileged"] is False


def test_stale_sign_in_marks_account_inactive():
    facts = {f.key: f for f in _connector().collect()}
    # signed in within 90d -> active; a year ago -> inactive (fail-closed)
    assert facts["u-admin"].data["hr_active"] is True
    assert facts["u-stale"].data["hr_active"] is False


def test_missing_sign_in_activity_is_inactive():
    users = {"value": [{"id": "u-x", "displayName": "X", "accountEnabled": True}]}
    facts = {f.key: f for f in _connector(routes={"/users": users}).collect()}
    assert facts["u-x"].data["hr_active"] is False


def test_token_failure_raises():
    def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
        return {}  # no access_token

    conn = EntraConnector(
        tenant_id="t", client_id="c", client_secret="s", transport=transport, now=lambda: NOW
    )
    with pytest.raises(RuntimeError, match="no access_token"):
        list(conn.collect())


def test_pagination_follows_next_link():
    page2_url = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
    page1 = {
        "value": [{"id": "u1", "displayName": "One", "accountEnabled": True}],
        "@odata.nextLink": page2_url,
    }
    page2 = {"value": [{"id": "u2", "displayName": "Two", "accountEnabled": True}]}

    def transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
        if "oauth2/v2.0/token" in url:
            return {"access_token": "t"}
        if url == page2_url:
            return page2
        if "/users" in url:
            return page1
        return {"value": []}

    conn = EntraConnector(
        tenant_id="t", client_id="c", client_secret="s", transport=transport, now=lambda: NOW
    )
    ids = {f.key for f in conn.collect()}
    assert ids == {"u1", "u2"}


def test_feeds_c19_and_c20_unchanged():
    facts = FactSet(list(_connector().collect()))

    c20 = C20Mfa().evaluate(facts)
    assert c20.status is Status.FAIL  # u-nomfa lacks MFA
    assert "1 of 3" in c20.summary

    c19 = C19Access().evaluate(facts)
    assert c19.status is Status.FAIL  # u-stale is enabled but inactive
    assert "1 privileged" in c19.summary  # u-stale is privileged
