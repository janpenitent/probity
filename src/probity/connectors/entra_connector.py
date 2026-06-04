# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Live Microsoft Entra ID (Azure AD) connector via Microsoft Graph.

Zero runtime dependencies: the OAuth2 client-credentials flow and the Graph
GETs use the Python standard library ``urllib`` only — no ``azure-identity`` or
``msgraph-sdk``. The connector emits the SAME ``identity.account`` facts as
:class:`~probity.connectors.mock_idp.MockIdpConnector`, so C19 (orphan / stale
accounts) and C20 (MFA) consume it unchanged.

Field mapping (Graph -> fact):

==============  ============================================================
``id``          ``user.id``
``display_name````user.displayName``
``enabled``     ``user.accountEnabled``
``privileged``  user is a member of any Entra directory role
``mfa_enabled`` ``userRegistrationDetails.isMfaRegistered``
``hr_active``   user signed in within :data:`STALE_SIGN_IN_DAYS` days
==============  ============================================================

Entra is the identity provider, not an HR system, so it has no authoritative
"is this person still employed" signal. ``hr_active`` is therefore a *proxy*:
an account with no successful sign-in inside the staleness window is treated as
inactive. This is deliberately fail-closed — a stale account is surfaced by C19
for human review rather than silently assumed healthy.

Tests inject a fake ``transport`` returning canned Graph JSON; the connector
never opens a socket and needs no credentials under test.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_idp import ACCOUNT_KIND
from probity.model.fact import Fact

#: An account with no successful sign-in within this many days is treated as
#: inactive (``hr_active = False``) so C19 surfaces it for review.
STALE_SIGN_IN_DAYS = 90

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_LOGIN_BASE = "https://login.microsoftonline.com"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_HTTP_TIMEOUT = 30.0

#: Transport seam: ``(method, url, headers, body) -> parsed JSON dict``.
#: The default implementation uses urllib; tests inject a fake.
Transport = Callable[[str, str, dict[str, str], bytes | None], dict[str, Any]]


def _urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> dict[str, Any]:
    """Default HTTPS transport over stdlib urllib, returning parsed JSON."""
    if not url.startswith("https://"):  # never send a bearer token in cleartext
        raise ValueError(f"refusing non-HTTPS request to {url!r}")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 - https enforced
        raw = resp.read()
    return cast(dict[str, Any], json.loads(raw)) if raw else {}


class EntraConnector(Connector):
    """Reads users, role memberships and MFA registration from Microsoft Graph."""

    id = "entra"
    title = "Microsoft Entra ID (live Graph API)"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        transport: Transport | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not (tenant_id and client_id and client_secret):
            raise ValueError("EntraConnector requires tenant_id, client_id and client_secret")
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._transport = transport or _urllib_transport
        self._now = now or (lambda: datetime.now(UTC))
        self._token: str | None = None

    # -- HTTP plumbing ----------------------------------------------------

    def _access_token(self) -> str:
        if self._token is not None:
            return self._token
        url = f"{_LOGIN_BASE}/{self._tenant_id}/oauth2/v2.0/token"
        form = urllib.parse.urlencode(
            {
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_type": "client_credentials",
                "scope": _GRAPH_SCOPE,
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = self._transport("POST", url, headers, form)
        token = payload.get("access_token")
        if not token:
            raise RuntimeError("Entra token endpoint returned no access_token")
        self._token = str(token)
        return self._token

    def _get_all(self, path: str) -> list[dict[str, Any]]:
        """GET a Graph collection, following ``@odata.nextLink`` pagination."""
        headers = {"Authorization": f"Bearer {self._access_token()}"}
        url: str | None = path if path.startswith("http") else f"{_GRAPH_BASE}{path}"
        items: list[dict[str, Any]] = []
        while url:
            page = self._transport("GET", url, headers, None)
            items.extend(page.get("value", []))
            url = page.get("@odata.nextLink")
        return items

    # -- collection -------------------------------------------------------

    def collect(self) -> Iterable[Fact]:
        privileged_ids = self._privileged_ids()
        mfa_by_id = self._mfa_by_id()
        users = self._get_all("/users?$select=id,displayName,accountEnabled,signInActivity")
        for user in users:
            uid = str(user.get("id", ""))
            data = {
                "id": uid,
                "display_name": user.get("displayName", ""),
                "enabled": bool(user.get("accountEnabled", False)),
                "privileged": uid in privileged_ids,
                "mfa_enabled": mfa_by_id.get(uid, False),
                "hr_active": self._is_active(user.get("signInActivity")),
            }
            yield Fact(kind=ACCOUNT_KIND, key=uid, data=data)

    def _privileged_ids(self) -> set[str]:
        """User ids holding any Entra directory role (privileged accounts)."""
        privileged: set[str] = set()
        for role in self._get_all("/directoryRoles"):
            role_id = role.get("id")
            if not role_id:
                continue
            for member in self._get_all(f"/directoryRoles/{role_id}/members"):
                member_id = member.get("id")
                if member_id:
                    privileged.add(str(member_id))
        return privileged

    def _mfa_by_id(self) -> dict[str, bool]:
        details = self._get_all("/reports/authenticationMethods/userRegistrationDetails")
        return {
            str(d.get("id", "")): bool(d.get("isMfaRegistered", False))
            for d in details
            if d.get("id")
        }

    def _is_active(self, sign_in: Any) -> bool:
        """True if a successful sign-in falls within the staleness window.

        Fail-closed: missing or unparseable activity counts as inactive so the
        account is surfaced by C19 rather than silently assumed healthy.
        """
        if not isinstance(sign_in, dict):
            return False
        stamp = sign_in.get("lastSuccessfulSignInDateTime") or sign_in.get("lastSignInDateTime")
        last = _parse_graph_time(stamp)
        if last is None:
            return False
        return last >= self._now() - timedelta(days=STALE_SIGN_IN_DAYS)


def _parse_graph_time(value: Any) -> datetime | None:
    """Parse a Graph ISO-8601 timestamp (``...Z``) to an aware datetime."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
