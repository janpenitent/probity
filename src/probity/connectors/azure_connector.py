# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Live Microsoft Azure connector for asset inventory (C02) and encryption (C17).

Zero runtime dependencies: the OAuth2 client-credentials flow and the Azure
Resource Manager (ARM) GETs use the Python standard library ``urllib`` only — no
``azure-identity`` or ``azure-mgmt-*`` SDK. The connector emits the SAME facts as
the file-backed mocks, so the controls run unchanged:

* ``asset.record`` (C02) — one per virtual machine, like
  :class:`~probity.connectors.mock_assets.MockAssetsConnector`.
* ``storage.volume`` (C17) — one per managed disk, like
  :class:`~probity.connectors.mock_cloud.MockCloudConnector`.

Authentication is the same Azure AD client-credentials grant the Entra connector
uses (a client secret POSTed as a form — no JWT signing, so it stays
zero-dependency), but with the ARM token scope
(``https://management.azure.com/.default``) and a target subscription. The tenant
id, client id, secret and subscription are read from the environment only, never
from CLI flags.

Field mapping (ARM Compute -> fact):

======================  ===================================================
asset ``id``            VM ``id`` (full ARM resource id)
asset ``name``          VM ``name``
asset ``type``          ``"azure-vm"``
asset ``managed``       always ``True`` — the VM is in the subscription
asset ``last_seen``     the scan time: listing the VM *is* the sighting
volume ``id``           disk ``id`` (full ARM resource id)
volume ``name``         disk ``name``
volume ``encrypted``    always ``True`` — Azure encrypts all managed disks at rest
volume ``kms``          ``"managed"`` for a customer key (CMK), else ``"platform"``
volume ``contains_pii`` the ``pii`` / ``contains_pii`` tag is ``"true"``
======================  ===================================================

``encrypted`` is ``True`` for every disk because Azure encrypts all managed
disks at rest with platform-managed keys and no opt-out; the ``kms`` field then
distinguishes a customer-managed key (``EncryptionAtRestWith*CustomerKey*``)
from the default platform key. ``managed`` is ``True`` and ``last_seen`` is the
scan time for the same reason as the other cloud connectors: a returned resource
is, by definition, a live managed inventory entry observed right now.

Tests inject a fake ``transport`` returning canned ARM JSON; the connector never
opens a socket and needs no credentials under test.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_assets import ASSET_KIND
from probity.connectors.mock_cloud import STORAGE_KIND
from probity.model.fact import Fact

_ARM_BASE = "https://management.azure.com"
_LOGIN_BASE = "https://login.microsoftonline.com"
_ARM_SCOPE = "https://management.azure.com/.default"
_VM_API_VERSION = "2023-07-01"
_DISK_API_VERSION = "2023-04-02"
_HTTP_TIMEOUT = 30.0
#: Guard against an unbounded nextLink loop from a misbehaving API.
_MAX_PAGES = 100

#: Transport seam: ``(method, url, headers, body) -> parsed JSON dict``.
#: The default implementation uses urllib; tests inject a fake.
Transport = Callable[[str, str, dict[str, str], bytes | None], dict[str, Any]]


class AzureError(RuntimeError):
    """A failure talking to Azure (token or ARM), carrying a message."""


def _urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> dict[str, Any]:
    """Default HTTPS transport over stdlib urllib, returning parsed JSON."""
    if not url.startswith("https://"):  # never send a bearer token in cleartext
        raise ValueError(f"refusing non-HTTPS request to {url!r}")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 - https enforced
        raw = resp.read()
    return cast("dict[str, Any]", json.loads(raw)) if raw else {}


class AzureConnector(Connector):
    """Reads virtual machines and managed disks from the Azure ARM REST API."""

    id = "azure"
    title = "Microsoft Azure Compute (live ARM API)"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        *,
        transport: Transport | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not (tenant_id and client_id and client_secret and subscription_id):
            raise ValueError(
                "AzureConnector requires tenant_id, client_id, client_secret and subscription_id"
            )
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._subscription_id = subscription_id
        self._transport = transport or _urllib_transport
        self._now = now or (lambda: datetime.now(UTC))
        self._token: str | None = None

    # -- collection -------------------------------------------------------

    def collect(self) -> Iterable[Fact]:
        seen = self._now().isoformat()
        for vm in self._list("virtualMachines", _VM_API_VERSION):
            vid = vm.get("id")
            if not vid:
                continue
            yield Fact(
                kind=ASSET_KIND,
                key=str(vid),
                data={
                    "id": str(vid),
                    "name": vm.get("name", str(vid)),
                    "type": "azure-vm",
                    "managed": True,
                    "last_seen": seen,
                },
            )
        for disk in self._list("disks", _DISK_API_VERSION):
            did = disk.get("id")
            if not did:
                continue
            yield Fact(
                kind=STORAGE_KIND,
                key=str(did),
                data={
                    "id": str(did),
                    "name": disk.get("name", str(did)),
                    "encrypted": True,  # Azure encrypts all managed disks at rest
                    "kms": "managed" if _has_cmk(disk) else "platform",
                    "contains_pii": _pii(disk),
                },
            )

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
                "scope": _ARM_SCOPE,
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = self._transport("POST", url, headers, form)
        token = payload.get("access_token")
        if not token:
            raise AzureError("Azure token endpoint returned no access_token")
        self._token = str(token)
        return self._token

    def _list(self, resource: str, api_version: str) -> Iterable[dict[str, Any]]:
        """GET a subscription-wide ARM collection, following ``nextLink`` pages."""
        headers = {"Authorization": f"Bearer {self._access_token()}"}
        query = urllib.parse.urlencode({"api-version": api_version})
        url: str | None = (
            f"{_ARM_BASE}/subscriptions/{self._subscription_id}"
            f"/providers/Microsoft.Compute/{resource}?{query}"
        )
        for _ in range(_MAX_PAGES):
            if not url:
                return
            page = self._transport("GET", url, headers, None)
            yield from page.get("value", [])
            url = page.get("nextLink")
        raise AzureError(f"{resource} listing exceeded {_MAX_PAGES} pages")


# -- helpers --------------------------------------------------------------


def _has_cmk(disk: dict[str, Any]) -> bool:
    """True if the disk uses a customer-managed key (CMK) for encryption."""
    props = disk.get("properties")
    if not isinstance(props, dict):
        return False
    encryption = props.get("encryption")
    if not isinstance(encryption, dict):
        return False
    return "CustomerKey" in str(encryption.get("type", ""))


def _pii(disk: dict[str, Any]) -> bool:
    """True if a ``pii`` or ``contains_pii`` tag is set to ``"true"``."""
    tags = disk.get("tags")
    if not isinstance(tags, dict):
        return False
    return tags.get("pii") == "true" or tags.get("contains_pii") == "true"
