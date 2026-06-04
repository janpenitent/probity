# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""AzureConnector tests — fake transport, no network, no real creds.

The fake answers the OAuth2 token POST and routes ARM GETs by the resource
segment of the URL (``virtualMachines`` / ``disks``), returning canned ARM
listing JSON. The connector is exercised end to end without a socket, and bearer
auth / pagination are checked from the captured requests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from probity.connectors.azure_connector import AzureConnector
from probity.connectors.mock_assets import ASSET_KIND
from probity.connectors.mock_cloud import STORAGE_KIND
from probity.controls.c02_asset_inventory import C02AssetInventory
from probity.controls.c17_encryption import C17Encryption
from probity.model.enums import Status
from probity.model.fact import FactSet

_NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)
_SUB = "/subscriptions/sub-1"

_DEFAULT_VMS = [
    {"id": f"{_SUB}/.../web-1", "name": "web-1"},
    {"id": f"{_SUB}/.../db-1", "name": "db-1"},
    {"name": "no-id"},  # no id -> skipped
]

_DEFAULT_DISKS = [
    {
        "id": f"{_SUB}/.../web-disk",
        "name": "web-disk",
        "properties": {"encryption": {"type": "EncryptionAtRestWithPlatformKey"}},
        "tags": {"pii": "false"},
    },
    {
        "id": f"{_SUB}/.../db-disk",
        "name": "db-disk",
        "properties": {"encryption": {"type": "EncryptionAtRestWithCustomerKey"}},
        "tags": {"pii": "true"},
    },
    {"name": "no-id-disk"},  # no id -> skipped
]

_TOKEN_RESPONSE = {"access_token": "azure-test-token", "expires_in": 3600}


def _fake_transport(
    *,
    vms: list[dict[str, Any]] | None = None,
    disks: list[dict[str, Any]] | None = None,
    captured: list[tuple[str, dict[str, str]]] | None = None,
) -> Any:
    vms = _DEFAULT_VMS if vms is None else vms
    disks = _DEFAULT_DISKS if disks is None else disks

    def transport(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> dict[str, Any]:
        if captured is not None:
            captured.append((url, headers))
        if url.endswith("/oauth2/v2.0/token"):
            return _TOKEN_RESPONSE
        if "virtualMachines" in url:
            return {"value": vms}
        if "/disks" in url:
            return {"value": disks}
        raise AssertionError(f"unexpected url: {url}")

    return transport


def _connector(**kw: Any) -> AzureConnector:
    transport = kw.pop("transport", None) or _fake_transport()
    return AzureConnector(
        tenant_id="tenant",
        client_id="client",
        client_secret="secret",
        subscription_id="sub-1",
        transport=transport,
        now=lambda: _NOW,
        **kw,
    )


def _facts(**kw: Any) -> FactSet:
    return FactSet(tuple(_connector(**kw).collect()))


# -- C02 / virtual machines ----------------------------------------------


def test_emits_one_asset_per_vm_with_id():
    assets = _facts().of_kind(ASSET_KIND)
    assert [a.data["name"] for a in assets] == ["web-1", "db-1"]


def test_asset_maps_fields():
    asset = {a.data["name"]: a for a in _facts().of_kind(ASSET_KIND)}["web-1"]
    assert asset.data == {
        "id": f"{_SUB}/.../web-1",
        "name": "web-1",
        "type": "azure-vm",
        "managed": True,
        "last_seen": _NOW.isoformat(),
    }


def test_feeds_c02_pass_when_vms_fresh_and_managed():
    finding = C02AssetInventory(now=_NOW).evaluate(_facts())
    assert finding.status is Status.PASS


# -- C17 / managed disks -------------------------------------------------


def test_emits_one_volume_per_disk_with_id():
    vols = _facts().of_kind(STORAGE_KIND)
    assert [v.data["name"] for v in vols] == ["web-disk", "db-disk"]


def test_volume_always_encrypted_and_maps_kms_and_pii():
    vols = {v.data["name"]: v for v in _facts().of_kind(STORAGE_KIND)}
    assert vols["web-disk"].data == {
        "id": f"{_SUB}/.../web-disk",
        "name": "web-disk",
        "encrypted": True,
        "kms": "platform",
        "contains_pii": False,
    }
    assert vols["db-disk"].data["kms"] == "managed"  # CustomerKey -> CMK
    assert vols["db-disk"].data["contains_pii"] is True


def test_double_encryption_with_customer_key_is_managed():
    disks = [
        {
            "id": f"{_SUB}/.../d",
            "name": "d",
            "properties": {
                "encryption": {"type": "EncryptionAtRestWithPlatformAndCustomerKeys"}
            },
        }
    ]
    vol = _facts(transport=_fake_transport(disks=disks)).of_kind(STORAGE_KIND)[0]
    assert vol.data["kms"] == "managed"


def test_missing_encryption_block_defaults_to_platform():
    disks = [{"id": f"{_SUB}/.../d", "name": "d"}]
    vol = _facts(transport=_fake_transport(disks=disks)).of_kind(STORAGE_KIND)[0]
    assert vol.data["kms"] == "platform"
    assert vol.data["encrypted"] is True


def test_feeds_c17_pass_all_disks_encrypted():
    finding = C17Encryption().evaluate(_facts())
    # Azure managed disks are always encrypted at rest -> never a C17 gap.
    assert finding.status is Status.PASS


# -- auth / HTTP / pagination -------------------------------------------


def test_acquires_token_then_sends_bearer_over_https():
    captured: list[tuple[str, dict[str, str]]] = []
    list(_connector(transport=_fake_transport(captured=captured)).collect())
    token_url, _ = captured[0]
    assert token_url == "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
    # every subsequent ARM call carries the bearer token from the token response
    arm = captured[1]
    assert arm[0].startswith("https://management.azure.com/subscriptions/sub-1/")
    assert arm[1]["Authorization"] == "Bearer azure-test-token"


def test_token_acquired_once_and_reused():
    captured: list[tuple[str, dict[str, str]]] = []
    list(_connector(transport=_fake_transport(captured=captured)).collect())
    token_calls = [u for u, _ in captured if u.endswith("/oauth2/v2.0/token")]
    assert len(token_calls) == 1


def test_api_version_is_sent():
    captured: list[tuple[str, dict[str, str]]] = []
    list(_connector(transport=_fake_transport(captured=captured)).collect())
    vm_url = next(u for u, _ in captured if "virtualMachines" in u)
    assert "api-version=2023-07-01" in vm_url


def test_pagination_follows_next_link():
    pages = [
        {
            "value": [{"id": f"{_SUB}/.../1", "name": "a"}],
            "nextLink": "https://management.azure.com/next/virtualMachines?skip=1",
        },
        {"value": [{"id": f"{_SUB}/.../2", "name": "b"}]},
    ]

    def transport(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> dict[str, Any]:
        if url.endswith("/oauth2/v2.0/token"):
            return _TOKEN_RESPONSE
        if "virtualMachines" in url:
            return pages.pop(0)
        return {"value": []}  # disks empty

    assert [a.data["name"] for a in _facts(transport=transport).of_kind(ASSET_KIND)] == ["a", "b"]


def test_empty_subscription_yields_nothing():
    def transport(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> dict[str, Any]:
        if url.endswith("/oauth2/v2.0/token"):
            return _TOKEN_RESPONSE
        return {"value": []}

    facts = _facts(transport=transport)
    assert facts.of_kind(ASSET_KIND) == []
    assert facts.of_kind(STORAGE_KIND) == []


def test_constructor_requires_credentials():
    with pytest.raises(ValueError, match="requires tenant_id"):
        AzureConnector(tenant_id="", client_id="c", client_secret="s", subscription_id="sub")
    with pytest.raises(ValueError, match="requires tenant_id"):
        AzureConnector(tenant_id="t", client_id="c", client_secret="s", subscription_id="")
