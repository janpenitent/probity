# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""GcpComputeConnector tests — fake transport, no network, no real creds.

The fake routes by the ``aggregated/<resource>`` segment of the URL and returns
canned Compute Engine aggregatedList JSON for instances and disks. The connector
is exercised end to end without a socket, and bearer auth / pagination are
checked from the captured requests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from probity.connectors.gcp_connector import GcpComputeConnector
from probity.connectors.mock_assets import ASSET_KIND
from probity.connectors.mock_cloud import STORAGE_KIND
from probity.controls.c02_asset_inventory import C02AssetInventory
from probity.controls.c17_encryption import C17Encryption
from probity.model.enums import Status
from probity.model.fact import FactSet

_NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)

_DEFAULT_INSTANCES = [
    {"id": "100", "name": "web-1"},
    {"id": "200", "name": "db-1"},
    {"name": "no-id"},  # no id -> skipped
]

_DEFAULT_DISKS = [
    {"id": "10", "name": "web-disk", "labels": {"pii": "false"}},
    {
        "id": "20",
        "name": "db-disk",
        "diskEncryptionKey": {"kmsKeyName": "projects/p/locations/eu/keyRings/r/cryptoKeys/k"},
        "labels": {"pii": "true"},
    },
    {"name": "no-id-disk"},  # no id -> skipped
]


def _aggregated(resource: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap items in the aggregatedList scope-keyed envelope."""
    return {"items": {"zones/europe-west1-b": {resource: items}}}


def _fake_transport(
    *,
    instances: list[dict[str, Any]] | None = None,
    disks: list[dict[str, Any]] | None = None,
    captured: list[tuple[str, dict[str, str]]] | None = None,
) -> Any:
    instances = _DEFAULT_INSTANCES if instances is None else instances
    disks = _DEFAULT_DISKS if disks is None else disks

    def transport(method: str, url: str, headers: dict[str, str]) -> dict[str, Any]:
        if captured is not None:
            captured.append((url, headers))
        if "aggregated/instances" in url:
            return _aggregated("instances", instances)
        if "aggregated/disks" in url:
            return _aggregated("disks", disks)
        raise AssertionError(f"unexpected url: {url}")

    return transport


def _connector(**kw: Any) -> GcpComputeConnector:
    transport = kw.pop("transport", None) or _fake_transport()
    return GcpComputeConnector(
        access_token="ya29.TESTTOKEN",
        project="proj-1",
        transport=transport,
        now=lambda: _NOW,
        **kw,
    )


def _facts(**kw: Any) -> FactSet:
    return FactSet(tuple(_connector(**kw).collect()))


# -- C02 / instances -----------------------------------------------------


def test_emits_one_asset_per_instance_with_id():
    assets = _facts().of_kind(ASSET_KIND)
    assert [a.data["id"] for a in assets] == ["100", "200"]


def test_asset_maps_fields():
    asset = {a.data["name"]: a for a in _facts().of_kind(ASSET_KIND)}["web-1"]
    assert asset.data == {
        "id": "100",
        "name": "web-1",
        "type": "gce",
        "managed": True,
        "last_seen": _NOW.isoformat(),
    }


def test_feeds_c02_pass_when_instances_fresh_and_managed():
    finding = C02AssetInventory(now=_NOW).evaluate(_facts())
    assert finding.status is Status.PASS


# -- C17 / disks ---------------------------------------------------------


def test_emits_one_volume_per_disk_with_id():
    vols = _facts().of_kind(STORAGE_KIND)
    assert [v.data["id"] for v in vols] == ["10", "20"]


def test_volume_always_encrypted_and_maps_kms_and_pii():
    vols = {v.data["id"]: v for v in _facts().of_kind(STORAGE_KIND)}
    assert vols["10"].data == {
        "id": "10",
        "name": "web-disk",
        "encrypted": True,
        "kms": "google",
        "contains_pii": False,
    }
    assert vols["20"].data["kms"] == "managed"  # CMEK present
    assert vols["20"].data["contains_pii"] is True


def test_feeds_c17_pass_all_disks_encrypted():
    finding = C17Encryption().evaluate(_facts())
    # GCP disks are always encrypted at rest -> never a C17 gap.
    assert finding.status is Status.PASS


def test_contains_pii_via_contains_pii_label():
    disks = [{"id": "30", "name": "d", "labels": {"contains_pii": "true"}}]
    vol = _facts(transport=_fake_transport(disks=disks)).of_kind(STORAGE_KIND)[0]
    assert vol.data["contains_pii"] is True


# -- HTTP / auth / pagination -------------------------------------------


def test_sends_bearer_token_over_https():
    captured: list[tuple[str, dict[str, str]]] = []
    list(_connector(transport=_fake_transport(captured=captured)).collect())
    url, headers = captured[0]
    assert url.startswith("https://compute.googleapis.com/compute/v1/projects/proj-1/")
    assert headers["Authorization"] == "Bearer ya29.TESTTOKEN"


def test_pagination_follows_page_token():
    pages = [
        {"items": {"z": {"instances": [{"id": "1", "name": "a"}]}}, "nextPageToken": "more"},
        {"items": {"z": {"instances": [{"id": "2", "name": "b"}]}}},
    ]

    def transport(method: str, url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "aggregated/instances" in url:
            return pages.pop(0)
        return {"items": {}}  # disks empty

    assert [a.data["id"] for a in _facts(transport=transport).of_kind(ASSET_KIND)] == ["1", "2"]


def test_page_token_is_passed_as_query_param():
    seen: list[str] = []
    pages = [
        {"items": {"z": {"disks": [{"id": "1", "name": "a"}]}}, "nextPageToken": "tok-XYZ"},
        {"items": {"z": {"disks": [{"id": "2", "name": "b"}]}}},
    ]

    def transport(method: str, url: str, headers: dict[str, str]) -> dict[str, Any]:
        if "aggregated/instances" in url:
            return {"items": {}}
        seen.append(url)
        return pages.pop(0)

    list(_connector(transport=transport).collect())
    assert "pageToken=tok-XYZ" in seen[1]


def test_empty_project_yields_nothing():
    facts = _facts(transport=lambda m, u, h: {"items": {}})
    assert facts.of_kind(ASSET_KIND) == []
    assert facts.of_kind(STORAGE_KIND) == []


def test_constructor_requires_credentials():
    with pytest.raises(ValueError, match="requires access_token"):
        GcpComputeConnector(access_token="", project="p")
    with pytest.raises(ValueError, match="requires access_token"):
        GcpComputeConnector(access_token="t", project="")
