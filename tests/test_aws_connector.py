# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""AwsConnector tests — fake transport, no network, no real credentials.

The fake routes by the ``Action=`` query parameter and returns canned EC2
Query-API XML (with the real default namespace, to prove the parser is
namespace-agnostic). The connector is exercised end to end without opening a
socket, and the SigV4 signing is checked by capturing the request headers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from probity.connectors.aws_connector import AwsConnector
from probity.connectors.mock_assets import ASSET_KIND
from probity.connectors.mock_cloud import STORAGE_KIND
from probity.controls.c02_asset_inventory import C02AssetInventory
from probity.controls.c17_encryption import C17Encryption
from probity.model.enums import Status
from probity.model.fact import FactSet

_NS = 'xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"'
_NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)

_INSTANCES_XML = f"""<?xml version="1.0"?>
<DescribeInstancesResponse {_NS}>
  <reservationSet>
    <item>
      <instancesSet>
        <item>
          <instanceId>i-0abc</instanceId>
          <instanceState><name>running</name></instanceState>
          <tagSet><item><key>Name</key><value>prod-web</value></item></tagSet>
        </item>
        <item>
          <instanceId>i-0def</instanceId>
          <tagSet></tagSet>
        </item>
        <item>
          <tagSet></tagSet>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>"""

_VOLUMES_XML = f"""<?xml version="1.0"?>
<DescribeVolumesResponse {_NS}>
  <volumeSet>
    <item>
      <volumeId>vol-enc</volumeId>
      <encrypted>true</encrypted>
      <kmsKeyId>arn:aws:kms:eu-west-1:111:key/abc</kmsKeyId>
      <tagSet>
        <item><key>Name</key><value>db-data</value></item>
        <item><key>pii</key><value>true</value></item>
      </tagSet>
    </item>
    <item>
      <volumeId>vol-plain</volumeId>
      <encrypted>false</encrypted>
      <tagSet></tagSet>
    </item>
    <item>
      <volumeId>vol-unknown</volumeId>
      <tagSet></tagSet>
    </item>
  </volumeSet>
</DescribeVolumesResponse>"""


def _fake_transport(captured: list[dict[str, str]] | None = None) -> Any:
    def transport(method: str, url: str, headers: dict[str, str]) -> bytes:
        if captured is not None:
            captured.append(headers)
        if "Action=DescribeInstances" in url:
            return _INSTANCES_XML.encode("utf-8")
        if "Action=DescribeVolumes" in url:
            return _VOLUMES_XML.encode("utf-8")
        raise AssertionError(f"unexpected action url: {url}")

    return transport


def _connector(**kw: Any) -> AwsConnector:
    return AwsConnector(
        access_key="AKIATESTKEY",
        secret_key="secret",
        region="eu-west-1",
        transport=_fake_transport(),
        now=lambda: _NOW,
        **kw,
    )


def _facts() -> FactSet:
    return FactSet(tuple(_connector().collect()))


def test_emits_one_asset_record_per_instance_with_id():
    assets = _facts().of_kind(ASSET_KIND)
    # Third instance has no instanceId and is skipped.
    assert [a.data["id"] for a in assets] == ["i-0abc", "i-0def"]


def test_asset_name_falls_back_to_instance_id():
    assets = {a.data["id"]: a for a in _facts().of_kind(ASSET_KIND)}
    assert assets["i-0abc"].data["name"] == "prod-web"
    assert assets["i-0def"].data["name"] == "i-0def"


def test_asset_is_managed_and_seen_at_scan_time():
    asset = _facts().of_kind(ASSET_KIND)[0]
    assert asset.data["managed"] is True
    assert asset.data["type"] == "ec2"
    assert asset.data["last_seen"] == _NOW.isoformat()


def test_emits_one_storage_volume_per_volume_with_id():
    volumes = _facts().of_kind(STORAGE_KIND)
    assert [v.data["id"] for v in volumes] == ["vol-enc", "vol-plain", "vol-unknown"]


def test_volume_encryption_and_kms_mapping():
    vols = {v.data["id"]: v for v in _facts().of_kind(STORAGE_KIND)}
    assert vols["vol-enc"].data == {
        "id": "vol-enc",
        "name": "db-data",
        "encrypted": True,
        "kms": "managed",
        "contains_pii": True,
    }
    assert vols["vol-plain"].data["encrypted"] is False
    assert vols["vol-plain"].data["kms"] == "none"
    assert vols["vol-plain"].data["contains_pii"] is False


def test_missing_encrypted_field_is_fail_closed_unencrypted():
    vols = {v.data["id"]: v for v in _facts().of_kind(STORAGE_KIND)}
    assert vols["vol-unknown"].data["encrypted"] is False


def test_feeds_c02_pass_for_live_managed_instances():
    finding = C02AssetInventory(now=_NOW).evaluate(_facts())
    assert finding.status is Status.PASS


def test_feeds_c17_fail_on_unencrypted_volume():
    finding = C17Encryption().evaluate(_facts())
    # vol-plain + vol-unknown are unencrypted -> 2 of 3.
    assert finding.status is Status.FAIL
    assert "2 of 3" in finding.summary


def test_sigv4_authorization_header_is_well_formed():
    captured: list[dict[str, str]] = []
    conn = AwsConnector(
        access_key="AKIATESTKEY",
        secret_key="secret",
        region="eu-west-1",
        transport=_fake_transport(captured),
        now=lambda: _NOW,
    )
    list(conn.collect())
    auth = captured[0]["Authorization"]
    assert auth.startswith(
        "AWS4-HMAC-SHA256 Credential=AKIATESTKEY/20260604/eu-west-1/ec2/aws4_request"
    )
    assert "SignedHeaders=host;x-amz-date" in auth
    assert captured[0]["x-amz-date"] == "20260604T120000Z"


def test_session_token_is_signed_and_sent():
    captured: list[dict[str, str]] = []
    conn = AwsConnector(
        access_key="AKIATESTKEY",
        secret_key="secret",
        region="eu-west-1",
        session_token="FwoTOKEN",
        transport=_fake_transport(captured),
        now=lambda: _NOW,
    )
    list(conn.collect())
    assert captured[0]["x-amz-security-token"] == "FwoTOKEN"
    assert "x-amz-security-token" in captured[0]["Authorization"]


def test_signature_is_deterministic_for_same_request():
    cap_a: list[dict[str, str]] = []
    cap_b: list[dict[str, str]] = []
    for cap in (cap_a, cap_b):
        conn = AwsConnector(
            access_key="AKIATESTKEY",
            secret_key="secret",
            region="eu-west-1",
            transport=_fake_transport(cap),
            now=lambda: _NOW,
        )
        list(conn.collect())
    assert cap_a[0]["Authorization"] == cap_b[0]["Authorization"]


def test_constructor_requires_credentials():
    with pytest.raises(ValueError, match="requires access_key"):
        AwsConnector(access_key="", secret_key="s", region="r")
