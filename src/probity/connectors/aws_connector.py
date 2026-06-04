# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Live AWS connector for the asset-inventory (C02) and encryption (C17) controls.

Zero runtime dependencies: the EC2 Query API calls are signed with AWS
Signature Version 4 built from the standard library (``hmac`` / ``hashlib``)
and sent over ``urllib`` — no ``boto3``. The connector emits the SAME facts as
the file-backed mocks, so the controls run unchanged:

* ``asset.record`` (C02) — one per EC2 instance, like
  :class:`~probity.connectors.mock_assets.MockAssetsConnector`.
* ``storage.volume`` (C17) — one per EBS volume, like
  :class:`~probity.connectors.mock_cloud.MockCloudConnector`.

Field mapping (EC2 -> fact):

==================  =====================================================
asset ``id``        instance ``instanceId``
asset ``name``      the ``Name`` tag, else the instance id
asset ``managed``   always ``True`` — the instance is in the AWS inventory
asset ``last_seen`` the scan time: the Describe call *is* the sighting
volume ``id``       ``volumeId``
volume ``encrypted````encrypted`` is ``"true"``
volume ``kms``      ``"managed"`` when a ``kmsKeyId`` is present, else ``"none"``
volume ``contains_pii`` the ``pii`` / ``contains_pii`` tag is ``"true"``
==================  =====================================================

``managed`` is ``True`` for every returned instance because an instance the EC2
API reports *is* a managed inventory entry, and ``last_seen`` is the scan time
because the successful Describe call is itself the observation — a live instance
therefore always satisfies C02's freshness window. ``encrypted`` is read
fail-closed: anything other than the literal ``"true"`` reads as unencrypted so
C17 surfaces the gap.

Tests inject a fake ``transport`` returning canned EC2 XML; the connector never
opens a socket and needs no credentials under test.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from xml.etree import ElementTree

from probity.connectors.aws_sigv4 import EMPTY_PAYLOAD_HASH, SigV4Signer
from probity.connectors.base import Connector
from probity.connectors.mock_assets import ASSET_KIND
from probity.connectors.mock_cloud import STORAGE_KIND
from probity.model.fact import Fact

_EC2_API_VERSION = "2016-11-15"
_HTTP_TIMEOUT = 30.0
_SERVICE = "ec2"

#: Transport seam: ``(method, url, headers) -> raw response bytes``.
#: The default implementation uses urllib; tests inject a fake.
Transport = Callable[[str, str, dict[str, str]], bytes]


class AwsError(RuntimeError):
    """A non-2xx response from the AWS EC2 API, carrying the status code."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(f"AWS EC2 API {status}: {message}")


def _urllib_transport(method: str, url: str, headers: dict[str, str]) -> bytes:
    """Default HTTPS transport over stdlib urllib, returning raw bytes."""
    if not url.startswith("https://"):  # never send a signature in cleartext
        raise ValueError(f"refusing non-HTTPS request to {url!r}")
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 - https enforced
            return bytes(resp.read())
    except urllib.error.HTTPError as exc:
        raise AwsError(exc.code, exc.reason or "") from exc


class AwsConnector(Connector):
    """Reads EC2 instances and EBS volumes from the AWS EC2 Query API."""

    id = "aws"
    title = "AWS EC2/EBS (live, SigV4-signed)"

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        region: str,
        *,
        session_token: str | None = None,
        transport: Transport | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not (access_key and secret_key and region):
            raise ValueError("AwsConnector requires access_key, secret_key and region")
        self._region = region
        self._transport = transport or _urllib_transport
        self._now = now or (lambda: datetime.now(UTC))
        self._signer = SigV4Signer(
            access_key, secret_key, region, session_token=session_token, now=self._now
        )

    # -- collection -------------------------------------------------------

    def collect(self) -> Iterable[Fact]:
        seen = self._now().isoformat()
        instances = self._query("DescribeInstances")
        for inst in _iter_instances(instances):
            iid = _text(inst, "instanceId")
            if not iid:
                continue
            yield Fact(
                kind=ASSET_KIND,
                key=iid,
                data={
                    "id": iid,
                    "name": _tag(inst, "Name") or iid,
                    "type": "ec2",
                    "managed": True,
                    "last_seen": seen,
                },
            )
        volumes = self._query("DescribeVolumes")
        for vol in _iter_items(volumes, "volumeSet"):
            vid = _text(vol, "volumeId")
            if not vid:
                continue
            kms = _text(vol, "kmsKeyId")
            yield Fact(
                kind=STORAGE_KIND,
                key=vid,
                data={
                    "id": vid,
                    "name": _tag(vol, "Name") or vid,
                    "encrypted": _text(vol, "encrypted") == "true",
                    "kms": "managed" if kms else "none",
                    "contains_pii": _pii(vol),
                },
            )

    # -- HTTP / SigV4 -----------------------------------------------------

    def _query(self, action: str) -> ElementTree.Element:
        """Sign and GET an EC2 Query-API action, returning the parsed XML root."""
        host = f"{_SERVICE}.{self._region}.amazonaws.com"
        params = {"Action": action, "Version": _EC2_API_VERSION}
        query = urllib.parse.urlencode(sorted(params.items()))
        headers = self._signer.sign(
            service=_SERVICE,
            method="GET",
            host=host,
            path="/",
            query=query,
            payload_hash=EMPTY_PAYLOAD_HASH,
        )
        raw = self._transport("GET", f"https://{host}/?{query}", headers)
        return ElementTree.fromstring(raw)


# -- XML helpers (namespace-agnostic via local names) ---------------------


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(elem: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [c for c in elem if _local(c.tag) == name]


def _find(elem: ElementTree.Element, name: str) -> ElementTree.Element | None:
    found = _children(elem, name)
    return found[0] if found else None


def _text(elem: ElementTree.Element, name: str) -> str:
    child = _find(elem, name)
    return (child.text or "").strip() if child is not None else ""


def _iter_items(root: ElementTree.Element, set_name: str) -> Iterable[ElementTree.Element]:
    """Yield each ``item`` under the named ``*Set`` element (empty if absent)."""
    container = _find(root, set_name)
    if container is None:
        return
    yield from _children(container, "item")


def _iter_instances(root: ElementTree.Element) -> Iterable[ElementTree.Element]:
    """Yield each instance ``item`` across all reservations."""
    for reservation in _iter_items(root, "reservationSet"):
        yield from _iter_items(reservation, "instancesSet")


def _tag(elem: ElementTree.Element, key: str) -> str:
    """Return the value of the resource tag named ``key`` (empty if absent)."""
    tag_set = _find(elem, "tagSet")
    if tag_set is None:
        return ""
    for item in _children(tag_set, "item"):
        if _text(item, "key") == key:
            return _text(item, "value")
    return ""


def _pii(elem: ElementTree.Element) -> bool:
    """True if a ``pii`` or ``contains_pii`` tag is set to ``"true"``."""
    return _tag(elem, "pii") == "true" or _tag(elem, "contains_pii") == "true"
