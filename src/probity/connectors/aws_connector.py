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

import hashlib
import hmac
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from xml.etree import ElementTree

from probity.connectors.base import Connector
from probity.connectors.mock_assets import ASSET_KIND
from probity.connectors.mock_cloud import STORAGE_KIND
from probity.model.fact import Fact

_EC2_API_VERSION = "2016-11-15"
_HTTP_TIMEOUT = 30.0
_SIGV4_ALGORITHM = "AWS4-HMAC-SHA256"
_SERVICE = "ec2"
#: SHA-256 of the empty string — the payload hash for a body-less GET request.
_EMPTY_PAYLOAD_HASH = hashlib.sha256(b"").hexdigest()

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
        self._access_key = access_key
        self._secret_key = secret_key
        self._region = region
        self._session_token = session_token
        self._transport = transport or _urllib_transport
        self._now = now or (lambda: datetime.now(UTC))

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
        headers = self._sign("GET", host, "/", query)
        raw = self._transport("GET", f"https://{host}/?{query}", headers)
        return ElementTree.fromstring(raw)

    def _sign(self, method: str, host: str, path: str, query: str) -> dict[str, str]:
        """Build the SigV4 ``Authorization`` and ``x-amz-*`` headers for a request."""
        now = self._now().astimezone(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        signed_headers = "host;x-amz-date"
        canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
        if self._session_token:
            signed_headers = "host;x-amz-date;x-amz-security-token"
            canonical_headers += f"x-amz-security-token:{self._session_token}\n"

        canonical_request = "\n".join(
            [method, path, query, canonical_headers, signed_headers, _EMPTY_PAYLOAD_HASH]
        )
        scope = f"{date_stamp}/{self._region}/{_SERVICE}/aws4_request"
        string_to_sign = "\n".join(
            [
                _SIGV4_ALGORITHM,
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signing_key = _signing_key(self._secret_key, date_stamp, self._region, _SERVICE)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        authorization = (
            f"{_SIGV4_ALGORITHM} Credential={self._access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        headers = {"x-amz-date": amz_date, "Authorization": authorization}
        if self._session_token:
            headers["x-amz-security-token"] = self._session_token
        return headers


# -- SigV4 key derivation -------------------------------------------------


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    """Derive the SigV4 signing key via the standard HMAC chain."""
    k_date = _hmac(f"AWS4{secret}".encode(), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


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
