# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Live Google Cloud connector for asset inventory (C02) and encryption (C17).

Zero runtime dependencies: the Compute Engine REST calls use the Python standard
library ``urllib`` only — no ``google-cloud-*`` SDK. The connector emits the SAME
facts as the file-backed mocks, so the controls run unchanged:

* ``asset.record`` (C02) — one per Compute Engine instance, like
  :class:`~probity.connectors.mock_assets.MockAssetsConnector`.
* ``storage.volume`` (C17) — one per persistent disk, like
  :class:`~probity.connectors.mock_cloud.MockCloudConnector`.

Authentication: a short-lived OAuth2 **access token** is read from the
environment (``PROBITY_GCP_ACCESS_TOKEN``) and sent as a bearer token, with the
target project in ``PROBITY_GCP_PROJECT``. A service-account key is deliberately
*not* accepted: minting a token from one requires signing an RS256 JWT, which
needs an RSA implementation the standard library does not provide — taking a
crypto dependency would break Probity's zero-dependency contract. Instead the
caller obtains the token out of band (``gcloud auth print-access-token`` or
Workload Identity) and exports it, exactly like the other live connectors read
credentials from the environment only, never from CLI flags.

Field mapping (Compute Engine -> fact):

======================  ===================================================
asset ``id``            instance ``id``
asset ``name``          instance ``name``
asset ``type``          ``"gce"``
asset ``managed``       always ``True`` — the instance is in the GCP inventory
asset ``last_seen``     the scan time: the aggregatedList call *is* the sighting
volume ``id``           disk ``id``
volume ``name``         disk ``name``
volume ``encrypted``    always ``True`` — GCP encrypts all persistent disks at rest
volume ``kms``          ``"managed"`` for a customer key (CMEK), else ``"google"``
volume ``contains_pii`` the ``pii`` / ``contains_pii`` label is ``"true"``
======================  ===================================================

``encrypted`` is ``True`` for every disk because Google Cloud encrypts all
persistent disks at rest with no opt-out; the ``kms`` field then distinguishes a
customer-managed key (``diskEncryptionKey.kmsKeyName`` present) from the default
Google-managed key. ``managed`` is ``True`` and ``last_seen`` is the scan time
for the same reason as the AWS connector: a returned instance is, by definition,
a live managed inventory entry observed right now.

Tests inject a fake ``transport`` returning canned Compute JSON; the connector
never opens a socket and needs no credentials under test.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_assets import ASSET_KIND
from probity.connectors.mock_cloud import STORAGE_KIND
from probity.model.fact import Fact

_COMPUTE_BASE = "https://compute.googleapis.com/compute/v1"
_HTTP_TIMEOUT = 30.0
#: Guard against an unbounded pageToken loop from a misbehaving API.
_MAX_PAGES = 100

#: Transport seam: ``(method, url, headers) -> parsed JSON dict``.
#: The default implementation uses urllib; tests inject a fake.
Transport = Callable[[str, str, dict[str, str]], dict[str, Any]]


class GcpError(RuntimeError):
    """A non-2xx response from the GCP Compute API, carrying the status code."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(f"GCP Compute API {status}: {message}")


def _urllib_transport(method: str, url: str, headers: dict[str, str]) -> dict[str, Any]:
    """Default HTTPS transport over stdlib urllib, returning parsed JSON."""
    if not url.startswith("https://"):  # never send a bearer token in cleartext
        raise ValueError(f"refusing non-HTTPS request to {url!r}")
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 - https enforced
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise GcpError(exc.code, exc.reason or "") from exc
    return cast("dict[str, Any]", json.loads(raw)) if raw else {}


class GcpComputeConnector(Connector):
    """Reads Compute Engine instances and persistent disks from the GCP REST API."""

    id = "gcp"
    title = "Google Cloud Compute (live REST API)"

    def __init__(
        self,
        access_token: str,
        project: str,
        *,
        transport: Transport | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not (access_token and project):
            raise ValueError("GcpComputeConnector requires access_token and project")
        self._access_token = access_token
        self._project = project
        self._transport = transport or _urllib_transport
        self._now = now or (lambda: datetime.now(UTC))

    # -- collection -------------------------------------------------------

    def collect(self) -> Iterable[Fact]:
        seen = self._now().isoformat()
        for inst in self._aggregated("instances"):
            iid = inst.get("id")
            if not iid:
                continue
            yield Fact(
                kind=ASSET_KIND,
                key=str(iid),
                data={
                    "id": str(iid),
                    "name": inst.get("name", str(iid)),
                    "type": "gce",
                    "managed": True,
                    "last_seen": seen,
                },
            )
        for disk in self._aggregated("disks"):
            did = disk.get("id")
            if not did:
                continue
            yield Fact(
                kind=STORAGE_KIND,
                key=str(did),
                data={
                    "id": str(did),
                    "name": disk.get("name", str(did)),
                    "encrypted": True,  # GCP encrypts all persistent disks at rest
                    "kms": "managed" if _has_cmek(disk) else "google",
                    "contains_pii": _pii(disk),
                },
            )

    # -- HTTP -------------------------------------------------------------

    def _aggregated(self, resource: str) -> Iterable[dict[str, Any]]:
        """Yield every item of an ``aggregated/<resource>`` list across scopes/pages."""
        base = f"{_COMPUTE_BASE}/projects/{self._project}/aggregated/{resource}"
        headers = {"Authorization": f"Bearer {self._access_token}"}
        token: str | None = None
        for _ in range(_MAX_PAGES):
            url = base if not token else f"{base}?{urllib.parse.urlencode({'pageToken': token})}"
            page = self._transport("GET", url, headers)
            for scope in page.get("items", {}).values():
                if isinstance(scope, dict):
                    yield from scope.get(resource, [])
            token = page.get("nextPageToken")
            if not token:
                return
        raise GcpError(0, f"aggregated/{resource} exceeded {_MAX_PAGES} pages")


# -- helpers --------------------------------------------------------------


def _has_cmek(disk: dict[str, Any]) -> bool:
    """True if the disk is encrypted with a customer-managed KMS key (CMEK)."""
    key = disk.get("diskEncryptionKey")
    return isinstance(key, dict) and bool(key.get("kmsKeyName"))


def _pii(resource: dict[str, Any]) -> bool:
    """True if a ``pii`` or ``contains_pii`` label is set to ``"true"``."""
    labels = resource.get("labels")
    if not isinstance(labels, dict):
        return False
    return labels.get("pii") == "true" or labels.get("contains_pii") == "true"
