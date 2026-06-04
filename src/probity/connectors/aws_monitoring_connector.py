# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Live AWS connector for centralised logging (C03) and patch management (C14).

Zero runtime dependencies: the CloudTrail and SSM calls use the AWS JSON-1.1
protocol (POST with a JSON body and an ``X-Amz-Target`` header), signed with
Signature Version 4 from :mod:`probity.connectors.aws_sigv4` and sent over
``urllib`` — no ``boto3``. The connector emits the SAME facts as the file-backed
mocks, so the controls run unchanged:

* ``logging.source`` (C03) — one per CloudTrail trail, like
  :class:`~probity.connectors.mock_siem.MockSiemConnector`.
* ``patch.host`` (C14) — one per SSM-managed instance, like
  :class:`~probity.connectors.mock_assets.MockAssetsConnector`.

Field mapping (CloudTrail -> logging.source):

====================  ===================================================
``id``                trail ``TrailARN``
``asset``             trail ``Name``
``critical``          always ``True`` — an account trail is critical infra
``forwarding``        ``GetTrailStatus.IsLogging``
``last_event``        ``GetTrailStatus.LatestDeliveryTime`` as ISO-8601
====================  ===================================================

Field mapping (SSM instance patch state -> patch.host):

====================  ===================================================
``id`` / ``host``     ``InstanceId``
``critical``          always ``True`` — an SSM-managed instance is in scope
``last_patched``      ``OperationEndTime`` as ISO-8601
``pending_critical``  ``CriticalNonCompliantCount + SecurityNonCompliantCount``
====================  ===================================================

Every trail is reported ``critical`` because an account-level trail is the
centralised logging spine, and every SSM-managed instance is reported
``critical`` because it is, by definition, under managed patching. Both reads
fail closed: ``forwarding`` is ``True`` only when CloudTrail reports
``IsLogging`` true, ``last_event`` / ``last_patched`` are ``None`` when AWS
returns no timestamp (so C03/C14 see a stale source), and ``pending_critical``
sums the non-compliant counts so any outstanding critical patch fails C14.

Tests inject a fake ``transport`` returning canned JSON; the connector never
opens a socket and needs no credentials under test.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from probity.connectors.aws_sigv4 import SigV4Signer, payload_hash
from probity.connectors.base import Connector
from probity.connectors.mock_assets import PATCH_KIND
from probity.connectors.mock_siem import LOGGING_KIND
from probity.model.fact import Fact

_HTTP_TIMEOUT = 30.0
_JSON_CONTENT_TYPE = "application/x-amz-json-1.1"
_CLOUDTRAIL_SERVICE = "cloudtrail"
_CLOUDTRAIL_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"
_SSM_SERVICE = "ssm"
_SSM_TARGET = "AmazonSSM"
#: Guard against an unbounded NextToken loop from a misbehaving API.
_MAX_PAGES = 100

#: Transport seam: ``(method, url, headers, body) -> raw response bytes``.
#: The default implementation uses urllib; tests inject a fake.
Transport = Callable[[str, str, dict[str, str], bytes], bytes]


class AwsError(RuntimeError):
    """A non-2xx response from an AWS JSON API, carrying the status code."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(f"AWS API {status}: {message}")


def _urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes) -> bytes:
    """Default HTTPS transport over stdlib urllib, returning raw bytes."""
    if not url.startswith("https://"):  # never send a signature in cleartext
        raise ValueError(f"refusing non-HTTPS request to {url!r}")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 - https enforced
            return bytes(resp.read())
    except urllib.error.HTTPError as exc:
        raise AwsError(exc.code, exc.reason or "") from exc


class AwsMonitoringConnector(Connector):
    """Reads CloudTrail trails and SSM patch states from the AWS JSON APIs."""

    id = "aws-monitoring"
    title = "AWS CloudTrail/SSM (live, SigV4-signed)"

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
            raise ValueError("AwsMonitoringConnector requires access_key, secret_key and region")
        self._region = region
        self._transport = transport or _urllib_transport
        self._now = now or (lambda: datetime.now(UTC))
        self._signer = SigV4Signer(
            access_key, secret_key, region, session_token=session_token, now=self._now
        )

    # -- collection -------------------------------------------------------

    def collect(self) -> Iterable[Fact]:
        yield from self._collect_logging()
        yield from self._collect_patches()

    def _collect_logging(self) -> Iterable[Fact]:
        trails = self._call(
            _CLOUDTRAIL_SERVICE, _CLOUDTRAIL_TARGET, "DescribeTrails", {}
        ).get("trailList", [])
        for trail in trails:
            arn = trail.get("TrailARN") or trail.get("Name")
            if not arn:
                continue
            status = self._call(
                _CLOUDTRAIL_SERVICE, _CLOUDTRAIL_TARGET, "GetTrailStatus", {"Name": arn}
            )
            yield Fact(
                kind=LOGGING_KIND,
                key=str(arn),
                data={
                    "id": str(arn),
                    "asset": trail.get("Name", str(arn)),
                    "critical": True,
                    "forwarding": status.get("IsLogging") is True,
                    "last_event": _epoch_iso(status.get("LatestDeliveryTime")),
                },
            )

    def _collect_patches(self) -> Iterable[Fact]:
        for state in self._paginate(
            _SSM_SERVICE, _SSM_TARGET, "DescribeInstancePatchStates", {}, "InstancePatchStates"
        ):
            iid = state.get("InstanceId")
            if not iid:
                continue
            critical = _int(state.get("CriticalNonCompliantCount"))
            security = _int(state.get("SecurityNonCompliantCount"))
            yield Fact(
                kind=PATCH_KIND,
                key=str(iid),
                data={
                    "id": str(iid),
                    "host": str(iid),
                    "critical": True,
                    "last_patched": _epoch_iso(state.get("OperationEndTime")),
                    "pending_critical": critical + security,
                },
            )

    # -- HTTP / SigV4 -----------------------------------------------------

    def _call(
        self, service: str, target_prefix: str, action: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Sign and POST one AWS JSON-1.1 action, returning the parsed response."""
        host = f"{service}.{self._region}.amazonaws.com"
        payload = json.dumps(body).encode("utf-8")
        headers = self._signer.sign(
            service=service,
            method="POST",
            host=host,
            path="/",
            query="",
            payload_hash=payload_hash(payload),
        )
        headers["Content-Type"] = _JSON_CONTENT_TYPE
        headers["X-Amz-Target"] = f"{target_prefix}.{action}"
        raw = self._transport("POST", f"https://{host}/", headers, payload)
        parsed: dict[str, Any] = json.loads(raw)
        return parsed

    def _paginate(
        self,
        service: str,
        target_prefix: str,
        action: str,
        body: dict[str, Any],
        item_key: str,
    ) -> Iterable[dict[str, Any]]:
        """Yield items across ``NextToken`` pages, bounded by ``_MAX_PAGES``."""
        request = dict(body)
        for _ in range(_MAX_PAGES):
            page = self._call(service, target_prefix, action, request)
            yield from page.get(item_key, [])
            token = page.get("NextToken")
            if not token:
                return
            request["NextToken"] = token


# -- helpers --------------------------------------------------------------


def _epoch_iso(value: object) -> str | None:
    """Convert an AWS epoch-seconds timestamp to ISO-8601, else ``None``."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    return datetime.fromtimestamp(value, UTC).isoformat()


def _int(value: object) -> int:
    """Coerce a non-negative count to ``int``, defaulting to ``0``."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
