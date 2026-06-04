# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Zero-dependency AWS Signature Version 4 signer (stdlib ``hmac`` / ``hashlib``).

Shared by every live AWS connector so the signing logic lives in one place and
is exercised by one set of tests. The signer is protocol-agnostic: callers pass
the service name, HTTP method, host, path, canonical query string and the
SHA-256 of the request body, and get back the ``Authorization`` and ``x-amz-*``
headers. EC2's XML Query API (GET, empty body) and the JSON-1.1 services
(CloudTrail, SSM — POST with a JSON body) both go through the same path.

Only ``host`` and ``x-amz-date`` (plus ``x-amz-security-token`` when a session
token is present) are signed. Additional request headers such as
``Content-Type`` and ``X-Amz-Target`` may be sent unsigned, which AWS accepts
for non-S3 services.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from datetime import UTC, datetime

_SIGV4_ALGORITHM = "AWS4-HMAC-SHA256"

#: SHA-256 of the empty string — the payload hash for a body-less GET request.
EMPTY_PAYLOAD_HASH = hashlib.sha256(b"").hexdigest()


def payload_hash(body: bytes) -> str:
    """SHA-256 hex digest of a request body (the empty-string hash for ``b""``)."""
    return hashlib.sha256(body).hexdigest()


class SigV4Signer:
    """Signs AWS requests with SigV4, carrying the caller's credentials."""

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        region: str,
        *,
        session_token: str | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not (access_key and secret_key and region):
            raise ValueError("SigV4Signer requires access_key, secret_key and region")
        self._access_key = access_key
        self._secret_key = secret_key
        self._region = region
        self._session_token = session_token
        self._now = now or (lambda: datetime.now(UTC))

    def sign(
        self,
        *,
        service: str,
        method: str,
        host: str,
        path: str,
        query: str,
        payload_hash: str,
    ) -> dict[str, str]:
        """Return the SigV4 ``Authorization`` and ``x-amz-*`` headers for a request."""
        now = self._now().astimezone(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        signed_headers = "host;x-amz-date"
        canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
        if self._session_token:
            signed_headers = "host;x-amz-date;x-amz-security-token"
            canonical_headers += f"x-amz-security-token:{self._session_token}\n"

        canonical_request = "\n".join(
            [method, path, query, canonical_headers, signed_headers, payload_hash]
        )
        scope = f"{date_stamp}/{self._region}/{service}/aws4_request"
        string_to_sign = "\n".join(
            [
                _SIGV4_ALGORITHM,
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signing_key = _signing_key(self._secret_key, date_stamp, self._region, service)
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


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    """Derive the SigV4 signing key via the standard HMAC chain."""
    k_date = _hmac(f"AWS4{secret}".encode(), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")
