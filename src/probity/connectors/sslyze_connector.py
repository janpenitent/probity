# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Real TLS connector backed by ``sslyze --json_out`` output.

Like :class:`~probity.connectors.testssl_connector.TesttsslConnector` this
ingests a free offline scanner's export (no credentials at scan time) and
normalises it into the ``tls.endpoint`` facts C18 grades. sslyze's JSON is
structured per server, so one ``server_scan_results`` entry maps to one fact.

Fail-closed: no supported protocol leaves ``tls_version`` blank, a certificate
deployment that failed path validation or hostname matching leaves
``cert_valid`` false, and ``cert_expires_in_days`` is derived from the leaf
certificate's ``not_valid_after`` (negative once past).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_tls import TLS_KIND
from probity.model.fact import Fact

# sslyze scan_result section prefixes, highest protocol first.
_PROTOCOLS: tuple[tuple[str, str], ...] = (
    ("tls_1_3", "1.3"),
    ("tls_1_2", "1.2"),
    ("tls_1_1", "1.1"),
    ("tls_1_0", "1.0"),
    ("ssl_3_0", "0.3"),
    ("ssl_2_0", "0.2"),
)


class SslyzeConnector(Connector):
    """Emits one ``tls.endpoint`` fact per sslyze server scan result."""

    id = "sslyze"
    title = "TLS scan (sslyze JSON)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for server in payload.get("server_scan_results", []):
            loc = server.get("server_location", {})
            host = str(loc.get("hostname", ""))
            port = str(loc.get("port", ""))
            scan = server.get("scan_result", {})
            key = f"{host}:{port}"
            data: dict[str, Any] = {
                "id": key,
                "host": host,
                "tls_version": _tls_version(scan),
                "cert_valid": _cert_valid(scan),
            }
            days = _cert_days(scan)
            if days is not None:
                data["cert_expires_in_days"] = days
            yield Fact(kind=TLS_KIND, key=key, data=data)


def _supported(scan: dict[str, Any], prefix: str) -> bool:
    section = scan.get(f"{prefix}_cipher_suites", {})
    result = section.get("result") or {}
    return bool(result.get("is_tls_version_supported", False))


def _tls_version(scan: dict[str, Any]) -> str:
    for prefix, version in _PROTOCOLS:
        if _supported(scan, prefix):
            return version
    return ""


def _deployment(scan: dict[str, Any]) -> dict[str, Any] | None:
    result = scan.get("certificate_info", {}).get("result") or {}
    deployments = result.get("certificate_deployments") or []
    return deployments[0] if deployments else None


def _cert_valid(scan: dict[str, Any]) -> bool:
    dep = _deployment(scan)
    if dep is None:
        return False
    if not dep.get("leaf_certificate_subject_matches_hostname", False):
        return False
    results = dep.get("path_validation_results") or []
    if not results:
        return False
    return all(r.get("was_validation_successful", False) for r in results)


def _cert_days(scan: dict[str, Any]) -> int | None:
    dep = _deployment(scan)
    if dep is None:
        return None
    chain = dep.get("received_certificate_chain") or []
    if not chain:
        return None
    raw = chain[0].get("not_valid_after")
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (dt - datetime.now(UTC)).days
