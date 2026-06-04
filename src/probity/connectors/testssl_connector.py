"""Real TLS connector backed by ``testssl.sh --jsonfile`` output.

Unlike :class:`~probity.connectors.mock_tls.MockTlsConnector`, this reads the
flat JSON array emitted by testssl.sh (free, offline, no credentials) against a
real endpoint and normalises it into the ``tls.endpoint`` facts C18 already
grades. testssl reports one finding per (id, target); we fold the per-target
findings into a single endpoint fact.

Normalisation is fail-closed: an endpoint that offers no modern protocol leaves
``tls_version`` blank (C18 -> obsolete_tls), a chain that did not pass leaves
``cert_valid`` false, and an "expired" cert maps to 0 days remaining.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_tls import TLS_KIND
from probity.model.fact import Fact

# testssl protocol ids, highest first. The first one "offered" wins.
_PROTOCOLS: tuple[tuple[str, str], ...] = (
    ("TLS1_3", "1.3"),
    ("TLS1_2", "1.2"),
    ("TLS1_1", "1.1"),
    ("TLS1", "1.0"),
    ("SSLv3", "0.3"),
    ("SSLv2", "0.2"),
)
_DIGITS = re.compile(r"\d+")


class TesttsslConnector(Connector):
    """Folds testssl.sh findings into one ``tls.endpoint`` fact per target."""

    id = "testssl"
    title = "TLS scan (testssl.sh JSON)"
    __test__ = False  # not a pytest test class despite the "Test..." name

    def __init__(self, source: str | Path | list[dict[str, Any]]) -> None:
        self._source = source

    def _load(self) -> list[dict[str, Any]]:
        if isinstance(self._source, list):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(list[dict[str, Any]], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        # group findings by target, preserving first-seen order
        targets: dict[str, list[dict[str, Any]]] = {}
        for finding in self._load():
            host = str(finding.get("ip", "")).split("/")[0]
            port = str(finding.get("port", ""))
            key = f"{host}:{port}"
            targets.setdefault(key, []).append(finding)

        for key, findings in targets.items():
            host = key.rsplit(":", 1)[0]
            data: dict[str, Any] = {
                "id": key,
                "host": host,
                "tls_version": _tls_version(findings),
                "cert_valid": _cert_valid(findings),
            }
            days = _cert_days(findings)
            if days is not None:
                data["cert_expires_in_days"] = days
            yield Fact(kind=TLS_KIND, key=key, data=data)


def _offered(findings: list[dict[str, Any]], proto_id: str) -> bool:
    return any(
        f.get("id") == proto_id and str(f.get("finding", "")).strip().lower() == "offered"
        for f in findings
    )


def _tls_version(findings: list[dict[str, Any]]) -> str:
    for proto_id, version in _PROTOCOLS:
        if _offered(findings, proto_id):
            return version
    return ""


def _cert_valid(findings: list[dict[str, Any]]) -> bool:
    for f in findings:
        if f.get("id") == "cert_chain_of_trust":
            return "passed" in str(f.get("finding", "")).lower()
    return False


def _cert_days(findings: list[dict[str, Any]]) -> int | None:
    for f in findings:
        if str(f.get("id", "")).startswith("cert_expiration"):
            text = str(f.get("finding", "")).lower()
            if "expired" in text:
                return 0
            match = _DIGITS.search(text)
            if match:
                return int(match.group())
    return None
