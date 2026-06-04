# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed TLS endpoint connector for development and tests."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

TLS_KIND = "tls.endpoint"


class MockTlsConnector(Connector):
    """Emits one ``tls.endpoint`` fact per declared endpoint.

    Source JSON shape::

        {"endpoints": [
            {"id": "e1", "host": "portal.example.com", "tls_version": "1.3",
             "cert_valid": true, "cert_expires_in_days": 90}
        ]}
    """

    id = "mock_tls"
    title = "Mock TLS Endpoint Scanner (file-backed)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for endpoint in payload.get("endpoints", []):
            yield Fact(kind=TLS_KIND, key=str(endpoint["id"]), data=dict(endpoint))
