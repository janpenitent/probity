# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed asset-management connector for the asset-plane HARD controls.

A real deployment fuses a CMDB / cloud inventory, a vulnerability scanner, and a
patch/EDR console; this single connector stands in for all three and emits the
per-asset facts they would provide:

* ``asset.record`` — inventory entry (C02)::

      {"id": "vm-1", "name": "prod-db", "type": "vm",
       "managed": true, "last_seen": "2026-06-03T12:00:00+00:00"}

* ``vulnscan.target`` — scan coverage per asset (C12)::

      {"id": "vm-1", "asset": "prod-db", "critical": true,
       "last_scan": "2026-05-20T00:00:00+00:00", "scanner": "nessus"}

* ``patch.host`` — patch state per host (C14)::

      {"id": "vm-1", "host": "prod-db", "critical": true,
       "last_patched": "2026-05-28T00:00:00+00:00", "pending_critical": 0}

Dates are ISO-8601. Real connectors (cloud API, scanner export, EDR) emit the
same facts, so the controls run unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

ASSET_KIND = "asset.record"
VULNSCAN_KIND = "vulnscan.target"
PATCH_KIND = "patch.host"


class MockAssetsConnector(Connector):
    """Emits ``asset.record``, ``vulnscan.target`` and ``patch.host`` facts."""

    id = "mock_assets"
    title = "Mock Asset Management (file-backed)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for asset in payload.get("assets", []):
            yield Fact(kind=ASSET_KIND, key=str(asset["id"]), data=dict(asset))
        for target in payload.get("vulnscans", []):
            yield Fact(kind=VULNSCAN_KIND, key=str(target["id"]), data=dict(target))
        for host in payload.get("patches", []):
            yield Fact(kind=PATCH_KIND, key=str(host["id"]), data=dict(host))
