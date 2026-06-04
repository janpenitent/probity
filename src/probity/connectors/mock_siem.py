# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed SIEM connector for the monitoring HARD controls.

Stands in for a SIEM / log-pipeline export and emits two fact kinds:

* ``logging.source`` — a log shipper per asset (C03)::

      {"id": "src-1", "asset": "prod-db", "critical": true,
       "forwarding": true, "last_event": "2026-06-04T11:00:00+00:00"}

* ``detection.rule`` — an alerting rule (C04)::

      {"id": "rule-1", "name": "Impossible travel", "enabled": true,
       "last_tested": "2026-04-01T00:00:00+00:00"}

Dates are ISO-8601. A real SIEM connector emits the same facts.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

LOGGING_KIND = "logging.source"
DETECTION_KIND = "detection.rule"


class MockSiemConnector(Connector):
    """Emits ``logging.source`` and ``detection.rule`` facts."""

    id = "mock_siem"
    title = "Mock SIEM (file-backed)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for source in payload.get("log_sources", []):
            yield Fact(kind=LOGGING_KIND, key=str(source["id"]), data=dict(source))
        for rule in payload.get("detection_rules", []):
            yield Fact(kind=DETECTION_KIND, key=str(rule["id"]), data=dict(rule))
