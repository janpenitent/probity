# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed cloud storage connector for development and tests."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

STORAGE_KIND = "storage.volume"


class MockCloudConnector(Connector):
    """Emits one ``storage.volume`` fact per declared volume.

    Source JSON shape::

        {"volumes": [
            {"id": "v1", "name": "prod-db", "encrypted": true,
             "kms": "managed", "contains_pii": true}
        ]}
    """

    id = "mock_cloud"
    title = "Mock Cloud Storage (file-backed)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for volume in payload.get("volumes", []):
            yield Fact(kind=STORAGE_KIND, key=str(volume["id"]), data=dict(volume))
