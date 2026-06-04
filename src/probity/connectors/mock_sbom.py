# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed SBOM (Software Bill of Materials) connector.

Stands in for a real SBOM toolchain (Syft, CycloneDX, SPDX): the source
already records, per shipped component, whether an SBOM exists and when it was
last generated. A live SBOM scanner arrives later; the control logic is
identical either way.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

SBOM_KIND = "sbom.component"


class MockSbomConnector(Connector):
    """Emits one ``sbom.component`` fact per shipped component.

    Source JSON shape::

        {"components": [
            {"name": "app", "version": "1.0", "has_sbom": true,
             "generated_at": "2026-05-01T00:00:00+00:00"}
        ]}
    """

    id = "mock_sbom"
    title = "Mock SBOM (file-backed bill of materials)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for comp in payload.get("components", []):
            key = f"{comp['name']}@{comp.get('version', '')}"
            yield Fact(kind=SBOM_KIND, key=key, data=dict(comp))
