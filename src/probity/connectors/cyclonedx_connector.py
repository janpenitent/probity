"""Real SBOM connector backed by a CycloneDX JSON bill of materials.

Unlike :class:`~probity.connectors.mock_sbom.MockSbomConnector`, this reads an
actual CycloneDX BOM produced by a standard tool (`cyclonedx-py`,
`syft -o cyclonedx-json`, `cdxgen`). No credentials and no network are needed
at scan time: the operator generates the BOM (free, offline) and hands Probity
the file as auditable supply-chain evidence.

A component's mere presence in a real BOM proves an SBOM exists for it; the
BOM's own ``metadata.timestamp`` is that SBOM's generation date. This emits the
same ``sbom.component`` facts the mock does, so C09 consumes either unchanged
and keeps its fail-closed staleness check (a BOM with no timestamp leaves
``generated_at`` blank, which C09 fails closed).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_sbom import SBOM_KIND
from probity.model.fact import Fact


class CycloneDxConnector(Connector):
    """Emits one ``sbom.component`` fact per component listed in the BOM."""

    id = "cyclonedx"
    title = "SBOM (CycloneDX JSON bill of materials)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        generated_at = str(payload.get("metadata", {}).get("timestamp", ""))
        for comp in payload.get("components", []):
            name = comp.get("name", "")
            version = comp.get("version", "")
            data = {
                "name": name,
                "version": version,
                "has_sbom": True,
                "generated_at": generated_at,
                "purl": comp.get("purl", ""),
            }
            yield Fact(kind=SBOM_KIND, key=f"{name}@{version}", data=data)
