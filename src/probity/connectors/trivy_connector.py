# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Real vulnerability-scanning connector backed by Trivy JSON output.

Unlike :class:`~probity.connectors.mock_assets.MockAssetsConnector`, this reads
the JSON produced by the industry-standard, free, offline-capable scanner
``trivy ... --format json``. The operator runs Trivy against the assets they
care about (container images, filesystems, repos) and hands Probity the
resulting file as auditable evidence — no credentials, no network at scan time.

Each Trivy report covers one scanned artifact and carries a ``CreatedAt``
timestamp; this connector turns each report into one ``vulnscan.target`` fact,
identical in shape to the mock connector, so C12 (vulnerability-scanning
coverage) consumes either source unchanged.

What C12 actually verifies is **freshness** of the scan, which Trivy records
exactly (``CreatedAt`` -> ``last_scan``). Business *criticality* is not
something a scanner knows, so a scanned target is treated as in scope
(``critical: True``): if you bothered to run Trivy against it, it belongs to
your scan programme. The one gap this evidence model cannot close on its own is
a critical asset that was *never scanned* — it simply produces no fact. Pair
this with an inventory connector to catch that.

A single ``trivy`` invocation emits one report object; concatenate several into
a JSON array to cover multiple assets in one file. Both shapes are accepted.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_assets import VULNSCAN_KIND
from probity.model.fact import Fact

_SCANNER = "trivy"


class TrivyConnector(Connector):
    """Emits one ``vulnscan.target`` fact per Trivy report (scanned artifact)."""

    id = "trivy"
    title = "Vulnerability Scanning (Trivy JSON)"

    def __init__(self, source: str | Path | dict[str, Any] | list[Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any] | list[Any]:
        if isinstance(self._source, (dict, list)):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast("dict[str, Any] | list[Any]", json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        for report in _reports(self._load()):
            artifact = str(report.get("ArtifactName", ""))
            if not artifact:
                # No artifact name -> not a usable scan record; skip rather than
                # emit a blank target that would mask, not surface, the gap.
                continue
            yield Fact(
                kind=VULNSCAN_KIND,
                key=artifact,
                data={
                    "id": artifact,
                    "asset": artifact,
                    "critical": True,
                    "last_scan": report.get("CreatedAt", ""),
                    "scanner": _SCANNER,
                },
            )


def _reports(raw: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    """Normalise Trivy output (single report object or array) to a list."""
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []
