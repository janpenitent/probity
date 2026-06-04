"""File-backed software-composition (dependency/CVE) connector.

Stands in for a real OSV/NVD lookup: the source already carries the
vulnerabilities matched against each installed dependency. A live OSV feed
arrives in E5; the control logic is identical either way.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

DEPENDENCY_KIND = "dependency"


class MockScaConnector(Connector):
    """Emits one ``dependency`` fact per installed package.

    Source JSON shape::

        {"dependencies": [
            {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI",
             "vulnerabilities": [
                {"id": "CVE-2023-1", "severity": "high", "fixed_version": "2.31.0"}
             ]}
        ]}
    """

    id = "mock_sca"
    title = "Mock Software Composition (file-backed OSV match)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for dep in payload.get("dependencies", []):
            key = f"{dep['name']}@{dep.get('version', '')}"
            yield Fact(kind=DEPENDENCY_KIND, key=key, data=dict(dep))
