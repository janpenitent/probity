# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed CI/CD connector for the pipeline-security HARD control (C13).

Stands in for an export of pipeline configuration (GitHub Actions, GitLab CI,
Jenkins) and emits one fact per repository pipeline:

* ``pipeline.config``::

      {"id": "repo-app", "repo": "org/app",
       "sast_enabled": true, "secret_scanning_enabled": true}

A real connector reading the platform API emits the same facts.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

PIPELINE_KIND = "pipeline.config"


class MockPipelineConnector(Connector):
    """Emits one ``pipeline.config`` fact per repository pipeline."""

    id = "mock_pipeline"
    title = "Mock CI/CD Pipelines (file-backed)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for pipeline in payload.get("pipelines", []):
            yield Fact(kind=PIPELINE_KIND, key=str(pipeline["id"]), data=dict(pipeline))
