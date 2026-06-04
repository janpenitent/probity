# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed HR/LMS connector for the security-training HARD control (C16).

Stands in for an export from an HR system or learning-management system and
emits one fact per person:

* ``training.record``::

      {"id": "u-1", "person": "Alice", "required": true,
       "completed_at": "2026-02-01T00:00:00+00:00"}

``completed_at`` is ISO-8601 (or null/absent when never completed). A real
HR/LMS connector emits the same facts.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

TRAINING_KIND = "training.record"


class MockTrainingConnector(Connector):
    """Emits one ``training.record`` fact per person."""

    id = "mock_training"
    title = "Mock Security Training (file-backed HR/LMS)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for record in payload.get("training", []):
            yield Fact(kind=TRAINING_KIND, key=str(record["id"]), data=dict(record))
