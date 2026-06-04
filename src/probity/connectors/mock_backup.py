# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed backup-job connector for development and tests."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

BACKUP_KIND = "backup.job"


class MockBackupConnector(Connector):
    """Emits one ``backup.job`` fact per declared backup job.

    Source JSON shape::

        {"backups": [
            {"id": "b1", "asset": "prod-db", "critical": true,
             "last_backup": "2026-06-03T00:00:00+00:00", "retention_days": 30}
        ]}
    """

    id = "mock_backup"
    title = "Mock Backup Jobs (file-backed)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for job in payload.get("backups", []):
            yield Fact(kind=BACKUP_KIND, key=str(job["id"]), data=dict(job))
