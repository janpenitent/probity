"""Real backup connector backed by a Veeam B&R job-report export.

Unlike :class:`~probity.connectors.mock_backup.MockBackupConnector`, this reads
an actual Veeam job report (exported offline, no live credentials at scan time)
and normalises each job into the ``backup.job`` facts C06/C07/C08 grade. Veeam
carries everything the three backup controls need: job criticality, last
successful run, SureBackup restore-test results, and repository immutability.

Fail-closed: a job whose last run was not "Success" exposes no usable
``last_backup`` (C06 -> missing); a SureBackup that did not succeed leaves
``restore_test_passed`` false (C07); a repository without immutability leaves
``immutable`` false (C08).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_backup import BACKUP_KIND
from probity.model.fact import Fact


class VeeamConnector(Connector):
    """Emits one ``backup.job`` fact per Veeam job in the report."""

    id = "veeam"
    title = "Backup jobs (Veeam B&R report JSON)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for job in payload.get("jobs", []):
            job_id = str(job.get("id", ""))
            repo = job.get("repository") or {}
            sure = job.get("sureBackup") or {}
            data: dict[str, Any] = {
                "id": job_id,
                "asset": str(job.get("objectName") or job.get("name", "")),
                "critical": bool(job.get("isHighPriority", False)),
                "immutable": bool(repo.get("immutabilityEnabled", False)),
                "last_restore_test": str(sure.get("lastRun", "")),
                "restore_test_passed": _ok(sure.get("lastResult")),
            }
            if _ok(job.get("lastResult")):
                # only a successful run is a usable backup point
                data["last_backup"] = str(job.get("lastRun", ""))
            yield Fact(kind=BACKUP_KIND, key=job_id, data=data)


def _ok(result: Any) -> bool:
    """Veeam reports an operation as healthy when its result is 'Success'."""
    return str(result).strip().lower() == "success"
