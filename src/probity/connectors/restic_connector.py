"""Real backup connector backed by ``restic snapshots --json`` output.

restic is a free, offline backup tool whose snapshot listing is JSON-native, so
it fits the same export-ingestion strategy as the other real connectors. It is
honest about scope: a snapshot listing proves *recency* (C06) but says nothing
about restore tests (C07) or repository immutability (C08), so those fields are
deliberately omitted and the corresponding controls fail closed for any asset
restic alone backs. Pair it with :class:`~probity.connectors.veeam_connector.
VeeamConnector` for full C06/C07/C08 coverage.

Convention: one ``backup.job`` per host (``hostname``), keyed by host, with the
most recent snapshot as ``last_backup`` and ``critical`` taken from the presence
of a ``critical`` tag.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_backup import BACKUP_KIND
from probity.model.fact import Fact

_CRITICAL_TAG = "critical"


class ResticConnector(Connector):
    """Emits one ``backup.job`` fact per host found in the snapshot listing."""

    id = "restic"
    title = "Backup snapshots (restic --json)"

    def __init__(self, source: str | Path | list[dict[str, Any]]) -> None:
        self._source = source

    def _load(self) -> list[dict[str, Any]]:
        if isinstance(self._source, list):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(list[dict[str, Any]], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        # keep the most recent snapshot per host, preserving first-seen order
        latest: dict[str, dict[str, Any]] = {}
        for snap in self._load():
            host = str(snap.get("hostname", ""))
            current = latest.get(host)
            if current is None or _when(snap) > _when(current):
                latest[host] = snap

        for host, snap in latest.items():
            tags = snap.get("tags") or []
            data: dict[str, Any] = {
                "id": str(snap.get("short_id", host)),
                "asset": host,
                "critical": _CRITICAL_TAG in tags,
                "last_backup": str(snap.get("time", "")),
            }
            yield Fact(kind=BACKUP_KIND, key=host, data=data)


def _when(snap: dict[str, Any]) -> datetime:
    """Parse a snapshot's timestamp (UTC-normalised); unparseable sort oldest."""
    try:
        dt = datetime.fromisoformat(str(snap.get("time", "")))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
