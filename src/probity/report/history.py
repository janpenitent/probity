"""Append-only scan history and trend scoring.

Each scan can be recorded as one JSON line in an append-only store (an audit
log of compliance posture over time). From that log we derive the score trend
(delta vs the previous scan) and per-control history.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from probity.model.finding import Report


@dataclass(frozen=True)
class Snapshot:
    """One recorded scan: its timestamp, score, and per-control statuses."""

    generated_at: str
    score: float
    statuses: dict[str, str]


@dataclass(frozen=True)
class Trend:
    """Score movement of the latest scan relative to the previous one."""

    current: float
    previous: float | None
    delta: float
    direction: str  # "up" | "down" | "flat" | "first"


def append_snapshot(report: Report, path: str | Path) -> Snapshot:
    """Append ``report`` to the JSONL store at ``path`` and return the snapshot."""
    snapshot = Snapshot(
        generated_at=report.generated_at.isoformat(),
        score=report.score,
        statuses={f.control_id: f.status.value for f in report.findings},
    )
    record = {
        "generated_at": snapshot.generated_at,
        "score": snapshot.score,
        "statuses": snapshot.statuses,
    }
    store = Path(path)
    store.parent.mkdir(parents=True, exist_ok=True)
    with store.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=False) + "\n")
    return snapshot


def load_snapshots(path: str | Path) -> tuple[Snapshot, ...]:
    """Load all snapshots from the store, oldest first. Empty if absent."""
    store = Path(path)
    if not store.exists():
        return ()
    snapshots: list[Snapshot] = []
    for line in store.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record: dict[str, Any] = json.loads(line)
        snapshots.append(
            Snapshot(
                generated_at=str(record.get("generated_at", "")),
                score=float(record.get("score", 0.0)),
                statuses=dict(record.get("statuses", {})),
            )
        )
    return tuple(snapshots)


def compute_trend(snapshots: tuple[Snapshot, ...]) -> Trend:
    """Compare the latest snapshot's score against the previous one."""
    if not snapshots:
        return Trend(current=0.0, previous=None, delta=0.0, direction="first")
    current = snapshots[-1].score
    if len(snapshots) == 1:
        return Trend(current=current, previous=None, delta=0.0, direction="first")
    previous = snapshots[-2].score
    delta = round(current - previous, 1)
    direction = "flat" if delta == 0 else "up" if delta > 0 else "down"
    return Trend(current=current, previous=previous, delta=delta, direction=direction)


def control_history(
    snapshots: tuple[Snapshot, ...], control_id: str
) -> tuple[tuple[str, str], ...]:
    """Return (generated_at, status) per snapshot that recorded ``control_id``."""
    return tuple(
        (s.generated_at, s.statuses[control_id])
        for s in snapshots
        if control_id in s.statuses
    )
