# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Regression alerting between consecutive scans.

Pure transition detection (testable, no IO) plus thin emitters (stdout, file,
webhook). A *regression* is a control moving to a worse posture (e.g. pass ->
fail); a *recovery* is the reverse. Detection is fail-closed: an unknown status
ranks as worst, so silent breakage still pages rather than being ignored.

Only regressions are *actionable* — recoveries are recorded for context but do
not, on their own, raise an alert.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from probity.report.history import Snapshot

# Posture ranking: higher == worse. Unknown labels fall through to worst (3)
# so an unexpected status is treated as a regression, never silently ignored.
_RANK: dict[str, int] = {
    "pass": 0,
    "not_applicable": 0,
    "partial": 1,
    "fail": 2,
    "error": 3,
}
_WORST = 3

_WEBHOOK_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class Transition:
    """A single control's status change between two scans."""

    control_id: str
    previous: str
    current: str
    kind: str  # "regression" | "recovery"

    def to_dict(self) -> dict[str, str]:
        return {
            "control_id": self.control_id,
            "previous": self.previous,
            "current": self.current,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class Alert:
    """The actionable summary of one scan relative to the previous one."""

    generated_at: str
    score: float
    previous_score: float | None
    regressions: tuple[Transition, ...]
    recoveries: tuple[Transition, ...]

    @property
    def is_actionable(self) -> bool:
        """An alert is worth paging on only when a control regressed."""
        return bool(self.regressions)

    def summary_line(self) -> str:
        reg = ", ".join(f"{t.control_id} {t.previous}->{t.current}" for t in self.regressions)
        delta = "" if self.previous_score is None else f" (was {self.previous_score}%)"
        return f"REGRESSION score {self.score}%{delta}: {reg}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "score": self.score,
            "previous_score": self.previous_score,
            "regressions": [t.to_dict() for t in self.regressions],
            "recoveries": [t.to_dict() for t in self.recoveries],
        }


def _rank(status: str) -> int:
    return _RANK.get(status, _WORST)


def detect_transitions(
    previous: Snapshot, current: Snapshot
) -> tuple[Transition, ...]:
    """Return per-control posture changes between two snapshots.

    Only controls present in ``current`` are considered. A label change with no
    posture change (e.g. pass <-> not_applicable, same rank) is not material and
    is skipped.
    """
    out: list[Transition] = []
    for control_id, cur in current.statuses.items():
        prev = previous.statuses.get(control_id)
        if prev is None or prev == cur:
            continue
        cur_rank, prev_rank = _rank(cur), _rank(prev)
        if cur_rank > prev_rank:
            kind = "regression"
        elif cur_rank < prev_rank:
            kind = "recovery"
        else:
            continue  # same posture, different label — not material
        out.append(Transition(control_id, prev, cur, kind))
    return tuple(out)


def build_alert(previous: Snapshot | None, current: Snapshot) -> Alert:
    """Build the alert for ``current`` relative to ``previous`` (None on first scan)."""
    if previous is None:
        return Alert(current.generated_at, current.score, None, (), ())
    transitions = detect_transitions(previous, current)
    regressions = tuple(t for t in transitions if t.kind == "regression")
    recoveries = tuple(t for t in transitions if t.kind == "recovery")
    return Alert(
        generated_at=current.generated_at,
        score=current.score,
        previous_score=previous.score,
        regressions=regressions,
        recoveries=recoveries,
    )


def emit_stdout(alert: Alert) -> None:
    print(alert.summary_line())


def emit_file(alert: Alert, path: str | Path) -> None:
    """Append the alert as one JSON line to an append-only alert log."""
    store = Path(path)
    store.parent.mkdir(parents=True, exist_ok=True)
    with store.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(alert.to_dict(), sort_keys=False) + "\n")


def emit_webhook(alert: Alert, url: str) -> bool:
    """POST the alert JSON to ``url``. Returns True on success.

    A webhook failure must never abort a scan loop, so transport errors are
    caught and reported to stderr rather than raised.
    """
    body = json.dumps(alert.to_dict()).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - operator-supplied alert URL
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=_WEBHOOK_TIMEOUT_SECONDS):  # noqa: S310
            return True
    except (urllib.error.URLError, OSError) as exc:
        print(f"probity: alert webhook to {url} failed: {exc}", file=sys.stderr)
        return False


def dispatch(
    alert: Alert,
    *,
    to_stdout: bool = True,
    file: str | Path | None = None,
    webhook: str | None = None,
) -> None:
    """Emit an actionable alert to every configured sink. No-op if not actionable."""
    if not alert.is_actionable:
        return
    if to_stdout:
        emit_stdout(alert)
    if file:
        emit_file(alert, file)
    if webhook:
        emit_webhook(alert, webhook)
