"""Scheduled scan loop.

Drives a scan on a fixed interval using only stdlib ``threading`` — no cron, no
external scheduler. Each tick: snapshot the previous posture, run the scan,
append the new snapshot to history, diff the two, and dispatch any regression
alert. The loop is stoppable via a :class:`threading.Event` so it shuts down
cleanly on SIGINT.

``tick`` is pure orchestration over injected pieces (a scan factory and a
history path), so it is unit-testable without sleeping or spawning threads.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from probity.model.finding import Report
from probity.report.history import append_snapshot, load_snapshots
from probity.service.alerts import Alert, build_alert, dispatch

# A scan factory produces a fresh Report each call (re-collecting facts).
ScanFactory = Callable[[], Report]

_MIN_INTERVAL_SECONDS = 1.0


@dataclass(frozen=True)
class AlertSinks:
    """Where regression alerts go. stdout on by default; file/webhook opt-in."""

    to_stdout: bool = True
    file: str | Path | None = None
    webhook: str | None = None


class ScanScheduler:
    """Runs ``scan_factory`` every ``interval_seconds`` and alerts on regressions."""

    def __init__(
        self,
        scan_factory: ScanFactory,
        history_path: str | Path,
        interval_seconds: float,
        sinks: AlertSinks | None = None,
    ) -> None:
        self._scan_factory = scan_factory
        self._history_path = Path(history_path)
        self._interval = max(float(interval_seconds), _MIN_INTERVAL_SECONDS)
        self._sinks = sinks or AlertSinks()

    def tick(self) -> Alert:
        """Run one scan, record it, and dispatch any regression alert."""
        existing = load_snapshots(self._history_path)
        previous = existing[-1] if existing else None
        report = self._scan_factory()
        current = append_snapshot(report, self._history_path)
        alert = build_alert(previous, current)
        dispatch(
            alert,
            to_stdout=self._sinks.to_stdout,
            file=self._sinks.file,
            webhook=self._sinks.webhook,
        )
        return alert

    def run_forever(self, stop: threading.Event | None = None) -> None:
        """Tick immediately, then every interval, until ``stop`` is set.

        Uses ``Event.wait`` for the delay so a stop request interrupts the sleep
        instead of waiting out the full interval.
        """
        stop = stop or threading.Event()
        while not stop.is_set():
            self.tick()
            stop.wait(self._interval)
