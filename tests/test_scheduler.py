# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Tests for the scheduled scan loop."""

from __future__ import annotations

import threading

from probity.model.enums import Severity, Status
from probity.model.finding import Finding, Report
from probity.report.history import load_snapshots
from probity.service.scheduler import AlertSinks, ScanScheduler


def _report(statuses: dict[str, str]) -> Report:
    findings = tuple(
        Finding(cid, cid, Severity.HIGH, Status(s), "synthetic")
        for cid, s in statuses.items()
    )
    return Report(findings)


def test_tick_records_snapshot_and_returns_alert(tmp_path):
    history = tmp_path / "history.jsonl"
    sched = ScanScheduler(
        scan_factory=lambda: _report({"C06": "pass"}),
        history_path=history,
        interval_seconds=1,
        sinks=AlertSinks(to_stdout=False),
    )
    alert = sched.tick()
    assert len(load_snapshots(history)) == 1
    assert alert.is_actionable is False  # first scan, nothing to regress from


def test_tick_detects_regression_across_two_runs(tmp_path):
    history = tmp_path / "history.jsonl"
    reports = iter([_report({"C06": "pass"}), _report({"C06": "fail"})])
    sched = ScanScheduler(
        scan_factory=lambda: next(reports),
        history_path=history,
        interval_seconds=1,
        sinks=AlertSinks(to_stdout=False),
    )
    sched.tick()
    alert = sched.tick()
    assert alert.is_actionable is True
    assert alert.regressions[0].control_id == "C06"
    assert len(load_snapshots(history)) == 2


def test_regression_dispatched_to_alert_file(tmp_path):
    history = tmp_path / "history.jsonl"
    alert_log = tmp_path / "alerts.jsonl"
    reports = iter([_report({"C18": "pass"}), _report({"C18": "fail"})])
    sched = ScanScheduler(
        scan_factory=lambda: next(reports),
        history_path=history,
        interval_seconds=1,
        sinks=AlertSinks(to_stdout=False, file=alert_log),
    )
    sched.tick()
    sched.tick()
    assert alert_log.exists()
    assert "C18" in alert_log.read_text(encoding="utf-8")


def test_run_forever_stops_when_event_set(tmp_path):
    history = tmp_path / "history.jsonl"
    stop = threading.Event()
    calls: list[int] = []

    def factory() -> Report:
        calls.append(1)
        stop.set()  # ask the loop to stop after this tick
        return _report({"C06": "pass"})

    sched = ScanScheduler(
        scan_factory=factory,
        history_path=history,
        interval_seconds=1,
        sinks=AlertSinks(to_stdout=False),
    )
    sched.run_forever(stop)
    assert len(calls) == 1  # Event.wait returns immediately once set -> single tick
