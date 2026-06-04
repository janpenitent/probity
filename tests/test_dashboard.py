# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Tests for the read-only dashboard renderer."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler

from probity.model.enums import Severity, Status
from probity.model.finding import Finding, Report
from probity.report.history import append_snapshot
from probity.service.dashboard import make_handler, render_dashboard


def _record(history, statuses: dict[str, str]) -> None:
    findings = tuple(
        Finding(cid, cid, Severity.HIGH, Status(s), "synthetic")
        for cid, s in statuses.items()
    )
    append_snapshot(Report(findings), history)


def test_empty_history_renders_placeholder(tmp_path):
    html = render_dashboard(tmp_path / "missing.jsonl")
    assert "No scans recorded yet" in html
    assert "<!DOCTYPE html>" in html


def test_dashboard_shows_score_and_controls(tmp_path):
    history = tmp_path / "history.jsonl"
    _record(history, {"C06": "pass", "C18": "fail"})
    html = render_dashboard(history)
    assert "Compliance Dashboard" in html
    assert "C06" in html and "C18" in html
    assert "50.0" in html  # one pass, one fail -> 50%


def test_sparkline_appears_once_two_scans_exist(tmp_path):
    history = tmp_path / "history.jsonl"
    _record(history, {"C06": "fail"})  # single scan -> placeholder, no svg
    assert "<svg" not in render_dashboard(history)
    _record(history, {"C06": "pass"})  # now two scans -> trend chart
    html = render_dashboard(history)
    assert "<svg" in html and "<polyline" in html


def test_recent_table_lists_scans(tmp_path):
    history = tmp_path / "history.jsonl"
    _record(history, {"C06": "fail"})
    _record(history, {"C06": "pass"})
    html = render_dashboard(history)
    assert "Recent scans" in html
    assert "Score" in html


def test_make_handler_returns_request_handler_subclass(tmp_path):
    handler = make_handler(tmp_path / "history.jsonl")
    assert issubclass(handler, BaseHTTPRequestHandler)
