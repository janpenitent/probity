"""Tests for regression alerting."""

from __future__ import annotations

import json

from probity.report.history import Snapshot
from probity.service.alerts import (
    Alert,
    build_alert,
    detect_transitions,
    dispatch,
    emit_file,
)


def _snap(score: float, statuses: dict[str, str], when: str = "2026-06-04T12:00:00+00:00"):
    return Snapshot(generated_at=when, score=score, statuses=statuses)


def test_detect_transitions_flags_regression_and_recovery():
    prev = _snap(100.0, {"C06": "pass", "C18": "pass", "C20": "fail"})
    cur = _snap(50.0, {"C06": "fail", "C18": "pass", "C20": "pass"})
    transitions = {t.control_id: t.kind for t in detect_transitions(prev, cur)}
    assert transitions == {"C06": "regression", "C20": "recovery"}


def test_same_rank_label_change_is_not_material():
    # pass <-> not_applicable share rank 0 -> no transition
    prev = _snap(100.0, {"C09": "pass"})
    cur = _snap(100.0, {"C09": "not_applicable"})
    assert detect_transitions(prev, cur) == ()


def test_unknown_status_ranks_worst_so_it_pages():
    prev = _snap(100.0, {"C18": "pass"})
    cur = _snap(0.0, {"C18": "weird-new-status"})
    transitions = detect_transitions(prev, cur)
    assert len(transitions) == 1
    assert transitions[0].kind == "regression"


def test_build_alert_first_scan_has_no_transitions():
    alert = build_alert(None, _snap(80.0, {"C06": "pass"}))
    assert alert.previous_score is None
    assert alert.regressions == ()
    assert alert.is_actionable is False


def test_build_alert_is_actionable_only_on_regression():
    prev = _snap(100.0, {"C06": "pass"})
    regressed = build_alert(prev, _snap(0.0, {"C06": "fail"}))
    recovered = build_alert(_snap(0.0, {"C06": "fail"}), _snap(100.0, {"C06": "pass"}))
    assert regressed.is_actionable is True
    assert recovered.is_actionable is False  # recovery alone does not page


def test_emit_file_appends_jsonl(tmp_path):
    alert = build_alert(_snap(100.0, {"C06": "pass"}), _snap(0.0, {"C06": "fail"}))
    log = tmp_path / "alerts.jsonl"
    emit_file(alert, log)
    emit_file(alert, log)
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    record = json.loads(lines[0])
    assert record["regressions"][0]["control_id"] == "C06"
    assert record["previous_score"] == 100.0


def test_dispatch_noop_when_not_actionable(tmp_path):
    log = tmp_path / "alerts.jsonl"
    alert = Alert("2026-06-04T12:00:00+00:00", 80.0, 80.0, regressions=(), recoveries=())
    dispatch(alert, to_stdout=False, file=log)
    assert not log.exists()


def test_dispatch_writes_when_actionable(tmp_path):
    log = tmp_path / "alerts.jsonl"
    alert = build_alert(_snap(100.0, {"C06": "pass"}), _snap(0.0, {"C06": "fail"}))
    dispatch(alert, to_stdout=False, file=log)
    assert log.exists()
    assert "C06" in log.read_text(encoding="utf-8")
