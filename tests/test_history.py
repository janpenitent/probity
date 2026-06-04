from datetime import UTC, datetime

from probity.model.enums import Severity, Status
from probity.model.finding import Finding, Report
from probity.report.history import (
    Snapshot,
    append_snapshot,
    compute_trend,
    control_history,
    load_snapshots,
)


def _report(score_findings: list[tuple[str, Status]], when: datetime) -> Report:
    findings = tuple(
        Finding(
            control_id=cid,
            title=cid,
            severity=Severity.HIGH,
            status=status,
            summary="",
        )
        for cid, status in score_findings
    )
    return Report(findings=findings, generated_at=when)


def _from(rows: list[tuple[str, float]]) -> tuple[Snapshot, ...]:
    return tuple(
        Snapshot(generated_at=ts, score=score, statuses={}) for ts, score in rows
    )


def test_append_then_load_roundtrip(tmp_path):
    store = tmp_path / "history.jsonl"
    report = _report([("C20", Status.PASS)], datetime(2026, 6, 1, tzinfo=UTC))
    append_snapshot(report, store)
    snaps = load_snapshots(store)
    assert len(snaps) == 1
    assert snaps[0].statuses == {"C20": "pass"}
    assert snaps[0].score == 100.0


def test_load_missing_store_is_empty(tmp_path):
    assert load_snapshots(tmp_path / "absent.jsonl") == ()


def test_append_is_append_only(tmp_path):
    store = tmp_path / "history.jsonl"
    append_snapshot(_report([("C20", Status.PASS)], datetime(2026, 6, 1, tzinfo=UTC)), store)
    append_snapshot(_report([("C20", Status.FAIL)], datetime(2026, 6, 2, tzinfo=UTC)), store)
    snaps = load_snapshots(store)
    assert [s.score for s in snaps] == [100.0, 0.0]


def test_trend_first_run_has_no_previous(tmp_path):
    store = tmp_path / "history.jsonl"
    append_snapshot(_report([("C20", Status.PASS)], datetime(2026, 6, 1, tzinfo=UTC)), store)
    trend = compute_trend(load_snapshots(store))
    assert trend.previous is None
    assert trend.delta == 0.0
    assert trend.direction == "first"


def test_trend_improving():
    trend = compute_trend(_from([("2026-06-01", 50.0), ("2026-06-02", 75.0)]))
    assert trend.current == 75.0
    assert trend.previous == 50.0
    assert trend.delta == 25.0
    assert trend.direction == "up"


def test_trend_regressing():
    trend = compute_trend(_from([("2026-06-01", 80.0), ("2026-06-02", 60.0)]))
    assert trend.delta == -20.0
    assert trend.direction == "down"


def test_trend_flat():
    trend = compute_trend(_from([("2026-06-01", 60.0), ("2026-06-02", 60.0)]))
    assert trend.direction == "flat"


def test_trend_empty_history():
    trend = compute_trend(())
    assert trend.current == 0.0
    assert trend.direction == "first"


def test_control_history_tracks_one_control(tmp_path):
    store = tmp_path / "history.jsonl"
    append_snapshot(_report([("C20", Status.FAIL)], datetime(2026, 6, 1, tzinfo=UTC)), store)
    append_snapshot(_report([("C20", Status.PASS)], datetime(2026, 6, 2, tzinfo=UTC)), store)
    hist = control_history(load_snapshots(store), "C20")
    assert [h[1] for h in hist] == ["fail", "pass"]
