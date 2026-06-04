from datetime import UTC, datetime

from probity.connectors.mock_backup import BACKUP_KIND
from probity.controls.c07_restore import C07Restore
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet

NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)


def _jobs(*specs: dict) -> FactSet:
    return FactSet([Fact(BACKUP_KIND, str(s["id"]), s) for s in specs])


def _control() -> C07Restore:
    # max_age_days=90, now pinned for determinism
    return C07Restore(max_age_days=90, now=NOW)


def test_passes_when_recent_successful_restore_test():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True,
         "last_restore_test": "2026-05-01T00:00:00+00:00", "restore_test_passed": True},
    )
    assert _control().evaluate(facts).status is Status.PASS


def test_fails_when_restore_test_missing():
    finding = _control().evaluate(_jobs({"id": "b1", "asset": "db", "critical": True}))
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "missing"


def test_fails_when_restore_test_stale():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True,
         "last_restore_test": "2026-01-01T00:00:00+00:00", "restore_test_passed": True},
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "stale"


def test_fails_when_restore_test_failed():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True,
         "last_restore_test": "2026-05-01T00:00:00+00:00", "restore_test_passed": False},
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "failed"


def test_fails_when_timestamp_unparseable():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True,
         "last_restore_test": "not-a-date", "restore_test_passed": True},
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "unparseable"


def test_naive_timestamp_unparseable_fail_closed():
    # timestamp without tzinfo cannot be compared safely → fail closed
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True,
         "last_restore_test": "2026-05-01T00:00:00", "restore_test_passed": True},
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "unparseable"


def test_non_critical_ignored():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True,
         "last_restore_test": "2026-05-01T00:00:00+00:00", "restore_test_passed": True},
        {"id": "b2", "asset": "scratch", "critical": False},
    )
    assert _control().evaluate(facts).status is Status.PASS


def test_not_applicable_without_critical_jobs():
    assert _control().evaluate(FactSet()).status is Status.NOT_APPLICABLE
