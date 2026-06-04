# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from datetime import UTC, datetime

from probity.connectors.mock_backup import BACKUP_KIND
from probity.controls.c06_backups import C06Backups
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet

NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)


def _jobs(*specs: dict) -> FactSet:
    return FactSet([Fact(BACKUP_KIND, str(s["id"]), s) for s in specs])


def _control() -> C06Backups:
    # max_age_hours=24, now pinned for determinism
    return C06Backups(max_age_hours=24, now=NOW)


def test_passes_when_all_critical_backups_recent():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True, "last_backup": "2026-06-04T06:00:00+00:00"},
        {"id": "b2", "asset": "app", "critical": True, "last_backup": "2026-06-03T18:00:00+00:00"},
    )
    assert _control().evaluate(facts).status is Status.PASS


def test_fails_and_lists_stale_critical_backups():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True, "last_backup": "2026-06-04T06:00:00+00:00"},
        {"id": "b2", "asset": "app", "critical": True, "last_backup": "2026-06-01T00:00:00+00:00"},
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    ids = {o["id"] for o in finding.evidence[0].items}
    assert ids == {"b2"}


def test_missing_timestamp_fails_closed():
    finding = _control().evaluate(_jobs({"id": "b1", "asset": "db", "critical": True}))
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "missing"


def test_unparseable_timestamp_fails_closed():
    facts = _jobs({"id": "b1", "asset": "db", "critical": True, "last_backup": "never"})
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "unparseable"


def test_non_critical_stale_backup_is_ignored():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True,
         "last_backup": "2026-06-04T06:00:00+00:00"},
        {"id": "b2", "asset": "scratch", "critical": False,
         "last_backup": "2025-01-01T00:00:00+00:00"},
    )
    assert _control().evaluate(facts).status is Status.PASS


def test_not_applicable_without_critical_jobs():
    facts = _jobs({"id": "b2", "asset": "scratch", "critical": False, "last_backup": "x"})
    assert _control().evaluate(facts).status is Status.NOT_APPLICABLE


def test_not_applicable_without_any_jobs():
    assert _control().evaluate(FactSet()).status is Status.NOT_APPLICABLE


def test_naive_timestamp_assumed_utc():
    # a timestamp without offset must be treated as UTC, not rejected
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True, "last_backup": "2026-06-04T06:00:00"}
    )
    assert _control().evaluate(facts).status is Status.PASS
