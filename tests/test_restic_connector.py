"""Tests for the real restic snapshots connector."""

from __future__ import annotations

from probity.connectors.mock_backup import BACKUP_KIND
from probity.connectors.restic_connector import ResticConnector

# Faithful slice of `restic snapshots --json`: two hosts, several snapshots.
_RESTIC = [
    {"time": "2026-06-01T02:00:00.000000+00:00", "hostname": "db01",
     "paths": ["/var/lib/postgresql"], "tags": ["prod-db", "critical"], "short_id": "a1"},
    {"time": "2026-06-03T02:00:00.000000+00:00", "hostname": "db01",
     "paths": ["/var/lib/postgresql"], "tags": ["prod-db", "critical"], "short_id": "a2"},
    {"time": "2026-05-20T02:00:00.000000+00:00", "hostname": "web01",
     "paths": ["/srv/www"], "tags": ["www"], "short_id": "b1"},
]


def test_emits_one_backup_fact_per_host():
    facts = list(ResticConnector(_RESTIC).collect())
    assert {f.kind for f in facts} == {BACKUP_KIND}
    assert {f.key for f in facts} == {"db01", "web01"}


def test_last_backup_is_most_recent_snapshot():
    facts = {f.key: f for f in ResticConnector(_RESTIC).collect()}
    # db01 has two snapshots; the newer one wins
    assert facts["db01"].data["last_backup"] == "2026-06-03T02:00:00.000000+00:00"


def test_critical_derived_from_tags():
    facts = {f.key: f for f in ResticConnector(_RESTIC).collect()}
    assert facts["db01"].data["critical"] is True
    assert facts["web01"].data["critical"] is False


def test_restore_test_and_immutable_absent_fail_closed():
    # restic snapshots prove neither restore tests nor immutability ->
    # the fields are omitted so C07/C08 fail closed for critical assets
    facts = {f.key: f for f in ResticConnector(_RESTIC).collect()}
    db01 = facts["db01"].data
    assert "last_restore_test" not in db01
    assert db01.get("immutable", False) is False


def test_empty_output_yields_no_facts():
    assert list(ResticConnector([]).collect()) == []
