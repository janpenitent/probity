"""Tests for the real Veeam backup job-report connector."""

from __future__ import annotations

from probity.connectors.mock_backup import BACKUP_KIND
from probity.connectors.veeam_connector import VeeamConnector

# Faithful slice of a Veeam B&R job report export, two jobs.
_VEEAM = {
    "jobs": [
        {
            "id": "job-1",
            "name": "Prod-DB Backup",
            "objectName": "prod-db",
            "isHighPriority": True,
            "lastResult": "Success",
            "lastRun": "2026-06-03T01:00:00+00:00",
            "repository": {"immutabilityEnabled": True, "immutabilityDays": 30},
            "sureBackup": {"lastRun": "2026-05-20T00:00:00+00:00", "lastResult": "Success"},
        },
        {
            "id": "job-2",
            "name": "Fileshare Backup",
            "objectName": "fileshare",
            "isHighPriority": False,
            "lastResult": "Failed",
            "lastRun": "2026-06-02T01:00:00+00:00",
            "repository": {"immutabilityEnabled": False},
            "sureBackup": {"lastRun": "", "lastResult": "None"},
        },
    ]
}


def test_emits_backup_facts_compatible_with_c06_07_08():
    facts = list(VeeamConnector(_VEEAM).collect())
    assert {f.kind for f in facts} == {BACKUP_KIND}
    assert {f.key for f in facts} == {"job-1", "job-2"}


def test_maps_criticality_asset_and_immutability():
    facts = {f.key: f for f in VeeamConnector(_VEEAM).collect()}
    j1 = facts["job-1"].data
    assert j1["critical"] is True
    assert j1["asset"] == "prod-db"
    assert j1["immutable"] is True
    assert facts["job-2"].data["critical"] is False
    assert facts["job-2"].data["immutable"] is False


def test_last_backup_only_when_run_succeeded():
    # a Failed run is not a usable backup -> omit last_backup -> C06 fails closed
    facts = {f.key: f for f in VeeamConnector(_VEEAM).collect()}
    assert facts["job-1"].data["last_backup"] == "2026-06-03T01:00:00+00:00"
    assert facts["job-2"].data.get("last_backup", "") == ""


def test_maps_surebackup_to_restore_test():
    facts = {f.key: f for f in VeeamConnector(_VEEAM).collect()}
    j1 = facts["job-1"].data
    assert j1["last_restore_test"] == "2026-05-20T00:00:00+00:00"
    assert j1["restore_test_passed"] is True
    assert facts["job-2"].data["restore_test_passed"] is False


def test_empty_output_yields_no_facts():
    assert list(VeeamConnector({}).collect()) == []
    assert list(VeeamConnector({"jobs": []}).collect()) == []
