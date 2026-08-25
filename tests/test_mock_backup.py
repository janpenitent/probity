# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_backup import BACKUP_KIND, MockBackupConnector


def test_emits_one_fact_per_backup_job():
    src = {
        "backups": [
            {
                "id": "b1",
                "asset": "prod-db",
                "critical": True,
                "last_backup": "2026-06-03T00:00:00+00:00",
            },
            {
                "id": "b2",
                "asset": "logs",
                "critical": False,
                "last_backup": "2026-06-01T00:00:00+00:00",
            },
        ]
    }
    facts = list(MockBackupConnector(src).collect())
    assert [f.kind for f in facts] == [BACKUP_KIND, BACKUP_KIND]
    assert {f.key for f in facts} == {"b1", "b2"}
    assert facts[0].data["asset"] == "prod-db"


def test_empty_source_yields_nothing():
    assert list(MockBackupConnector({}).collect()) == []


def test_loads_from_file_path(tmp_path):
    import json

    src = tmp_path / "backups.json"
    src.write_text(json.dumps({"backups": [{"id": "b1", "asset": "db", "critical": True}]}))
    facts = list(MockBackupConnector(str(src)).collect())
    assert [f.key for f in facts] == ["b1"]
