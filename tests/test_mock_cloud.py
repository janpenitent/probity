# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_cloud import STORAGE_KIND, MockCloudConnector


def test_emits_one_fact_per_volume():
    src = {"volumes": [
        {"id": "v1", "name": "db", "encrypted": True},
        {"id": "v2", "name": "logs", "encrypted": False},
    ]}
    facts = list(MockCloudConnector(src).collect())
    assert [f.kind for f in facts] == [STORAGE_KIND, STORAGE_KIND]
    assert {f.key for f in facts} == {"v1", "v2"}


def test_empty_source_yields_nothing():
    assert list(MockCloudConnector({}).collect()) == []
