# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_sbom import SBOM_KIND, MockSbomConnector


def test_emits_one_fact_per_component():
    src = {"components": [
        {"name": "app", "version": "1.0", "has_sbom": True,
         "generated_at": "2026-05-01T00:00:00+00:00"},
        {"name": "lib", "version": "2.0", "has_sbom": False},
    ]}
    facts = list(MockSbomConnector(src).collect())
    assert [f.kind for f in facts] == [SBOM_KIND, SBOM_KIND]
    assert {f.key for f in facts} == {"app@1.0", "lib@2.0"}
    assert facts[0].data["has_sbom"] is True


def test_empty_source_yields_nothing():
    assert list(MockSbomConnector({}).collect()) == []


def test_loads_from_file_path(tmp_path):
    import json

    src = tmp_path / "sbom.json"
    src.write_text(json.dumps({"components": [{"name": "app", "version": "1.0"}]}))
    facts = list(MockSbomConnector(str(src)).collect())
    assert [f.key for f in facts] == ["app@1.0"]
