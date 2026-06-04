# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_sca import DEPENDENCY_KIND, MockScaConnector


def test_emits_one_fact_per_dependency():
    src = {"dependencies": [
        {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI",
         "vulnerabilities": [{"id": "CVE-2023-1", "severity": "high",
                              "fixed_version": "2.31.0"}]},
        {"name": "flask", "version": "3.0.0", "ecosystem": "PyPI",
         "vulnerabilities": []},
    ]}
    facts = list(MockScaConnector(src).collect())
    assert [f.kind for f in facts] == [DEPENDENCY_KIND, DEPENDENCY_KIND]
    assert {f.key for f in facts} == {"requests@2.0.0", "flask@3.0.0"}
    assert facts[0].data["vulnerabilities"][0]["id"] == "CVE-2023-1"


def test_empty_source_yields_nothing():
    assert list(MockScaConnector({}).collect()) == []


def test_loads_from_file_path(tmp_path):
    import json

    src = tmp_path / "sca.json"
    src.write_text(json.dumps({"dependencies": [{"name": "flask", "version": "3.0.0"}]}))
    facts = list(MockScaConnector(str(src)).collect())
    assert [f.key for f in facts] == ["flask@3.0.0"]
