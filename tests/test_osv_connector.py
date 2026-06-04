# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Tests for the real osv-scanner JSON connector."""

from __future__ import annotations

from probity.connectors.mock_sca import DEPENDENCY_KIND
from probity.connectors.osv_connector import OsvConnector

# Minimal but faithful slice of `osv-scanner --format json` output.
_OSV_OUTPUT = {
    "results": [
        {
            "source": {"path": "/repo/uv.lock", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-x84v-xcm2-53pg",
                            "aliases": ["CVE-2018-18074"],
                            "database_specific": {"severity": "HIGH"},
                            "affected": [
                                {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}
                            ],
                        }
                    ],
                },
                {
                    "package": {"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-462w-v97r-4m45",
                            "aliases": ["CVE-2019-10906"],
                            "database_specific": {"severity": "MODERATE"},
                            "affected": [{"ranges": [{"events": [{"fixed": "2.10.1"}]}]}],
                        }
                    ],
                },
            ],
        }
    ]
}


def test_emits_dependency_facts_compatible_with_c10():
    facts = list(OsvConnector(_OSV_OUTPUT).collect())
    assert {f.kind for f in facts} == {DEPENDENCY_KIND}
    keys = {f.key for f in facts}
    assert keys == {"requests@2.19.0", "jinja2@2.10"}


def test_prefers_cve_alias_as_vulnerability_id():
    facts = {f.key: f for f in OsvConnector(_OSV_OUTPUT).collect()}
    vulns = facts["requests@2.19.0"].data["vulnerabilities"]
    assert vulns[0]["id"] == "CVE-2018-18074"  # CVE alias preferred over GHSA id


def test_normalizes_moderate_to_medium_for_grading():
    # OSV says MODERATE; C10 grades against {medium, low}, so it must be 'medium'
    facts = {f.key: f for f in OsvConnector(_OSV_OUTPUT).collect()}
    assert facts["jinja2@2.10"].data["vulnerabilities"][0]["severity"] == "medium"
    assert facts["requests@2.19.0"].data["vulnerabilities"][0]["severity"] == "high"


def test_extracts_fixed_version():
    facts = {f.key: f for f in OsvConnector(_OSV_OUTPUT).collect()}
    assert facts["requests@2.19.0"].data["vulnerabilities"][0]["fixed_version"] == "2.20.0"


def test_clean_package_yields_fact_with_no_vulnerabilities():
    payload = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "click", "version": "8.1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [],
                    }
                ]
            }
        ]
    }
    facts = list(OsvConnector(payload).collect())
    assert len(facts) == 1
    assert facts[0].data["vulnerabilities"] == []


def test_empty_output_yields_no_facts():
    # osv-scanner emits {} or {"results": []} for a clean tree; must not raise
    assert list(OsvConnector({}).collect()) == []
    assert list(OsvConnector({"results": []}).collect()) == []


def test_unrated_vulnerability_keeps_empty_severity_for_fail_closed():
    # no database_specific.severity -> empty string -> C10 escalates to 'severe'
    payload = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "pkg", "version": "1.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [{"id": "OSV-1", "aliases": []}],
                    }
                ]
            }
        ]
    }
    fact = next(iter(OsvConnector(payload).collect()))
    assert fact.data["vulnerabilities"][0]["severity"] == ""
    assert fact.data["vulnerabilities"][0]["id"] == "OSV-1"
