# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_sca import DEPENDENCY_KIND
from probity.controls.c10_cves import C10Cves
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet


def _deps(*specs: dict) -> FactSet:
    return FactSet([Fact(DEPENDENCY_KIND, f"{s['name']}@{s.get('version', '')}", s) for s in specs])


def test_passes_when_no_vulnerabilities():
    facts = _deps(
        {"name": "flask", "version": "3.0.0", "vulnerabilities": []},
        {"name": "click", "version": "8.0.0"},
    )
    assert C10Cves().evaluate(facts).status is Status.PASS


def test_fails_on_high_severity_cve():
    facts = _deps(
        {"name": "requests", "version": "2.0.0",
         "vulnerabilities": [{"id": "CVE-2023-1", "severity": "high"}]},
    )
    finding = C10Cves().evaluate(facts)
    assert finding.status is Status.FAIL
    ids = {o["id"] for o in finding.evidence[0].items}
    assert ids == {"requests@2.0.0"}


def test_fails_on_critical_severity_cve():
    facts = _deps(
        {"name": "lib", "version": "1.0",
         "vulnerabilities": [{"id": "C1", "severity": "critical"}]},
    )
    assert C10Cves().evaluate(facts).status is Status.FAIL


def test_partial_when_only_medium_or_low():
    facts = _deps(
        {"name": "lib", "version": "1.0",
         "vulnerabilities": [{"id": "M1", "severity": "medium"}]},
        {"name": "clean", "version": "2.0", "vulnerabilities": []},
    )
    finding = C10Cves().evaluate(facts)
    assert finding.status is Status.PARTIAL
    assert {o["id"] for o in finding.evidence[0].items} == {"lib@1.0"}


def test_unknown_severity_treated_as_high_fail_closed():
    # an unrated CVE must not silently pass
    facts = _deps(
        {"name": "lib", "version": "1.0", "vulnerabilities": [{"id": "X1"}]},
    )
    assert C10Cves().evaluate(facts).status is Status.FAIL


def test_not_applicable_without_dependencies():
    assert C10Cves().evaluate(FactSet()).status is Status.NOT_APPLICABLE
