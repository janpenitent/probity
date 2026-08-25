# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from datetime import UTC, datetime

from probity.connectors.mock_sbom import SBOM_KIND
from probity.controls.c09_sbom import C09Sbom
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet

NOW = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)


def _comps(*specs: dict) -> FactSet:
    return FactSet([Fact(SBOM_KIND, f"{s['name']}@{s.get('version', '')}", s) for s in specs])


def _control() -> C09Sbom:
    # max_age_days=180, now pinned
    return C09Sbom(max_age_days=180, now=NOW)


def test_passes_when_every_component_has_recent_sbom():
    facts = _comps(
        {
            "name": "app",
            "version": "1.0",
            "has_sbom": True,
            "generated_at": "2026-05-01T00:00:00+00:00",
        },
    )
    assert _control().evaluate(facts).status is Status.PASS


def test_fails_when_sbom_absent():
    facts = _comps({"name": "app", "version": "1.0", "has_sbom": False})
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "no_sbom"


def test_missing_has_sbom_flag_fail_closed():
    facts = _comps({"name": "app", "version": "1.0"})
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "no_sbom"


def test_fails_when_generated_at_missing():
    facts = _comps({"name": "app", "version": "1.0", "has_sbom": True})
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "no_date"


def test_fails_when_sbom_stale():
    facts = _comps(
        {
            "name": "app",
            "version": "1.0",
            "has_sbom": True,
            "generated_at": "2025-01-01T00:00:00+00:00",
        },
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "stale"


def test_fails_when_generated_at_unparseable():
    facts = _comps(
        {"name": "app", "version": "1.0", "has_sbom": True, "generated_at": "nope"},
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "unparseable"


def test_naive_generated_at_unparseable_fail_closed():
    facts = _comps(
        {"name": "app", "version": "1.0", "has_sbom": True, "generated_at": "2026-05-01T00:00:00"},
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "unparseable"


def test_reports_only_failing_components():
    facts = _comps(
        {
            "name": "app",
            "version": "1.0",
            "has_sbom": True,
            "generated_at": "2026-05-01T00:00:00+00:00",
        },
        {"name": "lib", "version": "2.0", "has_sbom": False},
    )
    finding = _control().evaluate(facts)
    assert finding.status is Status.FAIL
    assert {o["id"] for o in finding.evidence[0].items} == {"lib@2.0"}


def test_not_applicable_without_components():
    assert _control().evaluate(FactSet()).status is Status.NOT_APPLICABLE
