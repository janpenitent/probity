from probity.connectors.mock_backup import BACKUP_KIND
from probity.controls.c08_immutable import C08Immutable
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet


def _jobs(*specs: dict) -> FactSet:
    return FactSet([Fact(BACKUP_KIND, str(s["id"]), s) for s in specs])


def test_passes_when_each_critical_asset_has_immutable_copy():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True, "immutable": True},
        {"id": "b2", "asset": "db", "critical": True, "immutable": False},
    )
    assert C08Immutable().evaluate(facts).status is Status.PASS


def test_fails_when_critical_asset_has_no_immutable_copy():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True, "immutable": False},
        {"id": "b2", "asset": "db", "critical": True, "immutable": False},
    )
    finding = C08Immutable().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["asset"] == "db"
    assert finding.evidence[0].items[0]["immutable_copies"] == 0


def test_missing_immutable_field_treated_as_mutable_fail_closed():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True},
    )
    assert C08Immutable().evaluate(facts).status is Status.FAIL


def test_reports_only_assets_lacking_immutable_copy():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True, "immutable": True},
        {"id": "b2", "asset": "files", "critical": True, "immutable": False},
    )
    finding = C08Immutable().evaluate(facts)
    assert finding.status is Status.FAIL
    assert {o["asset"] for o in finding.evidence[0].items} == {"files"}


def test_non_critical_ignored():
    facts = _jobs(
        {"id": "b1", "asset": "db", "critical": True, "immutable": True},
        {"id": "b2", "asset": "scratch", "critical": False, "immutable": False},
    )
    assert C08Immutable().evaluate(facts).status is Status.PASS


def test_not_applicable_without_critical_jobs():
    assert C08Immutable().evaluate(FactSet()).status is Status.NOT_APPLICABLE
