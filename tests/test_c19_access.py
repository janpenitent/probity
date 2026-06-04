# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_idp import ACCOUNT_KIND
from probity.controls.c19_access import C19Access
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet


def _accounts(*specs: dict) -> FactSet:
    return FactSet([Fact(ACCOUNT_KIND, str(s["id"]), s) for s in specs])


def test_passes_when_every_enabled_account_is_hr_active():
    facts = _accounts(
        {"id": "u1", "enabled": True, "hr_active": True, "privileged": True},
        {"id": "u2", "enabled": True, "hr_active": True, "privileged": False},
    )
    assert C19Access().evaluate(facts).status is Status.PASS


def test_disabled_orphans_are_ignored():
    # ex-employee but the account is already disabled -> not a finding
    facts = _accounts({"id": "u1", "enabled": False, "hr_active": False})
    assert C19Access().evaluate(facts).status is Status.PASS


def test_fails_and_lists_orphan_accounts():
    facts = _accounts(
        {"id": "u1", "enabled": True, "hr_active": True, "privileged": False},
        {"id": "u2", "enabled": True, "hr_active": False, "privileged": False},
        {"id": "u3", "enabled": True, "hr_active": False, "privileged": True},
    )
    finding = C19Access().evaluate(facts)
    assert finding.status is Status.FAIL
    ids = {o["id"] for o in finding.evidence[0].items}
    assert ids == {"u2", "u3"}
    # a privileged orphan is the worst case and is surfaced in the summary
    assert "1 privileged" in finding.summary


def test_not_applicable_without_accounts():
    assert C19Access().evaluate(FactSet()).status is Status.NOT_APPLICABLE
