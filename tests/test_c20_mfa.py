# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_idp import ACCOUNT_KIND
from probity.controls.c20_mfa import C20Mfa
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet


def _accounts(*specs: dict) -> FactSet:
    return FactSet([Fact(ACCOUNT_KIND, str(s["id"]), s) for s in specs])


def test_passes_when_all_enabled_accounts_have_mfa():
    # Arrange
    facts = _accounts(
        {"id": "u1", "enabled": True, "mfa_enabled": True, "privileged": True},
        {"id": "u2", "enabled": True, "mfa_enabled": True, "privileged": False},
    )

    # Act
    finding = C20Mfa().evaluate(facts)

    # Assert
    assert finding.status is Status.PASS


def test_disabled_accounts_are_ignored():
    # Arrange: the only account without MFA is disabled
    facts = _accounts(
        {"id": "u1", "enabled": True, "mfa_enabled": True},
        {"id": "u2", "enabled": False, "mfa_enabled": False},
    )

    # Act / Assert
    assert C20Mfa().evaluate(facts).status is Status.PASS


def test_fails_and_lists_accounts_without_mfa():
    # Arrange
    facts = _accounts(
        {"id": "u1", "enabled": True, "mfa_enabled": True, "privileged": True},
        {"id": "u2", "enabled": True, "mfa_enabled": False, "privileged": False},
        {"id": "u3", "enabled": True, "mfa_enabled": False, "privileged": True},
    )

    # Act
    finding = C20Mfa().evaluate(facts)

    # Assert
    assert finding.status is Status.FAIL
    offenders = finding.evidence[0].items
    ids = {o["id"] for o in offenders}
    assert ids == {"u2", "u3"}
    # privileged offenders are called out in the summary
    assert "1 privileged" in finding.summary


def test_not_applicable_without_accounts():
    assert C20Mfa().evaluate(FactSet()).status is Status.NOT_APPLICABLE
