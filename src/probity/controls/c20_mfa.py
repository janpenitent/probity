# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

from probity.connectors.mock_idp import ACCOUNT_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding


class C20Mfa(Control):
    """NIS2 Art.21(2)(j): multi-factor authentication.

    FAIL if any enabled account lacks MFA. Privileged accounts without MFA are
    the highest risk and are counted explicitly in the summary.
    """

    id = "C20"
    title = "Multi-factor authentication enforced"
    severity = Severity.CRITICAL
    nis2_refs = ("Art.21(2)(j)",)

    def evaluate(self, facts: FactSet) -> Finding:
        accounts = facts.of_kind(ACCOUNT_KIND)
        if not accounts:
            return self._finding(
                Status.NOT_APPLICABLE, "No identity accounts found to evaluate."
            )

        enabled = [f for f in accounts if f.data.get("enabled", True)]
        without_mfa = [f for f in enabled if not f.data.get("mfa_enabled", False)]
        if not without_mfa:
            return self._finding(
                Status.PASS,
                f"All {len(enabled)} enabled accounts have MFA enabled.",
            )

        privileged = [f for f in without_mfa if f.data.get("privileged", False)]
        summary = (
            f"{len(without_mfa)} of {len(enabled)} enabled accounts lack MFA "
            f"({len(privileged)} privileged)."
        )
        return self._finding(
            Status.FAIL,
            summary,
            evidence=(Evidence("Enabled accounts without MFA", self._items(without_mfa)),),
        )

    @staticmethod
    def _items(facts: list[Fact]) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "id": f.data.get("id", f.key),
                "display_name": f.data.get("display_name", ""),
                "privileged": bool(f.data.get("privileged", False)),
            }
            for f in facts
        )

    def _finding(
        self,
        status: Status,
        summary: str,
        evidence: tuple[Evidence, ...] = (),
    ) -> Finding:
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
