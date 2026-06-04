# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C08 — Immutable/offline backup copy for critical assets (NIS2 Art.21(2)(c)).

A backup that can be altered or deleted by the same credentials that run the
workload offers no protection against ransomware. Each critical asset must
have at least one immutable (WORM/offline/air-gapped) copy.
"""

from __future__ import annotations

from collections import defaultdict

from probity.connectors.mock_backup import BACKUP_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding


class C08Immutable(Control):
    """Every critical asset must have at least one immutable backup copy.

    Fail closed: a job without an explicit ``immutable`` flag counts as
    mutable. Non-critical jobs never fail the control.
    """

    id = "C08"
    title = "Immutable backup copy for critical assets"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(c)",)

    def evaluate(self, facts: FactSet) -> Finding:
        critical = [f for f in facts.of_kind(BACKUP_KIND) if f.data.get("critical", False)]
        if not critical:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No critical backup jobs collected; control not applicable.",
            )

        by_asset: dict[str, list[Fact]] = defaultdict(list)
        for fact in critical:
            by_asset[str(fact.data.get("asset", fact.key))].append(fact)

        failing = [
            (asset, jobs)
            for asset, jobs in by_asset.items()
            if not any(j.data.get("immutable", False) for j in jobs)
        ]
        if not failing:
            return self._finding(
                Status.PASS,
                f"All {len(by_asset)} critical assets have an immutable backup copy.",
            )

        summary = (
            f"{len(failing)} of {len(by_asset)} critical assets lack an immutable "
            "backup copy."
        )
        return self._finding(Status.FAIL, summary, failing)

    def _finding(
        self,
        status: Status,
        summary: str,
        failing: list[tuple[str, list[Fact]]] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if failing:
            items = tuple(
                {
                    "asset": asset,
                    "copies": len(jobs),
                    "immutable_copies": sum(
                        1 for j in jobs if j.data.get("immutable", False)
                    ),
                }
                for asset, jobs in failing
            )
            evidence = (Evidence("Critical assets without an immutable copy", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
