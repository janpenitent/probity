# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C13 — CI/CD pipeline security controls enabled (NIS2 Art.21(2)(e)). HARD."""

from __future__ import annotations

from probity.connectors.mock_pipeline import PIPELINE_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding


class C13CicdSecurity(Control):
    """Every pipeline must run SAST and secret scanning.

    Fail closed: a pipeline missing either control is a gap. A missing flag is
    treated as disabled.
    """

    id = "C13"
    title = "CI/CD pipeline security controls enabled"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(e)",)

    def evaluate(self, facts: FactSet) -> Finding:
        pipelines = facts.of_kind(PIPELINE_KIND)
        if not pipelines:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No pipelines collected; control not applicable.",
            )

        gaps = [(p, missing) for p in pipelines if (missing := self._missing(p))]
        if not gaps:
            return self._finding(
                Status.PASS,
                f"All {len(pipelines)} pipelines run SAST and secret scanning.",
            )
        return self._finding(
            Status.FAIL,
            f"{len(gaps)} of {len(pipelines)} pipelines miss a required security control.",
            gaps,
        )

    def _missing(self, pipeline: Fact) -> list[str]:
        missing = []
        if not pipeline.data.get("sast_enabled", False):
            missing.append("sast")
        if not pipeline.data.get("secret_scanning_enabled", False):
            missing.append("secret_scanning")
        return missing

    def _finding(
        self,
        status: Status,
        summary: str,
        gaps: list[tuple[Fact, list[str]]] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if gaps:
            items = tuple(
                {
                    "id": p.data.get("id", p.key),
                    "repo": p.data.get("repo", ""),
                    "missing": missing,
                }
                for p, missing in gaps
            )
            evidence = (Evidence("Pipelines missing a required security control", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
