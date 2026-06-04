# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C10 — Known CVEs in dependencies (NIS2 Art.21(2)(d), supply chain)."""

from __future__ import annotations

from probity.connectors.mock_sca import DEPENDENCY_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

# Anything not explicitly medium/low is escalated to "severe" (fail closed):
# an unrated CVE must never silently pass.
_MODERATE = {"medium", "low"}


class C10Cves(Control):
    """Installed dependencies must carry no known unpatched CVEs.

    A high/critical (or unrated) vulnerability fails the control; a dependency
    affected only by medium/low issues yields PARTIAL. Clean trees pass.
    """

    id = "C10"
    title = "No known CVEs in dependencies"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(d)",)

    def evaluate(self, facts: FactSet) -> Finding:
        deps = facts.of_kind(DEPENDENCY_KIND)
        if not deps:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No dependencies collected; control not applicable.",
            )

        graded = [(f, self._worst(f)) for f in deps]
        affected = [(f, sev) for f, sev in graded if sev is not None]
        if not affected:
            return self._finding(Status.PASS, f"None of {len(deps)} dependencies has a known CVE.")

        severe = [f for f, sev in affected if sev == "severe"]
        if severe:
            summary = (
                f"{len(affected)} of {len(deps)} dependencies have known CVEs "
                f"({len(severe)} high/critical)."
            )
            return self._finding(Status.FAIL, summary, affected)

        summary = (
            f"{len(affected)} of {len(deps)} dependencies have only medium/low CVEs."
        )
        return self._finding(Status.PARTIAL, summary, affected)

    @staticmethod
    def _worst(fact: Fact) -> str | None:
        """Return 'severe', 'moderate', or None when the dependency is clean."""
        vulns = fact.data.get("vulnerabilities") or []
        if not vulns:
            return None
        for vuln in vulns:
            if str(vuln.get("severity", "")).lower() not in _MODERATE:
                return "severe"
        return "moderate"

    def _finding(
        self,
        status: Status,
        summary: str,
        affected: list[tuple[Fact, str]] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if affected:
            items = tuple(
                {
                    "id": f.key,
                    "name": f.data.get("name", ""),
                    "version": f.data.get("version", ""),
                    "level": sev,
                    "cves": [str(v.get("id", "")) for v in (f.data.get("vulnerabilities") or [])],
                }
                for f, sev in affected
            )
            evidence = (Evidence("Dependencies with known CVEs", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
