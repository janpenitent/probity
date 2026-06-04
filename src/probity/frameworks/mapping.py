# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Cross-framework references and per-framework coverage.

Each Probity control already carries its NIS2 article reference. The same
evidence also satisfies clauses in other regulations, so this module records
the DORA and EU AI Act cross-references and derives a coverage view (mapped
controls, their statuses, and a framework-scoped compliance score) directly
from a scan :class:`Report`.

A control is *mapped* to a framework when it has at least one reference there.
NIS2 references are read from the finding itself (single source of truth); DORA
and AI Act references come from :data:`CONTROL_CROSSREFS`. Controls with no
reference for a framework are simply excluded from that framework's coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from probity.model.finding import Finding, Report


class Framework(StrEnum):
    NIS2 = "nis2"
    DORA = "dora"
    AI_ACT = "ai_act"


FRAMEWORK_TITLES: dict[Framework, str] = {
    Framework.NIS2: "NIS2 Directive (EU) 2022/2555 — Art.21(2)",
    Framework.DORA: "DORA Regulation (EU) 2022/2554",
    Framework.AI_ACT: "EU AI Act Regulation (EU) 2024/1689",
}

# DORA / AI Act cross-references per control. NIS2 is intentionally absent here:
# it is taken from each finding's own ``nis2_refs`` to avoid drift. A control
# that does not meaningfully serve a framework is omitted for that framework.
CONTROL_CROSSREFS: dict[str, dict[Framework, tuple[str, ...]]] = {
    # Backup / restoration / business continuity
    "C06": {Framework.DORA: ("Art.12(1)",)},
    "C07": {Framework.DORA: ("Art.11", "Art.12(2)")},
    "C08": {Framework.DORA: ("Art.12(3)",)},
    # Supply chain / vulnerability management
    "C09": {Framework.DORA: ("Art.28",), Framework.AI_ACT: ("Art.15",)},
    "C10": {Framework.DORA: ("Art.8", "Art.10"), Framework.AI_ACT: ("Art.15",)},
    # Cryptography / protection
    "C17": {Framework.DORA: ("Art.9(2)",), Framework.AI_ACT: ("Art.15",)},
    "C18": {Framework.DORA: ("Art.9(2)",), Framework.AI_ACT: ("Art.15",)},
    # Access control / authentication
    "C19": {Framework.DORA: ("Art.9(3)",), Framework.AI_ACT: ("Art.15",)},
    "C20": {Framework.DORA: ("Art.9(4)",), Framework.AI_ACT: ("Art.15",)},
}

_SCORED = {"pass", "fail", "partial"}


@dataclass(frozen=True)
class ControlCoverage:
    """One control's contribution to a framework: its status and references."""

    control_id: str
    title: str
    status: str
    refs: tuple[str, ...]


@dataclass(frozen=True)
class FrameworkCoverage:
    """Coverage of a single framework derived from a scan."""

    framework: Framework
    title: str
    controls: tuple[ControlCoverage, ...]
    score: float

    @property
    def mapped_count(self) -> int:
        return len(self.controls)


def _refs_for(finding: Finding, framework: Framework) -> tuple[str, ...]:
    if framework is Framework.NIS2:
        return finding.nis2_refs
    return CONTROL_CROSSREFS.get(finding.control_id, {}).get(framework, ())


def _score(controls: tuple[ControlCoverage, ...]) -> float:
    scored = [c for c in controls if c.status in _SCORED]
    if not scored:
        return 0.0
    points = sum(
        1.0 if c.status == "pass" else 0.5 if c.status == "partial" else 0.0
        for c in scored
    )
    return round(100 * points / len(scored), 1)


def coverage(report: Report, framework: Framework) -> FrameworkCoverage:
    """Build the coverage view for ``framework`` from a scan ``report``."""
    controls = tuple(
        ControlCoverage(f.control_id, f.title, f.status.value, refs)
        for f in report.findings
        if (refs := _refs_for(f, framework))
    )
    return FrameworkCoverage(
        framework=framework,
        title=FRAMEWORK_TITLES[framework],
        controls=controls,
        score=_score(controls),
    )


def all_coverage(report: Report) -> tuple[FrameworkCoverage, ...]:
    """Coverage for every known framework, in declaration order."""
    return tuple(coverage(report, fw) for fw in Framework)
