# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

from collections.abc import Sequence

from probity.connectors.base import Connector
from probity.controls.base import Control
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Finding, Report


class Scan:
    """Wires connectors and controls into a single evaluation run."""

    def __init__(self, connectors: Sequence[Connector], controls: Sequence[Control]) -> None:
        self._connectors = list(connectors)
        self._controls = list(controls)

    def collect_facts(self) -> FactSet:
        facts: list[Fact] = []
        for connector in self._connectors:
            facts.extend(connector.collect())
        return FactSet(facts)

    def run(self) -> Report:
        facts = self.collect_facts()
        findings = [self._safe_evaluate(control, facts) for control in self._controls]
        return Report(tuple(findings))

    @staticmethod
    def _safe_evaluate(control: Control, facts: FactSet) -> Finding:
        try:
            return control.evaluate(facts)
        except Exception as exc:  # noqa: BLE001 - one bad control must not abort the scan
            return Finding(
                control_id=control.id,
                title=control.title,
                severity=control.severity,
                status=Status.ERROR,
                summary=f"Control raised an unexpected error: {exc}",
                nis2_refs=control.nis2_refs,
            )
