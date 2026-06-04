# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_idp import MockIdpConnector
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import FactSet
from probity.model.finding import Finding


class _AlwaysPass(Control):
    id = "T01"
    title = "always pass"
    severity = Severity.LOW

    def evaluate(self, facts: FactSet) -> Finding:
        return Finding(self.id, self.title, self.severity, Status.PASS, "ok")


class _Boom(Control):
    id = "T02"
    title = "explodes"
    severity = Severity.HIGH

    def evaluate(self, facts: FactSet) -> Finding:
        raise RuntimeError("kaboom")


def test_scan_runs_all_controls_over_collected_facts():
    from probity.engine.runner import Scan

    # Arrange
    scan = Scan([MockIdpConnector({"accounts": [{"id": "u1"}]})], [_AlwaysPass()])

    # Act
    report = scan.run()

    # Assert
    assert len(report.findings) == 1
    assert report.findings[0].status is Status.PASS
    assert report.score == 100.0


def test_scan_isolates_control_errors_as_error_finding():
    from probity.engine.runner import Scan

    # Arrange
    scan = Scan([MockIdpConnector({})], [_AlwaysPass(), _Boom()])

    # Act
    report = scan.run()

    # Assert: the bad control does not abort the run
    statuses = {f.control_id: f.status for f in report.findings}
    assert statuses["T01"] is Status.PASS
    assert statuses["T02"] is Status.ERROR
