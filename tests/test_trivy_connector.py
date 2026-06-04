# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Tests for the real Trivy JSON vulnerability-scanning connector."""

from __future__ import annotations

from datetime import UTC, datetime

from probity.connectors.mock_assets import VULNSCAN_KIND
from probity.connectors.trivy_connector import TrivyConnector
from probity.controls.c12_vuln_scanning import C12VulnScanning
from probity.model.enums import Status
from probity.model.fact import FactSet

NOW = datetime(2026, 6, 4, tzinfo=UTC)

# Minimal but faithful slice of `trivy image --format json` output.
_TRIVY_REPORT = {
    "SchemaVersion": 2,
    "CreatedAt": "2026-05-20T10:00:00+00:00",
    "ArtifactName": "prod-db:latest",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "prod-db:latest (debian 12)",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "Severity": "CRITICAL"}],
        }
    ],
}


def test_emits_vulnscan_target_compatible_with_c12():
    facts = list(TrivyConnector(_TRIVY_REPORT).collect())
    assert {f.kind for f in facts} == {VULNSCAN_KIND}
    assert [f.key for f in facts] == ["prod-db:latest"]
    data = facts[0].data
    assert data["asset"] == "prod-db:latest"
    assert data["scanner"] == "trivy"
    assert data["critical"] is True
    assert data["last_scan"] == "2026-05-20T10:00:00+00:00"


def test_artifact_name_maps_to_last_scan_freshness():
    # CreatedAt within C12's 30d window -> the scanned target passes.
    facts = list(TrivyConnector(_TRIVY_REPORT).collect())
    finding = C12VulnScanning(now=NOW).evaluate(FactSet(facts))
    assert finding.status is Status.PASS


def test_missing_created_at_fails_closed_as_stale():
    # Older Trivy builds omit CreatedAt -> empty last_scan -> stale -> C12 fails.
    report = {k: v for k, v in _TRIVY_REPORT.items() if k != "CreatedAt"}
    facts = list(TrivyConnector(report).collect())
    assert facts[0].data["last_scan"] == ""
    finding = C12VulnScanning(now=NOW).evaluate(FactSet(facts))
    assert finding.status is Status.FAIL


def test_stale_created_at_fails_c12():
    report = {**_TRIVY_REPORT, "CreatedAt": "2026-01-01T00:00:00+00:00"}
    facts = list(TrivyConnector(report).collect())
    finding = C12VulnScanning(now=NOW).evaluate(FactSet(facts))
    assert finding.status is Status.FAIL


def test_array_of_reports_yields_one_target_each():
    second = {**_TRIVY_REPORT, "ArtifactName": "prod-web:latest"}
    facts = list(TrivyConnector([_TRIVY_REPORT, second]).collect())
    assert {f.key for f in facts} == {"prod-db:latest", "prod-web:latest"}


def test_report_without_artifact_name_is_skipped():
    # A blank target would mask the gap rather than surface it -> skip it.
    facts = list(TrivyConnector({"CreatedAt": "2026-05-20T10:00:00+00:00"}).collect())
    assert facts == []


def test_empty_output_yields_no_facts():
    assert list(TrivyConnector({}).collect()) == []
    assert list(TrivyConnector([]).collect()) == []
