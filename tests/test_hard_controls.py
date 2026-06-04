# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Tests for the HARD monitoring/asset-plane controls (C02–C04, C12–C14, C16)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from probity.connectors.mock_assets import (
    ASSET_KIND,
    PATCH_KIND,
    VULNSCAN_KIND,
    MockAssetsConnector,
)
from probity.connectors.mock_pipeline import PIPELINE_KIND, MockPipelineConnector
from probity.connectors.mock_siem import (
    DETECTION_KIND,
    LOGGING_KIND,
    MockSiemConnector,
)
from probity.connectors.mock_training import TRAINING_KIND, MockTrainingConnector
from probity.controls.c02_asset_inventory import C02AssetInventory
from probity.controls.c03_logging import C03Logging
from probity.controls.c04_detection import C04Detection
from probity.controls.c12_vuln_scanning import C12VulnScanning
from probity.controls.c13_cicd_security import C13CicdSecurity
from probity.controls.c14_patch_management import C14PatchManagement
from probity.controls.c16_training import C16Training
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet

NOW = datetime(2026, 6, 4, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "hard_sample.json"


def _fs(kind: str, *records: dict[str, Any]) -> FactSet:
    return FactSet(Fact(kind=kind, key=str(r["id"]), data=r) for r in records)


# --- C02 asset inventory ---------------------------------------------------


def test_c02_not_applicable_without_assets() -> None:
    assert C02AssetInventory(now=NOW).evaluate(FactSet()).status is Status.NOT_APPLICABLE


def test_c02_passes_when_all_managed_and_fresh() -> None:
    facts = _fs(
        ASSET_KIND,
        {"id": "a", "name": "db", "managed": True, "last_seen": "2026-06-03T00:00:00+00:00"},
    )
    assert C02AssetInventory(now=NOW).evaluate(facts).status is Status.PASS


def test_c02_fails_on_unmanaged_asset() -> None:
    facts = _fs(
        ASSET_KIND,
        {"id": "a", "name": "db", "managed": True, "last_seen": "2026-06-03T00:00:00+00:00"},
        {"id": "b", "name": "rogue", "managed": False, "last_seen": "2026-06-03T00:00:00+00:00"},
    )
    finding = C02AssetInventory(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "unmanaged"


def test_c02_fails_on_stale_last_seen() -> None:
    facts = _fs(
        ASSET_KIND,
        {"id": "a", "name": "db", "managed": True, "last_seen": "2026-05-01T00:00:00+00:00"},
    )
    finding = C02AssetInventory(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "stale"


# --- C03 logging -----------------------------------------------------------


def test_c03_not_applicable_without_critical_sources() -> None:
    facts = _fs(LOGGING_KIND, {"id": "s", "critical": False, "forwarding": True})
    assert C03Logging(now=NOW).evaluate(facts).status is Status.NOT_APPLICABLE


def test_c03_passes_when_forwarding_and_fresh() -> None:
    facts = _fs(
        LOGGING_KIND,
        {
            "id": "s",
            "critical": True,
            "forwarding": True,
            "last_event": "2026-06-04T00:00:00+00:00",
        },
    )
    assert C03Logging(now=NOW).evaluate(facts).status is Status.PASS


def test_c03_fails_when_not_forwarding() -> None:
    facts = _fs(
        LOGGING_KIND,
        {
            "id": "s",
            "critical": True,
            "forwarding": False,
            "last_event": "2026-06-04T00:00:00+00:00",
        },
    )
    finding = C03Logging(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "not forwarding"


def test_c03_fails_on_stale_events() -> None:
    facts = _fs(
        LOGGING_KIND,
        {
            "id": "s",
            "critical": True,
            "forwarding": True,
            "last_event": "2026-06-01T00:00:00+00:00",
        },
    )
    finding = C03Logging(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "stale events"


# --- C04 detection ---------------------------------------------------------


def test_c04_not_applicable_without_rules() -> None:
    assert C04Detection(now=NOW).evaluate(FactSet()).status is Status.NOT_APPLICABLE


def test_c04_passes_when_enabled_and_tested() -> None:
    facts = _fs(
        DETECTION_KIND,
        {"id": "r", "name": "rule", "enabled": True, "last_tested": "2026-05-01T00:00:00+00:00"},
    )
    assert C04Detection(now=NOW).evaluate(facts).status is Status.PASS


def test_c04_fails_when_no_rule_enabled() -> None:
    facts = _fs(
        DETECTION_KIND,
        {"id": "r", "name": "rule", "enabled": False, "last_tested": "2026-05-01T00:00:00+00:00"},
    )
    finding = C04Detection(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert "None of" in finding.summary


def test_c04_fails_on_untested_enabled_rule() -> None:
    facts = _fs(
        DETECTION_KIND,
        {"id": "ok", "name": "a", "enabled": True, "last_tested": "2026-05-01T00:00:00+00:00"},
        {"id": "old", "name": "b", "enabled": True, "last_tested": "2025-01-01T00:00:00+00:00"},
    )
    finding = C04Detection(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "untested"


# --- C12 vulnerability scanning --------------------------------------------


def test_c12_not_applicable_without_critical_targets() -> None:
    facts = _fs(
        VULNSCAN_KIND, {"id": "t", "critical": False, "last_scan": "2026-06-01T00:00:00+00:00"}
    )
    assert C12VulnScanning(now=NOW).evaluate(facts).status is Status.NOT_APPLICABLE


def test_c12_passes_when_recently_scanned() -> None:
    facts = _fs(
        VULNSCAN_KIND, {"id": "t", "critical": True, "last_scan": "2026-05-20T00:00:00+00:00"}
    )
    assert C12VulnScanning(now=NOW).evaluate(facts).status is Status.PASS


def test_c12_fails_on_stale_scan() -> None:
    facts = _fs(
        VULNSCAN_KIND, {"id": "t", "critical": True, "last_scan": "2026-01-01T00:00:00+00:00"}
    )
    finding = C12VulnScanning(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["id"] == "t"


def test_c12_fails_on_missing_scan() -> None:
    facts = _fs(VULNSCAN_KIND, {"id": "t", "critical": True})
    assert C12VulnScanning(now=NOW).evaluate(facts).status is Status.FAIL


# --- C13 CI/CD security ----------------------------------------------------


def test_c13_not_applicable_without_pipelines() -> None:
    assert C13CicdSecurity().evaluate(FactSet()).status is Status.NOT_APPLICABLE


def test_c13_passes_when_both_controls_enabled() -> None:
    facts = _fs(
        PIPELINE_KIND,
        {"id": "p", "repo": "org/a", "sast_enabled": True, "secret_scanning_enabled": True},
    )
    assert C13CicdSecurity().evaluate(facts).status is Status.PASS


def test_c13_fails_listing_missing_controls() -> None:
    facts = _fs(
        PIPELINE_KIND,
        {"id": "p", "repo": "org/a", "sast_enabled": False, "secret_scanning_enabled": False},
    )
    finding = C13CicdSecurity().evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["missing"] == ["sast", "secret_scanning"]


# --- C14 patch management --------------------------------------------------


def test_c14_not_applicable_without_critical_hosts() -> None:
    facts = _fs(PATCH_KIND, {"id": "h", "critical": False})
    assert C14PatchManagement(now=NOW).evaluate(facts).status is Status.NOT_APPLICABLE


def test_c14_passes_when_patched_and_no_pending() -> None:
    facts = _fs(
        PATCH_KIND,
        {
            "id": "h",
            "host": "db",
            "critical": True,
            "last_patched": "2026-05-28T00:00:00+00:00",
            "pending_critical": 0,
        },
    )
    assert C14PatchManagement(now=NOW).evaluate(facts).status is Status.PASS


def test_c14_fails_on_pending_critical() -> None:
    facts = _fs(
        PATCH_KIND,
        {
            "id": "h",
            "host": "db",
            "critical": True,
            "last_patched": "2026-05-28T00:00:00+00:00",
            "pending_critical": 3,
        },
    )
    finding = C14PatchManagement(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert "3 critical patch" in finding.evidence[0].items[0]["reason"]


def test_c14_fails_on_stale_patch() -> None:
    facts = _fs(
        PATCH_KIND,
        {
            "id": "h",
            "host": "db",
            "critical": True,
            "last_patched": "2026-01-01T00:00:00+00:00",
            "pending_critical": 0,
        },
    )
    finding = C14PatchManagement(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["reason"] == "stale patch"


# --- C16 training ----------------------------------------------------------


def test_c16_not_applicable_without_required_people() -> None:
    facts = _fs(TRAINING_KIND, {"id": "u", "required": False})
    assert C16Training(now=NOW).evaluate(facts).status is Status.NOT_APPLICABLE


def test_c16_passes_when_recently_trained() -> None:
    facts = _fs(
        TRAINING_KIND,
        {"id": "u", "person": "A", "required": True, "completed_at": "2026-02-01T00:00:00+00:00"},
    )
    assert C16Training(now=NOW).evaluate(facts).status is Status.PASS


def test_c16_fails_on_overdue_or_missing() -> None:
    facts = _fs(
        TRAINING_KIND,
        {"id": "u1", "person": "A", "required": True, "completed_at": "2024-01-01T00:00:00+00:00"},
        {"id": "u2", "person": "B", "required": True, "completed_at": None},
    )
    finding = C16Training(now=NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert len(finding.evidence[0].items) == 2


# --- connectors ------------------------------------------------------------


def test_connectors_emit_expected_kinds_from_fixture() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assets = list(MockAssetsConnector(payload).collect())
    assert {f.kind for f in assets} == {ASSET_KIND, VULNSCAN_KIND, PATCH_KIND}
    siem = list(MockSiemConnector(payload).collect())
    assert {f.kind for f in siem} == {LOGGING_KIND, DETECTION_KIND}
    assert [f.kind for f in MockPipelineConnector(payload).collect()] == [PIPELINE_KIND]
    assert [f.kind for f in MockTrainingConnector(payload).collect()] == [
        TRAINING_KIND,
        TRAINING_KIND,
    ]


def test_connectors_handle_empty_payload() -> None:
    empty: dict[str, Any] = {}
    assert list(MockAssetsConnector(empty).collect()) == []
    assert list(MockSiemConnector(empty).collect()) == []
    assert list(MockPipelineConnector(empty).collect()) == []
    assert list(MockTrainingConnector(empty).collect()) == []


def test_all_controls_pass_on_healthy_fixture() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    facts = (
        FactSet(MockAssetsConnector(payload).collect())
        .merge(FactSet(MockSiemConnector(payload).collect()))
        .merge(FactSet(MockPipelineConnector(payload).collect()))
        .merge(FactSet(MockTrainingConnector(payload).collect()))
    )
    controls = [
        C02AssetInventory(now=NOW),
        C03Logging(now=NOW),
        C04Detection(now=NOW),
        C12VulnScanning(now=NOW),
        C13CicdSecurity(),
        C14PatchManagement(now=NOW),
        C16Training(now=NOW),
    ]
    assert all(c.evaluate(facts).status is Status.PASS for c in controls)
