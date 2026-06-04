# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Tests for the real CycloneDX SBOM connector."""

from __future__ import annotations

from probity.connectors.cyclonedx_connector import CycloneDxConnector
from probity.connectors.mock_sbom import SBOM_KIND

# Minimal but faithful slice of a CycloneDX 1.5 JSON BOM (what `cyclonedx-py`,
# `syft -o cyclonedx-json`, or `cdxgen` emit).
_BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "timestamp": "2026-05-20T09:30:00+00:00",
        "component": {"type": "application", "name": "probity", "version": "0.1.0"},
    },
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.32.0",
            "purl": "pkg:pypi/requests@2.32.0",
            "bom-ref": "pkg:pypi/requests@2.32.0",
        },
        {
            "type": "library",
            "name": "jinja2",
            "version": "3.1.4",
            "purl": "pkg:pypi/jinja2@3.1.4",
        },
    ],
}


def test_emits_sbom_facts_compatible_with_c09():
    facts = list(CycloneDxConnector(_BOM).collect())
    assert {f.kind for f in facts} == {SBOM_KIND}
    assert {f.key for f in facts} == {"requests@2.32.0", "jinja2@3.1.4"}


def test_presence_in_bom_means_has_sbom_true():
    facts = list(CycloneDxConnector(_BOM).collect())
    assert all(f.data["has_sbom"] is True for f in facts)


def test_generated_at_taken_from_bom_metadata_timestamp():
    # the BOM's own generation time is the SBOM date for every component
    facts = list(CycloneDxConnector(_BOM).collect())
    assert all(f.data["generated_at"] == "2026-05-20T09:30:00+00:00" for f in facts)


def test_carries_purl_when_present():
    facts = {f.key: f for f in CycloneDxConnector(_BOM).collect()}
    assert facts["requests@2.32.0"].data["purl"] == "pkg:pypi/requests@2.32.0"


def test_missing_timestamp_yields_empty_generated_at_for_fail_closed():
    # no metadata.timestamp -> empty date -> C09 fails the component closed
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"type": "library", "name": "lib", "version": "1.0"}],
    }
    fact = next(iter(CycloneDxConnector(bom).collect()))
    assert fact.data["generated_at"] == ""
    assert fact.data["has_sbom"] is True


def test_component_without_version_still_keyed():
    bom = {"components": [{"type": "library", "name": "headerlib"}]}
    fact = next(iter(CycloneDxConnector(bom).collect()))
    assert fact.key == "headerlib@"


def test_empty_bom_yields_no_facts():
    # an empty or component-less BOM must not raise
    assert list(CycloneDxConnector({}).collect()) == []
    assert list(CycloneDxConnector({"components": []}).collect()) == []
