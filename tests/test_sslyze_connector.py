# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Tests for the real sslyze JSON connector."""

from __future__ import annotations

from probity.connectors.mock_tls import TLS_KIND
from probity.connectors.sslyze_connector import SslyzeConnector


def _scan(hostname, port, supported, *, valid=True, not_after="2099-01-01T00:00:00"):
    """Build one sslyze server_scan_result with the given supported versions."""
    suites = {
        f"{k}_cipher_suites": {"status": "COMPLETED", "result": {"is_tls_version_supported": v}}
        for k, v in supported.items()
    }
    return {
        "server_location": {"hostname": hostname, "port": port},
        "scan_result": {
            **suites,
            "certificate_info": {
                "status": "COMPLETED",
                "result": {
                    "certificate_deployments": [
                        {
                            "leaf_certificate_subject_matches_hostname": valid,
                            "path_validation_results": [
                                {"was_validation_successful": valid}
                            ],
                            "received_certificate_chain": [{"not_valid_after": not_after}],
                        }
                    ]
                },
            },
        },
    }


_SSLYZE = {
    "server_scan_results": [
        _scan("portal.example.com", 443, {"tls_1_2": True, "tls_1_3": True, "tls_1_1": False}),
        _scan(
            "legacy.example.com", 443,
            {"tls_1_0": True, "tls_1_2": False}, valid=False, not_after="2000-01-01T00:00:00",
        ),
    ]
}


def test_emits_tls_facts_compatible_with_c18():
    facts = list(SslyzeConnector(_SSLYZE).collect())
    assert {f.kind for f in facts} == {TLS_KIND}
    assert {f.key for f in facts} == {"portal.example.com:443", "legacy.example.com:443"}


def test_picks_highest_supported_protocol():
    facts = {f.key: f for f in SslyzeConnector(_SSLYZE).collect()}
    assert facts["portal.example.com:443"].data["tls_version"] == "1.3"
    assert facts["legacy.example.com:443"].data["tls_version"] == "1.0"


def test_path_validation_drives_cert_valid():
    facts = {f.key: f for f in SslyzeConnector(_SSLYZE).collect()}
    assert facts["portal.example.com:443"].data["cert_valid"] is True
    assert facts["legacy.example.com:443"].data["cert_valid"] is False


def test_computes_days_from_not_valid_after():
    facts = {f.key: f for f in SslyzeConnector(_SSLYZE).collect()}
    # far-future cert -> large positive; year-2000 cert -> negative (expired)
    assert facts["portal.example.com:443"].data["cert_expires_in_days"] > 0
    assert facts["legacy.example.com:443"].data["cert_expires_in_days"] < 0


def test_hostname_mismatch_fails_cert_valid():
    scan = _scan("a.example.com", 443, {"tls_1_3": True}, valid=False)
    fact = next(iter(SslyzeConnector({"server_scan_results": [scan]}).collect()))
    assert fact.data["cert_valid"] is False


def test_no_supported_protocol_yields_empty_version_fail_closed():
    scan = _scan("down.example.com", 443, {"tls_1_2": False, "tls_1_3": False})
    fact = next(iter(SslyzeConnector({"server_scan_results": [scan]}).collect()))
    assert fact.data["tls_version"] == ""


def test_empty_output_yields_no_facts():
    assert list(SslyzeConnector({}).collect()) == []
    assert list(SslyzeConnector({"server_scan_results": []}).collect()) == []
