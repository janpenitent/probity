"""Tests for the real testssl.sh JSON connector."""

from __future__ import annotations

from probity.connectors.mock_tls import TLS_KIND
from probity.connectors.testssl_connector import TesttsslConnector

# Faithful slice of `testssl.sh --jsonfile` (flat array) output, two targets.
_TESTSSL = [
    {"id": "TLS1", "ip": "portal.example.com/93.184.216.34", "port": "443",
     "severity": "LOW", "finding": "offered"},
    {"id": "TLS1_1", "ip": "portal.example.com/93.184.216.34", "port": "443",
     "severity": "LOW", "finding": "not offered"},
    {"id": "TLS1_2", "ip": "portal.example.com/93.184.216.34", "port": "443",
     "severity": "OK", "finding": "offered"},
    {"id": "TLS1_3", "ip": "portal.example.com/93.184.216.34", "port": "443",
     "severity": "OK", "finding": "offered"},
    {"id": "cert_chain_of_trust", "ip": "portal.example.com/93.184.216.34", "port": "443",
     "severity": "OK", "finding": "passed."},
    {"id": "cert_expirationStatus", "ip": "portal.example.com/93.184.216.34", "port": "443",
     "severity": "OK", "finding": "89 >= 30 days"},
    # second target: obsolete protocol, broken chain, expired cert
    {"id": "TLS1", "ip": "legacy.example.com/10.0.0.1", "port": "443",
     "severity": "HIGH", "finding": "offered"},
    {"id": "cert_chain_of_trust", "ip": "legacy.example.com/10.0.0.1", "port": "443",
     "severity": "HIGH", "finding": "failed"},
    {"id": "cert_expirationStatus", "ip": "legacy.example.com/10.0.0.1", "port": "443",
     "severity": "CRITICAL", "finding": "expired"},
]


def test_emits_tls_facts_compatible_with_c18():
    facts = list(TesttsslConnector(_TESTSSL).collect())
    assert {f.kind for f in facts} == {TLS_KIND}
    assert {f.key for f in facts} == {"portal.example.com:443", "legacy.example.com:443"}


def test_picks_highest_offered_protocol_as_tls_version():
    facts = {f.key: f for f in TesttsslConnector(_TESTSSL).collect()}
    assert facts["portal.example.com:443"].data["tls_version"] == "1.3"
    assert facts["legacy.example.com:443"].data["tls_version"] == "1.0"


def test_chain_of_trust_drives_cert_valid():
    facts = {f.key: f for f in TesttsslConnector(_TESTSSL).collect()}
    assert facts["portal.example.com:443"].data["cert_valid"] is True
    assert facts["legacy.example.com:443"].data["cert_valid"] is False


def test_extracts_days_and_marks_expired_as_zero():
    facts = {f.key: f for f in TesttsslConnector(_TESTSSL).collect()}
    assert facts["portal.example.com:443"].data["cert_expires_in_days"] == 89
    assert facts["legacy.example.com:443"].data["cert_expires_in_days"] == 0


def test_host_split_from_fqdn_slash_ip():
    facts = list(TesttsslConnector(_TESTSSL).collect())
    assert all("/" not in f.data["host"] for f in facts)


def test_no_offered_protocol_yields_empty_version_fail_closed():
    data = [
        {"id": "TLS1_2", "ip": "down.example.com/1.2.3.4", "port": "443",
         "finding": "not offered"},
        {"id": "cert_chain_of_trust", "ip": "down.example.com/1.2.3.4", "port": "443",
         "finding": "passed."},
    ]
    fact = next(iter(TesttsslConnector(data).collect()))
    assert fact.data["tls_version"] == ""  # -> C18 obsolete_tls


def test_empty_output_yields_no_facts():
    assert list(TesttsslConnector([]).collect()) == []
