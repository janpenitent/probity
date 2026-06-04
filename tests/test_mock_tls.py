# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.connectors.mock_tls import TLS_KIND, MockTlsConnector


def test_emits_one_fact_per_endpoint():
    src = {"endpoints": [
        {"id": "e1", "host": "portal.example.com", "tls_version": "1.3"},
        {"id": "e2", "host": "legacy.example.com", "tls_version": "1.0"},
    ]}
    facts = list(MockTlsConnector(src).collect())
    assert [f.kind for f in facts] == [TLS_KIND, TLS_KIND]
    assert {f.key for f in facts} == {"e1", "e2"}


def test_empty_source_yields_nothing():
    assert list(MockTlsConnector({}).collect()) == []
