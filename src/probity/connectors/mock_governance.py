# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""File-backed governance connector for the SOFT (policy) controls.

SOFT controls reason over governance artifacts whose *existence and currency*
are machine-checkable but whose *adequacy* needs a human auditor. This single
connector feeds them all:

* ``governance.document`` — a policy / procedure record (C01, C05, C15)::

      {"id": "pol-sec", "type": "security_policy", "title": "InfoSec Policy",
       "approved_at": "2025-09-01", "review_due": "2026-09-01"}

* ``governance.supplier`` — a critical-supplier risk record (C11)::

      {"id": "sup-acme", "name": "AcmeCloud", "criticality": "high",
       "risk_assessed_at": "2026-01-15"}

Dates are ISO-8601 (date or datetime). A real deployment would replace this
with an export from a GRC / policy-management tool emitting the same facts.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

DOCUMENT_KIND = "governance.document"
SUPPLIER_KIND = "governance.supplier"


class MockGovernanceConnector(Connector):
    """Emits ``governance.document`` and ``governance.supplier`` facts."""

    id = "mock_governance"
    title = "Mock Governance Records (file-backed)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for doc in payload.get("documents", []):
            yield Fact(kind=DOCUMENT_KIND, key=str(doc["id"]), data=dict(doc))
        for supplier in payload.get("suppliers", []):
            yield Fact(kind=SUPPLIER_KIND, key=str(supplier["id"]), data=dict(supplier))
