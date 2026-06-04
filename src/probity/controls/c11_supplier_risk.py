# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C11 — Critical-supplier security risk assessed (NIS2 Art.21(2)(d)). SOFT.

Supply-chain security under NIS2 requires assessing the security posture of
critical suppliers. This control checks *deterministically* that every supplier
flagged ``critical``/``high`` has a risk assessment on record that is not older
than :data:`MAX_ASSESSMENT_AGE_DAYS`. It cannot judge the *quality* of that
assessment — that is the auditor's job — so a clean result is PARTIAL pending
human validation, never an automatic PASS.

* no critical suppliers on record -> :data:`Status.NOT_APPLICABLE`
* any critical supplier missing or with a stale assessment -> :data:`Status.FAIL`
* all critical suppliers assessed and current -> :data:`Status.PARTIAL`
  with ``requires_human_validation=True``
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from probity.connectors.mock_governance import SUPPLIER_KIND
from probity.controls.soft import SoftControl, parse_date, today
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Finding

MAX_ASSESSMENT_AGE_DAYS = 365

_CRITICAL = {"critical", "high"}


class C11SupplierRisk(SoftControl):
    id = "C11"
    title = "Critical suppliers have a current security risk assessment"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(d)",)

    def __init__(self, now: Any = None) -> None:
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        critical = [s for s in facts.of_kind(SUPPLIER_KIND) if self._is_critical(s)]
        if not critical:
            return self._make(
                Status.NOT_APPLICABLE,
                "No critical suppliers on record.",
                (),
            )

        cutoff = today(self._now) - timedelta(days=MAX_ASSESSMENT_AGE_DAYS)
        overdue: list[dict[str, Any]] = []
        ok: list[dict[str, Any]] = []
        for supplier in critical:
            assessed = parse_date(supplier.data.get("risk_assessed_at"))
            item = self._item(supplier)
            if assessed is None or assessed < cutoff:
                overdue.append(item)
            else:
                ok.append(item)

        if overdue:
            return self._fail(
                f"{len(overdue)} of {len(critical)} critical supplier(s) lack a current "
                "risk assessment.",
                "Critical suppliers without a current assessment",
                tuple(overdue),
            )
        return self._pending(
            f"All {len(critical)} critical supplier(s) have a current risk assessment; "
            "adequacy requires human validation.",
            "Critical suppliers pending human validation",
            tuple(ok),
        )

    def _is_critical(self, supplier: Fact) -> bool:
        return str(supplier.data.get("criticality", "")).lower() in _CRITICAL

    def _item(self, supplier: Fact) -> dict[str, Any]:
        return {
            "id": supplier.data.get("id", supplier.key),
            "name": supplier.data.get("name", ""),
            "criticality": supplier.data.get("criticality"),
            "risk_assessed_at": supplier.data.get("risk_assessed_at"),
        }
