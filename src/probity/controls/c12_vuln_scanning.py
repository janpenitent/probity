# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C12 — Vulnerability scanning coverage current (NIS2 Art.21(2)(e)). HARD."""

from __future__ import annotations

from datetime import datetime, timedelta

from probity.connectors.mock_assets import VULNSCAN_KIND
from probity.controls.base import Control
from probity.controls.freshness import is_stale, utcnow
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_DAYS = 30


class C12VulnScanning(Control):
    """Every critical asset must have a recent vulnerability scan.

    Fail closed: a critical scan target whose ``last_scan`` is missing or older
    than ``max_age_days`` is uncovered. Non-critical targets are out of scope.
    """

    id = "C12"
    title = "Vulnerability scanning coverage current"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(e)",)

    def __init__(
        self, max_age_days: int = _DEFAULT_MAX_AGE_DAYS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(days=max_age_days)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        targets = [f for f in facts.of_kind(VULNSCAN_KIND) if f.data.get("critical", False)]
        if not targets:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No critical scan targets collected; control not applicable.",
            )

        now = utcnow(self._now)
        stale = [t for t in targets if is_stale(t.data.get("last_scan"), now, self._max_age)]
        if not stale:
            return self._finding(
                Status.PASS,
                f"All {len(targets)} critical assets scanned within {self._max_age.days}d.",
            )
        return self._finding(
            Status.FAIL,
            f"{len(stale)} of {len(targets)} critical assets have a stale or missing scan.",
            stale,
        )

    def _finding(
        self,
        status: Status,
        summary: str,
        stale: list[Fact] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if stale:
            items = tuple(
                {
                    "id": t.data.get("id", t.key),
                    "asset": t.data.get("asset", ""),
                    "scanner": t.data.get("scanner", ""),
                    "last_scan": t.data.get("last_scan"),
                }
                for t in stale
            )
            evidence = (Evidence("Critical assets with a stale or missing scan", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
