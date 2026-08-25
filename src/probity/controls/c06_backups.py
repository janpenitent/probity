# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C06 — Backups recent for critical assets (NIS2 Art.21(2)(c))."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from probity.connectors.mock_backup import BACKUP_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_HOURS = 24


class C06Backups(Control):
    """Every critical asset must have a backup younger than ``max_age_hours``.

    Fail closed: a missing or unparseable ``last_backup`` timestamp counts as
    stale. Non-critical jobs are informational and never fail the control.
    """

    id = "C06"
    title = "Backups recent for critical assets"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(c)",)

    def __init__(
        self, max_age_hours: int = _DEFAULT_MAX_AGE_HOURS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(hours=max_age_hours)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        critical = [f for f in facts.of_kind(BACKUP_KIND) if f.data.get("critical", False)]
        if not critical:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No critical backup jobs collected; control not applicable.",
            )

        now = self._now or datetime.now(UTC)
        graded = [(f, *self._staleness(f, now)) for f in critical]
        failing = [(f, reason, age) for f, reason, age in graded if reason is not None]
        if not failing:
            return self._finding(
                Status.PASS,
                f"All {len(critical)} critical assets have a backup within "
                f"{self._max_age.total_seconds() / 3600:.0f}h.",
            )

        summary = f"{len(failing)} of {len(critical)} critical assets lack a recent backup."
        return self._finding(Status.FAIL, summary, failing)

    def _staleness(self, fact: Fact, now: datetime) -> tuple[str | None, float | None]:
        """Return (reason, age_hours). reason is None when the backup is fresh."""
        raw = fact.data.get("last_backup")
        if not raw:
            return "missing", None
        try:
            ts = datetime.fromisoformat(str(raw))
        except ValueError:
            return "unparseable", None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        age = now - ts
        age_hours = round(age.total_seconds() / 3600, 1)
        if age > self._max_age:
            return "stale", age_hours
        return None, age_hours

    def _finding(
        self,
        status: Status,
        summary: str,
        failing: list[tuple[Fact, str, float | None]] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if failing:
            items = tuple(
                {
                    "id": f.data.get("id", f.key),
                    "asset": f.data.get("asset", ""),
                    "last_backup": f.data.get("last_backup"),
                    "age_hours": age,
                    "reason": reason,
                }
                for f, reason, age in failing
            )
            evidence = (Evidence("Critical assets without a recent backup", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
