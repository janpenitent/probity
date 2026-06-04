# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C16 — Security awareness training current (NIS2 Art.21(2)(g)). HARD."""

from __future__ import annotations

from datetime import datetime, timedelta

from probity.connectors.mock_training import TRAINING_KIND
from probity.controls.base import Control
from probity.controls.freshness import is_stale, utcnow
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_DAYS = 365


class C16Training(Control):
    """Everyone required to train must have completed it within the last year.

    Fail closed: a required person whose ``completed_at`` is missing or older
    than ``max_age_days`` is overdue. People not flagged ``required`` are out of
    scope.
    """

    id = "C16"
    title = "Security awareness training current"
    severity = Severity.MEDIUM
    nis2_refs = ("Art.21(2)(g)",)

    def __init__(
        self, max_age_days: int = _DEFAULT_MAX_AGE_DAYS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(days=max_age_days)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        people = [f for f in facts.of_kind(TRAINING_KIND) if f.data.get("required", False)]
        if not people:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No required trainees collected; control not applicable.",
            )

        now = utcnow(self._now)
        overdue = [p for p in people if is_stale(p.data.get("completed_at"), now, self._max_age)]
        if not overdue:
            return self._finding(
                Status.PASS,
                f"All {len(people)} required people trained within {self._max_age.days}d.",
            )
        return self._finding(
            Status.FAIL,
            f"{len(overdue)} of {len(people)} required people are overdue for training.",
            overdue,
        )

    def _finding(
        self,
        status: Status,
        summary: str,
        overdue: list[Fact] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if overdue:
            items = tuple(
                {
                    "id": p.data.get("id", p.key),
                    "person": p.data.get("person", ""),
                    "completed_at": p.data.get("completed_at"),
                }
                for p in overdue
            )
            evidence = (Evidence("People overdue for security training", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
