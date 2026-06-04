# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C04 — Detection and alerting rules active and tested (NIS2 Art.21(2)(b)). HARD."""

from __future__ import annotations

from datetime import datetime, timedelta

from probity.connectors.mock_siem import DETECTION_KIND
from probity.controls.base import Control
from probity.controls.freshness import is_stale, utcnow
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_DAYS = 90


class C04Detection(Control):
    """At least one detection rule must be enabled, and each enabled rule tested.

    Fail closed: no enabled rule at all, or an enabled rule whose ``last_tested``
    is missing or older than ``max_age_days``, means detection cannot be relied
    on. Disabled rules are reported as gaps too — a rule that exists but is off
    is dead coverage.
    """

    id = "C04"
    title = "Detection and alerting rules active and tested"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(b)",)

    def __init__(
        self, max_age_days: int = _DEFAULT_MAX_AGE_DAYS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(days=max_age_days)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        rules = facts.of_kind(DETECTION_KIND)
        if not rules:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No detection rules collected; control not applicable.",
            )

        now = utcnow(self._now)
        enabled = [r for r in rules if r.data.get("enabled", False)]
        gaps = [(r, reason) for r in rules if (reason := self._reason(r, now)) is not None]
        if not enabled:
            return self._finding(
                Status.FAIL,
                f"None of {len(rules)} detection rules are enabled.",
                gaps,
            )
        if not gaps:
            return self._finding(
                Status.PASS,
                f"All {len(enabled)} enabled rules were tested within "
                f"{self._max_age.days}d.",
            )
        return self._finding(
            Status.FAIL,
            f"{len(gaps)} of {len(rules)} detection rules are disabled or untested.",
            gaps,
        )

    def _reason(self, rule: Fact, now: datetime) -> str | None:
        if not rule.data.get("enabled", False):
            return "disabled"
        if is_stale(rule.data.get("last_tested"), now, self._max_age):
            return "untested"
        return None

    def _finding(
        self,
        status: Status,
        summary: str,
        gaps: list[tuple[Fact, str]] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if gaps:
            items = tuple(
                {
                    "id": r.data.get("id", r.key),
                    "name": r.data.get("name", ""),
                    "last_tested": r.data.get("last_tested"),
                    "reason": reason,
                }
                for r, reason in gaps
            )
            evidence = (Evidence("Detection rules that are disabled or untested", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
