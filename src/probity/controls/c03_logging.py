# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C03 — Centralised logging for critical assets (NIS2 Art.21(2)(b)). HARD."""

from __future__ import annotations

from datetime import datetime, timedelta

from probity.connectors.mock_siem import LOGGING_KIND
from probity.controls.base import Control
from probity.controls.freshness import is_stale, utcnow
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_HOURS = 24


class C03Logging(Control):
    """Every critical asset must forward logs and have emitted a recent event.

    Fail closed: a critical log source that is not forwarding, or whose
    ``last_event`` is missing or older than ``max_age_hours``, is a blind spot.
    Non-critical sources are out of scope.
    """

    id = "C03"
    title = "Centralised logging for critical assets"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(b)",)

    def __init__(
        self, max_age_hours: int = _DEFAULT_MAX_AGE_HOURS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(hours=max_age_hours)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        sources = [f for f in facts.of_kind(LOGGING_KIND) if f.data.get("critical", False)]
        if not sources:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No critical log sources collected; control not applicable.",
            )

        now = utcnow(self._now)
        gaps = [(s, r) for s in sources if (r := self._reason(s, now)) is not None]
        if not gaps:
            return self._finding(
                Status.PASS,
                f"All {len(sources)} critical assets forward fresh logs.",
            )
        return self._finding(
            Status.FAIL,
            f"{len(gaps)} of {len(sources)} critical assets have a logging gap.",
            gaps,
        )

    def _reason(self, source: Fact, now: datetime) -> str | None:
        if not source.data.get("forwarding", False):
            return "not forwarding"
        if is_stale(source.data.get("last_event"), now, self._max_age):
            return "stale events"
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
                    "id": s.data.get("id", s.key),
                    "asset": s.data.get("asset", ""),
                    "last_event": s.data.get("last_event"),
                    "reason": reason,
                }
                for s, reason in gaps
            )
            evidence = (Evidence("Critical assets with a logging gap", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
