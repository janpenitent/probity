# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C14 — Patch management current on critical hosts (NIS2 Art.21(2)(e)). HARD."""

from __future__ import annotations

from datetime import datetime, timedelta

from probity.connectors.mock_assets import PATCH_KIND
from probity.controls.base import Control
from probity.controls.freshness import is_stale, utcnow
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_DAYS = 30


class C14PatchManagement(Control):
    """Every critical host must be recently patched with no critical patch pending.

    Fail closed: a critical host whose ``last_patched`` is missing or older than
    ``max_age_days``, or whose ``pending_critical`` is greater than zero, is a
    gap. Non-critical hosts are out of scope.
    """

    id = "C14"
    title = "Patch management current on critical hosts"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(e)",)

    def __init__(
        self, max_age_days: int = _DEFAULT_MAX_AGE_DAYS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(days=max_age_days)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        hosts = [f for f in facts.of_kind(PATCH_KIND) if f.data.get("critical", False)]
        if not hosts:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No critical hosts collected; control not applicable.",
            )

        now = utcnow(self._now)
        gaps = [(h, reason) for h in hosts if (reason := self._reason(h, now)) is not None]
        if not gaps:
            return self._finding(
                Status.PASS,
                f"All {len(hosts)} critical hosts patched within {self._max_age.days}d.",
            )
        return self._finding(
            Status.FAIL,
            f"{len(gaps)} of {len(hosts)} critical hosts are unpatched or behind.",
            gaps,
        )

    def _reason(self, host: Fact, now: datetime) -> str | None:
        pending = host.data.get("pending_critical", 0)
        if isinstance(pending, int) and pending > 0:
            return f"{pending} critical patch(es) pending"
        if is_stale(host.data.get("last_patched"), now, self._max_age):
            return "stale patch"
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
                    "id": h.data.get("id", h.key),
                    "host": h.data.get("host", ""),
                    "last_patched": h.data.get("last_patched"),
                    "pending_critical": h.data.get("pending_critical", 0),
                    "reason": reason,
                }
                for h, reason in gaps
            )
            evidence = (Evidence("Critical hosts unpatched or behind", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
