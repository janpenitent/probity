"""C07 — Backups restore-tested for critical assets (NIS2 Art.21(2)(c)).

A backup that has never been restore-tested is unproven. Each critical asset
must carry a ``last_restore_test`` within ``max_age_days`` and a
``restore_test_passed`` flag that is true.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from probity.connectors.mock_backup import BACKUP_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_DAYS = 90


class C07Restore(Control):
    """Every critical asset must have a recent, passing restore test.

    Fail closed: a missing, unparseable, naive, stale, or failed restore test
    counts against the control. Non-critical jobs never fail it.
    """

    id = "C07"
    title = "Backups restore-tested for critical assets"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(c)",)

    def __init__(
        self, max_age_days: int = _DEFAULT_MAX_AGE_DAYS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(days=max_age_days)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        critical = [f for f in facts.of_kind(BACKUP_KIND) if f.data.get("critical", False)]
        if not critical:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No critical backup jobs collected; control not applicable.",
            )

        now = self._now or datetime.now(UTC)
        graded = [(f, self._failure(f, now)) for f in critical]
        failing = [(f, reason) for f, reason in graded if reason is not None]
        if not failing:
            return self._finding(
                Status.PASS,
                f"All {len(critical)} critical assets have a passing restore test "
                f"within {self._max_age.days}d.",
            )

        summary = (
            f"{len(failing)} of {len(critical)} critical assets lack a recent "
            "passing restore test."
        )
        return self._finding(Status.FAIL, summary, failing)

    def _failure(self, fact: Fact, now: datetime) -> str | None:
        """Return a failure reason, or None when the restore test is valid."""
        raw = fact.data.get("last_restore_test")
        if not raw:
            return "missing"
        try:
            ts = datetime.fromisoformat(str(raw))
        except ValueError:
            return "unparseable"
        if ts.tzinfo is None:
            # naive timestamp is ambiguous; cannot trust it → fail closed
            return "unparseable"
        if now - ts > self._max_age:
            return "stale"
        if not fact.data.get("restore_test_passed", False):
            return "failed"
        return None

    def _finding(
        self,
        status: Status,
        summary: str,
        failing: list[tuple[Fact, str]] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if failing:
            items = tuple(
                {
                    "id": f.data.get("id", f.key),
                    "asset": f.data.get("asset", ""),
                    "last_restore_test": f.data.get("last_restore_test"),
                    "reason": reason,
                }
                for f, reason in failing
            )
            evidence = (Evidence("Critical assets without a valid restore test", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
