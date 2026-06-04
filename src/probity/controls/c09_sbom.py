"""C09 — SBOM present and current for shipped components (NIS2 Art.21(2)(d)).

Supply-chain risk cannot be assessed for software whose composition is
unknown. Every shipped component must have an SBOM that was (re)generated
recently — a stale SBOM no longer reflects the deployed artifact.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from probity.connectors.mock_sbom import SBOM_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_DAYS = 180


class C09Sbom(Control):
    """Every shipped component must carry a current SBOM.

    Fail closed: a component without ``has_sbom`` true, without a
    ``generated_at`` timestamp, or whose timestamp is unparseable, naive, or
    older than ``max_age_days`` fails the control.
    """

    id = "C09"
    title = "SBOM present and current for shipped components"
    severity = Severity.MEDIUM
    nis2_refs = ("Art.21(2)(d)",)

    def __init__(
        self, max_age_days: int = _DEFAULT_MAX_AGE_DAYS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(days=max_age_days)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        components = facts.of_kind(SBOM_KIND)
        if not components:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No components collected; control not applicable.",
            )

        now = self._now or datetime.now(UTC)
        graded = [(f, self._failure(f, now)) for f in components]
        failing = [(f, reason) for f, reason in graded if reason is not None]
        if not failing:
            return self._finding(
                Status.PASS,
                f"All {len(components)} components have an SBOM generated within "
                f"{self._max_age.days}d.",
            )

        summary = (
            f"{len(failing)} of {len(components)} components lack a current SBOM."
        )
        return self._finding(Status.FAIL, summary, failing)

    def _failure(self, fact: Fact, now: datetime) -> str | None:
        """Return a failure reason, or None when the SBOM is present and current."""
        if not fact.data.get("has_sbom", False):
            return "no_sbom"
        raw = fact.data.get("generated_at")
        if not raw:
            return "no_date"
        try:
            ts = datetime.fromisoformat(str(raw))
        except ValueError:
            return "unparseable"
        if ts.tzinfo is None:
            # naive timestamp is ambiguous; cannot trust it → fail closed
            return "unparseable"
        if now - ts > self._max_age:
            return "stale"
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
                    "id": f.key,
                    "name": f.data.get("name", ""),
                    "reason": reason,
                }
                for f, reason in failing
            )
            evidence = (Evidence("Components without a current SBOM", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
