"""C19 — Access control: orphan / stale-privilege accounts (NIS2 Art.21(2)(i))."""

from __future__ import annotations

from probity.connectors.mock_idp import ACCOUNT_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding


class C19Access(Control):
    """Enabled IdP accounts that no longer map to an active person are orphans.

    An orphan is an account that is still ``enabled`` in the identity provider
    while HR no longer marks the holder as active (``hr_active`` is false).
    Disabled accounts are already off and are not reported.
    """

    id = "C19"
    title = "No orphan or stale-privilege accounts"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(i)",)

    def evaluate(self, facts: FactSet) -> Finding:
        accounts = facts.of_kind(ACCOUNT_KIND)
        if not accounts:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No identity accounts collected; control not applicable.",
            )

        enabled = [f for f in accounts if f.data.get("enabled", True)]
        orphans = [f for f in enabled if not f.data.get("hr_active", True)]
        if not orphans:
            return self._finding(
                Status.PASS,
                f"All {len(enabled)} enabled accounts map to active personnel.",
            )

        privileged = [f for f in orphans if f.data.get("privileged", False)]
        summary = (
            f"{len(orphans)} of {len(enabled)} enabled accounts are orphaned "
            f"({len(privileged)} privileged)."
        )
        return self._finding(Status.FAIL, summary, orphans)

    def _finding(
        self, status: Status, summary: str, orphans: list[Fact] | None = None
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if orphans:
            items = tuple(
                {
                    "id": f.data.get("id", f.key),
                    "display_name": f.data.get("display_name", ""),
                    "privileged": bool(f.data.get("privileged", False)),
                }
                for f in orphans
            )
            evidence = (Evidence("Enabled accounts with no active HR record", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
