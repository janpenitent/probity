"""C17 — Encryption of data at rest (NIS2 Art.21(2)(h))."""

from __future__ import annotations

from probity.connectors.mock_cloud import STORAGE_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding


class C17Encryption(Control):
    """Every storage volume must be encrypted at rest.

    A volume is compliant only when ``encrypted`` is explicitly true; an
    unknown encryption state is treated as unencrypted (fail closed).
    Unencrypted volumes that hold PII are surfaced as the worst case.
    """

    id = "C17"
    title = "Data encrypted at rest"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(h)",)

    def evaluate(self, facts: FactSet) -> Finding:
        volumes = facts.of_kind(STORAGE_KIND)
        if not volumes:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No storage volumes collected; control not applicable.",
            )

        unencrypted = [f for f in volumes if not f.data.get("encrypted", False)]
        if not unencrypted:
            return self._finding(
                Status.PASS,
                f"All {len(volumes)} storage volumes are encrypted at rest.",
            )

        with_pii = [f for f in unencrypted if f.data.get("contains_pii", False)]
        summary = (
            f"{len(unencrypted)} of {len(volumes)} volumes are unencrypted "
            f"({len(with_pii)} with PII)."
        )
        return self._finding(Status.FAIL, summary, unencrypted)

    def _finding(
        self, status: Status, summary: str, volumes: list[Fact] | None = None
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if volumes:
            items = tuple(
                {
                    "id": f.data.get("id", f.key),
                    "name": f.data.get("name", ""),
                    "contains_pii": bool(f.data.get("contains_pii", False)),
                }
                for f in volumes
            )
            evidence = (Evidence("Unencrypted storage volumes", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
