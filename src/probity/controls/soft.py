# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Base class and helpers for SOFT (policy-reasoned) controls.

A SOFT control can verify *deterministically* that a governance artifact exists
and is current, but cannot judge whether its *content* is adequate — that needs
an auditor. The contract here encodes that honestly:

* artifact absent / overdue -> :data:`Status.FAIL` (deterministic non-compliance)
* artifact present and current -> :data:`Status.PARTIAL` with
  ``requires_human_validation=True`` — never an automatic PASS

This is the "explicit requires-human-validation flag" the roadmap gates SOFT
controls behind.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from probity.connectors.mock_governance import DOCUMENT_KIND
from probity.controls.base import Control
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding


class SoftControl(Control):
    """Control whose positive result is never fully machine-verified."""

    def _pending(
        self, summary: str, description: str, items: tuple[dict[str, Any], ...] = ()
    ) -> Finding:
        """Artifact present and current; content awaits human validation."""
        evidence = (Evidence(description, items),) if items else ()
        return self._make(Status.PARTIAL, summary, evidence, requires_human_validation=True)

    def _fail(
        self, summary: str, description: str = "", items: tuple[dict[str, Any], ...] = ()
    ) -> Finding:
        evidence = (Evidence(description, items),) if description else ()
        return self._make(Status.FAIL, summary, evidence)

    def _make(
        self,
        status: Status,
        summary: str,
        evidence: tuple[Evidence, ...],
        *,
        requires_human_validation: bool = False,
    ) -> Finding:
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
            requires_human_validation=requires_human_validation,
        )


class DocumentControl(SoftControl):
    """SOFT control backed by a single ``governance.document`` of one type.

    Subclasses set :attr:`doc_type`. The document must exist and not be past its
    ``review_due`` date; then the finding is PARTIAL pending human validation.
    Absent or overdue documents fail deterministically.
    """

    doc_type: str = ""
    artifact_label: str = "document"

    def __init__(self, now: date | None = None) -> None:
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        doc = self._document(facts)
        if doc is None:
            return self._fail(f"No {self.artifact_label} on record.")
        review_due = parse_date(doc.data.get("review_due"))
        item = {
            "id": doc.data.get("id", doc.key),
            "title": doc.data.get("title", ""),
            "approved_at": doc.data.get("approved_at"),
            "review_due": doc.data.get("review_due"),
        }
        if review_due is not None and review_due < today(self._now):
            due = doc.data.get("review_due")
            return self._fail(
                f"The {self.artifact_label} is past its review date ({due}).",
                f"Overdue {self.artifact_label}",
                (item,),
            )
        return self._pending(
            f"A {self.artifact_label} is on record and current; content requires human validation.",
            f"{self.artifact_label.capitalize()} pending human validation",
            (item,),
        )

    def _document(self, facts: FactSet) -> Fact | None:
        for fact in facts.of_kind(DOCUMENT_KIND):
            if fact.data.get("type") == self.doc_type:
                return fact
        return None


def parse_date(value: Any) -> date | None:
    """Parse an ISO-8601 date or datetime to a ``date``; ``None`` if invalid."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None


def today(now: date | None = None) -> date:
    return now or datetime.now(UTC).date()
