from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from probanza.model.enums import Severity, Status

_SCORED = (Status.PASS, Status.FAIL, Status.PARTIAL)


@dataclass(frozen=True)
class Evidence:
    description: str
    items: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"description": self.description, "items": [dict(i) for i in self.items]}


@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: Severity
    status: Status
    summary: str
    nis2_refs: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "summary": self.summary,
            "nis2_refs": list(self.nis2_refs),
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def score(self) -> float:
        """Compliance score: PASS=1, PARTIAL=0.5, FAIL=0, over scored controls."""
        scored = [f for f in self.findings if f.status in _SCORED]
        if not scored:
            return 0.0
        points = sum(
            1.0 if f.status is Status.PASS else 0.5 if f.status is Status.PARTIAL else 0.0
            for f in scored
        )
        return round(100 * points / len(scored), 1)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in Status}
        for f in self.findings:
            out[f.status.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "score": self.score,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }
