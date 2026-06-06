# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

from probity.model.finding import Report


def to_text(report: Report) -> str:
    """Render a human-readable terminal report (the default ``scan`` output)."""
    lines = [f"Probity scan — score {report.score}%  {report.counts()}"]
    for finding in report.findings:
        human = "  ⚑ requires human validation" if finding.requires_human_validation else ""
        lines.append(
            f"[{finding.status.value.upper():>14}] {finding.control_id} "
            f"{finding.title} — {finding.summary}{human}"
        )
        for ev in finding.evidence:
            lines.append(f"    - {ev.description} ({len(ev.items)} items)")
    return "\n".join(lines)
