# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C02 — Asset inventory complete and live (NIS2 Art.21(2)(a)(i)). HARD."""

from __future__ import annotations

from datetime import datetime, timedelta

from probity.connectors.mock_assets import ASSET_KIND
from probity.controls.base import Control
from probity.controls.freshness import is_stale, utcnow
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

_DEFAULT_MAX_AGE_HOURS = 24 * 7


class C02AssetInventory(Control):
    """Every inventoried asset must be managed and recently seen.

    Fail closed: an unmanaged asset, or one whose ``last_seen`` is missing or
    older than ``max_age_hours``, is a gap in the live inventory.
    """

    id = "C02"
    title = "Asset inventory complete and live"
    severity = Severity.MEDIUM
    nis2_refs = ("Art.21(2)(a)",)

    def __init__(
        self, max_age_hours: int = _DEFAULT_MAX_AGE_HOURS, now: datetime | None = None
    ) -> None:
        self._max_age = timedelta(hours=max_age_hours)
        self._now = now

    def evaluate(self, facts: FactSet) -> Finding:
        assets = facts.of_kind(ASSET_KIND)
        if not assets:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No assets collected; control not applicable.",
            )

        now = utcnow(self._now)
        gaps = [(a, r) for a in assets if (r := self._reason(a, now)) is not None]
        if not gaps:
            return self._finding(
                Status.PASS,
                f"All {len(assets)} assets are managed and seen within "
                f"{self._max_age.total_seconds() / 3600:.0f}h.",
            )
        return self._finding(
            Status.FAIL,
            f"{len(gaps)} of {len(assets)} assets are unmanaged or stale.",
            gaps,
        )

    def _reason(self, asset: Fact, now: datetime) -> str | None:
        if not asset.data.get("managed", False):
            return "unmanaged"
        if is_stale(asset.data.get("last_seen"), now, self._max_age):
            return "stale"
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
                    "id": a.data.get("id", a.key),
                    "name": a.data.get("name", ""),
                    "type": a.data.get("type", ""),
                    "last_seen": a.data.get("last_seen"),
                    "reason": reason,
                }
                for a, reason in gaps
            )
            evidence = (Evidence("Assets missing from the live inventory", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
