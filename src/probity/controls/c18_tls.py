# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C18 — Encryption in transit: healthy TLS on exposed endpoints (NIS2 Art.21(2)(h))."""

from __future__ import annotations

from probity.connectors.mock_tls import TLS_KIND
from probity.controls.base import Control
from probity.model.enums import Severity, Status
from probity.model.fact import Fact, FactSet
from probity.model.finding import Evidence, Finding

# Protocol versions still considered safe for data in transit.
_MODERN_TLS = frozenset({"1.2", "1.3"})


def _reasons(data: dict[str, object]) -> list[str]:
    """Return the list of TLS health problems for one endpoint (empty == healthy)."""
    reasons: list[str] = []
    if str(data.get("tls_version", "")) not in _MODERN_TLS:
        reasons.append("obsolete_tls")
    if not data.get("cert_valid", False):
        reasons.append("invalid_cert")
    expires = data.get("cert_expires_in_days")
    if isinstance(expires, int | float) and expires <= 0:
        reasons.append("expired_cert")
    return reasons


class C18Tls(Control):
    """Every exposed endpoint must negotiate modern TLS with a valid certificate.

    An endpoint fails when it offers an obsolete protocol (anything below
    TLS 1.2, including an unknown version), presents an invalid certificate,
    or serves an already-expired certificate.
    """

    id = "C18"
    title = "Encryption in transit (healthy TLS)"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(h)",)

    def evaluate(self, facts: FactSet) -> Finding:
        endpoints = facts.of_kind(TLS_KIND)
        if not endpoints:
            return self._finding(
                Status.NOT_APPLICABLE,
                "No TLS endpoints collected; control not applicable.",
            )

        flagged = [(f, _reasons(f.data)) for f in endpoints]
        bad = [(f, r) for f, r in flagged if r]
        if not bad:
            return self._finding(
                Status.PASS,
                f"All {len(endpoints)} endpoints negotiate modern TLS with valid certs.",
            )

        summary = f"{len(bad)} of {len(endpoints)} endpoints have unhealthy TLS."
        return self._finding(Status.FAIL, summary, bad)

    def _finding(
        self,
        status: Status,
        summary: str,
        bad: list[tuple[Fact, list[str]]] | None = None,
    ) -> Finding:
        evidence: tuple[Evidence, ...] = ()
        if bad:
            items = tuple(
                {
                    "id": f.data.get("id", f.key),
                    "host": f.data.get("host", ""),
                    "reasons": reasons,
                }
                for f, reasons in bad
            )
            evidence = (Evidence("Endpoints with unhealthy TLS", items),)
        return Finding(
            control_id=self.id,
            title=self.title,
            severity=self.severity,
            status=status,
            summary=summary,
            nis2_refs=self.nis2_refs,
            evidence=evidence,
        )
