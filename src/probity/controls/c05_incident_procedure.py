# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C05 — 24h/72h incident notification procedure (NIS2 Art.21(2)(b)). SOFT."""

from __future__ import annotations

from probity.controls.soft import DocumentControl
from probity.model.enums import Severity


class C05IncidentProcedure(DocumentControl):
    id = "C05"
    title = "Incident notification procedure (24h/72h)"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(b)",)
    doc_type = "incident_procedure"
    artifact_label = "incident-notification procedure"
