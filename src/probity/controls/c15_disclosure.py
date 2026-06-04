# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C15 — Coordinated vulnerability disclosure process (NIS2 Art.21(2)(e)). SOFT."""

from __future__ import annotations

from probity.controls.soft import DocumentControl
from probity.model.enums import Severity


class C15Disclosure(DocumentControl):
    id = "C15"
    title = "Coordinated vulnerability disclosure process"
    severity = Severity.MEDIUM
    nis2_refs = ("Art.21(2)(e)",)
    doc_type = "disclosure_policy"
    artifact_label = "vulnerability-disclosure process"
