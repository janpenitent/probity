# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""C01 — Security policy exists and is current (NIS2 Art.21(2)(a)). SOFT."""

from __future__ import annotations

from probity.controls.soft import DocumentControl
from probity.model.enums import Severity


class C01SecurityPolicy(DocumentControl):
    id = "C01"
    title = "Security policy exists and is current"
    severity = Severity.HIGH
    nis2_refs = ("Art.21(2)(a)",)
    doc_type = "security_policy"
    artifact_label = "security policy"
