# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from probity.model.finding import Report
from probity.plugins import load_plugins
from probity.report.html_report import to_html
from probity.report.json_report import to_json
from probity.report.pdf_report import to_pdf
from probity.report.text_report import to_text

# Entry-point group the Enterprise package (or any third party) registers extra
# output formats under — e.g. the inspector-grade audit PDF.
REPORT_FORMAT_GROUP = "probity.report_formats"


@dataclass(frozen=True)
class ReportFormat:
    """A named way to render a :class:`Report`.

    ``render`` returns text (``str``) for stdout-friendly formats or ``bytes``
    for binary ones; ``binary`` tells the CLI a file path is mandatory.
    """

    name: str
    render: Callable[[Report], str | bytes]
    binary: bool = False


# Core formats. These ship in the open AGPL Core; PDF stays here for now but is
# an Enterprise candidate (see docs/TIERING.md).
BUILTIN_FORMATS: tuple[ReportFormat, ...] = (
    ReportFormat("text", to_text),
    ReportFormat("json", to_json),
    ReportFormat("html", to_html),
    ReportFormat("pdf", to_pdf, binary=True),
)


def all_formats() -> dict[str, ReportFormat]:
    """Builtin formats plus any registered via entry points (plugins win on name)."""
    formats: dict[str, ReportFormat] = {fmt.name: fmt for fmt in BUILTIN_FORMATS}
    for fmt in cast("list[ReportFormat]", load_plugins(REPORT_FORMAT_GROUP)):
        formats[fmt.name] = fmt
    return formats
