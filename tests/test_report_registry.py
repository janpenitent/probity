# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

import probity.report.registry as reg
from probity.report.registry import ReportFormat, all_formats


def test_builtin_formats_present():
    fmts = all_formats()
    assert {"text", "json", "html", "pdf"} <= set(fmts)
    # PDF is binary (always needs a file); text formats render to str.
    assert fmts["pdf"].binary is True
    assert fmts["json"].binary is False


def test_plugin_format_merges_and_can_override(monkeypatch):
    custom = ReportFormat("csv", lambda r: "a,b\n1,2", binary=False)
    override = ReportFormat("json", lambda r: "OVERRIDDEN", binary=False)
    monkeypatch.setattr(reg, "load_plugins", lambda group: [custom, override])

    fmts = reg.all_formats()

    # A new format appears, and a plugin may override a builtin name.
    assert fmts["csv"] is custom
    assert fmts["json"] is override
