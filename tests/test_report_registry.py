# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

import probity.report.registry as reg
from probity.report.registry import BUILTIN_FORMATS, ReportFormat


def test_builtin_formats_present():
    fmts = {fmt.name: fmt for fmt in BUILTIN_FORMATS}
    # Core ships text/json/html only. PDF is Enterprise-only, registered via the
    # entry point — so it must not be a builtin (independent of what's installed).
    assert set(fmts) == {"text", "json", "html"}
    assert "pdf" not in fmts
    assert fmts["json"].binary is False


def test_plugin_format_merges_and_can_override(monkeypatch):
    custom = ReportFormat("csv", lambda r: "a,b\n1,2", binary=False)
    override = ReportFormat("json", lambda r: "OVERRIDDEN", binary=False)
    monkeypatch.setattr(reg, "load_plugins", lambda group: [custom, override])

    fmts = reg.all_formats()

    # A new format appears, and a plugin may override a builtin name.
    assert fmts["csv"] is custom
    assert fmts["json"] is override
