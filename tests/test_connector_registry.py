# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from collections.abc import Iterable

import probity.cli as cli
from probity.connectors.base import Connector
from probity.connectors.registry import ConnectorSource
from probity.model.fact import Fact


class _SentinelConnector(Connector):
    id = "sentinel"
    title = "Sentinel"

    def collect(self) -> Iterable[Fact]:
        return []


def test_discovered_source_flags_reach_the_parser(monkeypatch):
    src = ConnectorSource(
        name="sentinel",
        add_arguments=lambda p: p.add_argument("--sentinel", action="store_true"),
        build=lambda args: [],
    )
    monkeypatch.setattr(cli, "discovered_sources", lambda: [src])

    args = cli.build_parser().parse_args(["scan", "--source", "x.json", "--sentinel"])

    assert args.sentinel is True


def test_discovered_source_connector_is_built(monkeypatch):
    sentinel = _SentinelConnector()
    src = ConnectorSource(
        name="sentinel",
        add_arguments=lambda p: None,
        build=lambda args: [sentinel],
    )
    monkeypatch.setattr(cli, "discovered_sources", lambda: [src])

    args = cli.build_parser().parse_args(["scan", "--source", "x.json"])
    connectors = cli._connectors_from_args(args)

    # External connector lands in the run without any edit to cli.py's builtins.
    assert sentinel in connectors


def test_plugin_report_format_flows_through_cli(monkeypatch, capsys):
    from pathlib import Path

    from probity.report.registry import BUILTIN_FORMATS, ReportFormat

    fixture = str(Path(__file__).parent / "fixtures" / "idp_sample.json")
    oneline = ReportFormat("oneline", lambda r: f"ONELINE score={r.score}")
    merged = {f.name: f for f in BUILTIN_FORMATS} | {"oneline": oneline}
    monkeypatch.setattr(cli, "all_formats", lambda: merged)

    cli.main(["scan", "--source", fixture, "--format", "oneline"])

    assert "ONELINE score=" in capsys.readouterr().out
