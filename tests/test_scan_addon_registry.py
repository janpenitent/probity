# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from pathlib import Path

import probity.cli as cli
from probity.scan_addons.registry import ScanAddon

FIXTURE = str(Path(__file__).parent / "fixtures" / "idp_sample.json")


def test_addon_flag_and_after_scan_run_through_scan(monkeypatch, capsys):
    seen: list[str] = []

    def _configure(parser):
        parser.add_argument("--echo")

    def _after(report, args):
        if args.echo:
            seen.append(f"addon saw {len(report.findings)} findings: {args.echo}")

    addon = ScanAddon(name="echo", add_arguments=_configure, after_scan=_after)
    monkeypatch.setattr(cli, "discovered_addons", lambda: [addon])

    # The add-on's flag reaches the scan parser and after_scan runs post-emit,
    # without any edit to cli.py.
    rc = cli.main(["scan", "--source", FIXTURE, "--format", "json", "--echo", "hi"])

    assert rc in (0, 1)
    assert seen and seen[0].endswith("hi")


def test_addon_is_inert_without_its_flag(monkeypatch, capsys):
    calls: list[int] = []

    addon = ScanAddon(
        name="counter",
        add_arguments=lambda p: p.add_argument("--count", action="store_true"),
        after_scan=lambda report, args: calls.append(1) if args.count else None,
    )
    monkeypatch.setattr(cli, "discovered_addons", lambda: [addon])

    cli.main(["scan", "--source", FIXTURE, "--format", "json"])

    # after_scan ran but the add-on did nothing because its flag was unset.
    assert calls == []
