# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from pathlib import Path

import probity.cli as cli
from probity.commands.registry import Command

FIXTURE = str(Path(__file__).parent / "fixtures" / "idp_sample.json")


def test_core_ships_only_the_scan_command():
    # The builtin tuple is the Core contract: exactly one command, ``scan``.
    # discovered_commands() may add more in a dev venv with the overlay installed,
    # so the invariant is asserted against BUILTIN_COMMANDS, not _all_commands().
    assert tuple(c.name for c in cli.BUILTIN_COMMANDS) == ("scan",)


def test_discovered_command_joins_the_parser(monkeypatch):
    calls: list[str] = []

    def _configure(parser):
        parser.add_argument("--note")

    def _run(args):
        calls.append(args.note)
        return 0

    plugin = Command(name="ping", help="external", configure=_configure, run=_run)
    monkeypatch.setattr(cli, "discovered_commands", lambda: [plugin])

    # The external command is dispatched without any edit to cli.py's builtins.
    rc = cli.main(["ping", "--note", "hello"])

    assert rc == 0
    assert calls == ["hello"]


def test_scan_still_dispatches_through_the_registry(capsys):
    # The builtin scan command must keep working under registry dispatch.
    rc = cli.main(["scan", "--source", FIXTURE, "--format", "json"])
    assert rc in (0, 1)  # fixture fails C20 -> 1, but parsing/dispatch is the point
    assert "findings" in capsys.readouterr().out
