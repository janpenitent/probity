# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from probity.plugins import load_plugins

# Entry-point group the Enterprise package (or any third party) registers extra
# CLI subcommands under — e.g. the service-layer ``watch`` and ``serve``.
COMMAND_GROUP = "probity.commands"


@dataclass(frozen=True)
class Command:
    """A named CLI subcommand.

    ``configure`` receives the freshly created subparser to attach its own
    flags; ``run`` executes the command from parsed args and returns a process
    exit code. Core ships ``scan``; registered commands extend the CLI with no
    edit to Core's dispatch.
    """

    name: str
    help: str
    configure: Callable[[argparse.ArgumentParser], None]
    run: Callable[[argparse.Namespace], int]


def discovered_commands() -> list[Command]:
    """Subcommands registered via entry points (empty in a plain Core install)."""
    return cast("list[Command]", load_plugins(COMMAND_GROUP))
