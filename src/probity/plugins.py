# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

from importlib.metadata import entry_points


def load_plugins(group: str) -> list[object]:
    """Instantiate every plugin registered under an entry-point ``group``.

    Each entry point must resolve to a zero-argument callable returning the
    plugin object (a ``ConnectorSource``, a ``ReportFormat``, ...). This is the
    seam the closed Enterprise package plugs into: it declares entry points in
    its own packaging metadata and Core discovers them at runtime, with no edit
    to Core's CLI.

    Errors propagate (fail-closed): a broken or missing plugin must surface in a
    compliance run, never be silently dropped — silent omission of evidence is
    exactly the failure mode this tool exists to prevent.
    """
    return [entry_point.load()() for entry_point in entry_points(group=group)]
