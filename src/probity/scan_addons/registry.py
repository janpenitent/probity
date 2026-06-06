# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from probity.model.finding import Report
from probity.plugins import load_plugins

SCAN_ADDON_GROUP = "probity.scan_addons"


@dataclass(frozen=True)
class ScanAddon:
    """A post-scan extension to the ``scan`` command.

    ``add_arguments`` contributes the add-on's own flags to the scan parser;
    ``after_scan`` runs once the report is built and emitted. An add-on must be
    inert unless its own flag is set, so installing it never changes default
    ``scan`` output.
    """

    name: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    after_scan: Callable[[Report, argparse.Namespace], None]


def discovered_addons() -> list[ScanAddon]:
    """Scan add-ons registered via the ``probity.scan_addons`` entry point."""
    return cast("list[ScanAddon]", load_plugins(SCAN_ADDON_GROUP))
