# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

from argparse import ArgumentParser, Namespace
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from probity.connectors.base import Connector
from probity.plugins import load_plugins

# Entry-point group the Enterprise package registers live cloud connectors under
# (AWS, GCP, Azure, Entra, GitHub) once they move out of Core — see TIERING §3.
CONNECTOR_GROUP = "probity.connectors"


@dataclass(frozen=True)
class ConnectorSource:
    """An externally pluggable evidence source.

    A source owns both halves of the CLI seam: ``add_arguments`` contributes its
    own flags to the ``scan``/``watch`` parsers, and ``build`` turns the parsed
    args into zero or more connectors. This lets a plugin add (say) ``--aws``
    and construct an ``AwsConnector`` without any edit to Core's ``cli.py``.
    """

    name: str
    add_arguments: Callable[[ArgumentParser], None]
    build: Callable[[Namespace], list[Connector]]


def discovered_sources() -> list[ConnectorSource]:
    """Connector sources registered by external packages via entry points."""
    return cast("list[ConnectorSource]", load_plugins(CONNECTOR_GROUP))
