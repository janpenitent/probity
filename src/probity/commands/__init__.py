# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""CLI subcommand seam.

Core ships the ``scan`` command. Service commands (``watch``, ``serve``) are
Enterprise-only and register through the ``probity.commands`` entry-point group
defined in :mod:`probity.commands.registry`.
"""

from __future__ import annotations
