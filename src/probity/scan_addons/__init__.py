# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Scan add-on seam: post-scan extensions that hook into the ``scan`` command.

Core ships no add-ons. An add-on contributes its own ``scan`` flags and runs
after the report is built/emitted (e.g. the Enterprise multi-framework coverage
view). They join via the ``probity.scan_addons`` entry-point group, so Core's
``scan`` command never has to be edited to gain post-scan behaviour.
"""

from __future__ import annotations
