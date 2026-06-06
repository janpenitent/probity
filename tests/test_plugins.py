# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from probity.plugins import load_plugins


def test_load_plugins_unknown_group_returns_empty():
    # No package registers this group -> empty list, never an error.
    assert load_plugins("probity.nonexistent.group.xyz") == []
