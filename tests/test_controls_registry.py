# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Guard tests for the ALL_CONTROLS registry.

These assert the catalogue stays complete and consistent so a control can never
be silently dropped or duplicated when the registry is edited.
"""

from __future__ import annotations

from probity.controls import ALL_CONTROLS
from probity.controls.base import Control

_EXPECTED_IDS = tuple(f"C{n:02d}" for n in range(1, 21))


def test_registry_has_all_twenty_controls():
    assert len(ALL_CONTROLS) == 20


def test_registry_ids_are_the_full_nis2_catalogue_in_order():
    assert tuple(c.id for c in ALL_CONTROLS) == _EXPECTED_IDS


def test_registry_has_no_duplicate_ids():
    ids = [c.id for c in ALL_CONTROLS]
    assert len(set(ids)) == len(ids)


def test_every_entry_is_a_control_instance():
    assert all(isinstance(c, Control) for c in ALL_CONTROLS)


def test_every_control_has_a_title():
    assert all(c.title for c in ALL_CONTROLS)
