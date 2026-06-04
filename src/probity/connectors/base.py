# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from probity.model.fact import Fact


class Connector(ABC):
    """Reads a real system and emits Facts. Plugin unit (UDS module pattern)."""

    id: str = ""
    title: str = ""

    @abstractmethod
    def collect(self) -> Iterable[Fact]:
        """Return facts observed from the source. Must not raise on an empty source."""
        raise NotImplementedError
