from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Fact:
    """A single immutable observation emitted by a connector."""

    kind: str
    key: str
    data: dict[str, Any] = field(default_factory=dict)


class FactSet:
    """Immutable collection of facts, queryable by kind."""

    def __init__(self, facts: Iterable[Fact] = ()) -> None:
        self._facts: tuple[Fact, ...] = tuple(facts)

    def of_kind(self, kind: str) -> list[Fact]:
        return [f for f in self._facts if f.kind == kind]

    def kinds(self) -> set[str]:
        return {f.kind for f in self._facts}

    def merge(self, other: FactSet) -> FactSet:
        return FactSet([*self._facts, *other._facts])

    def __iter__(self) -> Iterator[Fact]:
        return iter(self._facts)

    def __len__(self) -> int:
        return len(self._facts)
