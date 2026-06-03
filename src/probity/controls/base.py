from __future__ import annotations

from abc import ABC, abstractmethod

from probity.model.enums import Severity
from probity.model.fact import FactSet
from probity.model.finding import Finding


class Control(ABC):
    """Evaluates a NIS2 technical control against collected facts.

    Pure: depends only on the FactSet, never on live I/O. Returns a Finding;
    must not raise (the engine wraps unexpected errors into ERROR findings).
    """

    id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    nis2_refs: tuple[str, ...] = ()

    @abstractmethod
    def evaluate(self, facts: FactSet) -> Finding:
        raise NotImplementedError
