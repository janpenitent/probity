# Architecture

Probity is a plugin pipeline. Each stage is replaceable and independently testable.

## Pipeline

```
Connector.collect() -> [Fact]  -->  FactSet  -->  Control.evaluate(FactSet) -> Finding
                                                                               |
                                                          Scan aggregates -> Report -> reporters
```

## Core types (`probity.model`)

- **Fact** — one immutable observation from a system: `kind`, `key`, `data`.
  Example kind: `identity.account`.
- **FactSet** — immutable, queryable collection (`of_kind`, `merge`).
- **Severity** — `critical | high | medium | low`.
- **Status** — `pass | fail | partial | not_applicable | error`.
- **Evidence** — human-readable description + the offending items.
- **Finding** — the result of one control: status, summary, evidence, NIS2 refs.
- **Report** — all findings + a compliance `score` + status counts.

## Extension points

- **Connector** (`probity.connectors.base.Connector`): `collect() -> Iterable[Fact]`.
  Mirrors the UDS module/plugin pattern. Must not raise on empty source.
- **Control** (`probity.controls.base.Control`): `evaluate(FactSet) -> Finding`.
  Pure: depends only on the facts, never on live I/O.

## Engine

`probity.engine.runner.Scan` wires connectors + controls. It isolates control
failures: an exception inside a control becomes an `ERROR` finding instead of
aborting the whole scan (no silent swallowing — the error is surfaced).

## Design rules

- Hard (deterministic) checks first; soft (LLM-reasoned) checks later behind an
  explicit "requires human validation" flag.
- Connectors do I/O; controls do logic. Never mix them — keeps controls trivially
  unit-testable with synthetic facts.
