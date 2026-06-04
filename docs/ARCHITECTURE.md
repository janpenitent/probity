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

## Reporting (`probity.report`)

A `Report` is rendered by independent, pure reporters — `json_report`,
`html_report`, and a zero-dependency pure-Python `pdf_report` writer. `history`
appends each scan as one line to an append-only JSONL store (`Snapshot`) and
derives a `Trend` (score delta vs the previous scan) — the only persistence
layer, deliberately no database.

## Service (`probity.service`)

The continuous layer, all stdlib:

- **scheduler** — `ScanScheduler` runs the pipeline on an interval (`threading`),
  records each scan to history, and dispatches alerts.
- **alerts** — pure `detect_transitions` / `build_alert` over consecutive
  snapshots (fail-closed: an unknown status ranks worst; a recovery alone is not
  actionable), with stdout / file / webhook (`urllib`) sinks.
- **dashboard** — `render_dashboard` is a pure function of the history file;
  `serve` is a thin `http.server` shell around it with an inline-SVG trend.

## Frameworks (`probity.frameworks`)

`mapping` maps the same evidence onto DORA and the EU AI Act. NIS2 references
stay on the control (single source of truth); cross-references live in a
constant table, and `coverage` / `all_coverage` derive a per-framework view
(mapped controls, statuses, framework-scoped score) from a `Report` without
modifying any control.

## Module map

```
probity/
  model/       Fact, FactSet, Finding, Report, enums   (immutable core types)
  connectors/  base + mock_* fixtures + real exports    (I/O -> Facts)
  controls/    base + c06..c20                          (Facts -> Finding, pure)
  engine/      runner.Scan                              (wires it together)
  report/      json / html / pdf / history              (Report -> artifacts)
  service/     scheduler / alerts / dashboard           (continuous layer)
  frameworks/  mapping                                  (NIS2 -> DORA / AI Act)
  cli.py       scan | watch | serve
```

## Design rules

- Hard (deterministic) checks first; soft (LLM-reasoned) checks later behind an
  explicit "requires human validation" flag.
- Connectors do I/O; controls do logic. Never mix them — keeps controls trivially
  unit-testable with synthetic facts.
- Zero runtime dependencies: every layer above is built on the Python stdlib.
