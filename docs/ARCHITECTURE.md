# Architecture

Probity is a plugin pipeline. Each stage is replaceable and independently testable.

This document describes the **open-source Core** (`pip install probity`, AGPL-3.0).
The proprietary **Enterprise** overlay adds live cloud connectors, a continuous
service layer, an audit PDF, and multi-framework mapping — it plugs into the same
seams documented here via entry points and never forks the Core. See
[TIERING.md](TIERING.md) for the tier boundary.

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

## Engine

`probity.engine.runner.Scan` wires connectors + controls. It isolates control
failures: an exception inside a control becomes an `ERROR` finding instead of
aborting the whole scan (no silent swallowing — the error is surfaced).

## Reporting (`probity.report`)

A `Report` is rendered by independent, pure reporters — `text_report`,
`json_report`, and `html_report`. `history` appends each scan as one line to an
append-only JSONL store (`Snapshot`) and derives a `Trend` (score delta vs the
previous scan) — the only persistence layer, deliberately no database.

> The inspector-grade **PDF** reporter ships in the Enterprise overlay as a
> `probity.report_formats` plugin (`--format pdf`).

## Extension points

Core discovers plugins through `importlib.metadata` entry points
(`probity.plugins.load_plugins`), so a separate package — the Enterprise overlay
or a community plugin — can extend Probity without editing Core. Discovery is
**fail-closed**: a broken plugin raises, it is never silently dropped.

Four entry-point groups, each backed by a frozen registry type:

| Group                   | Registry type                          | Extends                                   |
|-------------------------|----------------------------------------|-------------------------------------------|
| `probity.connectors`    | `connectors.registry.ConnectorSource`  | a CLI source flag + its connector builder |
| `probity.report_formats`| `report.registry.ReportFormat`         | a `--format` value (text/binary)          |
| `probity.commands`      | `commands.registry.Command`            | a top-level subcommand (e.g. `watch`)     |
| `probity.scan_addons`   | `scan_addons.registry.ScanAddon`       | extra `scan` flags + post-scan hooks      |

The two base extension contracts a plugin implements:

- **Connector** (`probity.connectors.base.Connector`): `collect() -> Iterable[Fact]`.
  Mirrors the UDS module/plugin pattern. Must not raise on an empty source.
- **Control** (`probity.controls.base.Control`): `evaluate(FactSet) -> Finding`.
  Pure: depends only on the facts, never on live I/O.

> The Enterprise overlay registers its live cloud connectors via
> `probity.connectors`, the `watch`/`serve` service commands via
> `probity.commands`, the audit PDF via `probity.report_formats`, and the
> DORA / EU AI Act `--framework` mapping via `probity.scan_addons`. When the
> overlay is installed into the same environment, these appear in `probity --help`
> automatically; without it, Core runs exactly as documented.

## Module map (Core)

```
probity/
  model/       Fact, FactSet, Finding, Report, enums   (immutable core types)
  connectors/  base + mock_* fixtures + offline exports (I/O -> Facts)
  controls/    base + c01..c20                          (Facts -> Finding, pure)
  engine/      runner.Scan                              (wires it together)
  report/      text / json / html + registry + history  (Report -> artifacts)
  commands/    registry                                 (subcommand seam)
  scan_addons/ registry                                 (scan-flag / hook seam)
  plugins.py   entry-point discovery                    (fail-closed loader)
  cli.py       scan                                     (the one builtin command)
```

## Design rules

- Hard (deterministic) checks first; soft (LLM-reasoned) checks later behind an
  explicit "requires human validation" flag.
- Connectors do I/O; controls do logic. Never mix them — keeps controls trivially
  unit-testable with synthetic facts.
- Zero runtime dependencies: every layer is built on the Python stdlib.
- Builtin tests assert the raw builtin tuples (`BUILTIN_FORMATS`,
  `BUILTIN_COMMANDS`), not the entry-point-merged sets — so Core CI stays green
  with or without the overlay installed.
```
