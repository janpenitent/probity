# Changelog

All notable changes to Probity are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-04

First feature-complete release.

### Added
- All 20 NIS2 controls (C01–C20), each a pure `FactSet -> Finding` function
  with attached evidence.
- Framework mapping layer projecting NIS2 findings onto DORA and the EU AI Act.
- Live `GitHubConnector` feeding C13 (CI/CD security), with paginated REST
  collection and a hard page cap to prevent runaway loops.
- `ALL_CONTROLS` registry as the single source of truth for the active
  catalogue, consumed by both the CLI and the scan runner.
- JSONL history store, hand-built SVG trend charts, and PDF/JSON/HTML reports.
- Local dashboard and scheduler service.

### Security
- Zero runtime dependencies (standard library only).
- Fail-closed control evaluation; credentials read from the environment only.

### Quality
- 252 tests, 94% coverage; `ruff` and `mypy --strict` clean.

[0.1.0]: https://github.com/janpenitent/probity/releases/tag/v0.1.0
