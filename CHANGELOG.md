# Changelog

All notable changes to Probity **Core** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Probity follows an open-core model: this changelog covers the open-source Core
> (`pip install probity`, AGPL-3.0). The proprietary Enterprise overlay (live
> cloud connectors, the `watch`/`serve` service layer, audit PDF, and DORA / EU
> AI Act mapping) is versioned separately.

## [Unreleased]

### Changed
- **Open-core split.** Live cloud connectors (AWS ×2, GCP, Azure, Entra, GitHub),
  the service layer (`watch`/`serve`, scheduler, alerts, dashboard), the audit
  PDF reporter, and the DORA / EU AI Act framework mapping were moved out of Core
  into the proprietary `probity-enterprise` overlay. They plug back in via four
  entry-point seams (`probity.connectors`, `probity.report_formats`,
  `probity.commands`, `probity.scan_addons`) and are not part of the PyPI Core.
- Documentation (README, ARCHITECTURE, CONTROLS, ROADMAP) updated to describe the
  Core as actually published; added `USAGE.md`, `SECURITY.md`, and
  `COMMERCIAL-LICENSE.md`.

## [0.1.0] - 2026-06-04

First feature-complete release of the Core.

### Added
- All 20 NIS2 controls (C01–C20), each a pure `FactSet -> Finding` function with
  attached evidence; `ALL_CONTROLS` registry as the single source of truth for
  the active catalogue, consumed by both the CLI and the scan runner.
- `probity scan` CLI with text, JSON, and HTML reports, plus an append-only
  JSONL history store and score trend (`--history`).
- Offline connectors (no credentials): osv-scanner, Trivy, CycloneDX, testssl.sh,
  sslyze, Veeam, restic, plus file-backed governance / assets / SIEM / pipeline /
  training fixtures.
- Four entry-point extension seams so external packages can register connectors,
  report formats, subcommands, and scan add-ons without forking the CLI.

### Security
- Zero runtime dependencies (standard library only).
- Fail-closed control evaluation; offline tool exports carry no secrets.

### Quality
- `ruff` and `mypy --strict` clean; pytest with coverage gate.

[Unreleased]: https://github.com/janpenitent/probity/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/janpenitent/probity/releases/tag/v0.1.0
