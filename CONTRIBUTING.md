# Contributing

Thanks for your interest in Probity. This covers Probity **Core** (the
open-source, AGPL-3.0 package). The Enterprise overlay is a separate, proprietary
repository.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality gates (must pass before merge)

```bash
ruff check .      # lint + import order
mypy              # strict type checking
pytest            # tests + coverage (target 80%+)
```

## Conventions

- TDD: write the failing test first, then the implementation.
- Conventional Commits: `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`.
- One control per module under `src/probity/controls/`, one connector per
  module under `src/probity/connectors/`. Keep files small and cohesive.
- Connectors must never raise on an empty source; controls return a `Finding`,
  never an exception (the engine converts unexpected errors into ERROR findings).

## Writing a plugin instead of patching Core

To add a connector, report format, subcommand, or scan add-on, prefer shipping it
as a **separate package** that registers through Core's entry-point seams — no
fork, no Core patch required:

| Group                    | What you register                          |
|--------------------------|--------------------------------------------|
| `probity.connectors`     | a `ConnectorSource` (a CLI flag + builder) |
| `probity.report_formats` | a `ReportFormat` (a `--format` value)      |
| `probity.commands`       | a `Command` (a top-level subcommand)       |
| `probity.scan_addons`    | a `ScanAddon` (extra scan flags + hooks)   |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the contracts. This is the
same mechanism the Enterprise overlay uses.

## Licensing of contributions

Core is **AGPL-3.0-or-later**. By submitting a contribution you agree it is
licensed under those terms (inbound = outbound).

Probity is dual-licensed: the copyright holder also sells a commercial license
(see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)). To keep that possible, the
project will require contributors to sign a lightweight **Contributor License
Agreement (CLA)** granting the copyright holder the right to relicense
contributions. The CLA is not yet in place; **until it is, only small,
non-substantial contributions can be merged.** If you are planning a larger
contribution, open an issue first so we can sort the CLA out before you invest
the work.

## Reporting security issues

Do not file public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).
