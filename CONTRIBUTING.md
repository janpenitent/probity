# Contributing

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
