## What this changes

<!-- One or two sentences. Why, not just what. -->

## Test plan

<!-- Commands you actually ran, with their result. Tick only what you verified. -->

- [ ] `ruff check .`
- [ ] `mypy`
- [ ] `pytest` (coverage stays at or above the 95% gate)

## Checklist

- [ ] Tests were written before the implementation, and one of them failed first.
- [ ] Public behaviour changes are reflected in the README or `docs/`.
- [ ] No credentials, hostnames, or customer data in code, tests, or fixtures.
- [ ] Enterprise-only functionality is not being added to Core (see `docs/TIERING.md`).
