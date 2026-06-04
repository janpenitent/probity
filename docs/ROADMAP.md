# Roadmap

Each stage ships as one or more short-lived feature branches merged to `main`,
each with tests and green CI. TDD throughout.

## E0 — Foundation (done)
Core model, plugin engine, file-backed mock connector, CI, docs, licence.

## E1 — First vertical slice (done)
- C20 MFA control end-to-end (connector -> fact -> control -> finding -> CLI).
- `probity scan` CLI with text and JSON output.

## E2 — HARD control set (identity & data) (done)
- C19 orphan / over-privileged accounts.
- C17 encryption at rest, C18 TLS in transit.

## E3 — HARD control set (resilience & supply chain) (done)
- C06 backups recent, C07 restore-tested, C08 immutable copy.
- C10 dependency CVEs (OSV feed), C09 SBOM present and current.

## E4 — Reporting (in progress)
- Evidence pack: JSON + HTML audit export (done), per-control history + trend score (done).
- PDF export pending.

## E5 — Real connectors
- Microsoft Entra ID / LDAP (identity), Azure + AWS config (encryption, assets),
  SIEM (logging), backup vendors.

## E6 — Service + dashboard
- Scheduled scans, persistence (Postgres/Timescale), web dashboard, alerts.
- Multi-framework mapping (DORA, AI Act) reusing shared controls.
