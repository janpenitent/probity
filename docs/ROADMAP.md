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

## E4 — Reporting (done)
- Evidence pack: JSON + HTML audit export (done), per-control history + trend score (done).
- PDF export (done) — zero-dep pure-Python writer, paginated Courier text, `--format pdf --out`.

## E5 — Real connectors
Strategy: ingest real exports of free offline tools (no live credentials).
- [x] E5a OsvConnector — `osv-scanner --format json` -> C10 (`--osv`).
- [x] E5b CycloneDxConnector — real CycloneDX JSON BOM -> C09 (`--cyclonedx`).
- [x] E5c TesttsslConnector + SslyzeConnector — testssl.sh / sslyze JSON ->
  C18 (`--testssl`, `--sslyze`).
- [ ] real backup-vendor export -> C06/07/08.
- Later (live APIs): Microsoft Entra ID / LDAP (identity), Azure + AWS config
  (encryption, assets), SIEM (logging), backup vendors.

## E6 — Service + dashboard
- Scheduled scans, persistence (Postgres/Timescale), web dashboard, alerts.
- Multi-framework mapping (DORA, AI Act) reusing shared controls.
