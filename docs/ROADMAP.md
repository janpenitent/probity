# Roadmap

Each stage ships as one or more short-lived feature branches merged to `main`,
each with tests and green CI. TDD throughout.

> **Open-core note.** Probity was built feature-first, then split into an
> open-source **Core** (AGPL-3.0, on PyPI) and a proprietary **Enterprise**
> overlay. Several items below were implemented in the original single tree and
> then *moved* to the overlay during the tiering work — they are marked
> **⊕ Enterprise**. They still exist and are maintained; they are simply not part
> of the free `pip install probity`. See [TIERING.md](TIERING.md).

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
- Evidence pack: JSON + HTML audit export (Core), per-control history + trend
  score (Core, `--history`).
- PDF export — zero-dep pure-Python writer, paginated Courier text
  (`--format pdf --out`). **⊕ Enterprise** (moved to the overlay as a
  `probity.report_formats` plugin).

## E5 — Real connectors (done)
Strategy: ingest real exports of free offline tools (no live credentials) — these
stay in **Core**.
- [x] E5a OsvConnector — `osv-scanner --format json` -> C10 (`--osv`).
- [x] E5b CycloneDxConnector — real CycloneDX JSON BOM -> C09 (`--cyclonedx`).
- [x] E5c TesttsslConnector + SslyzeConnector — testssl.sh / sslyze JSON ->
  C18 (`--testssl`, `--sslyze`).
- [x] E5d VeeamConnector (C06/07/08) + ResticConnector (C06) — real
  backup-vendor exports (`--veeam`, `--restic`).
- [x] TrivyConnector — `trivy --format json` -> C12 (`--trivy`).

### Live API connectors — **⊕ Enterprise**
Credentialed cloud collectors that emit the same facts as the offline connectors,
moved to the overlay during tiering:
- Microsoft Entra ID / Graph (`--entra`) -> C19/C20.
- GitHub REST API (`--github`) -> C13.
- AWS EC2/EBS (`--aws`) -> C02/C17; AWS CloudTrail + SSM (`--aws-monitoring`) ->
  C03/C14.
- GCP Compute (`--gcp`) and Azure ARM (`--azure`) -> C02/C17.

## E6 — Service + dashboard — **⊕ Enterprise**
The continuous layer was built in the single tree, then moved wholesale to the
overlay (registered via the `probity.commands` and `probity.scan_addons` seams):
- [x] Scheduled scans — `probity watch` (stdlib `threading` loop, `--interval`,
  `--once`).
- [x] Persistence — reuses Core's append-only JSONL history (no DB).
- [x] Web dashboard — `probity serve` (stdlib `http.server`, inline-SVG score
  trend, control grid).
- [x] Alerts — regression detection between scans -> stdout / `--alert-file` /
  `--alert-webhook` (urllib).
- [x] Multi-framework mapping (DORA, AI Act) reusing the shared controls —
  `probity scan --framework {nis2,dora,ai_act,all}` (NIS2 refs read from the
  control; DORA/AI Act cross-refs derived; per-framework score from the same
  evidence, no control modified).

Design note: the roadmap originally proposed Postgres/Timescale + a JS dashboard.
That was dropped to preserve Probity's zero-runtime-dependency guarantee — the
JSONL history is the store, `http.server` is the server, hand-built SVG is the
chart. A DB/UI backend can be added later as an optional extra, not a hard dep.

## Done: open-core tiering
Core / Enterprise split complete (TIERING steps 1–7): four entry-point seams in
Core, private `probity-enterprise` overlay, paid modules moved out and
relicensed, Core published to PyPI, commercial dual-license offer in place. See
[TIERING.md](TIERING.md).

## Next (not engineering)
Real-world validation with auditors / compliance teams, user docs polish, and
hardening the Enterprise install + licensing flow before selling.
