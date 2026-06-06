# Probity

**Continuous, auditable NIS2 compliance evidence. Open-core.**

Probity turns regulatory compliance from a once-a-year static document into
**continuous machine-checked evidence**. It connects to the systems you already
run (identity, cloud, backups, dependencies), evaluates them against concrete
NIS2 technical controls, and produces audit-ready findings — every day, not once.

> *Probity* (English): proven integrity — honesty and correctness demonstrated
> by evidence, not merely claimed. That is exactly what this tool produces for
> your compliance posture: integrity you can prove on demand.

## Why

EU regulation (NIS2, DORA, AI Act, CRA) now obliges thousands of mid-sized
organisations to prove cybersecurity risk management. Today they prove it with
consultants and spreadsheets: expensive, manual, and stale the day after the
audit. Probity closes that gap with **compliance-as-code**.

## How it works

```
Connector  ──►  Fact  ──►  Control  ──►  Finding (+ Evidence)  ──►  Report
(reads a       (typed     (evaluates    (pass / fail / partial    (score +
 real system)  observation) NIS2 rule)   + offending items)        audit pack)
```

The architecture is plugin-based: each connector and each control is an
independent unit, so coverage grows control by control.

## Quickstart

```bash
pip install probity
probity scan --source tests/fixtures/idp_sample.json
```

Or from source for development:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
probity scan --source tests/fixtures/idp_sample.json
```

Full flag and JSON-shape reference: **[docs/USAGE.md](docs/USAGE.md)**.

## Commands

```bash
# One-off scan; --format text|json|html, --out FILE to write to a file
probity scan --source idp.json --cloud cloud.json --tls tls.json --format html --out report.html

# Record every scan to an append-only JSONL history and print the score trend
probity scan --source idp.json --history history.jsonl
```

Connectors accept either mock fixtures or **real tool exports** — same controls,
no live credentials needed: osv-scanner (`--osv`), CycloneDX (`--cyclonedx`),
testssl.sh (`--testssl`), sslyze (`--sslyze`), Veeam (`--veeam`), restic
(`--restic`), Trivy (`--trivy`).

> **Enterprise tier (proprietary overlay, not in this package).** Live cloud
> connectors (AWS, GCP, Azure, Entra, GitHub), the `watch` scheduler and `serve`
> dashboard with regression alerts, inspector-grade PDF (`--format pdf`), and
> DORA / EU AI Act cross-framework mapping (`--framework`) ship in the closed
> Enterprise tier — they register into this same CLI via entry points when the
> overlay is installed. See [Licensing](#licensing).

The **SOFT** controls (C01/C05/C11/C15) reason over governance artifacts —
policies, procedures, supplier risk assessments — via `--governance gov.json`.
They are honest about automation's limit: a missing or overdue artifact is a hard
`FAIL`, but a present, current one is `PARTIAL` flagged `requires_human_validation`
(never an auto-PASS) so an auditor still judges the content.

## Zero runtime dependencies

Core ships with `dependencies = []` — Python standard library only. Persistence
is an append-only JSONL history (no database); reports are hand-written text,
JSON, and HTML. Nothing to audit but Python itself. (The Enterprise overlay keeps
the same discipline: its scheduler is stdlib `threading`, its dashboard is
`http.server` with hand-built inline SVG, and alert webhooks use `urllib` — still
zero third-party deps.)

## Status

Pre-alpha. **All 20 controls are implemented end-to-end**: the full HARD set
(C02–C04, C06–C10, C12–C14, C16–C20) and the SOFT set (C01, C05, C11, C15) with
the human-validation flag. The HARD monitoring/asset-plane controls fail closed
on stale or missing telemetry via a shared freshness helper. Core also ships
text/JSON/HTML reporting and history + trend. The scheduler, dashboard, PDF,
live cloud connectors, and DORA / EU AI Act mapping live in the proprietary
Enterprise overlay (see [Licensing](#licensing)).
See [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/CONTROLS.md](docs/CONTROLS.md).

## Documentation

- **[docs/USAGE.md](docs/USAGE.md)** — install, the `scan` command, every source
  flag, and the exact JSON shapes Core accepts.
- **[docs/CONTROLS.md](docs/CONTROLS.md)** — the 20-control NIS2 catalogue and
  evidence sources.
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — pipeline, module map, and the
  four plugin extension points.
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — what shipped and what's next.
- **[docs/TIERING.md](docs/TIERING.md)** — the open-core split (Core vs Enterprise).
- **[CONTRIBUTING.md](CONTRIBUTING.md)** · **[SECURITY.md](SECURITY.md)** —
  contributing and vulnerability disclosure.

## Licensing

Core is licensed under **AGPL-3.0-or-later** (see [`LICENSE`](LICENSE)). The
AGPL requires that if you run a modified Probity as a network service, you make
your source available to its users under the same terms. If that does not fit
your use — closed-source, SaaS without source disclosure, or bundling into a
proprietary product — a **commercial license** is available from the copyright
holder. See **[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)**.

The paid **Enterprise** overlay (live cloud connectors, scheduler/dashboard,
audit PDF, multi-framework mapping) is proprietary and is sold under that same
commercial agreement — the open-core model.
