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
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
probity scan --source tests/fixtures/idp_sample.json
```

## Commands

```bash
# One-off scan; --format text|json|html|pdf, --out FILE for pdf/files
probity scan --source idp.json --cloud cloud.json --tls tls.json --format html --out report.html

# Record every scan to an append-only JSONL history and print the score trend
probity scan --source idp.json --history history.jsonl

# Map the same evidence to other regulations (NIS2 is always on the control)
probity scan --source idp.json --framework all      # nis2 | dora | ai_act | all

# Run on a schedule and alert on regressions (stdout / file / webhook)
probity watch --source idp.json --history history.jsonl --interval 3600 \
    --alert-file alerts.jsonl --alert-webhook https://hooks.example/probity

# Serve the read-only compliance dashboard built from the history
probity serve --history history.jsonl --port 8080
```

Connectors accept either mock fixtures or **real tool exports** — same controls,
no live credentials needed: osv-scanner (`--osv`), CycloneDX (`--cyclonedx`),
testssl.sh (`--testssl`), sslyze (`--sslyze`), Veeam (`--veeam`), restic
(`--restic`). The first **live** connector, Microsoft Entra ID (`--entra`),
talks to the Graph API directly (OAuth2 client-credentials, stdlib `urllib`,
still zero deps) to feed C19/C20:

```bash
export PROBITY_ENTRA_TENANT_ID=... PROBITY_ENTRA_CLIENT_ID=... PROBITY_ENTRA_CLIENT_SECRET=...
probity scan --entra --format json
```

The first **SOFT** controls (C01/C05/C11/C15) reason over governance artifacts —
policies, procedures, supplier risk assessments — via `--governance gov.json`.
They are honest about automation's limit: a missing or overdue artifact is a hard
`FAIL`, but a present, current one is `PARTIAL` flagged `requires_human_validation`
(never an auto-PASS) so an auditor still judges the content.

## Zero runtime dependencies

The core ships with `dependencies = []`. Scheduling uses stdlib `threading`,
persistence is an append-only JSONL history (no database), the dashboard is
stdlib `http.server` with hand-built inline SVG, and alert webhooks use
`urllib`. Nothing to audit but Python itself.

## Status

Pre-alpha. **All 20 controls are implemented end-to-end**: the full HARD set
(C02–C04, C06–C10, C12–C14, C16–C20) and the SOFT set (C01, C05, C11, C15) with
the human-validation flag. The HARD monitoring/asset-plane controls fail closed
on stale or missing telemetry via a shared freshness helper. Also JSON/HTML/PDF
reporting, history + trend, scheduled `watch`, a `serve` dashboard, regression
alerts, a live Entra ID connector, and DORA / EU AI Act cross-framework mapping.
See [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/CONTROLS.md](docs/CONTROLS.md).

## Licensing

Core is licensed under **AGPL-3.0-or-later** (see `LICENSE`). A commercial
licence (for closed/SaaS use without AGPL obligations) and enterprise connectors
and support are offered separately — the open-core model.
