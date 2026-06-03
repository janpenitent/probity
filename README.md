# Probanza

**Continuous, auditable NIS2 compliance evidence. Open-core.**

Probanza turns regulatory compliance from a once-a-year static document into
**continuous machine-checked evidence**. It connects to the systems you already
run (identity, cloud, backups, dependencies), evaluates them against concrete
NIS2 technical controls, and produces audit-ready findings — every day, not once.

> *Probanza* (Spanish, legal): the body of evidence that proves a fact in court.
> That is exactly what this tool produces for your compliance posture.

## Why

EU regulation (NIS2, DORA, AI Act, CRA) now obliges thousands of mid-sized
organisations to prove cybersecurity risk management. Today they prove it with
consultants and spreadsheets: expensive, manual, and stale the day after the
audit. Probanza closes that gap with **compliance-as-code**.

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
probanza scan --source tests/fixtures/idp_sample.json
```

## Status

Pre-alpha. Building the HARD (deterministic) control set first. See
[docs/ROADMAP.md](docs/ROADMAP.md) and [docs/CONTROLS.md](docs/CONTROLS.md).

## Licensing

Core is licensed under **AGPL-3.0-or-later** (see `LICENSE`). A commercial
licence (for closed/SaaS use without AGPL obligations) and enterprise connectors
and support are offered separately — the open-core model.
