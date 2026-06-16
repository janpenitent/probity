# Usage

How to run Probity Core and how to feed it real evidence. Core is the
open-source tier (`pip install probity`, AGPL-3.0): one-shot scans over **offline
tool exports** and file-backed JSON — no credentials, no live access. (Live cloud
connectors and the continuous service layer ship in the Enterprise overlay; see
[TIERING.md](TIERING.md).)

## Install

```bash
pip install probity            # from PyPI
probity --help
```

Or from source for development:

```bash
git clone https://github.com/janpenitent/probity
cd probity
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## The scan command

```bash
probity scan [SOURCE FLAGS...] [--format text|json|html] [--out FILE] [--history FILE]
```

- Pass one or more **source flags** (below). Each flag points at a file; you can
  combine many in a single scan — all facts merge into one evaluation.
- `--format` selects the report: `text` (default, stdout), `json`, or `html`.
- `--out FILE` writes the report to a file instead of stdout.
- `--history FILE` appends this scan to an append-only JSONL history and prints
  the score trend versus the previous run.

A scan always runs **all 20 controls**. A control with no relevant evidence
returns `NOT_APPLICABLE` rather than failing — so you can start with one source
and add more over time.

### Reading the output

Each control yields one finding with a status:

| Status           | Meaning                                                        |
|------------------|---------------------------------------------------------------|
| `PASS`           | every in-scope item is healthy                                 |
| `FAIL`           | offenders found (listed in the finding's evidence)            |
| `PARTIAL`        | present but needs human judgement (SOFT controls) — `⚑` flag  |
| `NOT_APPLICABLE` | no relevant evidence was supplied                             |
| `ERROR`          | the control raised; surfaced, never silently swallowed        |

The report also carries a compliance **score** and per-status counts.

## Quickstart with bundled fixtures

The repo ships sample inputs under `tests/fixtures/` so you can see real output
before wiring up your own data:

```bash
probity scan --source tests/fixtures/idp_sample.json
probity scan --cloud tests/fixtures/cloud_sample.json --tls tests/fixtures/tls_sample.json
probity scan --governance tests/fixtures/governance_sample.json --format html --out report.html
```

## Offline tool exports

Core ingests the native JSON output of free, offline scanners and backup tools.
Generate the export, then hand the file to Probity.

### Dependency CVEs → C10 (`--osv`)

```bash
osv-scanner --format json --all-packages --output-file osv.json -L requirements.txt
probity scan --osv osv.json
```

`--all-packages` matters: without it, osv-scanner v2 writes **only the
vulnerable** packages to the JSON, so Probity can't see your clean ones — C10
then under-reports ("1 of 1 has a CVE" instead of "1 of 200") and a fully clean
project reads as `NOT_APPLICABLE` instead of `PASS`. With it, C10 reports
"N of M" honestly. Point `-L` at a lockfile (`requirements.txt`,
`poetry.lock`, `package-lock.json`, …) or use `-r .` to walk a directory.

### Vulnerability scanning → C12 (`--trivy`)

```bash
trivy image --format json --output trivy.json myimage:tag
probity scan --trivy trivy.json --assets assets.json
```

C12 checks scan *freshness* (Trivy's `CreatedAt` → `last_scan`; a missing
timestamp reads as stale, fail-closed). A critical asset that was never scanned
produces no Trivy fact, so pair `--trivy` with `--assets` to catch that gap. A
single report object or a JSON array of reports are both accepted.

### SBOM present and current → C09 (`--cyclonedx`)

```bash
# e.g. syft, cdxgen, or your build tool's CycloneDX output
syft myimage:tag -o cyclonedx-json > bom.json
probity scan --cyclonedx bom.json
```

### TLS in transit → C18 (`--testssl` / `--sslyze`)

```bash
testssl.sh --jsonfile tls.json https://portal.example.com
probity scan --testssl tls.json
# or
sslyze --json_out tls.json portal.example.com
probity scan --sslyze tls.json
```

### Backups → C06 / C07 / C08 (`--veeam` / `--restic`)

```bash
# Veeam Backup & Replication job report exported as JSON → C06/C07/C08
probity scan --veeam veeam.json
# restic snapshots → C06 only (no restore-test / immutability signal,
# so C07/C08 fail closed honestly)
restic snapshots --json > restic.json
probity scan --restic restic.json
```

## File-backed JSON sources

Where there is no single offline tool, Core reads a small JSON export you produce
from your own systems (CMDB, SIEM, IdP, GRC, HR/LMS). Each shape below is the
exact structure Core parses; all timestamps are ISO-8601 (UTC recommended).

### Identity → C19 / C20 (`--source`)

```json
{
  "accounts": [
    {"id": "u1", "display_name": "Alice Admin", "enabled": true,
     "privileged": true, "mfa_enabled": true, "hr_active": true}
  ]
}
```

C19 flags enabled accounts with no active HR record (orphans) and stale
privilege; C20 flags enabled accounts without MFA.

### Encryption at rest → C17 (`--cloud`)

```json
{
  "volumes": [
    {"id": "vol-db", "name": "prod-postgres", "encrypted": true,
     "kms": "managed", "contains_pii": true}
  ]
}
```

### TLS endpoints (manual) → C18 (`--tls`)

```json
{
  "endpoints": [
    {"id": "ep-portal", "host": "portal.example.com", "tls_version": "1.3",
     "cert_valid": true, "cert_expires_in_days": 60}
  ]
}
```

### Governance → C01 / C05 / C11 / C15 (`--governance`)

```json
{
  "documents": [
    {"id": "pol-sec", "type": "security_policy", "title": "InfoSec Policy",
     "approved_at": "2025-09-01", "review_due": "2026-09-01"}
  ],
  "suppliers": [
    {"id": "sup-acme", "name": "AcmeCloud", "criticality": "high",
     "risk_assessed_at": "2026-01-15"}
  ]
}
```

Document `type` values: `security_policy` (C01), `incident_procedure` (C05),
`disclosure_policy` (C15). These SOFT controls **never auto-PASS**: absent or
overdue → `FAIL`; present and current → `PARTIAL` + `requires_human_validation`.

### Asset / monitoring plane → C02 / C03 / C04 / C12 / C13 / C14 / C16

One JSON file can feed several of these (each top-level key is optional):

```json
{
  "assets":   [{"id": "vm-1", "managed": true, "last_seen": "2026-06-03T12:00:00+00:00"}],
  "vulnscans":[{"id": "vm-1", "critical": true, "last_scan": "2026-05-20T00:00:00+00:00"}],
  "patches":  [{"id": "vm-1", "critical": true, "last_patched": "2026-05-28T00:00:00+00:00", "pending_critical": 0}],
  "log_sources":    [{"id": "src-1", "critical": true, "forwarding": true, "last_event": "2026-06-04T06:00:00+00:00"}],
  "detection_rules":[{"id": "rule-1", "enabled": true, "last_tested": "2026-04-01T00:00:00+00:00"}],
  "pipelines":[{"id": "repo-app", "sast_enabled": true, "secret_scanning_enabled": true}],
  "training": [{"id": "u-1", "required": true, "completed_at": "2026-02-01T00:00:00+00:00"}]
}
```

The relevant flag selects which keys are read: `--assets` (assets / vulnscans /
patches → C02/C12/C14), `--siem` (log_sources / detection_rules → C03/C04),
`--pipeline` (pipelines → C13), `--training` (training → C16). All are
fail-closed on stale or missing timestamps. Freshness windows: assets 7d,
logging 24h, detection 90d, scanning 30d, patching 30d, training 365d.

## Continuous scanning (history + trend)

```bash
probity scan --source idp.json --history history.jsonl
```

Each run appends one line to `history.jsonl` and prints the score delta versus
the previous scan. This is the Core persistence layer — a flat JSONL file, no
database. (Scheduling these scans, alerting on regressions, and a web dashboard
are the Enterprise `watch` / `serve` commands.)

## Exit status

`probity scan` exits **0** when no control failed, and **1** when at least one
control returned `FAIL` — so you can gate a CI pipeline on compliance directly
(`probity scan ... || exit 1`). `PARTIAL`, `NOT_APPLICABLE`, and `ERROR` do not
by themselves make the exit non-zero. A non-zero exit also occurs when the scan
cannot run at all (bad input, no usable source). For finer-grained gating, parse
the JSON report instead of relying on the exit code.

## Enterprise (live + continuous)

When the proprietary overlay is installed in the same environment, extra flags
and subcommands appear automatically in `probity --help`: live cloud connectors
(`--aws`, `--aws-monitoring`, `--gcp`, `--azure`, `--entra`, `--github`, all
reading credentials from the environment only), `--format pdf`, `--framework`
(DORA / EU AI Act), and the `watch` / `serve` service commands. See
[COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md).
