# NIS2 Control Catalogue

Controls map NIS2 Article 21(2) measures to concrete technical checks.

- **HARD** = deterministic (API/config returns a yes/no). Cheap, objective.
- **SOFT** = requires reasoning over policy text; flagged for human validation.

All 20 controls live in the open-source **Core**. What differs by tier is the
*evidence source*: Core ingests offline tool exports and file-backed fixtures;
the Enterprise overlay adds **live** connectors that collect the same facts
straight from cloud APIs (marked **⊕ Enterprise** below). Because every connector
emits the same typed `Fact`, a control runs unchanged regardless of source.

| ID  | NIS2 ref        | Control                                   | Source            | Type | Status  |
|-----|-----------------|-------------------------------------------|-------------------|------|---------|
| C01 | 21(2)(a)        | Security policy exists and is current     | docs              | SOFT | done    |
| C02 | 21(2)(a)(i)     | Asset inventory complete and live         | cloud + CMDB      | HARD | done    |
| C03 | 21(2)(b)        | Centralised logging active                | SIEM + cloud      | HARD | done    |
| C04 | 21(2)(b)        | Detection and alerting operational        | SIEM rules        | HARD | done    |
| C05 | 21(2)(b)        | 24h/72h incident notification procedure   | runbooks          | SOFT | done    |
| C06 | 21(2)(c)        | Backups exist and are recent              | backup API        | HARD | done    |
| C07 | 21(2)(c)        | Backups restore-tested                    | restore logs      | HARD | done    |
| C08 | 21(2)(c)        | Immutable / offline backup copy           | storage config    | HARD | done    |
| C09 | 21(2)(d)        | Dependency inventory (SBOM)               | repos + build     | HARD | done    |
| C10 | 21(2)(d)        | Known CVEs in dependencies                | SBOM + OSV/NVD     | HARD | done    |
| C11 | 21(2)(d)        | Critical supplier risk assessed           | vendor list       | SOFT | done    |
| C12 | 21(2)(e)        | Periodic vulnerability scanning           | scanner API       | HARD | done    |
| C13 | 21(2)(e)        | CI/CD security (SAST + secret scanning)   | pipeline config   | HARD | done    |
| C14 | 21(2)(e)        | System patch management                   | endpoints + cloud | HARD | done    |
| C15 | 21(2)(e)        | Vulnerability disclosure process          | security.txt      | SOFT | done    |
| C16 | 21(2)(g)        | Security training completed               | HR/LMS            | HARD | done    |
| C17 | 21(2)(h)        | Encryption at rest                        | cloud + DB config | HARD | done    |
| C18 | 21(2)(h)        | Encryption in transit (healthy TLS)       | endpoint scan     | HARD | done    |
| C19 | 21(2)(i)        | Access control: orphan & over-privileged  | IdP + HR          | HARD | done    |
| C20 | 21(2)(j)        | Multi-factor authentication enforced      | IdP config        | HARD | done    |

Implementation order favoured high-pain + low-effort HARD controls first:
C20, C19, C17, C06, C10, C03, C14, C18.

## Evidence sources

Each control consumes typed Facts, so it runs unchanged against a mock fixture,
a real offline tool export (Core), or a live cloud API (Enterprise). For the
exact CLI flags and the JSON shapes Core accepts, see **[USAGE.md](USAGE.md)**.

| Control(s)      | Core source (offline export / fixture, flag)               | ⊕ Enterprise (live API)            |
|-----------------|------------------------------------------------------------|------------------------------------|
| C01/C05/C11/C15 | governance records JSON (`--governance`)                   | —                                  |
| C02             | asset inventory JSON (`--assets`)                          | AWS / GCP / Azure (`--aws`/`--gcp`/`--azure`) |
| C03             | SIEM export JSON (`--siem`)                                | AWS CloudTrail (`--aws-monitoring`) |
| C04             | SIEM export JSON (`--siem`)                                | —                                  |
| C06/C07/C08     | Veeam B&R report (`--veeam`), restic (`--restic`)          | —                                  |
| C09             | CycloneDX BOM (`--cyclonedx`)                              | —                                  |
| C10             | osv-scanner JSON (`--osv`)                                 | —                                  |
| C12             | asset JSON (`--assets`), Trivy scan JSON (`--trivy`)       | —                                  |
| C13             | CI/CD pipeline config JSON (`--pipeline`)                  | GitHub REST API (`--github`)       |
| C14             | asset JSON (`--assets`)                                    | AWS SSM patch state (`--aws-monitoring`) |
| C16             | HR/LMS training records JSON (`--training`)               | —                                  |
| C17             | cloud config JSON (`--cloud`)                              | AWS / GCP / Azure (`--aws`/`--gcp`/`--azure`) |
| C18             | testssl.sh (`--testssl`), sslyze (`--sslyze`)             | —                                  |
| C19/C20         | IdP export JSON (`--source`)                               | Microsoft Entra ID / Graph (`--entra`) |

> **⊕ Enterprise (live connectors).** AWS (×2), GCP, Azure, Microsoft Entra ID,
> and GitHub connectors authenticate to the live API (stdlib `urllib`, zero
> third-party deps), read credentials **from the environment only** (never CLI
> flags), and emit the exact same facts as the Core offline connectors above —
> so every control runs unchanged. They ship in the proprietary overlay; see
> [TIERING.md](TIERING.md).

### Offline tool exports (Core)

Core ingests the JSON output of free, offline scanners and backup tools — no
credentials, no live access. Generate the export, hand the file to Probity:

- **osv-scanner** `--osv` → C10 (dependency CVEs).
- **Trivy** `--trivy` → C12 (vulnerability scanning). One `vulnscan.target` per
  scanned artifact; what C12 verifies is scan *freshness* (Trivy's `CreatedAt`
  becomes `last_scan`, a missing timestamp reads as stale — fail-closed). A
  critical asset that was never scanned produces no fact, so pair `--trivy` with
  an inventory source (`--assets`) to catch that gap.
- **CycloneDX** `--cyclonedx` → C09 (SBOM present and current).
- **testssl.sh** / **sslyze** `--testssl` / `--sslyze` → C18 (TLS health).
- **Veeam B&R** / **restic** `--veeam` / `--restic` → C06/C07/C08. restic covers
  C06 only (one backup job per host, latest snapshot); it omits restore-test and
  immutability signals, so C07/C08 fail closed honestly.

The exact command to produce each export and the JSON Probity expects are in
**[USAGE.md](USAGE.md)**.

### SOFT controls and human validation

C01/C05/C11/C15 reason over governance artifacts (policies, procedures, supplier
risk assessments) whose *existence and currency* are machine-checkable but whose
*adequacy* is not. `--governance` reads a JSON export from a GRC / policy tool:

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

These controls **never auto-PASS**. The contract is honest about the limit of
automation: an artifact that is absent or past its review date is a hard `FAIL`;
an artifact that is present and current is `PARTIAL` carrying
`requires_human_validation: true` — surfaced with a `⚑` in the text report and a
flag in the JSON — so an auditor still judges the content. C11 returns
`NOT_APPLICABLE` when no critical/high supplier is on record.

### HARD monitoring and asset-plane controls

C02/C03/C04/C12/C13/C14/C16 are deterministic and fail closed on missing or
stale evidence. They share `controls/freshness.py`: a timestamp that is absent
or unparseable is **never** treated as fresh, so a gap in telemetry reads as a
gap in control — not a silent pass. Each control returns `NOT_APPLICABLE` when
nothing in scope is collected (e.g. no critical assets), `PASS` when every
in-scope item is healthy, and `FAIL` listing the offenders in its `Evidence`.

Four file-backed connectors stand in for the real sources and emit the same
typed facts a live integration would:

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

Freshness windows: assets 7d, logging 24h, detection 90d, scanning 30d,
patching 30d, training 365d.

## Cross-framework mapping (⊕ Enterprise)

The same evidence answers more than one regulation. Each control's NIS2 article
is the single source of truth (read from each finding's own `nis2_refs`); DORA
and EU AI Act cross-references are derived without duplicating any control. This
mapping (`probity scan --framework {nis2,dora,ai_act,all}`) ships in the
Enterprise overlay as a `probity.scan_addons` plugin.
