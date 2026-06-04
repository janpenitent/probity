# NIS2 Control Catalogue

Controls map NIS2 Article 21(2) measures to concrete technical checks.

- **HARD** = deterministic (API/config returns a yes/no). Cheap, objective.
- **SOFT** = requires reasoning over policy text; flagged for human validation.

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

Implementation order favours high-pain + low-effort HARD controls first:
C20, C19, C17, C06, C10, C03, C14, C18.

## Evidence sources

Each control consumes typed Facts, so it runs unchanged against either a mock
fixture or a real tool export:

| Control(s)   | Real connector (flag)                                  |
|--------------|--------------------------------------------------------|
| C06/C07/C08  | Veeam B&R job report (`--veeam`), restic (`--restic`)  |
| C09          | CycloneDX BOM (`--cyclonedx`)                           |
| C10          | osv-scanner JSON (`--osv`)                              |
| C18          | testssl.sh (`--testssl`), sslyze (`--sslyze`)          |
| C19/C20      | **live** Microsoft Entra ID / Graph API (`--entra`)    |
| C01/C05/C11/C15 | governance records JSON (`--governance`)            |
| C02/C12/C14  | asset management JSON (`--assets`)                      |
| C12          | Trivy scan JSON (`--trivy`) — real scanner export       |
| C03/C04      | SIEM export JSON (`--siem`)                             |
| C13          | CI/CD pipeline config JSON (`--pipeline`)              |
| C16          | HR/LMS training records JSON (`--training`)            |

`--entra` is the first *live* connector: it authenticates to Microsoft Graph
(OAuth2 client-credentials, stdlib `urllib`, zero deps) and emits the same
`identity.account` facts as the mock, so C19/C20 run unchanged. Credentials come
from the environment (`PROBITY_ENTRA_TENANT_ID`, `PROBITY_ENTRA_CLIENT_ID`,
`PROBITY_ENTRA_CLIENT_SECRET`), never CLI flags. `hr_active` is a sign-in
staleness proxy (Entra has no HR feed): an account with no successful sign-in in
90 days is treated as inactive so C19 surfaces it — fail-closed.

`--trivy` ingests a real `trivy ... --format json` export (free, offline, no
credentials) and emits one `vulnscan.target` per scanned artifact, so C12 runs
unchanged against either the mock or a real scan. What C12 verifies is scan
*freshness*: Trivy's `CreatedAt` becomes `last_scan`, and a missing timestamp
(older Trivy builds) reads as stale — fail-closed. Each scanned artifact is
treated as in scope; a critical asset that was never scanned produces no fact,
so pair `--trivy` with an inventory source (`--assets`) to catch that gap. A
single report object or a JSON array of reports are both accepted.

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

## Cross-framework mapping

The same evidence answers more than one regulation. Each control's NIS2 article
is the single source of truth; DORA and EU AI Act cross-references live in
`probity.frameworks.mapping` and are reported with
`probity scan --framework {nis2,dora,ai_act,all}` — no control is duplicated.
