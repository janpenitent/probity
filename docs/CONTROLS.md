# NIS2 Control Catalogue

Controls map NIS2 Article 21(2) measures to concrete technical checks.

- **HARD** = deterministic (API/config returns a yes/no). Cheap, objective.
- **SOFT** = requires reasoning over policy text; flagged for human validation.

| ID  | NIS2 ref        | Control                                   | Source            | Type | Status  |
|-----|-----------------|-------------------------------------------|-------------------|------|---------|
| C01 | 21(2)(a)        | Security policy exists and is current     | docs              | SOFT | done    |
| C02 | 21(2)(a)(i)     | Asset inventory complete and live         | cloud + CMDB      | HARD | planned |
| C03 | 21(2)(b)        | Centralised logging active                | SIEM + cloud      | HARD | planned |
| C04 | 21(2)(b)        | Detection and alerting operational        | SIEM rules        | HARD | planned |
| C05 | 21(2)(b)        | 24h/72h incident notification procedure   | runbooks          | SOFT | done    |
| C06 | 21(2)(c)        | Backups exist and are recent              | backup API        | HARD | done    |
| C07 | 21(2)(c)        | Backups restore-tested                    | restore logs      | HARD | done    |
| C08 | 21(2)(c)        | Immutable / offline backup copy           | storage config    | HARD | done    |
| C09 | 21(2)(d)        | Dependency inventory (SBOM)               | repos + build     | HARD | done    |
| C10 | 21(2)(d)        | Known CVEs in dependencies                | SBOM + OSV/NVD     | HARD | done    |
| C11 | 21(2)(d)        | Critical supplier risk assessed           | vendor list       | SOFT | done    |
| C12 | 21(2)(e)        | Periodic vulnerability scanning           | scanner API       | HARD | planned |
| C13 | 21(2)(e)        | CI/CD security (SAST + secret scanning)   | pipeline config   | HARD | planned |
| C14 | 21(2)(e)        | System patch management                   | endpoints + cloud | HARD | planned |
| C15 | 21(2)(e)        | Vulnerability disclosure process          | security.txt      | SOFT | done    |
| C16 | 21(2)(g)        | Security training completed               | HR/LMS            | HARD | planned |
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

`--entra` is the first *live* connector: it authenticates to Microsoft Graph
(OAuth2 client-credentials, stdlib `urllib`, zero deps) and emits the same
`identity.account` facts as the mock, so C19/C20 run unchanged. Credentials come
from the environment (`PROBITY_ENTRA_TENANT_ID`, `PROBITY_ENTRA_CLIENT_ID`,
`PROBITY_ENTRA_CLIENT_SECRET`), never CLI flags. `hr_active` is a sign-in
staleness proxy (Entra has no HR feed): an account with no successful sign-in in
90 days is treated as inactive so C19 surfaces it — fail-closed.

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

## Cross-framework mapping

The same evidence answers more than one regulation. Each control's NIS2 article
is the single source of truth; DORA and EU AI Act cross-references live in
`probity.frameworks.mapping` and are reported with
`probity scan --framework {nis2,dora,ai_act,all}` — no control is duplicated.
