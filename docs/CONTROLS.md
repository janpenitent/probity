# NIS2 Control Catalogue

Controls map NIS2 Article 21(2) measures to concrete technical checks.

- **HARD** = deterministic (API/config returns a yes/no). Cheap, objective.
- **SOFT** = requires reasoning over policy text; flagged for human validation.

| ID  | NIS2 ref        | Control                                   | Source            | Type | Status  |
|-----|-----------------|-------------------------------------------|-------------------|------|---------|
| C01 | 21(2)(a)        | Security policy exists and is current     | docs              | SOFT | planned |
| C02 | 21(2)(a)(i)     | Asset inventory complete and live         | cloud + CMDB      | HARD | planned |
| C03 | 21(2)(b)        | Centralised logging active                | SIEM + cloud      | HARD | planned |
| C04 | 21(2)(b)        | Detection and alerting operational        | SIEM rules        | HARD | planned |
| C05 | 21(2)(b)        | 24h/72h incident notification procedure   | runbooks          | SOFT | planned |
| C06 | 21(2)(c)        | Backups exist and are recent              | backup API        | HARD | planned |
| C07 | 21(2)(c)        | Backups restore-tested                    | restore logs      | HARD | planned |
| C08 | 21(2)(c)        | Immutable / offline backup copy           | storage config    | HARD | planned |
| C09 | 21(2)(d)        | Dependency inventory (SBOM)               | repos + build     | HARD | planned |
| C10 | 21(2)(d)        | Known CVEs in dependencies                | SBOM + OSV/NVD     | HARD | planned |
| C11 | 21(2)(d)        | Critical supplier risk assessed           | vendor list       | SOFT | planned |
| C12 | 21(2)(e)        | Periodic vulnerability scanning           | scanner API       | HARD | planned |
| C13 | 21(2)(e)        | CI/CD security (SAST + secret scanning)   | pipeline config   | HARD | planned |
| C14 | 21(2)(e)        | System patch management                   | endpoints + cloud | HARD | planned |
| C15 | 21(2)(e)        | Vulnerability disclosure process          | security.txt      | SOFT | planned |
| C16 | 21(2)(g)        | Security training completed               | HR/LMS            | HARD | planned |
| C17 | 21(2)(h)        | Encryption at rest                        | cloud + DB config | HARD | planned |
| C18 | 21(2)(h)        | Encryption in transit (healthy TLS)       | endpoint scan     | HARD | planned |
| C19 | 21(2)(i)        | Access control: orphan & over-privileged  | IdP + HR          | HARD | planned |
| C20 | 21(2)(j)        | Multi-factor authentication enforced      | IdP config        | HARD | done    |

Implementation order favours high-pain + low-effort HARD controls first:
C20, C19, C17, C06, C10, C03, C14, C18.
