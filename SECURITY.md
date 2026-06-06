# Security Policy

Probity is a security and compliance tool, so we hold its own posture to the same
bar it checks for (this is control **C15 — vulnerability disclosure process** —
applied to ourselves).

## Supported versions

Probity Core is pre-1.0. Security fixes are applied to the latest released
version on PyPI and the `main` branch. Older versions are not maintained — please
upgrade before reporting against an old release.

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |
| < latest| :x:                |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either of:

- **GitHub Security Advisories** — the "Report a vulnerability" button under the
  repository's **Security** tab (preferred; keeps the report private and
  coordinated).
- **Email** — `jrodriguez@virtualcable.es` with subject `PROBITY SECURITY`.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal proof of concept if possible).
- The affected version (`probity --version` or the commit SHA) and environment.

## What to expect

- **Acknowledgement** within a few business days.
- An assessment of severity and an indication of a fix timeline.
- Coordinated disclosure: we will agree a disclosure date with you and credit you
  in the advisory and changelog unless you prefer to remain anonymous.

## Scope

In scope: the Probity Core codebase published from this repository.

Out of scope: vulnerabilities in your own evidence exports or third-party tools
whose output Probity merely ingests (osv-scanner, Trivy, etc.), and issues that
require a pre-compromised host or non-default, unsupported configuration.

Because Core has **zero runtime dependencies** (Python standard library only),
the third-party dependency attack surface is limited to your Python runtime
itself.

## A note on credentials

Core never reads credentials — it operates on offline files. The Enterprise
overlay's live connectors read credentials **from the environment only**, never
from CLI flags or files, so secrets do not land in shell history or scan inputs.
Report credential-handling concerns through the same private channel above.
