# Probity Tiering — Open-Core Model

This document defines the boundary between the free open-source **Core** and the
paid proprietary **Enterprise** edition, the licensing of each, and the plan to
separate them into two repositories.

> Status: planning. Nothing has been moved yet — the whole codebase currently
> lives in the AGPL Core repo (`github.com/janpenitent/probity`). This document
> is the agreed target.

## 1. Strategy

Probity follows an **open-core** model (the same shape Virtual Cable uses for
OpenUDS: open base + closed `enterprise/` overlay), with one deliberate
difference: Probity's Core is **AGPL-3.0**, not permissive.

**Why AGPL for the Core (and not BSD/MIT like OpenUDS):** OpenUDS can afford a
permissive license because a full VDI broker is hard to clone — its moat is
complexity plus the enterprise overlay. Probity is the opposite: small, pure
Python, trivially forkable. A permissive license would let anyone fork the Core,
add the Enterprise features themselves, and out-market us. AGPL is the moat this
product needs:

- Nobody can take the Core closed — not even behind a SaaS (AGPL's network
  clause forces source disclosure).
- **Dual licensing** becomes a revenue lever: companies whose legal teams forbid
  AGPL buy a commercial license instead. AGPL-aversion becomes a sales trigger,
  not just a blocker (the GitLab / MongoDB play).

## 2. Tier boundary

The cut: **Core is genuinely useful on its own** (an auditor can self-serve a
one-shot scan over offline exports), while the work that actually saves an
organisation time — connecting live cloud accounts and watching continuously —
is **Enterprise**.

### Core — free, AGPL-3.0 — "the auditor self-serves"

- All 20 NIS2 controls (C01–C20) — the compliance logic *is* the transparency
  that builds trust; keeping it open is marketing for a compliance tool.
- Offline / file-backed connectors: OSV, Trivy, CycloneDX, testssl, sslyze,
  Veeam, Restic, and the mock connectors. No secrets, no ops.
- One-shot `scan` via the CLI.
- Reporting: JSON, text, HTML.
- The Connector → Control → Report framework (so the community can write their
  own connectors).

### Enterprise — paid, proprietary — "automation and scale"

- Live cloud connectors: AWS (×2), GCP, Azure, Entra, GitHub — the real
  labour-saver: point it at your accounts and it collects evidence itself.
- Service layer: `watch` (scheduler), `serve` (dashboard), alerts / webhooks.
- Inspector-grade audit PDF.
- Multi-framework mapping: DORA, EU AI Act.
- Multi-tenant, RBAC, scaled history / trends.
- Support and SLA.

> Note: some Enterprise items (PDF, multi-framework, dashboard) already exist in
> the current Core codebase. Moving them to the closed edition is fine — we own
> the copyright and can relicense what we hold (see §4).

## 3. Repository separation plan

Phased so the Core stays green and installable throughout.

1. **Define the seam (this doc).** ✅
2. **Carve an extension point in Core** so Enterprise can register connectors,
   report formats, and service commands without forking the CLI — mirror the
   existing connector-registry pattern (entry points / plugin discovery). ✅
   Done for **connectors** (`probity.plugins.load_plugins`,
   `connectors.registry.ConnectorSource` / group `probity.connectors`) and
   **report formats** (`report.registry.ReportFormat` / group
   `probity.report_formats`). Service commands (`watch`/`serve`) are not yet
   pluggable — defer until they actually move to Enterprise in step 4.
3. **Create the closed Enterprise repo** (`probity-enterprise`, private),
   overlaying Core the way `enterprise/` overlays `openuds/` — symlink/install
   into a shared venv for dev. ✅
   Done: private repo `github.com/janpenitent/probity-enterprise`, sibling
   `~/work/probity-enterprise`, proprietary license, hatchling + ruff/mypy
   mirroring Core. Carries a smoke overlay (`enterprise-health` report format,
   `--enterprise-demo` connector source) that proves cross-package discovery
   end to end via Core's entry-point groups. Dev install:
   `pip install -e ../probity-enterprise --no-deps` into Core's venv. Core also
   gained a PEP 561 `py.typed` marker so the overlay (and PyPI consumers) see
   its types.
4. **Move the Enterprise modules** out of Core into the new repo; in Core leave
   only the framework + offline connectors + JSON/text/HTML + the 20 controls.
   Keep Core's tests green after each move.
5. **Relicense moved Enterprise modules** to the commercial license; Core stays
   AGPL.
6. **Publish Core to PyPI** as the shopfront (`pip install probity`).
7. **Commercial licensing**: add a `COMMERCIAL-LICENSE.md` / contact path for the
   AGPL dual-license offer.

## 4. Open questions for the owner (legal, not technical)

- **Copyright holder.** Headers currently say "Janier Rodríguez", but commits use
  `@virtualcable.es` and OpenUDS copyrights to **Virtual Cable S.L.U.** Dual
  licensing requires a single, clear copyright owner. If Probity was built on
  company time/resources it may already belong to Virtual Cable. This decides
  *who can sell the commercial license and who earns*. Resolve internally before
  any commercial offer.
- **Contributor License Agreement (CLA).** To keep the right to dual-license, any
  outside contributions to Core need a CLA assigning rights to the copyright
  holder. Add one before accepting external PRs.

## 5. Reality check

Probity is **v0.1.0 / beta** — built fast, 308 tests, CI green. The architecture
and the licensing strategy are sound, but selling to paying customers still needs
real-world validation, user docs, and the Enterprise layer actually split out and
hardened. This document is the plan, not a finished product.
