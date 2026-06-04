# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence

from probity.connectors.base import Connector
from probity.connectors.cyclonedx_connector import CycloneDxConnector
from probity.connectors.entra_connector import EntraConnector
from probity.connectors.mock_assets import MockAssetsConnector
from probity.connectors.mock_backup import MockBackupConnector
from probity.connectors.mock_cloud import MockCloudConnector
from probity.connectors.mock_governance import MockGovernanceConnector
from probity.connectors.mock_idp import MockIdpConnector
from probity.connectors.mock_pipeline import MockPipelineConnector
from probity.connectors.mock_sbom import MockSbomConnector
from probity.connectors.mock_sca import MockScaConnector
from probity.connectors.mock_siem import MockSiemConnector
from probity.connectors.mock_tls import MockTlsConnector
from probity.connectors.mock_training import MockTrainingConnector
from probity.connectors.osv_connector import OsvConnector
from probity.connectors.restic_connector import ResticConnector
from probity.connectors.sslyze_connector import SslyzeConnector
from probity.connectors.testssl_connector import TesttsslConnector
from probity.connectors.trivy_connector import TrivyConnector
from probity.connectors.veeam_connector import VeeamConnector
from probity.controls.base import Control
from probity.controls.c01_security_policy import C01SecurityPolicy
from probity.controls.c02_asset_inventory import C02AssetInventory
from probity.controls.c03_logging import C03Logging
from probity.controls.c04_detection import C04Detection
from probity.controls.c05_incident_procedure import C05IncidentProcedure
from probity.controls.c06_backups import C06Backups
from probity.controls.c07_restore import C07Restore
from probity.controls.c08_immutable import C08Immutable
from probity.controls.c09_sbom import C09Sbom
from probity.controls.c10_cves import C10Cves
from probity.controls.c11_supplier_risk import C11SupplierRisk
from probity.controls.c12_vuln_scanning import C12VulnScanning
from probity.controls.c13_cicd_security import C13CicdSecurity
from probity.controls.c14_patch_management import C14PatchManagement
from probity.controls.c15_disclosure import C15Disclosure
from probity.controls.c16_training import C16Training
from probity.controls.c17_encryption import C17Encryption
from probity.controls.c18_tls import C18Tls
from probity.controls.c19_access import C19Access
from probity.controls.c20_mfa import C20Mfa
from probity.engine.runner import Scan
from probity.frameworks.mapping import Framework, FrameworkCoverage, all_coverage, coverage
from probity.model.enums import Status
from probity.model.finding import Report
from probity.report.history import Trend, append_snapshot, compute_trend, load_snapshots
from probity.report.html_report import to_html
from probity.report.json_report import to_json
from probity.report.pdf_report import to_pdf
from probity.service.dashboard import serve
from probity.service.scheduler import AlertSinks, ScanScheduler

# Registry of active controls. New controls are appended here as they land.
CONTROLS: list[Control] = [
    C01SecurityPolicy(),
    C02AssetInventory(),
    C03Logging(),
    C04Detection(),
    C05IncidentProcedure(),
    C06Backups(),
    C07Restore(),
    C08Immutable(),
    C09Sbom(),
    C10Cves(),
    C11SupplierRisk(),
    C12VulnScanning(),
    C13CicdSecurity(),
    C14PatchManagement(),
    C15Disclosure(),
    C16Training(),
    C17Encryption(),
    C18Tls(),
    C19Access(),
    C20Mfa(),
]


# Env vars holding the Entra app-registration credentials. Never accepted as
# CLI flags (would leak into shell history / process listings) — read from the
# environment only, validated at connector construction.
_ENTRA_ENV = {
    "tenant_id": "PROBITY_ENTRA_TENANT_ID",
    "client_id": "PROBITY_ENTRA_CLIENT_ID",
    "client_secret": "PROBITY_ENTRA_CLIENT_SECRET",
}


def _add_source_args(parser: argparse.ArgumentParser) -> None:
    """Attach the shared connector-source flags used by ``scan`` and ``watch``.

    Identity facts come from either a file source (``--source``) or a live
    Entra tenant (``--entra``); at least one is required.
    """
    parser.add_argument("--source", help="Path to identity source JSON (mock_idp).")
    parser.add_argument(
        "--entra",
        action="store_true",
        help=(
            "Collect identities live from Microsoft Entra ID. Reads credentials from "
            f"{_ENTRA_ENV['tenant_id']}, {_ENTRA_ENV['client_id']}, "
            f"{_ENTRA_ENV['client_secret']}."
        ),
    )
    parser.add_argument("--cloud", help="Path to cloud storage source JSON (mock_cloud).")
    parser.add_argument("--tls", help="Path to TLS endpoint source JSON (mock_tls).")
    parser.add_argument("--testssl", help="Path to real testssl.sh --jsonfile output.")
    parser.add_argument("--sslyze", help="Path to real sslyze --json_out output.")
    parser.add_argument("--backup", help="Path to backup-jobs source JSON (mock_backup).")
    parser.add_argument("--veeam", help="Path to real Veeam B&R job-report JSON.")
    parser.add_argument("--restic", help="Path to real restic snapshots --json output.")
    parser.add_argument("--sca", help="Path to dependency/CVE source JSON (mock_sca).")
    parser.add_argument("--osv", help="Path to real osv-scanner --format json output.")
    parser.add_argument("--sbom", help="Path to SBOM component source JSON (mock_sbom).")
    parser.add_argument("--cyclonedx", help="Path to a real CycloneDX JSON BOM.")
    parser.add_argument(
        "--governance",
        help="Path to governance records JSON (documents + suppliers) for SOFT controls.",
    )
    parser.add_argument(
        "--assets",
        help="Path to asset-management JSON (assets + vulnscans + patches) for C02/C12/C14.",
    )
    parser.add_argument("--trivy", help="Path to real Trivy --format json output for C12.")
    parser.add_argument(
        "--siem",
        help="Path to SIEM JSON (log sources + detection rules) for C03/C04.",
    )
    parser.add_argument("--pipeline", help="Path to CI/CD pipeline config JSON for C13.")
    parser.add_argument("--training", help="Path to HR/LMS training records JSON for C16.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probity", description="Continuous NIS2 compliance evidence."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run controls against sources and emit findings.")
    _add_source_args(scan)
    scan.add_argument("--format", choices=["text", "json", "html", "pdf"], default="text")
    scan.add_argument(
        "--out",
        help="Write the report to this file instead of stdout (required for --format pdf).",
    )
    scan.add_argument(
        "--history",
        help="Append-only JSONL store; records this scan and reports the score trend.",
    )
    scan.add_argument(
        "--framework",
        choices=["nis2", "dora", "ai_act", "all"],
        help="Also print per-framework coverage mapping the same evidence to NIS2/DORA/AI Act.",
    )

    watch = sub.add_parser("watch", help="Run scans on a schedule and alert on regressions.")
    _add_source_args(watch)
    watch.add_argument(
        "--history", required=True, help="Append-only JSONL store the loop records into."
    )
    watch.add_argument(
        "--interval", type=float, default=3600.0, help="Seconds between scans (default 3600)."
    )
    watch.add_argument("--alert-file", help="Append regression alerts as JSONL to this path.")
    watch.add_argument("--alert-webhook", help="POST regression alerts as JSON to this URL.")
    watch.add_argument(
        "--once", action="store_true", help="Run a single scan tick and exit (no loop)."
    )

    serve_p = sub.add_parser("serve", help="Serve the read-only compliance dashboard.")
    serve_p.add_argument("--history", required=True, help="Append-only JSONL store to render.")
    serve_p.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1).")
    serve_p.add_argument("--port", type=int, default=8080, help="Bind port (default 8080).")
    return parser


def _render_text(report: Report) -> str:
    lines = [f"Probity scan — score {report.score}%  {report.counts()}"]
    for finding in report.findings:
        human = "  ⚑ requires human validation" if finding.requires_human_validation else ""
        lines.append(
            f"[{finding.status.value.upper():>14}] {finding.control_id} "
            f"{finding.title} — {finding.summary}{human}"
        )
        for ev in finding.evidence:
            lines.append(f"    - {ev.description} ({len(ev.items)} items)")
    return "\n".join(lines)


_TREND_ARROW = {"up": "▲", "down": "▼", "flat": "▬", "first": "•"}


def _render_trend(trend: Trend) -> str:
    arrow = _TREND_ARROW[trend.direction]
    if trend.previous is None:
        return f"Trend {arrow} first recorded scan — score {trend.current}%."
    sign = "+" if trend.delta >= 0 else ""
    return (
        f"Trend {arrow} {trend.direction} — score {trend.current}% "
        f"({sign}{trend.delta} vs previous {trend.previous}%)."
    )


def _render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return to_json(report)
    if fmt == "html":
        return to_html(report)
    return _render_text(report)


def _emit(report: Report, fmt: str, out: str | None) -> None:
    """Write the report in ``fmt`` to ``out`` (file) or stdout.

    PDF is binary and therefore always requires ``--out``; text formats print
    to stdout unless a path is given.
    """
    if fmt == "pdf":
        if not out:
            raise SystemExit("--format pdf requires --out FILE")
        with open(out, "wb") as fh:
            fh.write(to_pdf(report))
        print(f"Wrote PDF evidence pack to {out}")
        return
    rendered = _render(report, fmt)
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"Wrote {fmt} report to {out}")
    else:
        print(rendered)


def _entra_from_env() -> EntraConnector:
    """Build an EntraConnector from the credential env vars, or fail clearly."""
    creds: dict[str, str] = {}
    for arg, var in _ENTRA_ENV.items():
        value = os.environ.get(var)
        if not value:
            raise SystemExit(f"--entra requires {var} to be set in the environment")
        creds[arg] = value
    return EntraConnector(creds["tenant_id"], creds["client_id"], creds["client_secret"])


def _connectors_from_args(args: argparse.Namespace) -> list[Connector]:
    """Build the connector list from the shared source flags on ``args``.

    Identity facts (C19/C20) come from ``--source`` and/or ``--entra``; at
    least one must be supplied.
    """
    if not args.source and not args.entra:
        raise SystemExit("provide an identity source: --source FILE and/or --entra")
    connectors: list[Connector] = []
    if args.source:
        connectors.append(MockIdpConnector(args.source))
    if args.entra:
        connectors.append(_entra_from_env())
    if args.cloud:
        connectors.append(MockCloudConnector(args.cloud))
    if args.tls:
        connectors.append(MockTlsConnector(args.tls))
    if args.testssl:
        connectors.append(TesttsslConnector(args.testssl))
    if args.sslyze:
        connectors.append(SslyzeConnector(args.sslyze))
    if args.backup:
        connectors.append(MockBackupConnector(args.backup))
    if args.veeam:
        connectors.append(VeeamConnector(args.veeam))
    if args.restic:
        connectors.append(ResticConnector(args.restic))
    if args.sca:
        connectors.append(MockScaConnector(args.sca))
    if args.osv:
        connectors.append(OsvConnector(args.osv))
    if args.sbom:
        connectors.append(MockSbomConnector(args.sbom))
    if args.cyclonedx:
        connectors.append(CycloneDxConnector(args.cyclonedx))
    if args.governance:
        connectors.append(MockGovernanceConnector(args.governance))
    if args.assets:
        connectors.append(MockAssetsConnector(args.assets))
    if args.trivy:
        connectors.append(TrivyConnector(args.trivy))
    if args.siem:
        connectors.append(MockSiemConnector(args.siem))
    if args.pipeline:
        connectors.append(MockPipelineConnector(args.pipeline))
    if args.training:
        connectors.append(MockTrainingConnector(args.training))
    return connectors


def _render_coverage(fc: FrameworkCoverage) -> str:
    lines = [f"{fc.title} — score {fc.score}% ({fc.mapped_count} controls mapped)"]
    for c in fc.controls:
        refs = ", ".join(c.refs)
        lines.append(f"  [{c.status.upper():>14}] {c.control_id} {c.title} → {refs}")
    return "\n".join(lines)


def _emit_frameworks(report: Report, framework: str) -> None:
    if framework == "all":
        views = all_coverage(report)
    else:
        views = (coverage(report, Framework(framework)),)
    print("\nFramework coverage")
    for fc in views:
        print(_render_coverage(fc))


def _run_scan(args: argparse.Namespace) -> int:
    report = Scan(_connectors_from_args(args), CONTROLS).run()
    _emit(report, args.format, args.out)
    if args.history:
        append_snapshot(report, args.history)
        trend = compute_trend(load_snapshots(args.history))
        print(_render_trend(trend))
    if args.framework:
        _emit_frameworks(report, args.framework)
    failed = any(f.status is Status.FAIL for f in report.findings)
    return 1 if failed else 0


def _run_watch(args: argparse.Namespace) -> int:
    connectors = _connectors_from_args(args)
    sinks = AlertSinks(to_stdout=True, file=args.alert_file, webhook=args.alert_webhook)
    scheduler = ScanScheduler(
        scan_factory=lambda: Scan(connectors, CONTROLS).run(),
        history_path=args.history,
        interval_seconds=args.interval,
        sinks=sinks,
    )
    if args.once:
        alert = scheduler.tick()
        return 1 if alert.is_actionable else 0
    print(f"Probity watch — scanning every {args.interval:g}s into {args.history}. Ctrl-C to stop.")
    try:
        scheduler.run_forever()
    except KeyboardInterrupt:
        print("\nProbity watch stopped.")
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    serve(args.history, host=args.host, port=args.port)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "watch":
        return _run_watch(args)
    if args.command == "serve":
        return _run_serve(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
