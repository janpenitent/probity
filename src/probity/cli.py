from __future__ import annotations

import argparse
from collections.abc import Sequence

from probity.connectors.base import Connector
from probity.connectors.mock_backup import MockBackupConnector
from probity.connectors.mock_cloud import MockCloudConnector
from probity.connectors.mock_idp import MockIdpConnector
from probity.connectors.mock_sbom import MockSbomConnector
from probity.connectors.mock_sca import MockScaConnector
from probity.connectors.mock_tls import MockTlsConnector
from probity.controls.base import Control
from probity.controls.c06_backups import C06Backups
from probity.controls.c07_restore import C07Restore
from probity.controls.c08_immutable import C08Immutable
from probity.controls.c09_sbom import C09Sbom
from probity.controls.c10_cves import C10Cves
from probity.controls.c17_encryption import C17Encryption
from probity.controls.c18_tls import C18Tls
from probity.controls.c19_access import C19Access
from probity.controls.c20_mfa import C20Mfa
from probity.engine.runner import Scan
from probity.model.enums import Status
from probity.model.finding import Report
from probity.report.html_report import to_html
from probity.report.json_report import to_json

# Registry of active controls. New controls are appended here as they land.
CONTROLS: list[Control] = [
    C06Backups(),
    C07Restore(),
    C08Immutable(),
    C09Sbom(),
    C10Cves(),
    C17Encryption(),
    C18Tls(),
    C19Access(),
    C20Mfa(),
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probity", description="Continuous NIS2 compliance evidence."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run controls against sources and emit findings.")
    scan.add_argument("--source", required=True, help="Path to identity source JSON (mock_idp).")
    scan.add_argument("--cloud", help="Path to cloud storage source JSON (mock_cloud).")
    scan.add_argument("--tls", help="Path to TLS endpoint source JSON (mock_tls).")
    scan.add_argument("--backup", help="Path to backup-jobs source JSON (mock_backup).")
    scan.add_argument("--sca", help="Path to dependency/CVE source JSON (mock_sca).")
    scan.add_argument("--sbom", help="Path to SBOM component source JSON (mock_sbom).")
    scan.add_argument("--format", choices=["text", "json", "html"], default="text")
    return parser


def _render_text(report: Report) -> str:
    lines = [f"Probity scan — score {report.score}%  {report.counts()}"]
    for finding in report.findings:
        lines.append(
            f"[{finding.status.value.upper():>14}] {finding.control_id} "
            f"{finding.title} — {finding.summary}"
        )
        for ev in finding.evidence:
            lines.append(f"    - {ev.description} ({len(ev.items)} items)")
    return "\n".join(lines)


def _render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return to_json(report)
    if fmt == "html":
        return to_html(report)
    return _render_text(report)


def _run_scan(
    source: str,
    cloud: str | None,
    tls: str | None,
    backup: str | None,
    sca: str | None,
    sbom: str | None,
    fmt: str,
) -> int:
    connectors: list[Connector] = [MockIdpConnector(source)]
    if cloud:
        connectors.append(MockCloudConnector(cloud))
    if tls:
        connectors.append(MockTlsConnector(tls))
    if backup:
        connectors.append(MockBackupConnector(backup))
    if sca:
        connectors.append(MockScaConnector(sca))
    if sbom:
        connectors.append(MockSbomConnector(sbom))
    report = Scan(connectors, CONTROLS).run()
    print(_render(report, fmt))
    failed = any(f.status is Status.FAIL for f in report.findings)
    return 1 if failed else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _run_scan(
            args.source, args.cloud, args.tls, args.backup, args.sca, args.sbom,
            args.format,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
