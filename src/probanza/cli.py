from __future__ import annotations

import argparse
from collections.abc import Sequence

from probanza.connectors.mock_idp import MockIdpConnector
from probanza.controls.base import Control
from probanza.controls.c20_mfa import C20Mfa
from probanza.engine.runner import Scan
from probanza.model.enums import Status
from probanza.model.finding import Report
from probanza.report.json_report import to_json

# Registry of active controls. New controls are appended here as they land.
CONTROLS: list[Control] = [C20Mfa()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probanza", description="Continuous NIS2 compliance evidence."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run controls against a source and emit findings.")
    scan.add_argument("--source", required=True, help="Path to identity source JSON (mock_idp).")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    return parser


def _render_text(report: Report) -> str:
    lines = [f"Probanza scan — score {report.score}%  {report.counts()}"]
    for finding in report.findings:
        lines.append(
            f"[{finding.status.value.upper():>14}] {finding.control_id} "
            f"{finding.title} — {finding.summary}"
        )
        for ev in finding.evidence:
            lines.append(f"    - {ev.description} ({len(ev.items)} items)")
    return "\n".join(lines)


def _run_scan(source: str, fmt: str) -> int:
    report = Scan([MockIdpConnector(source)], CONTROLS).run()
    print(to_json(report) if fmt == "json" else _render_text(report))
    failed = any(f.status is Status.FAIL for f in report.findings)
    return 1 if failed else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _run_scan(args.source, args.format)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
