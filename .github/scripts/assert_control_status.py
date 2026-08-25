"""Assert that a control reached an expected status in a Probity JSON report.

Used by the dogfood CI job: Probity scans its own supply chain and this turns
one finding into a build gate, so a regression in our own evidence breaks the
build instead of sitting unread in an artifact.

Usage: assert_control_status.py REPORT.json CONTROL_ID EXPECTED_STATUS
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_ARGUMENT_COUNT = 3


def finding_for(report: dict[str, Any], control_id: str) -> dict[str, Any]:
    for finding in report.get("findings", []):
        if finding.get("control_id") == control_id:
            return dict(finding)
    sys.exit(f"{control_id} is not in the report")


def main(argv: list[str]) -> int:
    if len(argv) != EXPECTED_ARGUMENT_COUNT:
        sys.exit("usage: assert_control_status.py REPORT.json CONTROL_ID EXPECTED_STATUS")
    report_path, control_id, expected = argv
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    finding = finding_for(report, control_id)
    actual = finding.get("status")
    if actual != expected:
        print(
            f"{control_id} is {actual!r}, expected {expected!r}: {finding.get('summary')}",
            file=sys.stderr,
        )
        return 1
    print(f"{control_id} {actual}: {finding.get('summary')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
