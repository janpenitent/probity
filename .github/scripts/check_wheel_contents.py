"""Fail the build if the wheel carries anything that is not Core.

Probity is open-core: the paid modules live in a separate overlay repo and
must never reach the AGPL wheel. This has already gone wrong once — a wheel
built before the modules were moved out still bundled them. A build-time
assertion is cheaper than noticing on PyPI.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

# Top-level packages under src/probity that the Core is allowed to ship.
CORE_PACKAGES = frozenset(
    {
        "commands",
        "connectors",
        "controls",
        "engine",
        "model",
        "report",
        "scan_addons",
    }
)


def wheel_path() -> Path:
    wheels = sorted(Path("dist").glob("*.whl"))
    if not wheels:
        sys.exit("no wheel found in dist/ — did `python -m build` run?")
    if len(wheels) > 1:
        sys.exit(f"expected one wheel in dist/, found {len(wheels)}: {wheels}")
    return wheels[0]


def offending_members(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()

    offenders = []
    for name in names:
        parts = name.split("/")
        if not parts or parts[0] != "probity":
            continue
        if len(parts) < 3:
            continue  # a module directly under probity/, always Core
        if parts[1] not in CORE_PACKAGES:
            offenders.append(name)
    return offenders


def main() -> int:
    wheel = wheel_path()
    offenders = offending_members(wheel)
    if offenders:
        print(f"{wheel.name} ships non-Core packages:", file=sys.stderr)
        for name in sorted(offenders):
            print(f"  {name}", file=sys.stderr)
        return 1
    print(f"{wheel.name}: Core packages only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
