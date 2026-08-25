"""Assert that the pushed git tag matches the version in pyproject.toml.

A tag and a version that disagree publish a wheel nobody can trace back to a
commit, and the mistake is only visible once it is already on PyPI, where a
version can never be reused.

Usage: check_tag_matches_version.py TAG   (e.g. v0.1.0)
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

EXPECTED_ARGUMENT_COUNT = 1
TAG_PREFIX = "v"


def packaged_version() -> str:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    return str(pyproject["project"]["version"])


def version_in(tag: str) -> str:
    if not tag.startswith(TAG_PREFIX):
        sys.exit(f"tag {tag!r} does not start with {TAG_PREFIX!r}")
    return tag[len(TAG_PREFIX) :]


def main(argv: list[str]) -> int:
    if len(argv) != EXPECTED_ARGUMENT_COUNT:
        sys.exit("usage: check_tag_matches_version.py TAG")
    tagged = version_in(argv[0])
    packaged = packaged_version()
    if tagged != packaged:
        print(
            f"tag says {tagged!r} but pyproject.toml says {packaged!r}",
            file=sys.stderr,
        )
        return 1
    print(f"tag and package agree on {packaged}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
