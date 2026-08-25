"""The version has to be reachable from the CLI and true in both places.

The bug report form asks for the Probity version, so `probity --version` has to
answer it. And `__version__` is duplicated in `pyproject.toml`; if the two ever
disagree, a bug report names a build that does not exist.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import probity
from probity.cli import main

PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"


def test_version_flag_prints_the_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"probity {probity.__version__}"


def test_packaged_version_matches_the_module() -> None:
    packaged = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]

    assert packaged == probity.__version__
