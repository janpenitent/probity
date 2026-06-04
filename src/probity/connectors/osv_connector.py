# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Real software-composition connector backed by osv-scanner output.

Unlike :class:`~probity.connectors.mock_sca.MockScaConnector`, this reads the
JSON produced by the industry-standard `osv-scanner --format json` against a
real lockfile or directory. No credentials and no network are needed at scan
time: the operator runs osv-scanner (free, offline-capable) and hands Probity
the resulting file as auditable evidence.

It emits the same ``dependency`` facts as the mock connector, so the existing
C10 control consumes either source unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.connectors.mock_sca import DEPENDENCY_KIND
from probity.model.fact import Fact

# OSV severity labels -> the lowercase bands C10 grades against. "moderate" is
# OSV's word for what C10 calls "medium"; anything unmapped stays as-is and an
# empty/unknown severity is left blank so C10 fails closed on it.
_SEVERITY_MAP = {"moderate": "medium"}


class OsvConnector(Connector):
    """Emits one ``dependency`` fact per vulnerable/clean package found by OSV."""

    id = "osv"
    title = "Software Composition (osv-scanner JSON)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for result in payload.get("results", []):
            for entry in result.get("packages", []):
                pkg = entry.get("package", {})
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                data = {
                    "name": name,
                    "version": version,
                    "ecosystem": pkg.get("ecosystem", ""),
                    "vulnerabilities": [
                        _normalize_vuln(v) for v in entry.get("vulnerabilities", [])
                    ],
                }
                yield Fact(kind=DEPENDENCY_KIND, key=f"{name}@{version}", data=data)


def _normalize_vuln(vuln: dict[str, Any]) -> dict[str, Any]:
    """Reduce an OSV vulnerability to the {id, severity, fixed_version} shape."""
    return {
        "id": _preferred_id(vuln),
        "severity": _severity(vuln),
        "fixed_version": _fixed_version(vuln),
    }


def _preferred_id(vuln: dict[str, Any]) -> str:
    """Prefer a CVE alias (what auditors cite) over the OSV/GHSA database id."""
    for alias in vuln.get("aliases", []) or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return str(vuln.get("id", ""))


def _severity(vuln: dict[str, Any]) -> str:
    label = str(vuln.get("database_specific", {}).get("severity", "")).lower()
    return _SEVERITY_MAP.get(label, label)


def _fixed_version(vuln: dict[str, Any]) -> str:
    """First 'fixed' event across the affected ranges, if OSV recorded one."""
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""
