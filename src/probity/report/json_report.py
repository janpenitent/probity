from __future__ import annotations

import json

from probity.model.finding import Report


def to_json(report: Report, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)
