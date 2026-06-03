from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

from probity.connectors.base import Connector
from probity.model.fact import Fact

ACCOUNT_KIND = "identity.account"


class MockIdpConnector(Connector):
    """File-backed identity provider connector for development and tests.

    Source JSON shape::

        {"accounts": [
            {"id": "u1", "display_name": "Alice", "enabled": true,
             "privileged": true, "mfa_enabled": true, "hr_active": true}
        ]}

    Every account becomes one ``identity.account`` fact.
    """

    id = "mock_idp"
    title = "Mock Identity Provider (file-backed)"

    def __init__(self, source: str | Path | dict[str, Any]) -> None:
        self._source = source

    def _load(self) -> dict[str, Any]:
        if isinstance(self._source, dict):
            return self._source
        raw = Path(self._source).read_text(encoding="utf-8")
        return cast(dict[str, Any], json.loads(raw))

    def collect(self) -> Iterable[Fact]:
        payload = self._load()
        for account in payload.get("accounts", []):
            yield Fact(kind=ACCOUNT_KIND, key=str(account["id"]), data=dict(account))
