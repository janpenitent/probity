# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Timestamp-freshness helpers shared by the asset-plane and monitoring controls.

Several HARD controls fail closed on a stale or missing timestamp (last scan,
last patch, last log event, last training). These helpers centralise that
parsing so the rule stays the same everywhere: a missing or unparseable value is
never treated as fresh.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def parse_ts(raw: object) -> datetime | None:
    """Parse an ISO-8601 timestamp to a tz-aware UTC datetime, else ``None``.

    Naive timestamps are assumed UTC. A missing or unparseable value yields
    ``None`` so callers can fail closed.
    """
    if not raw or not isinstance(raw, str):
        return None
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=UTC)


def is_stale(raw: object, now: datetime, max_age: timedelta) -> bool:
    """True when ``raw`` is missing, unparseable, or older than ``max_age``."""
    ts = parse_ts(raw)
    if ts is None:
        return True
    return (now - ts) > max_age


def utcnow(now: datetime | None = None) -> datetime:
    return now or datetime.now(UTC)
