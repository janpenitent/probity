# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Service layer: scheduled scans, regression alerting, and a read-only dashboard.

Everything here is zero-dependency stdlib: ``threading`` drives the scan loop,
``http.server`` serves the dashboard, and ``urllib`` posts webhook alerts. The
append-only JSONL history (:mod:`probity.report.history`) is the only store, so
Probity stays a single ``pip install`` with no database to operate.
"""

from __future__ import annotations
