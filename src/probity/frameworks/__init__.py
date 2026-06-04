"""Multi-framework mapping.

The same control evidence answers more than one regulation. A control's NIS2
references live on the control itself (single source of truth); this package
adds the cross-references to other frameworks (DORA, EU AI Act) and computes
per-framework coverage from a :class:`~probity.model.finding.Report` without
modifying any control.
"""

from __future__ import annotations
