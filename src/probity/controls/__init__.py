# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Control registry.

``ALL_CONTROLS`` is the single source of truth for the active NIS2 control
catalogue. The runner and CLI consume it instead of hand-maintaining their own
lists, so a control cannot be silently dropped from a scan. Adding a control is
two lines here (import + tuple entry); a guard test asserts the catalogue stays
complete and free of duplicate ids.
"""

from __future__ import annotations

from probity.controls.base import Control
from probity.controls.c01_security_policy import C01SecurityPolicy
from probity.controls.c02_asset_inventory import C02AssetInventory
from probity.controls.c03_logging import C03Logging
from probity.controls.c04_detection import C04Detection
from probity.controls.c05_incident_procedure import C05IncidentProcedure
from probity.controls.c06_backups import C06Backups
from probity.controls.c07_restore import C07Restore
from probity.controls.c08_immutable import C08Immutable
from probity.controls.c09_sbom import C09Sbom
from probity.controls.c10_cves import C10Cves
from probity.controls.c11_supplier_risk import C11SupplierRisk
from probity.controls.c12_vuln_scanning import C12VulnScanning
from probity.controls.c13_cicd_security import C13CicdSecurity
from probity.controls.c14_patch_management import C14PatchManagement
from probity.controls.c15_disclosure import C15Disclosure
from probity.controls.c16_training import C16Training
from probity.controls.c17_encryption import C17Encryption
from probity.controls.c18_tls import C18Tls
from probity.controls.c19_access import C19Access
from probity.controls.c20_mfa import C20Mfa

#: The active NIS2 control catalogue, in id order. Single source of truth.
ALL_CONTROLS: tuple[Control, ...] = (
    C01SecurityPolicy(),
    C02AssetInventory(),
    C03Logging(),
    C04Detection(),
    C05IncidentProcedure(),
    C06Backups(),
    C07Restore(),
    C08Immutable(),
    C09Sbom(),
    C10Cves(),
    C11SupplierRisk(),
    C12VulnScanning(),
    C13CicdSecurity(),
    C14PatchManagement(),
    C15Disclosure(),
    C16Training(),
    C17Encryption(),
    C18Tls(),
    C19Access(),
    C20Mfa(),
)

__all__ = ["ALL_CONTROLS"]
