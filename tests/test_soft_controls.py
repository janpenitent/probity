# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""SOFT (policy-reasoned) controls: C01, C05, C11, C15 and the governance feed.

SOFT controls never auto-PASS: a present, current artifact is PARTIAL with
``requires_human_validation=True``; an absent or overdue artifact is a hard FAIL.
"""

from datetime import date

from probity.connectors.mock_governance import (
    DOCUMENT_KIND,
    SUPPLIER_KIND,
    MockGovernanceConnector,
)
from probity.controls.c01_security_policy import C01SecurityPolicy
from probity.controls.c05_incident_procedure import C05IncidentProcedure
from probity.controls.c11_supplier_risk import C11SupplierRisk
from probity.controls.c15_disclosure import C15Disclosure
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet

NOW = date(2026, 6, 4)


def _docs(*docs: dict) -> FactSet:
    return FactSet([Fact(DOCUMENT_KIND, str(d["id"]), d) for d in docs])


def _suppliers(*suppliers: dict) -> FactSet:
    return FactSet([Fact(SUPPLIER_KIND, str(s["id"]), s) for s in suppliers])


# --- DocumentControl contract via C01 -------------------------------------


def test_document_absent_fails():
    finding = C01SecurityPolicy(NOW).evaluate(FactSet())
    assert finding.status is Status.FAIL
    assert finding.requires_human_validation is False


def test_document_present_and_current_is_partial_pending_human():
    facts = _docs(
        {
            "id": "pol-sec",
            "type": "security_policy",
            "title": "InfoSec Policy",
            "approved_at": "2025-09-01",
            "review_due": "2026-09-01",
        }
    )
    finding = C01SecurityPolicy(NOW).evaluate(facts)
    assert finding.status is Status.PARTIAL
    assert finding.requires_human_validation is True
    assert finding.evidence[0].items[0]["id"] == "pol-sec"


def test_document_past_review_due_fails():
    facts = _docs(
        {
            "id": "pol-sec",
            "type": "security_policy",
            "title": "InfoSec Policy",
            "approved_at": "2024-01-01",
            "review_due": "2026-01-01",
        }
    )
    finding = C01SecurityPolicy(NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert "review" in finding.summary.lower()


def test_document_without_review_due_is_current():
    facts = _docs({"id": "pol-sec", "type": "security_policy", "title": "InfoSec"})
    assert C01SecurityPolicy(NOW).evaluate(facts).status is Status.PARTIAL


def test_wrong_doc_type_is_invisible_to_control():
    # an incident procedure must not satisfy the security-policy control
    facts = _docs({"id": "ir", "type": "incident_procedure", "title": "IR"})
    assert C01SecurityPolicy(NOW).evaluate(facts).status is Status.FAIL


def test_c05_matches_its_own_doc_type():
    facts = _docs(
        {"id": "ir", "type": "incident_procedure", "title": "IR", "review_due": "2027-01-01"}
    )
    finding = C05IncidentProcedure(NOW).evaluate(facts)
    assert finding.status is Status.PARTIAL
    assert finding.control_id == "C05"


def test_c15_matches_its_own_doc_type():
    facts = _docs({"id": "vd", "type": "disclosure_policy", "title": "CVD"})
    finding = C15Disclosure(NOW).evaluate(facts)
    assert finding.status is Status.PARTIAL
    assert finding.control_id == "C15"


# --- C11 supplier risk ----------------------------------------------------


def test_c11_not_applicable_without_critical_suppliers():
    facts = _suppliers({"id": "s1", "name": "Minor", "criticality": "low"})
    finding = C11SupplierRisk(NOW).evaluate(facts)
    assert finding.status is Status.NOT_APPLICABLE


def test_c11_current_assessment_is_partial_pending_human():
    facts = _suppliers(
        {"id": "s1", "name": "AcmeCloud", "criticality": "high", "risk_assessed_at": "2026-01-15"}
    )
    finding = C11SupplierRisk(NOW).evaluate(facts)
    assert finding.status is Status.PARTIAL
    assert finding.requires_human_validation is True


def test_c11_stale_assessment_fails():
    facts = _suppliers(
        {
            "id": "s1",
            "name": "AcmeCloud",
            "criticality": "critical",
            "risk_assessed_at": "2024-01-01",
        }
    )
    finding = C11SupplierRisk(NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    assert finding.evidence[0].items[0]["id"] == "s1"


def test_c11_missing_assessment_fails():
    facts = _suppliers({"id": "s1", "name": "AcmeCloud", "criticality": "high"})
    finding = C11SupplierRisk(NOW).evaluate(facts)
    assert finding.status is Status.FAIL


def test_c11_mixed_lists_only_the_overdue():
    facts = _suppliers(
        {"id": "ok", "name": "Good", "criticality": "high", "risk_assessed_at": "2026-01-15"},
        {
            "id": "bad",
            "name": "Stale",
            "criticality": "critical",
            "risk_assessed_at": "2020-01-01",
        },
        {"id": "minor", "name": "Minor", "criticality": "low"},
    )
    finding = C11SupplierRisk(NOW).evaluate(facts)
    assert finding.status is Status.FAIL
    ids = {i["id"] for i in finding.evidence[0].items}
    assert ids == {"bad"}
    assert "1 of 2" in finding.summary


# --- Governance connector -------------------------------------------------


def test_governance_connector_emits_documents_and_suppliers():
    payload = {
        "documents": [{"id": "d1", "type": "security_policy", "title": "P"}],
        "suppliers": [{"id": "s1", "name": "Acme", "criticality": "high"}],
    }
    facts = list(MockGovernanceConnector(payload).collect())
    assert {f.kind for f in facts} == {DOCUMENT_KIND, SUPPLIER_KIND}
    assert len(facts) == 2


def test_governance_connector_reads_from_file(tmp_path):
    import json

    path = tmp_path / "gov.json"
    path.write_text(
        json.dumps({"documents": [{"id": "d1", "type": "security_policy", "title": "P"}]})
    )
    facts = list(MockGovernanceConnector(str(path)).collect())
    assert facts[0].kind == DOCUMENT_KIND
    assert facts[0].key == "d1"


def test_governance_connector_tolerates_empty_payload():
    assert list(MockGovernanceConnector({}).collect()) == []
