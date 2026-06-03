from probity.connectors.mock_cloud import STORAGE_KIND
from probity.controls.c17_encryption import C17Encryption
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet


def _volumes(*specs: dict) -> FactSet:
    return FactSet([Fact(STORAGE_KIND, str(s["id"]), s) for s in specs])


def test_passes_when_all_volumes_encrypted():
    facts = _volumes(
        {"id": "v1", "encrypted": True},
        {"id": "v2", "encrypted": True, "contains_pii": True},
    )
    assert C17Encryption().evaluate(facts).status is Status.PASS


def test_fails_and_lists_unencrypted_volumes():
    facts = _volumes(
        {"id": "v1", "encrypted": True},
        {"id": "v2", "encrypted": False},
        {"id": "v3", "encrypted": False, "contains_pii": True},
    )
    finding = C17Encryption().evaluate(facts)
    assert finding.status is Status.FAIL
    ids = {o["id"] for o in finding.evidence[0].items}
    assert ids == {"v2", "v3"}
    # an unencrypted PII volume is the worst case, surfaced in summary
    assert "1 with PII" in finding.summary


def test_missing_encrypted_flag_treated_as_unencrypted():
    # unknown encryption state must not silently pass
    finding = C17Encryption().evaluate(_volumes({"id": "v1"}))
    assert finding.status is Status.FAIL


def test_not_applicable_without_volumes():
    assert C17Encryption().evaluate(FactSet()).status is Status.NOT_APPLICABLE
