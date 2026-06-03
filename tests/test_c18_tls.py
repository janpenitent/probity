from probity.connectors.mock_tls import TLS_KIND
from probity.controls.c18_tls import C18Tls
from probity.model.enums import Status
from probity.model.fact import Fact, FactSet


def _ep(id: str, version: str | None = "1.3", valid: bool = True, days: int = 90) -> dict:
    data: dict = {"id": id, "host": id, "cert_valid": valid, "cert_expires_in_days": days}
    if version is not None:
        data["tls_version"] = version
    return data


def _endpoints(*specs: dict) -> FactSet:
    return FactSet([Fact(TLS_KIND, str(s["id"]), s) for s in specs])


def test_passes_when_all_endpoints_modern_tls_valid_cert():
    facts = _endpoints(_ep("e1", "1.2", days=90), _ep("e2", "1.3", days=10))
    assert C18Tls().evaluate(facts).status is Status.PASS


def test_fails_on_obsolete_protocol():
    finding = C18Tls().evaluate(_endpoints(_ep("e1", "1.1")))
    assert finding.status is Status.FAIL
    assert "obsolete_tls" in finding.evidence[0].items[0]["reasons"]


def test_fails_on_invalid_or_expired_cert():
    facts = _endpoints(_ep("e1", "1.3", valid=False), _ep("e2", "1.3", days=-1))
    finding = C18Tls().evaluate(facts)
    assert finding.status is Status.FAIL
    assert {o["id"] for o in finding.evidence[0].items} == {"e1", "e2"}


def test_missing_tls_version_treated_as_failure():
    finding = C18Tls().evaluate(_endpoints(_ep("e1", version=None)))
    assert finding.status is Status.FAIL


def test_not_applicable_without_endpoints():
    assert C18Tls().evaluate(FactSet()).status is Status.NOT_APPLICABLE
