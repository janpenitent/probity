from probanza.model.fact import Fact, FactSet


def test_factset_filters_by_kind():
    # Arrange
    facts = FactSet([
        Fact("identity.account", "u1", {"mfa_enabled": True}),
        Fact("identity.account", "u2", {"mfa_enabled": False}),
        Fact("cloud.volume", "v1", {"encrypted": True}),
    ])

    # Act
    accounts = facts.of_kind("identity.account")

    # Assert
    assert len(accounts) == 2
    assert facts.kinds() == {"identity.account", "cloud.volume"}
    assert len(facts) == 3


def test_factset_merge_is_immutable():
    # Arrange
    a = FactSet([Fact("k", "1")])
    b = FactSet([Fact("k", "2")])

    # Act
    merged = a.merge(b)

    # Assert
    assert len(merged) == 2
    assert len(a) == 1  # original untouched
