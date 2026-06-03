from pathlib import Path

from probity.connectors.mock_idp import ACCOUNT_KIND, MockIdpConnector

FIXTURE = Path(__file__).parent / "fixtures" / "idp_sample.json"


def test_connector_emits_one_fact_per_account_from_file():
    # Arrange
    connector = MockIdpConnector(FIXTURE)

    # Act
    facts = list(connector.collect())

    # Assert
    assert len(facts) == 5
    assert all(f.kind == ACCOUNT_KIND for f in facts)
    assert facts[0].data["display_name"] == "Alice Admin"


def test_connector_accepts_inline_dict():
    # Arrange
    connector = MockIdpConnector({"accounts": [{"id": "x"}]})

    # Act
    facts = list(connector.collect())

    # Assert
    assert len(facts) == 1
    assert facts[0].key == "x"


def test_connector_does_not_raise_on_empty_source():
    assert list(MockIdpConnector({}).collect()) == []
