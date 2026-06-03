import json
from pathlib import Path

from probanza.cli import main

FIXTURE = str(Path(__file__).parent / "fixtures" / "idp_sample.json")


def test_scan_text_returns_nonzero_when_a_control_fails(capsys):
    # Arrange / Act: fixture has accounts without MFA -> C20 fails
    code = main(["scan", "--source", FIXTURE])
    out = capsys.readouterr().out

    # Assert
    assert code == 1
    assert "C20" in out
    assert "score" in out.lower()


def test_scan_json_emits_parseable_report(capsys):
    # Act
    main(["scan", "--source", FIXTURE, "--format", "json"])
    out = capsys.readouterr().out

    # Assert
    report = json.loads(out)
    assert "findings" in report
    assert report["findings"][0]["control_id"] == "C20"
