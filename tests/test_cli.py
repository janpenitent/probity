import json
from pathlib import Path

from probity.cli import main

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
    control_ids = {f["control_id"] for f in report["findings"]}
    assert "C20" in control_ids


def test_scan_with_cloud_source_includes_c17(capsys):
    # Arrange / Act
    from pathlib import Path

    cloud = str(Path(FIXTURE).parent / "cloud_sample.json")
    rc = main(["scan", "--source", FIXTURE, "--cloud", cloud, "--format", "json"])
    out = capsys.readouterr().out

    # Assert
    report = json.loads(out)
    ids = {f["control_id"] for f in report["findings"]}
    assert "C17" in ids
    assert rc == 1  # unencrypted volumes present
