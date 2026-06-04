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


def test_scan_with_tls_source_includes_c18(capsys):
    from pathlib import Path

    tls = str(Path(FIXTURE).parent / "tls_sample.json")
    rc = main(["scan", "--source", FIXTURE, "--tls", tls, "--format", "json"])
    out = capsys.readouterr().out

    report = json.loads(out)
    ids = {f["control_id"] for f in report["findings"]}
    assert "C18" in ids
    assert rc == 1  # obsolete TLS / bad certs present


def test_history_records_snapshot_and_reports_trend(capsys, tmp_path):
    store = str(tmp_path / "history.jsonl")

    # First scan: no prior history -> "first recorded scan"
    main(["scan", "--source", FIXTURE, "--history", store])
    first = capsys.readouterr().out
    assert "first recorded scan" in first.lower()

    # Second scan against the same store -> trend line vs previous
    main(["scan", "--source", FIXTURE, "--history", store])
    second = capsys.readouterr().out
    assert "trend" in second.lower()
    assert "vs previous" in second.lower()

    # Store is append-only: two lines recorded
    assert len(Path(store).read_text().splitlines()) == 2
