# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

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


def test_scan_pdf_writes_file(capsys, tmp_path):
    out = tmp_path / "evidence.pdf"
    rc = main(["scan", "--source", FIXTURE, "--format", "pdf", "--out", str(out)])
    assert rc in (0, 1)  # exit code reflects findings, not output success
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    assert b"%%EOF" in data
    assert str(out) in capsys.readouterr().out


def test_scan_pdf_without_out_errors(capsys):
    try:
        main(["scan", "--source", FIXTURE, "--format", "pdf"])
    except SystemExit as exc:
        assert "requires --out" in str(exc.code)
    else:  # pragma: no cover - guard against silent success
        raise AssertionError("expected SystemExit when --out is missing")


def test_scan_with_cyclonedx_feeds_c09(capsys, tmp_path):
    # a real CycloneDX BOM with a current timestamp should pass C09
    bom = tmp_path / "bom.json"
    bom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {"timestamp": "2026-06-01T00:00:00+00:00"},
                "components": [{"type": "library", "name": "requests", "version": "2.32.0"}],
            }
        )
    )
    main(["scan", "--source", FIXTURE, "--cyclonedx", str(bom), "--format", "json"])
    out = capsys.readouterr().out
    report = json.loads(out)
    c09 = next(f for f in report["findings"] if f["control_id"] == "C09")
    assert c09["status"] == "pass"


def test_scan_with_single_framework_prints_coverage(capsys):
    main(["scan", "--source", FIXTURE, "--framework", "dora"])
    out = capsys.readouterr().out
    assert "Framework coverage" in out
    assert "DORA Regulation" in out
    # NIS2-only and AI-Act titles must not appear for a single dora view.
    assert "AI Act" not in out


def test_scan_with_all_frameworks_prints_every_view(capsys):
    main(["scan", "--source", FIXTURE, "--framework", "all"])
    out = capsys.readouterr().out
    assert "NIS2 Directive" in out
    assert "DORA Regulation" in out
    assert "EU AI Act" in out


def test_scan_without_identity_source_errors():
    try:
        main(["scan", "--cloud", str(Path(FIXTURE).parent / "cloud_sample.json")])
    except SystemExit as exc:
        assert "identity source" in str(exc.code)
    else:  # pragma: no cover - guard against silent success
        raise AssertionError("expected SystemExit when no identity source is given")


def test_scan_entra_without_env_errors(monkeypatch):
    for var in (
        "PROBITY_ENTRA_TENANT_ID",
        "PROBITY_ENTRA_CLIENT_ID",
        "PROBITY_ENTRA_CLIENT_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    try:
        main(["scan", "--entra"])
    except SystemExit as exc:
        assert "PROBITY_ENTRA_TENANT_ID" in str(exc.code)
    else:  # pragma: no cover - guard against silent success
        raise AssertionError("expected SystemExit when Entra env vars are unset")


def test_scan_with_governance_feeds_soft_controls(capsys, tmp_path):
    # a current security policy makes C01 partial (pending human validation),
    # never an auto-pass; an absent disclosure policy fails C15.
    gov = tmp_path / "gov.json"
    gov.write_text(
        json.dumps(
            {
                "documents": [
                    {
                        "id": "pol-sec",
                        "type": "security_policy",
                        "title": "InfoSec Policy",
                        "review_due": "2099-01-01",
                    }
                ],
                "suppliers": [],
            }
        )
    )
    main(["scan", "--source", FIXTURE, "--governance", str(gov), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    c01 = next(f for f in report["findings"] if f["control_id"] == "C01")
    assert c01["status"] == "partial"
    assert c01["requires_human_validation"] is True
    c15 = next(f for f in report["findings"] if f["control_id"] == "C15")
    assert c15["status"] == "fail"
