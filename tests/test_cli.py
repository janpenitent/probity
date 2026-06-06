# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

import json
from datetime import UTC, datetime, timedelta
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


def test_scan_without_any_source_errors():
    # With no flags at all, no connector resolves and the scan is refused.
    # Live cloud sources (--aws/--entra/...) are Enterprise-only and arrive via
    # the connector entry point, so they are not tested in Core.
    try:
        main(["scan"])
    except SystemExit as exc:
        assert "evidence source" in str(exc.code)
    else:  # pragma: no cover - guard against silent success
        raise AssertionError("expected SystemExit when no source is given")


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


def test_scan_with_trivy_feeds_c12(capsys, tmp_path):
    # a real Trivy report with a recent CreatedAt should drive C12 to pass.
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "CreatedAt": "2099-01-01T00:00:00+00:00",
                "ArtifactName": "prod-db:latest",
                "ArtifactType": "container_image",
                "Results": [],
            }
        )
    )
    main(["scan", "--source", FIXTURE, "--trivy", str(report), "--format", "json"])
    out = capsys.readouterr().out
    c12 = next(f for f in json.loads(out)["findings"] if f["control_id"] == "C12")
    assert c12["status"] == "pass"


def test_scan_with_hard_sources_feeds_all_hard_controls(capsys, tmp_path):
    # The HARD controls apply freshness windows against the wall clock, so a
    # static fixture rots: its "fresh" timestamps eventually fall outside the
    # window and the healthy case starts failing on a later run date. Build the
    # fixture relative to now so this test stays date-independent.
    now = datetime.now(UTC)

    def ago(**kw: int) -> str:
        return (now - timedelta(**kw)).isoformat()

    fixture = tmp_path / "hard.json"
    fixture.write_text(
        json.dumps(
            {
                "assets": [
                    {"id": "vm-1", "name": "prod-db", "type": "vm",
                     "managed": True, "last_seen": ago(hours=1)},
                ],
                "vulnscans": [
                    {"id": "vm-1", "asset": "prod-db", "critical": True,
                     "last_scan": ago(days=5), "scanner": "nessus"},
                ],
                "patches": [
                    {"id": "vm-1", "host": "prod-db", "critical": True,
                     "last_patched": ago(days=5), "pending_critical": 0},
                ],
                "log_sources": [
                    {"id": "src-1", "asset": "prod-db", "critical": True,
                     "forwarding": True, "last_event": ago(hours=1)},
                ],
                "detection_rules": [
                    {"id": "rule-1", "name": "Impossible travel",
                     "enabled": True, "last_tested": ago(days=10)},
                ],
                "pipelines": [
                    {"id": "repo-app", "repo": "org/app",
                     "sast_enabled": True, "secret_scanning_enabled": True},
                ],
                "training": [
                    {"id": "u-1", "person": "Alice", "required": True,
                     "completed_at": ago(days=30)},
                ],
            }
        )
    )
    hard = str(fixture)
    # the healthy hard fixture should drive every HARD control to pass.
    main(
        [
            "scan",
            "--source",
            FIXTURE,
            "--assets",
            hard,
            "--siem",
            hard,
            "--pipeline",
            hard,
            "--training",
            hard,
            "--format",
            "json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    by_id = {f["control_id"]: f for f in report["findings"]}
    for cid in ("C02", "C03", "C04", "C12", "C13", "C14", "C16"):
        assert by_id[cid]["status"] == "pass", cid
