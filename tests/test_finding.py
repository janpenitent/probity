from probanza.model.enums import Severity, Status
from probanza.model.finding import Evidence, Finding, Report


def _finding(status: Status) -> Finding:
    return Finding("C00", "t", Severity.HIGH, status, "s")


def test_report_score_weights_partial_as_half():
    # Arrange
    report = Report((
        _finding(Status.PASS),
        _finding(Status.FAIL),
        _finding(Status.PARTIAL),
    ))

    # Act / Assert: (1 + 0 + 0.5) / 3 = 50.0
    assert report.score == 50.0


def test_report_score_ignores_non_scored_statuses():
    # Arrange
    report = Report((
        _finding(Status.PASS),
        _finding(Status.NOT_APPLICABLE),
        _finding(Status.ERROR),
    ))

    # Act / Assert: only PASS is scored -> 100%
    assert report.score == 100.0


def test_report_score_zero_when_nothing_scored():
    assert Report((_finding(Status.NOT_APPLICABLE),)).score == 0.0


def test_finding_serialises_evidence():
    # Arrange
    finding = Finding(
        "C20", "MFA", Severity.CRITICAL, Status.FAIL, "2 accounts",
        nis2_refs=("Art.21(2)(j)",),
        evidence=(Evidence("missing mfa", ({"id": "u2"},)),),
    )

    # Act
    data = finding.to_dict()

    # Assert
    assert data["control_id"] == "C20"
    assert data["status"] == "fail"
    assert data["evidence"][0]["items"] == [{"id": "u2"}]
