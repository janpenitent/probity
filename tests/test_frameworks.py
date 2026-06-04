from __future__ import annotations

from probity.frameworks.mapping import (
    Framework,
    all_coverage,
    coverage,
)
from probity.model.enums import Severity, Status
from probity.model.finding import Finding, Report


def _finding(control_id: str, status: Status, nis2_refs: tuple[str, ...]) -> Finding:
    return Finding(
        control_id=control_id,
        title=f"{control_id} title",
        severity=Severity.HIGH,
        status=status,
        summary="synthetic",
        nis2_refs=nis2_refs,
        evidence=(),
    )


def _report(*findings: Finding) -> Report:
    return Report(findings=tuple(findings))


def test_nis2_coverage_reads_refs_from_finding() -> None:
    report = _report(
        _finding("C20", Status.PASS, ("Art.21(2)(d)",)),
        _finding("C06", Status.FAIL, ("Art.21(2)(c)",)),
    )

    fc = coverage(report, Framework.NIS2)

    assert fc.framework is Framework.NIS2
    assert fc.mapped_count == 2
    by_id = {c.control_id: c for c in fc.controls}
    assert by_id["C20"].refs == ("Art.21(2)(d)",)
    assert by_id["C06"].refs == ("Art.21(2)(c)",)


def test_dora_coverage_reads_refs_from_crossref_table() -> None:
    report = _report(
        _finding("C06", Status.PASS, ("Art.21(2)(c)",)),
        _finding("C07", Status.PASS, ("Art.21(2)(c)",)),
    )

    fc = coverage(report, Framework.DORA)

    by_id = {c.control_id: c for c in fc.controls}
    assert by_id["C06"].refs == ("Art.12(1)",)
    assert by_id["C07"].refs == ("Art.11", "Art.12(2)")


def test_ai_act_excludes_controls_without_crossref() -> None:
    # C06 has no AI Act mapping; C09 does.
    report = _report(
        _finding("C06", Status.PASS, ("Art.21(2)(c)",)),
        _finding("C09", Status.PASS, ("Art.21(2)(e)",)),
    )

    fc = coverage(report, Framework.AI_ACT)

    ids = {c.control_id for c in fc.controls}
    assert ids == {"C09"}


def test_score_excludes_na_and_error() -> None:
    report = _report(
        _finding("C09", Status.PASS, ("x",)),  # DORA + AI Act
        _finding("C10", Status.FAIL, ("x",)),  # DORA + AI Act
        _finding("C17", Status.NOT_APPLICABLE, ("x",)),  # DORA + AI Act
        _finding("C18", Status.ERROR, ("x",)),  # DORA + AI Act
    )

    fc = coverage(report, Framework.DORA)

    # Only PASS (1.0) and FAIL (0.0) are scored → 50%.
    assert fc.score == 50.0
    assert fc.mapped_count == 4


def test_partial_counts_as_half() -> None:
    report = _report(
        _finding("C09", Status.PASS, ("x",)),
        _finding("C10", Status.PARTIAL, ("x",)),
    )

    fc = coverage(report, Framework.DORA)

    # (1.0 + 0.5) / 2 = 75%.
    assert fc.score == 75.0


def test_score_zero_when_no_scored_controls() -> None:
    report = _report(_finding("C09", Status.NOT_APPLICABLE, ("x",)))

    fc = coverage(report, Framework.DORA)

    assert fc.score == 0.0
    assert fc.mapped_count == 1


def test_all_coverage_returns_every_framework_in_order() -> None:
    report = _report(_finding("C09", Status.PASS, ("Art.21(2)(e)",)))

    views = all_coverage(report)

    assert tuple(v.framework for v in views) == (
        Framework.NIS2,
        Framework.DORA,
        Framework.AI_ACT,
    )


def test_unmapped_control_excluded_from_all_frameworks() -> None:
    # A control id not in CONTROL_CROSSREFS and with no nis2 refs maps nowhere.
    report = _report(_finding("C99", Status.PASS, ()))

    for fc in all_coverage(report):
        assert fc.mapped_count == 0
        assert fc.score == 0.0
