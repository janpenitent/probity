# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

from datetime import UTC, datetime

from probity.model.enums import Severity, Status
from probity.model.finding import Evidence, Finding, Report
from probity.report.html_report import to_html

GEN_AT = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)


def _report(*findings: Finding) -> Report:
    return Report(findings=findings, generated_at=GEN_AT)


def _finding(**kw) -> Finding:
    base = dict(
        control_id="C20",
        title="MFA enforced",
        severity=Severity.HIGH,
        status=Status.PASS,
        summary="All users have MFA.",
        nis2_refs=("Art.21(2)(g)",),
        evidence=(),
    )
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


def test_renders_self_contained_html_document():
    html = to_html(_report(_finding()))
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "<html" in html and "</html>" in html
    # self-contained: styles inlined, no external links
    assert "<style" in html
    assert "http://" not in html and "https://" not in html


def test_includes_score_and_counts():
    html = to_html(_report(_finding(status=Status.PASS), _finding(status=Status.FAIL)))
    assert "50.0" in html  # one pass, one fail -> 50%
    assert "generated" in html.lower()


def test_renders_one_section_per_finding():
    html = to_html(
        _report(
            _finding(control_id="C17", title="Encryption at rest"),
            _finding(control_id="C18", title="TLS in transit"),
        )
    )
    assert "C17" in html and "Encryption at rest" in html
    assert "C18" in html and "TLS in transit" in html


def test_renders_evidence_items_as_rows():
    finding = _finding(
        status=Status.FAIL,
        evidence=(Evidence("Offenders", ({"id": "u1", "reason": "no_mfa"},)),),
    )
    html = to_html(_report(finding))
    assert "Offenders" in html
    assert "u1" in html and "no_mfa" in html


def test_escapes_html_in_dynamic_values():
    # a summary containing markup must not break out of the document
    finding = _finding(summary="<script>alert('x')</script>")
    html = to_html(_report(finding))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_status_appears_as_class_for_styling():
    html = to_html(_report(_finding(status=Status.FAIL)))
    assert "fail" in html.lower()
