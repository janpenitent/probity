from datetime import UTC, datetime

from probity.model.enums import Severity, Status
from probity.model.finding import Evidence, Finding, Report
from probity.report.pdf_report import to_pdf

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


def test_emits_valid_pdf_envelope():
    pdf = to_pdf(_report(_finding()))
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf
    # cross-reference table + trailer are mandatory for a loadable PDF
    assert b"xref" in pdf
    assert b"trailer" in pdf
    assert b"/Root" in pdf


def test_self_contained_no_external_references():
    # like the HTML pack: nothing to fetch, safe to archive offline
    pdf = to_pdf(_report(_finding()))
    assert b"http://" not in pdf and b"https://" not in pdf


def test_includes_score_and_control_text():
    pdf = to_pdf(_report(_finding(status=Status.PASS), _finding(status=Status.FAIL)))
    # uncompressed content stream -> human-readable text appears verbatim
    assert b"50" in pdf  # one pass, one fail -> 50%
    assert b"C20" in pdf
    assert b"MFA enforced" in pdf


def test_renders_evidence_items():
    finding = _finding(
        status=Status.FAIL,
        evidence=(Evidence("Offenders", ({"id": "u1", "reason": "no_mfa"},)),),
    )
    pdf = to_pdf(_report(finding))
    assert b"Offenders" in pdf
    assert b"u1" in pdf and b"no_mfa" in pdf


def test_escapes_pdf_string_metacharacters():
    # parens and backslashes are PDF string delimiters; unescaped -> corrupt file
    finding = _finding(summary="balance (50%) \\ pending")
    pdf = to_pdf(_report(finding))
    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf
    assert rb"\(50%\)" in pdf  # parens escaped in the content stream


def test_paginates_across_many_findings():
    findings = tuple(_finding(control_id=f"C{i:02d}", title=f"Control {i}") for i in range(60))
    pdf = to_pdf(_report(*findings))
    # more than one page object emitted for a long report
    assert pdf.count(b"/Type /Page\n") >= 2
    assert b"C59" in pdf  # last finding still rendered


def test_byte_offsets_in_xref_are_accurate():
    # a malformed xref makes the PDF unopenable even if bytes look plausible
    pdf = to_pdf(_report(_finding(), _finding(status=Status.FAIL)))
    _, _, tail = pdf.rpartition(b"startxref")
    startxref = int(tail.strip().split(b"\n")[0])
    # the offset recorded in startxref must point at the 'xref' keyword
    assert pdf[startxref : startxref + 4] == b"xref"
