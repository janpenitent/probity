# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Janier Rodríguez

"""Self-contained PDF evidence pack.

Renders a :class:`Report` to a paginated PDF with no third-party dependencies.
The project ships zero runtime deps on purpose, so this is a minimal pure-Python
PDF writer: a single Courier text column, hand-built xref table, uncompressed
content streams. Like the HTML pack it references nothing external — safe to
email, archive, or hand to an auditor offline.

Only the 14 standard PDF fonts are used (Courier), so no font embedding is
needed and every viewer can open the result.
"""

from __future__ import annotations

from probity.model.finding import Evidence, Finding, Report

# US Letter at 72 dpi, generous margins for an audit document.
_PAGE_W, _PAGE_H = 612, 792
_MARGIN = 54
_FONT_SIZE = 10
_LEADING = 14
_TOP = _PAGE_H - _MARGIN
_BOTTOM = _MARGIN
_LINES_PER_PAGE = int((_TOP - _BOTTOM) / _LEADING)
# Courier glyphs are 600/1000 em wide; chars that fit across the text column.
_WRAP = int((_PAGE_W - 2 * _MARGIN) / (_FONT_SIZE * 0.6))


def to_pdf(report: Report) -> bytes:
    """Render ``report`` to a complete, self-contained PDF document."""
    lines = _report_lines(report)
    pages = [lines[i : i + _LINES_PER_PAGE] for i in range(0, len(lines), _LINES_PER_PAGE)] or [[]]
    return _assemble(pages)


def _report_lines(report: Report) -> list[str]:
    """Flatten a report into the ordered text lines that fill the pages."""
    counts = ", ".join(f"{status} {n}" for status, n in report.counts().items() if n)
    lines = [
        "PROBITY - NIS2 COMPLIANCE EVIDENCE PACK",
        "",
        f"Compliance score: {report.score} / 100",
        f"Findings: {counts}",
        f"Generated: {report.generated_at.isoformat()}",
        "",
        "-" * _WRAP,
        "",
    ]
    for finding in report.findings:
        lines.extend(_finding_lines(finding))
    lines.append("Probity - continuous, auditable NIS2 compliance evidence.")
    return lines


def _finding_lines(finding: Finding) -> list[str]:
    out = [f"[{finding.status.value.upper()}] {finding.control_id}  {finding.title}"]
    out.extend(_wrap(finding.summary, indent="    "))
    if finding.nis2_refs:
        out.append(f"    NIS2: {', '.join(finding.nis2_refs)}")
    for ev in finding.evidence:
        out.extend(_evidence_lines(ev))
    out.append("")
    return out


def _evidence_lines(evidence: Evidence) -> list[str]:
    out = [f"    Evidence: {evidence.description}"]
    for item in evidence.items:
        pairs = "  ".join(f"{k}={v}" for k, v in item.items())
        out.extend(_wrap(pairs, indent="      - "))
    return out


def _wrap(text: str, *, indent: str) -> list[str]:
    """Greedy word-wrap to the Courier column width, preserving the indent."""
    width = max(1, _WRAP - len(indent))
    words = text.split()
    if not words:
        return [indent.rstrip()]
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(indent + current)
            current = word
        else:
            current = candidate
    lines.append(indent + current)
    return lines


def _escape(text: str) -> str:
    """Escape the three PDF literal-string metacharacters; drop non-Latin-1."""
    escaped = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    return escaped.encode("latin-1", "replace").decode("latin-1")


def _content_stream(lines: list[str]) -> bytes:
    """One page's text drawing operators (BT/ET with per-line offsets)."""
    body = [f"BT /F1 {_FONT_SIZE} Tf {_LEADING} TL {_MARGIN} {_TOP - _FONT_SIZE} Td"]
    for i, line in enumerate(lines):
        leading = "T*" if i else ""  # first line already positioned by Td
        body.append(f"{leading} ({_escape(line)}) Tj".strip())
    body.append("ET")
    return "\n".join(body).encode("latin-1")


def _assemble(pages: list[list[str]]) -> bytes:
    """Build the object table, xref, and trailer into final PDF bytes."""
    # Object layout: 1=Catalog, 2=Pages, 3=Font, then per page (Page, Contents).
    page_obj_ids = [4 + 2 * i for i in range(len(pages))]
    kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("latin-1"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    for pid, page in zip(page_obj_ids, pages, strict=True):
        contents_id = pid + 1
        objects.append(
            f"<< /Type /Page\n /Parent 2 0 R "
            f"/MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R >> >> "
            f"/Contents {contents_id} 0 R >>".encode("latin-1")
        )
        stream = _content_stream(page)
        objects.append(
            b"<< /Length %d >>\nstream\n%b\nendstream" % (len(stream), stream)
        )

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%b\nendobj\n" % (i, body)

    xref_pos = len(out)
    count = len(objects) + 1  # +1 for the free object 0
    out += b"xref\n0 %d\n" % count
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % count
    out += b"startxref\n%d\n%%%%EOF\n" % xref_pos
    return bytes(out)
