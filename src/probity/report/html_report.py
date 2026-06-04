"""Self-contained HTML evidence pack.

Renders a :class:`Report` to a single standalone HTML document with inlined
styles and no external references — safe to email, archive, or hand to an
auditor offline. All dynamic values are HTML-escaped.
"""

from __future__ import annotations

from html import escape

from probity.model.enums import Status
from probity.model.finding import Evidence, Finding, Report

# Semantic status colours (oklch, audit-doc palette — calm, high-contrast).
_STATUS_COLOR = {
    Status.PASS.value: "oklch(62% 0.14 150)",
    Status.FAIL.value: "oklch(58% 0.20 25)",
    Status.PARTIAL.value: "oklch(72% 0.15 75)",
    Status.NOT_APPLICABLE.value: "oklch(60% 0 0)",
    Status.ERROR.value: "oklch(50% 0.18 25)",
}

_STYLE = """
:root {
  --bg: oklch(98% 0 0); --surface: oklch(100% 0 0); --text: oklch(20% 0 0);
  --muted: oklch(50% 0 0); --line: oklch(90% 0 0);
  --mono: ui-monospace, "SF Mono", "Cascadia Code", monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
}
.wrap { max-width: 900px; margin: 0 auto; padding: 4rem 1.5rem; }
header { border-bottom: 2px solid var(--text); padding-bottom: 1.5rem; margin-bottom: 2.5rem; }
.eyebrow { font: 600 0.75rem/1 var(--mono); letter-spacing: 0.18em;
  text-transform: uppercase; color: var(--muted); }
h1 { font-size: clamp(2rem, 1rem + 4vw, 3.25rem); margin: 0.4rem 0 0; letter-spacing: -0.02em; }
.score { display: flex; align-items: baseline; gap: 0.5rem; margin-top: 1.5rem; }
.score b { font: 700 clamp(3rem, 1rem + 8vw, 5.5rem)/1 var(--mono); letter-spacing: -0.03em; }
.score span { color: var(--muted); font: 0.9rem/1 var(--mono); }
.counts { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1rem; }
.pill { font: 600 0.78rem/1 var(--mono); padding: 0.35rem 0.6rem; border-radius: 999px;
  color: #fff; }
.meta { color: var(--muted); font: 0.82rem/1.4 var(--mono); margin-top: 1.5rem; }
.finding { background: var(--surface); border: 1px solid var(--line); border-left: 4px solid;
  border-radius: 8px; padding: 1.4rem 1.6rem; margin-bottom: 1.1rem; }
.finding h2 { font-size: 1.1rem; margin: 0; display: flex; align-items: center; gap: 0.7rem; }
.cid { font: 700 0.8rem/1 var(--mono); color: var(--muted); }
.tag { margin-left: auto; font: 700 0.7rem/1 var(--mono); letter-spacing: 0.08em;
  text-transform: uppercase; color: #fff; padding: 0.3rem 0.55rem; border-radius: 5px; }
.summary { margin: 0.6rem 0 0; }
.refs { color: var(--muted); font: 0.78rem/1.4 var(--mono); margin-top: 0.5rem; }
.evidence { margin-top: 1rem; }
.evidence h3 { font-size: 0.85rem; margin: 0 0 0.4rem; color: var(--muted); }
table { width: 100%; border-collapse: collapse; font: 0.82rem/1.4 var(--mono); }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
footer { margin-top: 3rem; color: var(--muted); font: 0.78rem/1.4 var(--mono);
  border-top: 1px solid var(--line); padding-top: 1.2rem; }
"""


def to_html(report: Report) -> str:
    """Render ``report`` to a complete standalone HTML document string."""
    counts = report.counts()
    pills = "".join(
        f'<span class="pill" style="background:{_STATUS_COLOR[status]}">'
        f"{escape(status)} {count}</span>"
        for status, count in counts.items()
        if count
    )
    findings_html = "\n".join(_render_finding(f) for f in report.findings)
    generated = escape(report.generated_at.isoformat())
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Probity NIS2 Evidence Pack</title>
<style>{_STYLE}</style>
</head>
<body>
<main class="wrap">
<header>
  <p class="eyebrow">Probity &middot; NIS2 Compliance Evidence</p>
  <h1>Evidence Pack</h1>
  <div class="score"><b>{report.score}</b><span>/ 100 compliance score</span></div>
  <div class="counts">{pills}</div>
  <p class="meta">Generated {generated}</p>
</header>
<section>
{findings_html}
</section>
<footer>Probity &mdash; continuous, auditable NIS2 compliance evidence.
Generated {generated}.</footer>
</main>
</body>
</html>"""


def _render_finding(finding: Finding) -> str:
    status = finding.status.value
    color = _STATUS_COLOR[status]
    refs = escape(", ".join(finding.nis2_refs)) if finding.nis2_refs else ""
    refs_html = f'<p class="refs">NIS2: {refs}</p>' if refs else ""
    evidence_html = "".join(_render_evidence(e) for e in finding.evidence)
    return f"""<article class="finding {status}" style="border-left-color:{color}">
  <h2><span class="cid">{escape(finding.control_id)}</span> {escape(finding.title)}
    <span class="tag" style="background:{color}">{escape(status)}</span></h2>
  <p class="summary">{escape(finding.summary)}</p>
  {refs_html}
  {evidence_html}
</article>"""


def _render_evidence(evidence: Evidence) -> str:
    if not evidence.items:
        return f'<div class="evidence"><h3>{escape(evidence.description)}</h3></div>'
    columns: list[str] = []
    for item in evidence.items:
        for key in item:
            if key not in columns:
                columns.append(key)
    head = "".join(f"<th>{escape(c)}</th>" for c in columns)
    rows = "".join(
        "<tr>"
        + "".join(f"<td>{escape(str(item.get(c, '')))}</td>" for c in columns)
        + "</tr>"
        for item in evidence.items
    )
    return f"""<div class="evidence">
  <h3>{escape(evidence.description)}</h3>
  <table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>
</div>"""
