"""Read-only compliance dashboard served over stdlib ``http.server``.

Renders the append-only scan history into a single self-contained HTML page: a
headline score, an SVG score-trend sparkline (no JS, no chart library), the
latest per-control status grid, and a table of recent scans. ``render_dashboard``
is a pure function of the history file, so it is testable without a socket; the
``http.server`` wrapper is a thin shell around it.

Zero dependencies: ``http.server`` for serving, hand-built inline SVG for the
trend, all dynamic values HTML-escaped.
"""

from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from probity.model.enums import Status
from probity.report.history import Snapshot, compute_trend, load_snapshots

_STATUS_COLOR = {
    Status.PASS.value: "oklch(62% 0.14 150)",
    Status.FAIL.value: "oklch(58% 0.20 25)",
    Status.PARTIAL.value: "oklch(72% 0.15 75)",
    Status.NOT_APPLICABLE.value: "oklch(60% 0 0)",
    Status.ERROR.value: "oklch(50% 0.18 25)",
}
_UNKNOWN_COLOR = "oklch(50% 0.18 25)"

_RECENT_LIMIT = 20
_SPARK_W = 640
_SPARK_H = 140
_SPARK_PAD = 8

_TREND_ARROW = {"up": "▲", "down": "▼", "flat": "▬", "first": "•"}

_STYLE = """
:root {
  --bg: oklch(98% 0 0); --surface: oklch(100% 0 0); --text: oklch(20% 0 0);
  --muted: oklch(50% 0 0); --line: oklch(90% 0 0);
  --mono: ui-monospace, "SF Mono", "Cascadia Code", monospace;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
.wrap { max-width: 940px; margin: 0 auto; padding: 3.5rem 1.5rem; }
.eyebrow { font: 600 0.75rem/1 var(--mono); letter-spacing: 0.18em;
  text-transform: uppercase; color: var(--muted); }
h1 { font-size: clamp(2rem, 1rem + 4vw, 3rem); margin: 0.4rem 0 0; letter-spacing: -0.02em; }
.score { display: flex; align-items: baseline; gap: 0.6rem; margin-top: 1.4rem; }
.score b { font: 700 clamp(3rem, 1rem + 8vw, 5rem)/1 var(--mono); letter-spacing: -0.03em; }
.score span { color: var(--muted); font: 0.9rem/1 var(--mono); }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
  padding: 1.6rem; margin-top: 1.8rem; }
.card h2 { font-size: 0.8rem; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--muted); margin: 0 0 1rem; font-family: var(--mono); }
.grid { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.cell { font: 600 0.78rem/1 var(--mono); color: #fff; padding: 0.5rem 0.7rem;
  border-radius: 6px; }
table { width: 100%; border-collapse: collapse; font: 0.85rem/1.4 var(--mono); }
th, td { text-align: left; padding: 0.45rem 0.6rem; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; }
.delta-up { color: oklch(55% 0.16 150); } .delta-down { color: oklch(55% 0.20 25); }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 2.5rem; color: var(--muted); font: 0.78rem/1.4 var(--mono);
  border-top: 1px solid var(--line); padding-top: 1.2rem; }
svg { width: 100%; height: auto; display: block; }
"""


def _sparkline(snapshots: tuple[Snapshot, ...]) -> str:
    """Inline SVG polyline of scores over time. Empty placeholder if <2 points."""
    if len(snapshots) < 2:
        return '<p class="empty">Not enough scans yet to chart a trend.</p>'
    scores = [s.score for s in snapshots]
    n = len(scores)
    span = _SPARK_W - 2 * _SPARK_PAD
    inner_h = _SPARK_H - 2 * _SPARK_PAD
    points = []
    for i, score in enumerate(scores):
        x = _SPARK_PAD + (span * i / (n - 1))
        y = _SPARK_PAD + inner_h * (1 - score / 100)
        points.append(f"{x:.1f},{y:.1f}")
    polyline = " ".join(points)
    last_x, last_y = points[-1].split(",")
    return (
        f'<svg viewBox="0 0 {_SPARK_W} {_SPARK_H}" role="img" '
        f'aria-label="Score trend over {n} scans">'
        f'<polyline fill="none" stroke="oklch(55% 0.16 250)" stroke-width="2.5" '
        f'stroke-linejoin="round" stroke-linecap="round" points="{polyline}"/>'
        f'<circle cx="{last_x}" cy="{last_y}" r="4" fill="oklch(55% 0.16 250)"/>'
        f"</svg>"
    )


def _control_grid(latest: Snapshot) -> str:
    cells = []
    for control_id, status in sorted(latest.statuses.items()):
        color = _STATUS_COLOR.get(status, _UNKNOWN_COLOR)
        cells.append(
            f'<span class="cell" style="background:{color}" '
            f'title="{escape(status)}">{escape(control_id)}</span>'
        )
    return f'<div class="grid">{"".join(cells)}</div>'


def _recent_table(snapshots: tuple[Snapshot, ...]) -> str:
    recent = list(snapshots[-_RECENT_LIMIT:])
    recent.reverse()  # newest first
    rows = []
    for i, snap in enumerate(recent):
        older = recent[i + 1] if i + 1 < len(recent) else None
        if older is None:
            delta_html = '<td class="empty">—</td>'
        else:
            delta = round(snap.score - older.score, 1)
            cls = "delta-up" if delta > 0 else "delta-down" if delta < 0 else ""
            sign = "+" if delta >= 0 else ""
            delta_html = f'<td class="{cls}">{sign}{delta}</td>'
        rows.append(
            f"<tr><td>{escape(snap.generated_at)}</td>"
            f"<td>{snap.score}%</td>{delta_html}</tr>"
        )
    body = "".join(rows)
    return (
        "<table><thead><tr><th>Scan time</th><th>Score</th><th>Δ</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
    )


def render_dashboard(history_path: str | Path) -> str:
    """Render the full dashboard HTML from the scan history at ``history_path``."""
    snapshots = load_snapshots(history_path)
    if not snapshots:
        return _empty_page()
    trend = compute_trend(snapshots)
    latest = snapshots[-1]
    arrow = _TREND_ARROW[trend.direction]
    if trend.previous is None:
        trend_line = f"{arrow} first recorded scan"
    else:
        sign = "+" if trend.delta >= 0 else ""
        trend_line = f"{arrow} {trend.direction} {sign}{trend.delta} vs previous {trend.previous}%"
    return _page(
        score=latest.score,
        trend_line=escape(trend_line),
        generated=escape(latest.generated_at),
        sparkline=_sparkline(snapshots),
        control_grid=_control_grid(latest),
        recent_table=_recent_table(snapshots),
        count=len(snapshots),
    )


def _page(
    *,
    score: float,
    trend_line: str,
    generated: str,
    sparkline: str,
    control_grid: str,
    recent_table: str,
    count: int,
) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Probity Dashboard</title>
<style>{_STYLE}</style>
</head>
<body>
<main class="wrap">
  <p class="eyebrow">Probity &middot; NIS2 Compliance</p>
  <h1>Compliance Dashboard</h1>
  <div class="score"><b>{score}</b><span>/ 100 &middot; {trend_line}</span></div>
  <section class="card"><h2>Score trend &middot; {count} scans</h2>{sparkline}</section>
  <section class="card"><h2>Latest control status</h2>{control_grid}</section>
  <section class="card"><h2>Recent scans</h2>{recent_table}</section>
  <footer>Latest scan {generated}. Continuous, auditable NIS2 compliance evidence.</footer>
</main>
</body>
</html>"""


def _empty_page() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Probity Dashboard</title>
<style>{_STYLE}</style>
</head>
<body>
<main class="wrap">
  <p class="eyebrow">Probity &middot; NIS2 Compliance</p>
  <h1>Compliance Dashboard</h1>
  <section class="card"><p class="empty">No scans recorded yet.
  Run <code>probity scan --history &lt;path&gt;</code> to populate this dashboard.</p></section>
</main>
</body>
</html>"""


def make_handler(history_path: str | Path) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to ``history_path`` (re-read on each request)."""
    resolved = Path(history_path)

    class _DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server API
            html = render_dashboard(resolved)
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:  # silence default stderr logging
            return

    return _DashboardHandler


def serve(history_path: str | Path, host: str = "127.0.0.1", port: int = 8080) -> None:
    """Serve the dashboard until interrupted (Ctrl-C)."""
    handler = make_handler(history_path)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Probity dashboard on http://{host}:{port}  (history: {history_path})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
