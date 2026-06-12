"""Self-contained HTML dashboard report for local lab detection findings."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape

from .models import DetectionFinding, ParseError

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def render_html_report(
    findings: list[DetectionFinding],
    errors: list[ParseError],
    *,
    log_file: str = "",
    event_count: int | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render findings and parse errors as a standalone SOC-style dashboard.

    The output is a single HTML document with inline CSS and no external
    resources, so it can be opened offline or archived as an artifact.
    """

    generated = (generated_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
    severity_counts = Counter(finding.severity for finding in findings)
    rule_counts = Counter(finding.rule_id for finding in findings)
    unique_ips = {finding.source_ip for finding in findings}

    stats = [
        ("Findings", str(len(findings))),
        ("Rules triggered", str(len(rule_counts))),
        ("Unique source IPs", str(len(unique_ips))),
        ("Parse errors", str(len(errors))),
    ]
    if event_count is not None:
        stats.insert(1, ("Events analyzed", str(event_count)))

    return _PAGE_TEMPLATE.format(
        generated=escape(generated),
        log_file=escape(log_file or "n/a"),
        stat_cards=_stat_cards(stats),
        severity_chips=_severity_chips(severity_counts),
        rule_bars=_rule_bars(rule_counts),
        findings_section=_findings_section(findings),
        errors_section=_errors_section(errors),
    )


def _stat_cards(stats: list[tuple[str, str]]) -> str:
    """Render the headline stat cards row."""

    cards = "".join(
        f'<div class="stat"><div class="stat-value">{escape(value)}</div>'
        f'<div class="stat-label">{escape(label)}</div></div>'
        for label, value in stats
    )
    return f'<div class="stats">{cards}</div>'


def _severity_chips(severity_counts: Counter) -> str:
    """Render one chip per severity present in the findings."""

    if not severity_counts:
        return '<span class="chip sev-none">no findings</span>'

    ordered = sorted(
        severity_counts.items(),
        key=lambda item: SEVERITY_ORDER.index(item[0]) if item[0] in SEVERITY_ORDER else 99,
    )
    return "".join(
        f'<span class="chip sev-{escape(severity.lower())}">{escape(severity)}: {count}</span>'
        for severity, count in ordered
    )


def _rule_bars(rule_counts: Counter) -> str:
    """Render a simple horizontal bar per triggered rule."""

    if not rule_counts:
        return '<p class="empty">No rules triggered.</p>'

    peak = max(rule_counts.values())
    rows = []
    for rule_id, count in rule_counts.most_common():
        width = max(6, round(count / peak * 100))
        rows.append(
            '<div class="bar-row">'
            f'<span class="bar-label">{escape(rule_id)}</span>'
            f'<span class="bar-track"><span class="bar-fill" style="width: {width}%"></span></span>'
            f'<span class="bar-count">{count}</span>'
            "</div>"
        )
    return "".join(rows)


def _findings_section(findings: list[DetectionFinding]) -> str:
    """Render the findings table, or an empty state."""

    if not findings:
        return '<p class="empty">No findings. The analyzed telemetry did not trigger any rule.</p>'

    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f'<td class="mono">{escape(finding.rule_id)}</td>'
            f'<td><span class="chip sev-{escape(finding.severity.lower())}">{escape(finding.severity)}</span></td>'
            f'<td class="mono">{escape(finding.source_ip)}</td>'
            f'<td class="mono">{escape(finding.username)}</td>'
            f'<td class="num">{finding.event_count}</td>'
            f'<td class="mono dim">{escape(_fmt(finding.first_seen))}</td>'
            f'<td class="mono dim">{escape(_fmt(finding.last_seen))}</td>'
            f"<td>{escape(finding.reason)}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr>"
        "<th>Rule</th><th>Severity</th><th>Source IP</th><th>Username</th>"
        "<th>Events</th><th>First seen</th><th>Last seen</th><th>Reason</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _errors_section(errors: list[ParseError]) -> str:
    """Render recoverable parse errors, or an empty state."""

    if not errors:
        return '<p class="empty">No parse errors. Every log line was valid JSONL.</p>'

    rows = "".join(
        "<tr>"
        f'<td class="num">{error.line_number}</td>'
        f"<td>{escape(error.reason)}</td>"
        f'<td class="mono dim">{escape(_truncate(error.raw_line))}</td>'
        "</tr>"
        for error in errors
    )
    return (
        "<table><thead><tr><th>Line</th><th>Reason</th><th>Raw line</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _fmt(value: datetime) -> str:
    """Format a timestamp compactly for table cells."""

    return value.isoformat().replace("+00:00", "Z")


def _truncate(value: str, limit: int = 120) -> str:
    """Trim long raw log lines for display."""

    return value if len(value) <= limit else value[: limit - 1] + "…"


_PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OWASP Lab &middot; Detection Findings</title>
<style>
  :root {{
    --bg: #0b1120;
    --surface: #111a2e;
    --surface-2: #16213a;
    --border: #243352;
    --text: #e2e8f0;
    --text-muted: #8fa3c4;
    --text-faint: #64748b;
    --accent: #22d3ee;
    --mono: "SF Mono", "Cascadia Code", "JetBrains Mono", Consolas, monospace;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 2rem 1.5rem 3rem;
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    color: var(--text);
    background:
      radial-gradient(60rem 30rem at 15% 0%, rgba(99, 102, 241, 0.10), transparent 60%),
      radial-gradient(50rem 28rem at 85% 100%, rgba(34, 211, 238, 0.08), transparent 60%),
      var(--bg);
    min-height: 100vh;
  }}
  .wrap {{ max-width: 72rem; margin: 0 auto; }}
  .brand {{
    display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.4rem;
    font-family: var(--mono); font-size: 0.95rem; letter-spacing: 0.08em;
    color: var(--text-muted); text-transform: uppercase;
  }}
  .brand .dot {{
    width: 0.55rem; height: 0.55rem; border-radius: 50%;
    background: var(--accent); box-shadow: 0 0 10px var(--accent);
  }}
  h1 {{ margin: 0 0 0.3rem; font-size: 1.5rem; font-weight: 600; }}
  .meta {{ font-family: var(--mono); font-size: 0.78rem; color: var(--text-faint); margin-bottom: 1.6rem; }}
  .panel {{
    background: linear-gradient(180deg, var(--surface-2), var(--surface));
    border: 1px solid var(--border); border-radius: 14px;
    padding: 1.3rem 1.5rem; margin-bottom: 1.2rem;
    box-shadow: 0 18px 40px rgba(0, 0, 0, 0.35);
  }}
  h2 {{
    margin: 0 0 1rem; font-size: 0.8rem; font-weight: 600;
    color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em;
  }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); gap: 0.8rem; }}
  .stat {{
    border: 1px solid var(--border); border-radius: 10px;
    padding: 0.9rem 1rem; background: rgba(255, 255, 255, 0.02);
  }}
  .stat-value {{ font-family: var(--mono); font-size: 1.6rem; font-weight: 700; color: var(--accent); }}
  .stat-label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; margin-top: 0.25rem; }}
  .chip {{
    display: inline-block; font-family: var(--mono); font-size: 0.72rem;
    letter-spacing: 0.05em; text-transform: uppercase;
    padding: 0.25rem 0.6rem; border-radius: 999px; margin-right: 0.4rem;
    border: 1px solid var(--border); color: var(--text-muted);
  }}
  .chip.sev-critical {{ color: #fda4af; border-color: rgba(244, 63, 94, 0.45); background: rgba(244, 63, 94, 0.12); }}
  .chip.sev-high {{ color: #fca5a5; border-color: rgba(248, 113, 113, 0.40); background: rgba(248, 113, 113, 0.10); }}
  .chip.sev-medium {{ color: #fcd34d; border-color: rgba(251, 191, 36, 0.35); background: rgba(251, 191, 36, 0.08); }}
  .chip.sev-low {{ color: #93c5fd; border-color: rgba(96, 165, 250, 0.35); background: rgba(96, 165, 250, 0.08); }}
  .chip.sev-info, .chip.sev-none {{ color: var(--text-muted); }}
  .bar-row {{ display: grid; grid-template-columns: 14rem 1fr 3rem; gap: 0.8rem; align-items: center; margin-bottom: 0.55rem; }}
  .bar-label {{ font-family: var(--mono); font-size: 0.78rem; color: var(--text-muted); }}
  .bar-track {{ height: 0.55rem; border-radius: 999px; background: rgba(255, 255, 255, 0.05); overflow: hidden; }}
  .bar-fill {{ display: block; height: 100%; border-radius: 999px; background: linear-gradient(90deg, #06b6d4, var(--accent)); }}
  .bar-count {{ font-family: var(--mono); font-size: 0.8rem; color: var(--text); text-align: right; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.83rem; }}
  th {{
    text-align: left; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--text-faint); font-weight: 600; padding: 0.45rem 0.7rem;
    border-bottom: 1px solid var(--border);
  }}
  td {{ padding: 0.55rem 0.7rem; border-bottom: 1px solid rgba(36, 51, 82, 0.55); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  .mono {{ font-family: var(--mono); font-size: 0.78rem; }}
  .num {{ font-family: var(--mono); text-align: right; }}
  .dim {{ color: var(--text-faint); }}
  .empty {{ color: var(--text-faint); font-size: 0.85rem; margin: 0; }}
  .footer {{
    margin-top: 1.6rem; font-family: var(--mono); font-size: 0.72rem;
    color: var(--text-faint); letter-spacing: 0.05em; text-align: center;
  }}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand"><span class="dot"></span> OWASP Lab Detection Engine</div>
  <h1>Detection Findings</h1>
  <p class="meta">generated: {generated} &middot; log file: {log_file}</p>
  <div class="panel">
    <h2>Overview</h2>
    {stat_cards}
    <p style="margin: 1rem 0 0;">{severity_chips}</p>
  </div>
  <div class="panel">
    <h2>Findings by rule</h2>
    {rule_bars}
  </div>
  <div class="panel">
    <h2>Findings</h2>
    {findings_section}
  </div>
  <div class="panel">
    <h2>Parse errors</h2>
    {errors_section}
  </div>
  <div class="footer">local educational lab &middot; do not deploy publicly</div>
</div>
</body>
</html>
"""
