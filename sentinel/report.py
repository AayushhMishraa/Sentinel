"""Sentinel printable compliance report generator."""

from __future__ import annotations

import html
import time
from typing import List
from sentinel.models import Alert
from sentinel.server.repo import Repository


def generate_compliance_report_html(repo: Repository, days: int = 30) -> str:
    cutoff = time.time() - (days * 86400)
    alerts = [a for a in repo.list_alerts() if a.last_seen >= cutoff]

    approved = [a for a in alerts if a.status == "approved"]
    rejected = [a for a in alerts if a.status in ("rejected", "acknowledged")]
    open_alerts = [a for a in alerts if a.status == "open"]

    rows_html = []
    for a in alerts:
        res_info = "—"
        if a.resolution:
            res_info = f"{a.resolution.get('actor', '')} ({a.resolution.get('note', '')})"
        time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(a.last_seen))
        rows_html.append(f"""
        <tr>
          <td>#{a.id}</td>
          <td><b>{html.escape(a.severity.upper())}</b></td>
          <td><code>{html.escape(a.path)}</code></td>
          <td>{html.escape(", ".join(a.kinds))}</td>
          <td>{html.escape(", ".join(a.signals) or "—")}</td>
          <td>{html.escape(a.status.upper())}</td>
          <td>{html.escape(time_str)}</td>
          <td>{html.escape(res_info)}</td>
        </tr>
        """)

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<script>
(function() {{
  try {{
    var stored = localStorage.getItem('sentinel_theme');
    var theme = stored || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    document.documentElement.setAttribute('data-theme', theme);
  }} catch(e) {{
    document.documentElement.setAttribute('data-theme', 'dark');
  }}
}})();
</script>
<title>Sentinel Compliance Report ({days} Days)</title>
<link rel="stylesheet" href="/static/tokens.css">
<style>
  body {{
    font-family: var(--font-sans);
    margin: 40px;
    background-color: var(--surface-bg);
    color: var(--text-primary);
    line-height: 1.5;
    font-size: 13px;
  }}
  h1 {{ margin: 0 0 4px; font-size: 20px; }}
  h2 {{ margin: 24px 0 12px; font-size: 15px; }}
  .meta {{ color: var(--text-muted); font-size: 12px; }}
  .summary-grid {{ display: flex; gap: 16px; margin: 24px 0; }}
  .card {{ border: 1px solid var(--border-subtle); border-radius: 6px; padding: 14px; flex: 1; text-align: center; background: var(--surface-card); }}
  .card-val {{ font-size: 22px; font-weight: bold; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }}
  th, td {{ border: 1px solid var(--border-subtle); padding: 8px 10px; text-align: left; }}
  th {{ background: var(--table-head-bg); color: var(--text-faint); font-weight: 600; font-size: 11px; text-transform: uppercase; }}
  code {{ font-family: var(--font-mono); font-size: 11px; }}
  @media print {{
    body {{ margin: 15mm; }}
    .no-print {{ display: none; }}
  }}
</style>
</head>
<body>
  <header style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; position: relative;">
    <div>
      <h1>Sentinel File Integrity Compliance Report</h1>
      <div class="meta">Audit Window: Last {days} Days | Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</div>
    </div>
    <img src="/static/brand/fingerprint.svg" alt="" width="96" height="96" style="opacity: 0.07; pointer-events: none;">
  </header>

  <div class="summary-grid">
    <div class="card"><div>Total Incidents</div><div class="card-val">{len(alerts)}</div></div>
    <div class="card"><div>Open Alerts</div><div class="card-val" style="color: var(--danger);">{len(open_alerts)}</div></div>
    <div class="card"><div>Approved Changes</div><div class="card-val" style="color: var(--ok);">{len(approved)}</div></div>
    <div class="card"><div>Rejected Violations</div><div class="card-val" style="color: var(--sev-high);">{len(rejected)}</div></div>
  </div>

  <h2>Audit Trail &amp; Change Records</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Severity</th>
        <th>Path</th>
        <th>Kinds</th>
        <th>Signals</th>
        <th>Status</th>
        <th>Timestamp</th>
        <th>Resolution / Actor</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows_html) if rows_html else '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No alert activity recorded in this period.</td></tr>'}
    </tbody>
  </table>
</body>
</html>
"""
