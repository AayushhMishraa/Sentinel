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
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #111; line-height: 1.5; }}
  h1 {{ margin-bottom: 4px; }}
  .meta {{ color: #666; font-size: 14px; margin-bottom: 24px; }}
  .summary-grid {{ display: flex; gap: 20px; margin-bottom: 30px; }}
  .card {{ border: 1px solid #ddd; border-radius: 6px; padding: 14px; flex: 1; text-align: center; }}
  .card-val {{ font-size: 24px; font-weight: bold; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; }}
  th {{ background: #f5f5f5; }}
  code {{ font-family: monospace; font-size: 12px; }}
  @media print {{
    body {{ margin: 15mm; }}
    .no-print {{ display: none; }}
  }}
</style>
</head>
<body>
  <h1>Sentinel File Integrity Compliance Report</h1>
  <div class="meta">Audit Window: Last {days} Days | Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</div>

  <div class="summary-grid">
    <div class="card"><div>Total Incidents</div><div class="card-val">{len(alerts)}</div></div>
    <div class="card"><div>Open Alerts</div><div class="card-val" style="color: #d9534f;">{len(open_alerts)}</div></div>
    <div class="card"><div>Approved Changes</div><div class="card-val" style="color: #5cb85c;">{len(approved)}</div></div>
    <div class="card"><div>Rejected Violations</div><div class="card-val" style="color: #f0ad4e;">{len(rejected)}</div></div>
  </div>

  <h2>Audit Trail & Change Records</h2>
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
      {''.join(rows_html) if rows_html else '<tr><td colspan="8" style="text-align: center;">No alert activity recorded in this period.</td></tr>'}
    </tbody>
  </table>
</body>
</html>
"""

