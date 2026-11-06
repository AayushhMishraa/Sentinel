"""Sentinel Web Dashboard application.

Provides alert feed, detailed inspection views with safe text diff rendering,
and approval / rejection workflows. Reuses cinematic dark terminal theme.
"""

from __future__ import annotations

import html
import json
import os
import time
from typing import Optional
from flask import Flask, abort, jsonify, redirect, render_template, request, url_for

from sentinel.report import generate_compliance_report_html
from sentinel.server.api_v1 import api_v1
from sentinel.server.repo import Repository, SQLiteRepository


def create_sentinel_app(repo: Repository, token: Optional[str] = None, engine=None) -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), "templates")),
        static_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), "static")),
    )
    app.config["REPO"] = repo
    app.config["SENTINEL_TOKEN"] = token
    app.config["ENGINE"] = engine
    app.register_blueprint(api_v1)

    @app.before_request
    def guard_hosts():
        host = request.host.split(":")[0]
        if host not in ("127.0.0.1", "localhost", "testserver"):
            abort(403)

    @app.route("/")
    def index():
        alerts = repo.list_alerts()
        stats = {
            "critical": sum(1 for a in alerts if a.severity == "critical" and a.status == "open"),
            "high": sum(1 for a in alerts if a.severity == "high" and a.status == "open"),
            "medium": sum(1 for a in alerts if a.severity == "medium" and a.status == "open"),
            "low": sum(1 for a in alerts if a.severity == "low" and a.status == "open"),
            "info": sum(1 for a in alerts if a.severity == "info" and a.status == "open"),
            "total_open": sum(1 for a in alerts if a.status == "open"),
        }

        # Calculate SVG change-over-time path (24 data points)
        points = [max(1, (a.count if i < len(alerts) else (i % 3 + 1))) for i, a in enumerate(alerts[:24])]
        while len(points) < 24:
            points.append(1)
        max_v = max(points)
        width, height = 600, 100
        step = width / (len(points) - 1)
        d_line = f"M 0 {height - int((points[0] / max_v) * 80)}"
        for i in range(1, len(points)):
            x = int(i * step)
            y = int(height - (points[i] / max_v) * 80)
            d_line += f" L {x} {y}"
        d_area = f"{d_line} L {width} {height} L 0 {height} Z"

        return render_template(
            "alerts.html",
            alerts=alerts,
            stats=stats,
            chart_line_path=d_line,
            chart_area_path=d_area,
        )

    @app.route("/assets")
    def assets_view():
        hosts = []
        now = time.time()
        if hasattr(repo, "_get_connection"):
            with repo._get_connection() as conn:
                for row in conn.execute("SELECT * FROM hosts ORDER BY last_seen DESC"):
                    h = dict(row)
                    h["is_online"] = (now - h["last_seen"]) < 90
                    h["last_seen_str"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["last_seen"]))
                    hosts.append(h)

        sample_paths = [
            {"id": "ssh", "path": "~/.ssh", "mode": "monitor", "decoys": False, "capture_content": True},
            {"id": "web", "path": "/var/www/html", "mode": "monitor", "decoys": True, "capture_content": False},
            {"id": "docs", "path": "~/important", "mode": "protect", "decoys": True, "capture_content": True},
        ]
        return render_template("assets.html", hosts=hosts, paths=sample_paths)

    @app.route("/alerts/<int:alert_id>")
    def alert_detail(alert_id: int):
        alert = repo.get_alert(alert_id)
        if not alert:
            abort(404)

        # Retrieve changes associated with this alert
        changes = []
        if isinstance(repo, SQLiteRepository):
            with repo._get_connection() as conn:
                rows = conn.execute(
                    "SELECT json FROM changes WHERE alert_id = ? ORDER BY ts DESC",
                    (alert_id,)
                ).fetchall()
                for r in rows:
                    try:
                        changes.append(json.loads(r["json"]))
                    except Exception:
                        pass

        latest_diff = ""
        diff_truncated = False
        if changes:
            ch = changes[0].get("change", {})
            latest_diff = ch.get("diff") or ""
            diff_truncated = ch.get("diff_truncated", False)

        return render_template(
            "alert_detail.html",
            alert=alert,
            changes=changes,
            latest_diff=latest_diff,
            diff_truncated=diff_truncated,
        )

    @app.route("/alerts/<int:alert_id>/<action>", methods=["POST"])
    def resolve_alert_route(alert_id: int, action: str):
        if action not in ("approve", "reject"):
            abort(400)
        actor = request.form.get("actor", "web-admin")
        note = request.form.get("note", "")
        engine = app.config.get("ENGINE")
        if engine:
            if action == "approve":
                engine.approve_alert(alert_id, actor=actor, note=note)
            else:
                engine.reject_alert(alert_id, actor=actor, note=note)
        else:
            repo.resolve_alert(alert_id, action, actor=actor, note=note)
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.route("/report")
    def report_view():
        days = request.args.get("days", 30, type=int)
        return generate_compliance_report_html(repo, days=days)

    @app.route("/api/v1/stats")
    def api_stats():
        alerts = repo.list_alerts()
        return jsonify({
            "critical": sum(1 for a in alerts if a.severity == "critical" and a.status == "open"),
            "high": sum(1 for a in alerts if a.severity == "high" and a.status == "open"),
            "medium": sum(1 for a in alerts if a.severity == "medium" and a.status == "open"),
            "low": sum(1 for a in alerts if a.severity == "low" and a.status == "open"),
            "info": sum(1 for a in alerts if a.severity == "info" and a.status == "open"),
            "total_open": sum(1 for a in alerts if a.status == "open"),
        })

    return app

