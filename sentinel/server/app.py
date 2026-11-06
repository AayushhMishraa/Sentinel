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

from sentinel.server.repo import Repository, SQLiteRepository


def create_sentinel_app(repo: Repository) -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), "templates")),
        static_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), "static")),
    )

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
        return render_template("alerts.html", alerts=alerts, stats=stats)

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
        repo.resolve_alert(alert_id, action, actor=actor, note=note)
        return redirect(url_for("alert_detail", alert_id=alert_id))

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
