"""Sentinel REST API v1 Blueprint.

Follows scaling rules S-1, S-2:
- Versioned endpoints: /api/v1/*
- Bearer token authentication via hmac.compare_digest
- Idempotent event ingestion keyed by event_id
- Commands polling channel and host registry
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from functools import wraps
from typing import Optional
from flask import Blueprint, abort, current_app, jsonify, request

from sentinel.models import EventEnvelope
from sentinel.server.repo import Repository

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")


def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        expected_token = current_app.config.get("SENTINEL_TOKEN")
        if not expected_token:
            # If no token configured on server, permit localhost
            remote_ip = request.remote_addr or "127.0.0.1"
            if remote_ip in ("127.0.0.1", "::1", "localhost", "testclient"):
                return f(*args, **kwargs)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Missing or invalid Authorization header"}), 401
        token = auth_header[7:].strip()

        if not hmac.compare_digest(token, expected_token or ""):
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return decorated


def get_repo() -> Repository:
    return current_app.config["REPO"]


@api_v1.route("/heartbeat", methods=["POST"])
@require_token
def heartbeat():
    data = request.get_json(silent=True) or {}
    host_id = data.get("host_id")
    if not host_id or not isinstance(host_id, str):
        return jsonify({"ok": False, "error": "Missing or invalid 'host_id'"}), 400

    name = str(data.get("name", host_id))
    agent_version = str(data.get("agent_version", "0.1.0"))
    repo = get_repo()
    repo.record_host(host_id=host_id, name=name, agent_version=agent_version)
    return jsonify({"ok": True, "ts": time.time()})


@api_v1.route("/events", methods=["POST"])
@require_token
def ingest_events():
    """Batch ingest versioned EventEnvelopes. Idempotent by event_id."""
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"ok": False, "error": "Payload must be a JSON array of EventEnvelopes"}), 400

    repo = get_repo()
    processed = 0
    alerts_created = []

    for item in data:
        if not isinstance(item, dict):
            return jsonify({"ok": False, "error": "Each event item must be a JSON object"}), 400
        try:
            envelope = EventEnvelope.from_dict(item)
        except Exception as e:
            return jsonify({"ok": False, "error": f"Invalid EventEnvelope: {e}"}), 400

        alert = repo.upsert_alert(envelope)
        processed += 1
        if alert and alert.id not in alerts_created:
            alerts_created.append(alert.id)

    return jsonify({
        "ok": True,
        "processed": processed,
        "alert_ids": alerts_created,
    })


@api_v1.route("/hosts", methods=["GET"])
@require_token
def list_hosts():
    repo = get_repo()
    hosts = []
    if hasattr(repo, "_get_connection"):
        with repo._get_connection() as conn:
            for row in conn.execute("SELECT * FROM hosts ORDER BY last_seen DESC"):
                hosts.append(dict(row))
    return jsonify({"ok": True, "hosts": hosts})


@api_v1.route("/alerts", methods=["GET"])
@require_token
def get_alerts():
    repo = get_repo()
    status = request.args.get("status")
    severity = request.args.get("severity")
    host_id = request.args.get("host_id") or request.args.get("host")

    alerts = repo.list_alerts(status=status, severity=severity, host_id=host_id)
    return jsonify({"ok": True, "alerts": [a.to_dict() for a in alerts]})


@api_v1.route("/alerts/<int:alert_id>", methods=["GET"])
@require_token
def get_alert_detail(alert_id: int):
    repo = get_repo()
    alert = repo.get_alert(alert_id)
    if not alert:
        return jsonify({"ok": False, "error": "Alert not found"}), 404
    return jsonify({"ok": True, "alert": alert.to_dict()})


@api_v1.route("/alerts/bulk-acknowledge", methods=["POST"])
@require_token
def api_bulk_acknowledge():
    data = request.get_json(silent=True) or {}
    actor = data.get("actor", "api-admin")
    note = data.get("note", "Bulk acknowledged")
    action = data.get("action", "reject")
    repo = get_repo()
    count = repo.bulk_resolve_alerts(action=action, actor=actor, note=note)
    return jsonify({"ok": True, "acknowledged": count})


@api_v1.route("/commands", methods=["GET"])
@require_token
def get_commands():
    """Agent command channel for pulling pending approve/reject actions."""
    host_id = request.args.get("host_id")
    if not host_id:
        return jsonify({"ok": False, "error": "Missing host_id query parameter"}), 400

    repo = get_repo()
    commands = []
    if hasattr(repo, "_get_connection"):
        with repo._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM commands WHERE host_id = ? AND status = 'pending' ORDER BY created_at ASC",
                (host_id,)
            )
            for row in cur.fetchall():
                commands.append(dict(row))
    return jsonify({"ok": True, "commands": commands})

