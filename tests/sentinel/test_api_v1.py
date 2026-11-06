"""Tests for Sentinel API v1 and HttpSink."""

import json
import pytest
from sentinel.models import Change, EventEnvelope, Meta
from sentinel.server.app import create_sentinel_app
from sentinel.server.repo import SQLiteRepository
from sentinel.sinks import HttpSink


@pytest.fixture
def api_client(tmp_path):
    repo = SQLiteRepository(str(tmp_path / "api_test.db"))
    app = create_sentinel_app(repo, token="secret-token-123")
    app.config["TESTING"] = True
    return app.test_client(), repo


def test_api_v1_token_auth_required(api_client):
    client, _ = api_client
    # No auth header -> 401
    resp = client.post("/api/v1/heartbeat", json={"host_id": "box-1"})
    assert resp.status_code == 401

    # Bad token -> 401
    resp = client.post(
        "/api/v1/heartbeat",
        headers={"Authorization": "Bearer wrong-token"},
        json={"host_id": "box-1"},
    )
    assert resp.status_code == 401

    # Good token -> 200
    resp = client.post(
        "/api/v1/heartbeat",
        headers={"Authorization": "Bearer secret-token-123"},
        json={"host_id": "box-1"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_api_v1_idempotent_event_ingestion(api_client):
    client, repo = api_client
    change = Change(kinds=["created"], new=Meta(sha256="abc", size=100))
    envelope = EventEnvelope(
        event_id="fixed-event-id-999",
        root_id="app",
        path="/var/app/index.js",
        host_id="box-1",
        ts=1700000000.0,
        change=change,
        severity="medium",
        summary="new file created",
    )

    headers = {"Authorization": "Bearer secret-token-123"}

    # Ingest event first time
    resp1 = client.post("/api/v1/events", headers=headers, json=[envelope.to_dict()])
    assert resp1.status_code == 200
    assert resp1.get_json()["processed"] == 1

    # Ingest duplicate event second time
    resp2 = client.post("/api/v1/events", headers=headers, json=[envelope.to_dict()])
    assert resp2.status_code == 200

    # Verify repository has only 1 change row for fixed-event-id-999
    with repo._get_connection() as conn:
        count = conn.execute(
            "SELECT count(*) as c FROM changes WHERE event_id = 'fixed-event-id-999'"
        ).fetchone()["c"]
        assert count == 1


def test_api_v1_malformed_payload_rejected(api_client):
    client, _ = api_client
    headers = {"Authorization": "Bearer secret-token-123"}
    resp = client.post("/api/v1/events", headers=headers, json="not-a-list")
    assert resp.status_code == 400
