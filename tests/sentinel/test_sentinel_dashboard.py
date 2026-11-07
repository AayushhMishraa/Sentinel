"""Tests for Sentinel Web Dashboard."""

import pytest
from sentinel.models import Change, EventEnvelope, Meta
from sentinel.server.app import create_sentinel_app
from sentinel.server.repo import SQLiteRepository


@pytest.fixture
def dashboard_client(tmp_path):
    repo = SQLiteRepository(str(tmp_path / "dashboard_test.db"))

    # Seed an alert
    meta_old = Meta(sha256="old1", size=10, mode=0o644, uid=1000, gid=1000)
    meta_new = Meta(sha256="new2", size=25, mode=0o644, uid=1000, gid=1000)
    change = Change(kinds=["modified"], old=meta_old, new=meta_new, diff="--- a/test.txt\n+++ b/test.txt\n@@ -1 +1 @@\n-old\n+new\n")
    envelope = EventEnvelope(
        root_id="ssh",
        path="/etc/ssh/sshd_config",
        host_id="box-alpha",
        ts=1700000000.0,
        change=change,
        severity="critical",
        summary="SSH config modified",
    )
    repo.upsert_alert(envelope)

    app = create_sentinel_app(repo)
    app.config["TESTING"] = True
    return app.test_client(), repo


def test_dashboard_index(dashboard_client):
    client, _ = dashboard_client
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Live Threat &amp; Integrity Alerts" in html or "Live Threat & Integrity Alerts" in html
    assert "/etc/ssh/sshd_config" in html
    assert "critical" in html


def test_dashboard_alert_detail_and_diff(dashboard_client):
    client, _ = dashboard_client
    resp = client.get("/alerts/1")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Alert #1 Overview" in html
    assert "+new" in html
    # Verify strong confirmation modal for approve
    assert "Are you sure you want to approve this change? This will update the Golden Baseline." in html
    assert "openApproveModal()" in html
    assert 'id="approve-modal"' in html
    # Verify lightweight inline swap for reject (no browser window.confirm popup)
    assert 'id="reject-container"' in html
    assert 'id="reject-inline-confirm"' in html
    assert "Revert to baseline?" in html
    assert 'onsubmit="return confirm' not in html


def test_dashboard_approve_action(dashboard_client):
    client, repo = dashboard_client
    resp = client.post("/alerts/1/approve", data={"actor": "analyst", "note": "approved update"}, follow_redirects=True)
    assert resp.status_code == 200
    alert = repo.get_alert(1)
    assert alert.status == "approved"
    assert alert.resolution["actor"] == "analyst"


def test_dashboard_reject_action(dashboard_client):
    client, repo = dashboard_client
    resp = client.post("/alerts/1/reject", data={"actor": "analyst", "note": "rejected malicious drift"}, follow_redirects=True)
    assert resp.status_code == 200
    alert = repo.get_alert(1)
    assert alert.status == "rejected"
    assert alert.resolution["actor"] == "analyst"
    assert alert.resolution["note"] == "rejected malicious drift"


def test_dashboard_host_guard(dashboard_client):
    client, _ = dashboard_client
    resp = client.get("/", headers={"Host": "evil.com"})
    assert resp.status_code == 403

