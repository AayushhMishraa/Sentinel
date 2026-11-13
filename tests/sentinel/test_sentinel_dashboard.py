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
    assert "<title>(1) Alerts - Alert #1 · Sentinel</title>" in html
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


def test_dynamic_tab_title_and_components(dashboard_client):
    """Verifies dynamic tab title, counter animation ID, and toast notification container."""
    client, repo = dashboard_client

    # 1. With 1 open alert, title should reflect '(1) Alerts - Sentinel'
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "<title>(1) Alerts - Sentinel</title>" in html
    assert 'id="toast-container"' in html
    assert 'id="open-alerts-count"' in html
    assert 'id="latest-alert-meta"' in html
    assert "showToast" in html
    assert "bounce-anim" in html
    assert "@keyframes bounce-anim" in html
    assert "1.5s ease-in-out" in html
    assert "scale(1.6)" in html
    assert "offsetHeight" in html
    assert "newCount > oldCount" in html
    assert "previousOpenCount" in html
    assert "el.textContent = newCount" in html
    assert "el.style.animation = 'none'" in html
    assert "el.style.animation = 'bounce-anim 1.5s ease-in-out'" in html
    assert "main.innerHTML" not in html
    assert 'id="alerts-feed-section"' in html

    # 2. Add 2 more open alerts (total 3) -> title should become '(3) Alerts - Sentinel'
    for i in (2, 3):
        meta = Meta(sha256=f"hash{i}", size=10, mode=0o644, uid=1000, gid=1000)
        ch = Change(kinds=["modified"], old=meta, new=meta)
        env = EventEnvelope(
            root_id="ssh",
            path=f"/etc/ssh/file_{i}.txt",
            host_id="box-alpha",
            ts=1700000000.0 + i,
            change=ch,
            severity="high",
            summary=f"File {i} modified",
        )
        repo.upsert_alert(env)

    resp3 = client.get("/")
    assert "<title>(3) Alerts - Sentinel</title>" in resp3.get_data(as_text=True)

    # 3. Resolve all alerts (0 open) -> title should become 'Sentinel'
    repo.bulk_resolve_alerts(action="reject", actor="admin")
    resp_zero = client.get("/")
    assert "<title>Sentinel</title>" in resp_zero.get_data(as_text=True)


def test_no_concept_references_in_served_pages(dashboard_client):
    """Smoke test asserting no served dashboard page contains Concept A, B, or C."""
    client, _ = dashboard_client
    routes = ["/", "/assets", "/alerts/1", "/report", "/ui-kit"]
    for r in routes:
        resp = client.get(r)
        assert resp.status_code == 200
        text = resp.get_data(as_text=True)
        assert "Concept A" not in text, f"Route {r} contains 'Concept A'"
        assert "Concept B" not in text, f"Route {r} contains 'Concept B'"
        assert "Concept C" not in text, f"Route {r} contains 'Concept C'"


def test_api_v1_search_empty_query(dashboard_client):
    """Search endpoint with empty query returns empty results."""
    client, _ = dashboard_client
    resp = client.get("/api/v1/search?q=")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["query"] == ""
    assert data["total"] == 0
    assert data["alerts"] == []
    assert data["hosts"] == []
    assert data["paths"] == []


def test_api_v1_search_no_match(dashboard_client):
    """Search endpoint with unmatched query returns total=0."""
    client, _ = dashboard_client
    resp = client.get("/api/v1/search?q=xyz_nonexistent_token_12345")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 0
    assert len(data["alerts"]) == 0
    assert len(data["hosts"]) == 0
    assert len(data["paths"]) == 0


def test_api_v1_search_xss_safety(dashboard_client):
    """Search query with XSS payloads executes safely without injection."""
    client, _ = dashboard_client
    xss_payload = "<script>alert('xss')</script>\"'--;"
    resp = client.get(f"/api/v1/search?q={xss_payload}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["query"] == xss_payload
    assert data["total"] == 0


def test_api_v1_search_long_query(dashboard_client):
    """Search endpoint handles long queries safely without blowing up."""
    client, _ = dashboard_client
    long_q = "A" * 4000
    resp = client.get(f"/api/v1/search?q={long_q}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 0


def test_api_v1_search_matches(dashboard_client):
    """Search endpoint finds seeded alert by path, host, or severity."""
    client, repo = dashboard_client
    # Search by path
    resp = client.get("/api/v1/search?q=sshd_config")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] >= 1
    assert any("sshd_config" in a["path"] for a in data["alerts"])

    # Search by host_id
    resp_host = client.get("/api/v1/search?q=box-alpha")
    assert resp_host.status_code == 200
    data_host = resp_host.get_json()
    assert data_host["total"] >= 1
    assert any("box-alpha" in a["host_id"] for a in data_host["alerts"])




