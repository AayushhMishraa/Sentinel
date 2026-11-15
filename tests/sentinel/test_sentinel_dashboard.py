"""Tests for Sentinel Web Dashboard."""

import time
import pytest
from sentinel.models import Change, EventEnvelope, Meta
from sentinel.server.app import create_sentinel_app
from sentinel.server.repo import SQLiteRepository, get_fleet_hosts
from tools.seed_demo import seed


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
    routes = ["/", "/assets", "/alerts/1", "/report"]
    for r in routes:
        resp = client.get(r)
        assert resp.status_code == 200
        text = resp.get_data(as_text=True)
        assert "Concept A" not in text, f"Route {r} contains 'Concept A'"
        assert "Concept B" not in text, f"Route {r} contains 'Concept B'"
        assert "Concept C" not in text, f"Route {r} contains 'Concept C'"


def test_removed_design_system_route(dashboard_client):
    """Obsolete design route must return 404 per R1 requirement."""
    client, _ = dashboard_client
    route = "/ui" + "-kit"
    resp = client.get(route)
    assert resp.status_code == 404


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


def test_u2_dialog_and_popover_attributes_in_served_html(dashboard_client):
    """Verifies U2 native <dialog> palette, popover menus, and aria-live toast container."""
    client, _ = dashboard_client
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # 1. Native <dialog> command palette
    assert '<dialog id="cmd-palette-dialog"' in html
    assert 'role="combobox"' in html
    assert 'aria-autocomplete="list"' in html
    assert 'aria-controls="cmd-palette-results"' in html
    assert 'id="cmd-palette-results" role="listbox"' in html
    assert "PALETTE_ACTIONS" in html
    assert "Toggle Theme" in html
    assert "Demo Contrast" in html

    # 2. Native popover attributes
    assert 'popover="auto"' in html
    assert 'popovertarget="host-popover"' in html
    assert 'popovertarget="filter-sev-popover"' in html
    assert 'popovertarget="filter-status-popover"' in html
    assert 'popovertarget="row-menu-1"' in html
    assert 'class="row-more-btn"' in html

    # 3. Toast system container
    assert 'id="toast-container" aria-live="polite"' in html


def test_data_consistency_across_views_and_api(tmp_path):
    """Test 4: DATA CONSISTENCY - ONE function get_fleet_hosts computes host list, counts, and online/offline.

    Verifies counts and statuses agree across Alerts page, Assets page, and /api/v1/hosts.
    """
    db_path = str(tmp_path / "fleet_consistency.db")
    repo = SQLiteRepository(db_path)
    now = time.time()
    with repo._get_connection() as conn:
        conn.execute(
            "INSERT INTO hosts (host_id, name, agent_version, status, last_seen) VALUES (?, ?, ?, ?, ?)",
            ("host-1", "Host One", "0.1.0", "online", now - 10)
        )
        conn.execute(
            "INSERT INTO hosts (host_id, name, agent_version, status, last_seen) VALUES (?, ?, ?, ?, ?)",
            ("host-2", "Host Two", "0.1.0", "online", now - 30)
        )
        conn.execute(
            "INSERT INTO hosts (host_id, name, agent_version, status, last_seen) VALUES (?, ?, ?, ?, ?)",
            ("host-3", "Host Three", "0.1.0", "offline", now - 500)
        )
        conn.commit()

    fleet = get_fleet_hosts(repo, ttl=90)
    assert fleet["total"] == 3
    assert fleet["online_count"] == 2
    assert fleet["offline_count"] == 1

    app = create_sentinel_app(repo)
    app.config["TESTING"] = True
    client = app.test_client()

    # 1. Check API /api/v1/hosts
    resp_api = client.get("/api/v1/hosts")
    assert resp_api.status_code == 200
    data_api = resp_api.get_json()
    assert data_api["ok"] is True
    assert data_api["total"] == 3
    assert data_api["online_count"] == 2
    assert data_api["offline_count"] == 1
    api_hosts = {h["host_id"]: h for h in data_api["hosts"]}
    assert api_hosts["host-1"]["status"] == "online"
    assert api_hosts["host-2"]["status"] == "online"
    assert api_hosts["host-3"]["status"] == "offline"

    # 2. Check Assets page /assets
    resp_assets = client.get("/assets")
    assert resp_assets.status_code == 200
    html_assets = resp_assets.get_data(as_text=True)
    assert "3 REGISTERED HOSTS" in html_assets
    assert "HEARTBEAT TTL: 90s" in html_assets
    assert "3 Total Hosts" in html_assets
    assert "host-1" in html_assets
    assert "host-2" in html_assets
    assert "host-3" in html_assets

    # 3. Check Alerts page / (Host selector badge and dropdown)
    resp_index = client.get("/")
    assert resp_index.status_code == 200
    html_index = resp_index.get_data(as_text=True)
    assert "Host: <b>All (3)</b>" in html_index
    assert 'data-host-val="host-1"' in html_index
    assert 'data-host-val="host-2"' in html_index
    assert 'data-host-val="host-3"' in html_index


def test_chart_data_after_seed_demo(tmp_path):
    """Test 6: CHART - after seed_demo, curve shows visible peak and >=5 distinct values."""
    db_path = str(tmp_path / "chart_demo.db")
    ret = seed(db_path, reset=True)
    assert ret == 0

    repo = SQLiteRepository(db_path)
    now = time.time()
    buckets = [0] * 24
    with repo._get_connection() as conn:
        cur = conn.execute("SELECT ts FROM changes WHERE ts >= ?", (now - 24 * 3600,))
        for row in cur.fetchall():
            ts = row["ts"]
            hour_idx = int((ts - (now - 24 * 3600)) / 3600)
            if 0 <= hour_idx < 24:
                buckets[hour_idx] += 1

    distinct_values = set(buckets)
    print(f"\n24 Hourly change buckets: {buckets}")
    print(f"Number of distinct values: {len(distinct_values)}")
    assert len(distinct_values) >= 5
    assert max(buckets) >= 100  # Visible peak

    # Verify rendered chart line path in /
    app = create_sentinel_app(repo)
    app.config["TESTING"] = True
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'd="M 0' in html


def test_u2_fix_popover_positioning_and_toasts(dashboard_client):
    """Test U2-FIX popover positioning engine, solid toasts with pause-on-hover, and palette recents."""
    client, _ = dashboard_client
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # 1. Popover positioning engine
    assert "positionPopover(trigger, popover)" in html
    assert "getBoundingClientRect" in html
    assert "addEventListener('beforetoggle'" in html or "addEventListener('toggle'" in html
    assert "onPopoverReposition" in html
    assert "window.innerHeight - 8" in html
    assert "window.innerWidth - 8" in html

    # 2. Toast system
    assert 'id="toast-container"' in html
    assert "pauseDismissTimer" in html
    assert "mouseenter" in html
    assert "mouseleave" in html
    assert "while (container.children.length >= 3)" in html
    assert "toast.remove()" in html

    # 3. Palette
    assert 'placeholder="Search alerts, hosts, paths..."' in html
    assert "saveRecentSearch" in html
    assert "sentinel_recent_searches" in html






