"""Regression tests for Bulk Acknowledge Alerts feature and slow_3s terminal detachment."""

import signal
import sys
import pytest
from sentinel.models import Change, EventEnvelope, Meta
from sentinel.server.app import create_sentinel_app
from sentinel.server.repo import SQLiteRepository
from test_ransomware.slow_3s import detach_stdin_and_ignore_signals


def test_slow_3s_detaches_stdin_and_ignores_terminal_signals():
    """Verify slow_3s detaches stdin and sets SIG_IGN on terminal suspension signals."""
    detach_stdin_and_ignore_signals()

    for sig_name in ("SIGTSTP", "SIGTTIN", "SIGTTOU"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            handler = signal.getsignal(sig)
            assert handler == signal.SIG_IGN, f"Signal {sig_name} was not ignored"

    # stdin must be redirected (not a tty)
    assert not sys.stdin.isatty()


def test_bulk_acknowledge_55_alerts(tmp_path):
    """Verify bulk acknowledge marks 55 open alerts as rejected/acknowledged without deleting them."""
    db_path = str(tmp_path / "bulk_test.db")
    repo = SQLiteRepository(db_path)

    # Seed 55 alerts representing recursive chmod permission changes
    for i in range(1, 56):
        meta_old = Meta(sha256=f"hash{i}", size=100, mode=0o644, uid=1000, gid=1000)
        meta_new = Meta(sha256=f"hash{i}", size=100, mode=0o777, uid=1000, gid=1000)
        change = Change(kinds=["permissions"], old=meta_old, new=meta_new)
        env = EventEnvelope(
            root_id="docs",
            path=f"/home/aayush/protected_folder/file_{i}.txt",
            host_id="LAPTOP-HE02HM0R",
            ts=1700000000.0 + i,
            change=change,
            severity="high",
            summary=f"Permissions changed on file_{i}.txt",
        )
        repo.upsert_alert(env)

    app = create_sentinel_app(repo)
    app.config["TESTING"] = True
    client = app.test_client()

    # 1. Initial State: 55 open alerts
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Bulk Acknowledge (55)" in html
    all_alerts = repo.list_alerts()
    assert len(all_alerts) == 55
    assert all(a.status == "open" for a in all_alerts)

    # 2. Trigger Bulk Acknowledge via dashboard route
    resp = client.post("/alerts/bulk-acknowledge", data={"actor": "admin", "note": "Bulk resolved"}, follow_redirects=True)
    assert resp.status_code == 200
    html_after = resp.get_data(as_text=True)

    # 3. Verify Open Alerts counter cleared to 0 (assert equivalent data element per copy diet)
    assert '<div id="open-alerts-count" class="stat-val">0</div>' in html_after
    open_alerts_after = repo.list_alerts(status="open")
    assert len(open_alerts_after) == 0

    # 4. Verify alerts are NOT deleted and audit trail is preserved
    all_alerts_after = repo.list_alerts()
    assert len(all_alerts_after) == 55, "Alerts must NOT be deleted from the database!"
    assert all(a.status in ("rejected", "acknowledged") for a in all_alerts_after)

    # 5. Verify Compliance Report page displays all 55 historical records
    report_resp = client.get("/report?days=3650")
    assert report_resp.status_code == 200
    report_html = report_resp.get_data(as_text=True)
    assert "Total Incidents" in report_html
    assert ">55</div>" in report_html
    assert ">0</div>" in report_html  # 0 open alerts in report summary card
    assert "/home/aayush/protected_folder/file_1.txt" in report_html
    assert "/home/aayush/protected_folder/file_55.txt" in report_html

