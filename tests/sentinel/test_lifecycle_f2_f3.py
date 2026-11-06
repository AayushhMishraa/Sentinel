"""Tests for Alert Lifecycle, Approve / Reject, and Acceptance Checkpoints F2 and F3.

F2: Config file edited, then Approved -> baseline updated, no repeat alert
F3: Config file edited, then Rejected -> stays flagged (baseline not updated)
"""

import os
import time
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


@pytest.fixture
def lifecycle_env(tmp_path):
    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()
    cfg_file = watch_dir / "nginx.conf"
    cfg_file.write_text("worker_processes 1;\n")

    config_dict = {
        "host_id": "test-host",
        "paths": [
            {
                "id": "etc",
                "path": str(watch_dir),
                "mode": "monitor",
                "capture_content": True,
            }
        ],
    }

    cfg = load_settings_dict(config_dict)
    store = BaselineStore(str(tmp_path / "baseline.db"))
    repo = SQLiteRepository(str(tmp_path / "repo.db"))
    sink = LocalSink(repo)

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()
    engine.start()

    time.sleep(0.5)

    yield {
        "engine": engine,
        "repo": repo,
        "store": store,
        "watch_dir": watch_dir,
        "cfg_file": cfg_file,
    }

    engine.stop()


def wait_for_alert(repo, path_part, timeout=3.5):
    start = time.time()
    while time.time() - start < timeout:
        alerts = repo.list_alerts()
        for a in alerts:
            if path_part in a.path:
                return a
        time.sleep(0.1)
    return None


def test_f2_approve_updates_baseline_and_no_repeat_alert(lifecycle_env):
    """F2: Config file edited, then Approved -> baseline updated, no repeat alert."""
    f = lifecycle_env["cfg_file"]
    repo = lifecycle_env["repo"]
    store = lifecycle_env["store"]
    engine = lifecycle_env["engine"]

    # 1. Edit the config file
    with open(f, "a") as fp:
        fp.write("worker_connections 1024;\n")

    alert = wait_for_alert(repo, "nginx.conf")
    assert alert is not None
    assert alert.status == "open"

    # 2. Approve the alert
    success = engine.approve_alert(alert.id, actor="admin", note="authorized maintenance")
    assert success is True

    # Check alert status in repo
    updated_alert = repo.get_alert(alert.id)
    assert updated_alert.status == "approved"
    assert updated_alert.resolution["actor"] == "admin"

    # Verify baseline was updated to the new state
    entry = store.get_entry("etc", "nginx.conf")
    assert "worker_connections 1024" in (entry.content or "")

    # Wait another quiet period; ensure NO new alert is opened for this same content
    time.sleep(1.2)
    open_alerts = repo.list_alerts(status="open")
    assert len(open_alerts) == 0


def test_f3_reject_keeps_drift_flagged_without_updating_baseline(lifecycle_env):
    """F3: Config file edited, then Rejected -> alert becomes rejected, baseline NOT updated."""
    f = lifecycle_env["cfg_file"]
    repo = lifecycle_env["repo"]
    store = lifecycle_env["store"]
    engine = lifecycle_env["engine"]

    orig_entry = store.get_entry("etc", "nginx.conf")
    orig_hash = orig_entry.sha256

    # 1. Tamper with config file
    with open(f, "w") as fp:
        fp.write("malicious payload\n")

    alert = wait_for_alert(repo, "nginx.conf")
    assert alert is not None
    assert alert.status == "open"

    # 2. Reject the alert
    success = engine.reject_alert(alert.id, actor="security-analyst", note="unauthorized tampering")
    assert success is True

    updated_alert = repo.get_alert(alert.id)
    assert updated_alert.status == "rejected"
    assert updated_alert.resolution["actor"] == "security-analyst"

    # 3. Baseline must NOT be updated (the drift stays visible)
    current_entry = store.get_entry("etc", "nginx.conf")
    assert current_entry.sha256 == orig_hash
    assert "malicious payload" not in (current_entry.content or "")
