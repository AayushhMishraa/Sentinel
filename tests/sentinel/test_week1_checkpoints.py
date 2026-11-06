"""Week 1 Checkpoint Tests: F1, F4, F5, F6.

F1: Key appended to watched authorized_keys -> CRITICAL alert with diff
F4: Watched file deleted -> Alert
F5: chmod 777 / chown on a watched file -> HIGH, 'permissions changed'
F6: New file in a watched folder -> Alert per policy (INFO by default)
"""

import os
import stat
import time
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


@pytest.fixture
def sentinel_env(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    auth_keys = ssh_dir / "authorized_keys"
    auth_keys.write_text("ssh-ed25519 AAAAC3initialkey user@host\n")

    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()
    file_to_del = watch_dir / "todelete.txt"
    file_to_del.write_text("will be deleted\n")

    file_to_chmod = watch_dir / "secure.sh"
    file_to_chmod.write_text("#!/bin/sh\necho safe\n")
    os.chmod(file_to_chmod, 0o644)

    config_dict = {
        "host_id": "test-box",
        "defaults": {
            "new_file_severity": "info",
            "exclude": ["*.tmp"],
        },
        "paths": [
            {
                "id": "ssh",
                "path": str(ssh_dir),
                "mode": "monitor",
                "include": ["authorized_keys"],
                "capture_content": True,
            },
            {
                "id": "app",
                "path": str(watch_dir),
                "mode": "monitor",
                "capture_content": True,
            },
        ],
        "rules": [
            {
                "match": "**/authorized_keys",
                "severity": "critical",
                "reason": "SSH access list changed",
            }
        ],
    }

    cfg = load_settings_dict(config_dict)
    baseline_db = str(tmp_path / "baseline.db")
    repo_db = str(tmp_path / "repo.db")

    store = BaselineStore(baseline_db)
    repo = SQLiteRepository(repo_db)
    sink = LocalSink(repo)

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()
    engine.start()

    time.sleep(0.5)  # Ensure watcher is active

    yield {
        "engine": engine,
        "repo": repo,
        "store": store,
        "ssh_dir": ssh_dir,
        "auth_keys": auth_keys,
        "watch_dir": watch_dir,
        "file_to_del": file_to_del,
        "file_to_chmod": file_to_chmod,
    }

    engine.stop()


def wait_for_alert(repo, expected_path_part, timeout=3.0):
    start = time.time()
    while time.time() - start < timeout:
        alerts = repo.list_alerts()
        for a in alerts:
            if expected_path_part in a.path:
                return a
        time.sleep(0.1)
    return None


def test_f1_authorized_keys_appended_critical_with_diff(sentinel_env):
    """F1: Key appended to watched authorized_keys -> CRITICAL alert with diff."""
    auth_keys = sentinel_env["auth_keys"]
    repo = sentinel_env["repo"]

    # Append attacker key
    with open(auth_keys, "a") as f:
        f.write("ssh-ed25519 AAAAC3ATTACKERKEY evil@attacker\n")

    alert = wait_for_alert(repo, "authorized_keys", timeout=3.5)
    assert alert is not None, "Alert was not raised for authorized_keys modification"
    assert alert.severity == "critical"
    assert "modified" in alert.kinds

    # Verify diff is recorded in the change event
    with repo._get_connection() as conn:
        row = conn.execute("SELECT json FROM changes WHERE alert_id = ?", (alert.id,)).fetchone()
        assert row is not None
        change_json = row["json"]
        assert "+ssh-ed25519 AAAAC3ATTACKERKEY" in change_json


def test_f4_watched_file_deleted(sentinel_env):
    """F4: Watched file deleted -> alert."""
    f = sentinel_env["file_to_del"]
    repo = sentinel_env["repo"]

    os.remove(f)

    alert = wait_for_alert(repo, "todelete.txt", timeout=3.5)
    assert alert is not None, "Alert was not raised for deleted file"
    assert "deleted" in alert.kinds
    assert alert.severity in ("high", "critical")


def test_f5_chmod_permissions_changed(sentinel_env):
    """F5: chmod 777 on a watched file -> HIGH, 'permissions changed'."""
    f = sentinel_env["file_to_chmod"]
    repo = sentinel_env["repo"]

    os.chmod(f, 0o777)

    alert = wait_for_alert(repo, "secure.sh", timeout=3.5)
    assert alert is not None, "Alert was not raised for chmod"
    assert "permissions" in alert.kinds
    assert alert.severity == "high"


def test_f6_new_file_in_watched_folder_info(sentinel_env):
    """F6: New file in a watched folder -> alert per policy (INFO by default)."""
    watch_dir = sentinel_env["watch_dir"]
    repo = sentinel_env["repo"]

    new_file = watch_dir / "brand_new.txt"
    new_file.write_text("hello fresh data\n")

    alert = wait_for_alert(repo, "brand_new.txt", timeout=3.5)
    assert alert is not None, "Alert was not raised for new file"
    assert "created" in alert.kinds
    assert alert.severity == "info"
