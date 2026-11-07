"""Tests verifying clean slate startup for decoys and subsequent tamper detection."""

import os
import shutil
import time
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.app import create_sentinel_app
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


def test_clean_slate_startup_and_tamper_detection(tmp_path):
    """1. Fresh temporary directory initialized with a baseline.

    2. Engine starts with decoys enabled -> 0 alerts generated on startup (decoys plant silently).
    3. Tamper with planted decoy -> exactly 1 CRITICAL alert is generated with signal [DECOY].
    """
    watch_dir = tmp_path / "fresh_vault"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")
    (watch_dir / "secret.txt").write_text("top secret data\n")

    cfg_dict = {
        "host_id": "clean-slate-box",
        "paths": [
            {
                "id": "vault",
                "path": str(watch_dir),
                "mode": "protect",
                "decoys": True,
            }
        ],
    }

    cfg = load_settings_dict(cfg_dict)
    store = BaselineStore(str(tmp_path / "baseline.db"))
    repo = SQLiteRepository(str(tmp_path / "repo.db"))
    sink = LocalSink(repo)

    # 1. Initialize baseline
    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()

    # 2. Start engine
    engine.start()
    time.sleep(1.5)

    # Assert 0 alerts on startup (decoys planted completely silently)
    startup_alerts = repo.list_alerts()
    open_alerts = [a for a in startup_alerts if a.status == "open"]
    assert len(open_alerts) == 0, f"Expected 0 open alerts on clean startup, found: {[a.summary for a in open_alerts]}"

    # Verify decoys exist
    decoy_001 = watch_dir / "!DECOY_001.txt"
    assert decoy_001.exists(), "Expected !DECOY_001.txt to be planted"

    # 3. Tamper with planted decoy
    with open(decoy_001, "a") as fp:
        fp.write("malicious encryption bytes\n")

    time.sleep(1.5)
    engine.stop()

    # Assert exactly 1 CRITICAL alert was generated for the decoy tamper
    tamper_alerts = [a for a in repo.list_alerts() if "!DECOY" in a.path]
    assert len(tamper_alerts) == 1, f"Expected exactly 1 decoy alert, got {len(tamper_alerts)}"

    alert = tamper_alerts[0]
    assert alert.severity == "critical"
    assert "DECOY" in alert.signals
    assert "modified" in alert.kinds
    assert alert.status == "open"


def test_recreate_folder_clean_slate_reinit(tmp_path):
    """Simulates: deleting the folder, recreating it with secret.txt,

    re-running init_baseline, and restarting the engine -> stays at 0 Open Alerts.
    """
    watch_dir = tmp_path / "important"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")
    (watch_dir / "secret.txt").write_text("confidential\n")

    cfg_dict = {
        "host_id": "reinit-box",
        "paths": [
            {
                "id": "docs",
                "path": str(watch_dir),
                "mode": "protect",
                "decoys": True,
            }
        ],
    }

    cfg = load_settings_dict(cfg_dict)
    store = BaselineStore(str(tmp_path / "baseline.db"))
    repo = SQLiteRepository(str(tmp_path / "repo.db"))
    sink = LocalSink(repo)

    # First run: start, tamper decoy, stop
    eng1 = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    eng1.init_baseline()
    eng1.start()
    time.sleep(1.0)
    with open(watch_dir / "!DECOY_001.txt", "a") as fp:
        fp.write("tampered\n")
    time.sleep(1.5)
    eng1.stop()

    assert len([a for a in repo.list_alerts() if a.status == "open"]) == 1

    # Now clean up: delete folder, recreate with secret.txt, reset/clear repo alerts
    shutil.rmtree(watch_dir)
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")
    (watch_dir / "secret.txt").write_text("confidential\n")

    # Clean repo open alerts for the fresh start
    with repo._get_connection() as conn:
        conn.execute("DELETE FROM alerts WHERE status = 'open'")
        conn.commit()

    # Re-run init_baseline and restart engine
    eng2 = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    eng2.init_baseline()
    eng2.start()
    time.sleep(1.5)
    eng2.stop()

    # Verify dashboard stays at 0 Open Alerts
    open_alerts = [a for a in repo.list_alerts() if a.status == "open"]
    assert len(open_alerts) == 0, f"Expected 0 open alerts on reset, found: {[a.summary for a in open_alerts]}"


def test_multi_folder_old_modified_decoys_reinit_no_false_alarms(tmp_path):
    """Regression: 12 old modified decoy files across multiple folders do not false alarm on startup after init_baseline."""
    folder_a = tmp_path / "sandbox"
    folder_b = tmp_path / "web"
    folder_c = tmp_path / "docs"

    for f in (folder_a, folder_b, folder_c):
        f.mkdir()
        (f / ".REWIND_SANDBOX").write_text("ok")
        # Pre-seed old modified/scrambled decoy files from past attacks (12 decoys total)
        for i in range(1, 5):
            (f / f"!DECOY_{i:03d}.txt").write_text(f"corrupted_ransomware_payload_{i}\n")

    cfg_dict = {
        "host_id": "multi-decoy-box",
        "paths": [
            {"id": "sandbox", "path": str(folder_a), "mode": "protect", "decoys": True},
            {"id": "web", "path": str(folder_b), "mode": "monitor", "decoys": True},
            {"id": "docs", "path": str(folder_c), "mode": "protect", "decoys": True},
        ],
    }

    cfg = load_settings_dict(cfg_dict)
    store = BaselineStore(str(tmp_path / "baseline.db"))
    repo = SQLiteRepository(str(tmp_path / "repo.db"))
    sink = LocalSink(repo)

    # 1. Re-init baseline: engine cleanly replants all 12 decoys with clean canary text
    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()

    # 2. Start engine: file watcher must NOT trigger false alarms for any of the 12 decoys
    engine.start()
    time.sleep(2.0)
    engine.stop()

    open_alerts = [a for a in repo.list_alerts() if a.status == "open"]
    assert len(open_alerts) == 0, f"Expected 0 false alarm alerts on startup, got {len(open_alerts)}: {[a.summary for a in open_alerts]}"

