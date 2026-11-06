"""Tests for Sentinel Protect Mode, Safety Guards, and Checkpoints F7, F8, F9.

F7: 25+ files edited within 5 s -> HIGH (SPEED)
F8: Decoy tampered with -> CRITICAL
F9: Ransomware simulator vs a protect-mode path -> stopped and restored 100/100
"""

import os
import subprocess
import sys
import time
import pytest
from core.events import FileEvent
from detection.speed_checker import SpeedChecker
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.modes import validate_protect_safety
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


def test_protect_safety_guards(tmp_path):
    # Refuse root /
    with pytest.raises(ValueError, match="root filesystem"):
        validate_protect_safety("/")

    # Refuse user $HOME
    home = os.path.expanduser("~")
    with pytest.raises(ValueError, match="user home directory"):
        validate_protect_safety(home)

    # File cap test
    capped_dir = tmp_path / "capped"
    capped_dir.mkdir()
    for i in range(15):
        (capped_dir / f"f_{i}.txt").write_text("x")

    with pytest.raises(ValueError, match="exceeds file cap"):
        validate_protect_safety(str(capped_dir), max_files=10)


def test_f8_decoy_tampered_critical(tmp_path):
    """F8: Decoy tampered with -> CRITICAL alert."""
    watch_dir = tmp_path / "protect_monitored"
    watch_dir.mkdir()
    # Create marker
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")

    config_dict = {
        "host_id": "test-host",
        "paths": [
            {
                "id": "protected_docs",
                "path": str(watch_dir),
                "mode": "protect",
                "decoys": True,
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

    # Tamper with planted decoy
    decoy_file = watch_dir / "!DECOY_001.txt"
    assert decoy_file.exists()
    decoy_file.write_text("tampered decoy content")

    # Wait for alert
    start = time.time()
    alert = None
    while time.time() - start < 4.0:
        for a in repo.list_alerts():
            if "!DECOY" in a.path:
                alert = a
                break
        if alert:
            break
        time.sleep(0.1)

    engine.stop()

    assert alert is not None
    assert alert.severity == "critical"
    assert "DECOY" in alert.signals


def test_f7_speed_rule_bulk_edits(tmp_path):
    """F7: 25+ files edited within 5 s -> HIGH (SPEED)."""
    watch_dir = tmp_path / "speed_folder"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")

    # Create 30 files
    files = []
    for i in range(30):
        fp = watch_dir / f"doc_{i}.txt"
        fp.write_text(f"initial content {i}\n")
        files.append(fp)

    config_dict = {
        "host_id": "speed-host",
        "paths": [
            {
                "id": "speed_path",
                "path": str(watch_dir),
                "mode": "protect",
                "decoys": False,
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

    # Rapid bulk modification of 26 files within < 1 second
    for i in range(26):
        with open(files[i], "w") as fp:
            fp.write("bulk modified data\n")

    start = time.time()
    speed_alert = None
    while time.time() - start < 4.5:
        for a in repo.list_alerts():
            if "SPEED" in a.signals:
                speed_alert = a
                break
        if speed_alert:
            break
        time.sleep(0.1)

    engine.stop()

    assert speed_alert is not None
    assert speed_alert.severity in ("high", "critical")
    assert "SPEED" in speed_alert.signals


def test_f9_ransomware_stopped_and_restored(tmp_path):
    """F9: Ransomware simulator vs a protect-mode path -> stopped and restored 100/100."""
    watch_dir = tmp_path / "ransom_sandbox"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")

    # Generate 15 sample files
    test_files = []
    for i in range(15):
        fp = watch_dir / f"data_{i:03d}.txt"
        fp.write_text(f"Important business record #{i}\n" * 50)
        test_files.append((str(fp), fp.read_text()))

    config_dict = {
        "host_id": "protect-host",
        "paths": [
            {
                "id": "vault",
                "path": str(watch_dir),
                "mode": "protect",
                "decoys": True,
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

    time.sleep(1.6)  # Allow initial snapshot to settle past margin

    # Launch harmless ransomware simulator against sandbox
    script_path = os.path.abspath("test_ransomware/ransomware_v1.py")
    proc = subprocess.Popen(
        [sys.executable, script_path, "--target", str(watch_dir), "--rate", "20", "--hold", "0.04"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for response engine
    proc.wait(timeout=10)

    start = time.time()
    restored = False
    while time.time() - start < 6.0:
        all_intact = True
        for fp, content in test_files:
            if not os.path.exists(fp) or open(fp).read() != content:
                all_intact = False
                break
        if all_intact:
            restored = True
            break
        time.sleep(0.2)

    engine.stop()
    assert restored is True, "Files were not restored after ransomware attack"
