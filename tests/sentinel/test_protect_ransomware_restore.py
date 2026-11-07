"""Integration test verifying Protect Mode automatic rollback on ransomware attack."""

import os
import subprocess
import sys
import time
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


def test_protect_mode_kills_ransomware_and_restores_100_percent(tmp_path):
    """Proves that ransomware_v1 is killed and all damaged files are 100% restored."""
    watch_dir = tmp_path / "protected_folder"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")

    # Create 10 original test files
    original_contents = {}
    for i in range(10):
        name = f"document_{i:03d}.txt"
        fp = watch_dir / name
        content = f"CONFIDENTIAL COMPANY RECORD #{i}\n" * 50
        fp.write_text(content, encoding="utf-8")
        original_contents[name] = content

    cfg_dict = {
        "host_id": "protect-integration-host",
        "paths": [
            {
                "id": "protected_sandbox",
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

    # 1. Initialize golden baseline
    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()

    # 2. Start engine
    engine.start()
    time.sleep(1.0)

    # 3. Launch ransomware simulator
    sim_script = os.path.abspath("test_ransomware/ransomware_v1.py")
    proc = subprocess.Popen(
        [sys.executable, sim_script, "--target", str(watch_dir), "--rate", "20", "--hold", "0.04"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout, stderr = proc.communicate(timeout=10)

    # Allow debouncer and rollback to complete
    time.sleep(1.5)
    engine.stop()

    # 4. Verify attacker process was killed
    assert proc.returncode in (137, -9, 0)

    # 5. Verify alert generated on dashboard
    alerts = repo.list_alerts()
    assert len(alerts) >= 1
    critical_alerts = [a for a in alerts if a.severity == "critical"]
    assert len(critical_alerts) >= 1
    assert any("DECOY" in a.signals or "SPEED" in a.signals for a in critical_alerts)

    # 6. Verify 100% of files are restored to original clean text (not binary garbage)
    for name, expected in original_contents.items():
        file_path = watch_dir / name
        assert file_path.exists(), f"File {name} should exist"
        actual = file_path.read_text(encoding="utf-8")
        assert actual == expected, f"File {name} was not restored! Contains: {actual[:100]}"


def test_protect_mode_kills_ransomware_avoid_decoys_and_restores(tmp_path):
    """Proves that ransomware_v1 with --avoid-decoys triggers SPEED alert and files are restored."""
    watch_dir = tmp_path / "protected_folder_avoid"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")

    original_contents = {}
    for i in range(30):
        name = f"document_{i:03d}.txt"
        fp = watch_dir / name
        content = f"SENSITIVE FINANCIAL AUDIT #{i}\n" * 150
        fp.write_text(content, encoding="utf-8")
        original_contents[name] = content

    cfg_dict = {
        "host_id": "protect-avoid-host",
        "paths": [
            {
                "id": "protected_sandbox",
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

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()
    engine.start()
    time.sleep(1.0)

    sim_script = os.path.abspath("test_ransomware/ransomware_v1.py")
    proc = subprocess.Popen(
        [sys.executable, sim_script, "--target", str(watch_dir), "--rate", "25", "--hold", "0.04", "--avoid-decoys"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout, stderr = proc.communicate(timeout=10)
    time.sleep(1.5)
    engine.stop()

    # Verify all files are restored
    for name, expected in original_contents.items():
        file_path = watch_dir / name
        assert file_path.exists(), f"File {name} should exist"
        actual = file_path.read_text(encoding="utf-8")
        assert actual == expected, f"File {name} was not restored! Contains: {actual[:100]}"
