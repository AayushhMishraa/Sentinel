"""Regression test to ensure starting the engine with decoys enabled does not trigger false-positive CRITICAL alerts."""

import os
import time
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


def test_protect_mode_decoy_startup_no_self_alert(tmp_path):
    """Ensure that starting the engine with decoys in protect mode does not alert on decoy creation."""
    watch_dir = tmp_path / "protected_vault"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")
    (watch_dir / "legit_file.txt").write_text("hello world\n")

    cfg_dict = {
        "host_id": "test-box",
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

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.start()

    # Wait for startup and debounce window to settle
    time.sleep(1.5)

    startup_alerts = repo.list_alerts()
    decoy_startup_alerts = [a for a in startup_alerts if "!DECOY" in a.path]
    assert len(decoy_startup_alerts) == 0, (
        f"Expected 0 decoy alerts on startup, but found: {[a.summary for a in decoy_startup_alerts]}"
    )

    # Now verify that real tampering with a decoy still triggers a CRITICAL alert
    decoy_file = watch_dir / "!DECOY_001.txt"
    assert decoy_file.exists(), "Decoy file was not planted"
    with open(decoy_file, "a") as fp:
        fp.write("malicious payload tampering\n")

    time.sleep(1.5)
    engine.stop()

    tamper_alerts = [a for a in repo.list_alerts() if "!DECOY" in a.path]
    assert len(tamper_alerts) == 1, "Expected exactly 1 alert after tampering with decoy"
    alert = tamper_alerts[0]
    assert alert.severity == "critical"
    assert "DECOY" in alert.signals
    assert "modified" in alert.kinds


def test_monitor_mode_decoy_startup_no_self_alert(tmp_path):
    """Ensure that starting the engine with decoys in monitor mode does not alert on decoy creation."""
    watch_dir = tmp_path / "monitor_vault"
    watch_dir.mkdir()
    (watch_dir / "data.txt").write_text("regular data\n")

    cfg_dict = {
        "host_id": "test-box",
        "paths": [
            {
                "id": "monitored",
                "path": str(watch_dir),
                "mode": "monitor",
                "decoys": True,
            }
        ],
    }

    cfg = load_settings_dict(cfg_dict)
    store = BaselineStore(str(tmp_path / "baseline.db"))
    repo = SQLiteRepository(str(tmp_path / "repo.db"))
    sink = LocalSink(repo)

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.start()

    time.sleep(1.5)
    engine.stop()

    alerts = repo.list_alerts()
    decoy_alerts = [a for a in alerts if "!DECOY" in a.path]
    assert len(decoy_alerts) == 0, (
        f"Expected 0 decoy alerts in monitor mode startup, but found: {[a.summary for a in decoy_alerts]}"
    )
