"""Regression test proving slow_3s triggers exactly 1 CRITICAL SLOW_SUSPICION alert."""

import os
import random
import subprocess
import sys
import time
import pytest

from generate_samples import make_document_text
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


def test_slow_3s_triggers_exactly_one_critical_slow_suspicion_alert(tmp_path):
    """Proves that slow_3s against protected_folder triggers exactly 1 CRITICAL SLOW_SUSPICION alert."""
    watch_dir = tmp_path / "protected_folder"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")

    # Generate 5 document_*.txt files each >= 8 KB so entropy checker evaluates them
    rng = random.Random(42)
    for i in range(5):
        doc_path = watch_dir / f"document_{i:03d}.txt"
        doc_text = make_document_text(i, rng)
        assert len(doc_text) >= 8192, f"Document {doc_path} should be at least 8 KB"
        doc_path.write_text(doc_text, encoding="utf-8")

    cfg_dict = {
        "host_id": "test-slow-burn-box",
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
    time.sleep(1.5)

    # 0 open alerts on startup
    assert len([a for a in repo.list_alerts() if a.status == "open"]) == 0

    # 3. Launch slow_3s simulator with --avoid-decoys, interval 2.5s, limit 3 files
    # The slow-burn rule triggers once 3 distinct files become noise and >= 5.0s has elapsed
    sim_script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "test_ransomware", "slow_3s.py")
    res = subprocess.run(
        [sys.executable, sim_script, "--target", str(watch_dir), "--avoid-decoys", "--interval", "2.5", "--limit", "3"],
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Wait for debouncing to flush all 3 files
    time.sleep(2.0)
    engine.stop()

    all_alerts = repo.list_alerts()
    assert len(all_alerts) >= 3, f"Expected at least 3 alerts, found: {[a.summary for a in all_alerts]}"

    # Check for SLOW_SUSPICION signals
    slow_suspicion_alerts = [a for a in all_alerts if "SLOW_SUSPICION" in a.signals]
    assert len(slow_suspicion_alerts) == 1, (
        f"Expected exactly 1 alert with SLOW_SUSPICION signal, found {len(slow_suspicion_alerts)}: "
        f"{[a.to_dict() for a in all_alerts]}"
    )

    crit_alert = slow_suspicion_alerts[0]
    assert crit_alert.severity == "critical", f"Expected severity 'critical' for SLOW_SUSPICION, got {crit_alert.severity}"
    assert "ENTROPY" in crit_alert.signals or "SLOW_SUSPICION" in crit_alert.signals

    # Earlier modified files (documents 0 and 1) should be MEDIUM severity
    medium_alerts = [a for a in all_alerts if a.severity == "medium"]
    assert len(medium_alerts) >= 2, f"Expected at least 2 medium alerts before slow-burn escalation, got {len(medium_alerts)}"

