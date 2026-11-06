"""Tests for re-flagging after approval and handling atomic rename tools like sed -i."""

import os
import subprocess
import time
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


def test_approved_alert_reflagged_on_drift_and_sed_i(tmp_path):
    """Ensure that an approved alert can be re-flagged if the file drifts again,

    and verify that atomic rename tools like sed -i produce a new alert with diff.
    """
    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()
    sample_file = watch_dir / "sample.txt"
    sample_file.write_text("initial line 1\ninitial line 2\n")

    cfg_dict = {
        "host_id": "test-box",
        "paths": [
            {
                "id": "vault",
                "path": str(watch_dir),
                "mode": "monitor",
                "capture_content": True,
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

    time.sleep(0.5)

    # 1. Modify file (e.g. malicious line added)
    with open(sample_file, "a") as fp:
        fp.write("malicious_addition = True\n")

    time.sleep(1.2)
    alerts = [a for a in repo.list_alerts() if "sample.txt" in a.path]
    assert len(alerts) == 1
    first_alert = alerts[0]
    assert first_alert.status == "open"
    assert "modified" in first_alert.kinds

    # 2. Approve the alert (e.g. user approved by mistake or as routine)
    engine.approve_alert(first_alert.id, actor="admin-user", note="accidental approval")
    assert repo.get_alert(first_alert.id).status == "approved"

    # 3. Modify again using sed -i (atomic rename temp file) to remove bad line
    subprocess.run(["sed", "-i", "/malicious_addition/d", str(sample_file)], check=True)

    # Wait for debounce and processing
    time.sleep(1.5)
    alerts_after = [a for a in repo.list_alerts() if "sample.txt" in a.path]

    # Verify a NEW open alert was generated
    assert len(alerts_after) == 2, "Expected a new open alert for post-approval drift"
    new_alert = alerts_after[0]
    assert new_alert.status == "open"
    assert new_alert.id != first_alert.id
    assert "modified" in new_alert.kinds

    # Verify diff in changes table shows removal of malicious_addition
    with repo._get_connection() as conn:
        row = conn.execute("SELECT json FROM changes WHERE alert_id = ?", (new_alert.id,)).fetchone()
        assert row is not None
        assert "-malicious_addition = True" in row["json"]

    engine.stop()

