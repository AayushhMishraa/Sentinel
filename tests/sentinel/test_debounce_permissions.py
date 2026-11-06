"""Regression test for capturing permission changes on new files within the debounce window."""

import os
import time
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.classifier import classify_file_change
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink
from core.events import FileEvent


def test_create_and_chmod_within_debounce_window(tmp_path):
    """Scenario:

    1. touch protected_folder/runner.sh
    2. chmod 777 protected_folder/runner.sh immediately (within debounce window)
    Expected:
    Sentinel registers a HIGH severity alert with the kind 'permissions' (and 'created').
    """
    watch_dir = tmp_path / "protected_folder"
    watch_dir.mkdir()

    cfg_dict = {
        "host_id": "test-box",
        "paths": [
            {
                "id": "protected",
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

    runner_path = watch_dir / "runner.sh"
    # Create file
    with open(runner_path, "w") as fp:
        fp.write("#!/bin/bash\necho hello\n")
    # Immediately change permissions within debounce window
    os.chmod(runner_path, 0o777)

    # Wait for debounce quiet period and processing
    time.sleep(1.2)
    engine.stop()

    alerts = repo.list_alerts()
    runner_alerts = [a for a in alerts if "runner.sh" in a.path]
    assert len(runner_alerts) >= 1, "Expected an alert for runner.sh"

    alert = runner_alerts[0]
    assert alert.severity == "high", f"Expected HIGH severity, got {alert.severity}"
    assert "permissions" in alert.kinds, f"Expected 'permissions' in kinds, got {alert.kinds}"
    assert "created" in alert.kinds, f"Expected 'created' in kinds, got {alert.kinds}"


def test_classify_file_change_with_debounce_permission_events(tmp_path):
    """Direct classifier test ensuring new files chmod'ed during debounce are classified with 'permissions'."""
    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()
    runner = watch_dir / "script.sh"
    runner.write_text("#!/bin/sh\n")
    os.chmod(runner, 0o777)

    events = [
        FileEvent(path=str(runner), event_type="created", timestamp=time.time()),
        FileEvent(path=str(runner), event_type="modified", timestamp=time.time() + 0.05),
    ]

    change = classify_file_change(
        root_id="r1",
        root_path=str(watch_dir),
        relpath="script.sh",
        baseline_entry=None,
        capture_content=True,
        initial_mode=0o644,
        events=events,
    )

    assert change is not None
    assert "created" in change.kinds
    assert "permissions" in change.kinds
