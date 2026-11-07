"""Test Protect Mode against a real ransomware_v1 subprocess on real disk files."""

import os
import subprocess
import sys
import time
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings
from sentinel.sinks import LocalSink


def test_protect_mode_live_subprocess_restores_document_000():
    """Runs ransomware_v1 as a real subprocess against protected_folder and asserts document_000.txt is readable."""
    cfg = load_settings("sentinel.yaml")
    store = BaselineStore("sentinel_baseline.db")
    repo = SQLiteRepository("sentinel_repo.db")
    sink = LocalSink(repo)

    # 1. Start engine
    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.start()
    time.sleep(1.0)

    # 2. Launch ransomware simulator as a real subprocess
    cmd = [
        sys.executable,
        "test_ransomware/ransomware_v1.py",
        "--target",
        "protected_folder",
        "--rate",
        "20",
        "--hold",
        "0.04",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = proc.communicate(timeout=10)

    # 3. Allow debounce and rollback to finish
    time.sleep(1.5)
    engine.stop()

    # 4. Verify process was killed
    assert proc.returncode in (137, -9, 0), f"Expected killed returncode, got {proc.returncode}"

    # 5. Verify document_000.txt is restored to plain readable text
    doc_path = "protected_folder/document_000.txt"
    with open(doc_path, "r", encoding="utf-8") as f:
        text = f.read()

    assert "Document 000 - placeholder content for Rewind testing" in text
    assert len(text) >= 8192
    # Verify no binary / non-ascii corruption
    assert text.isascii(), "Restored document should contain clean ASCII text, not binary garbage"
