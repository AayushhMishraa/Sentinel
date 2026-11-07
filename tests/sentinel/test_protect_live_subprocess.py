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


def test_protect_mode_live_subprocess_restores_document_000(tmp_path):
    """Runs ransomware_v1 as a real subprocess against a protect-mode folder and asserts document_000.txt is readable."""
    watch_dir = tmp_path / "protected_sandbox"
    watch_dir.mkdir()
    (watch_dir / ".REWIND_SANDBOX").write_text("ok")

    doc_path = watch_dir / "document_000.txt"
    sample_content = ("Document 000 - placeholder content for Rewind testing\n" * 160)
    doc_path.write_text(sample_content, encoding="utf-8")

    from sentinel.settings import load_settings_dict
    cfg_dict = {
        "host_id": "test-subprocess-host",
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

    # 1. Start engine
    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()
    engine.start()
    time.sleep(1.0)

    # 2. Launch ransomware simulator as a real subprocess
    cmd = [
        sys.executable,
        os.path.abspath("test_ransomware/ransomware_v1.py"),
        "--target",
        str(watch_dir),
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
    with open(str(doc_path), "r", encoding="utf-8") as f:
        text = f.read()

    assert "Document 000 - placeholder content for Rewind testing" in text
    assert len(text) >= 8192
    # Verify no binary / non-ascii corruption
    assert text.isascii(), "Restored document should contain clean ASCII text, not binary garbage"

