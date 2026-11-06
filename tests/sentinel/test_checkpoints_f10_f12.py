"""Tests for Checkpoint F10 (Archive creation) and Checkpoint F12 (Webhook notification).

F10: Legitimate zip or tar created -> no alarm beyond the INFO new-file alert
F12: Webhook alert to a local receiver -> delivered; retried on failure
"""

import http.server
import json
import tarfile
import threading
import time
import zipfile
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.models import Alert
from sentinel.notifier import WebhookNotifier
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


def test_f10_legitimate_zip_tar_only_raises_info(tmp_path):
    """F10: Legitimate zip or tar created -> no alarm beyond the INFO new-file alert."""
    watch_dir = tmp_path / "monitored_archives"
    watch_dir.mkdir()
    (watch_dir / "sample.txt").write_text("Hello archive content\n" * 20)

    config_dict = {
        "host_id": "archive-host",
        "paths": [{"id": "arch", "path": str(watch_dir), "mode": "protect"}],
    }

    cfg = load_settings_dict(config_dict)
    store = BaselineStore(str(tmp_path / "baseline.db"))
    repo = SQLiteRepository(str(tmp_path / "repo.db"))
    sink = LocalSink(repo)

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()
    engine.start()

    time.sleep(0.5)

    # 1. Create a zip archive inside watched directory
    zip_path = watch_dir / "backup.zip"
    with zipfile.ZipFile(str(zip_path), "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("data.txt", "archived data content")

    # 2. Create a tar archive inside watched directory
    tar_path = watch_dir / "backup.tar.gz"
    with tarfile.open(str(tar_path), "w:gz") as t:
        t.add(str(watch_dir / "sample.txt"), arcname="sample.txt")

    # Wait for debouncing
    time.sleep(2.0)
    engine.stop()

    alerts = repo.list_alerts()
    # Check that zip and tar did not trigger high/critical alarms (only default info)
    for a in alerts:
        if "backup.zip" in a.path or "backup.tar.gz" in a.path:
            assert a.severity == "info"
            assert "SPEED" not in a.signals
            assert "DECOY" not in a.signals
            assert "ENTROPY" not in a.signals


class WebhookReceiver(http.server.BaseHTTPRequestHandler):
    received = []
    fail_attempts = 0

    def do_POST(self):
        if WebhookReceiver.fail_attempts > 0:
            WebhookReceiver.fail_attempts -= 1
            self.send_response(500)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        WebhookReceiver.received.append(json.loads(body.decode("utf-8")))

        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture
def webhook_server():
    WebhookReceiver.received = []
    WebhookReceiver.fail_attempts = 0
    server = http.server.HTTPServer(("127.0.0.1", 0), WebhookReceiver)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}/hook", WebhookReceiver

    server.shutdown()
    server.server_close()


def test_f12_webhook_delivered_with_retries(webhook_server):
    """F12: Webhook alert to a local receiver -> delivered; retried on failure."""
    url, receiver = webhook_server

    # Configure notifier with 3 retries, backoff
    notifier = WebhookNotifier(url=url, min_severity="high", max_retries=3, backoff_factor=0.05)

    alert_low = Alert(
        id=1,
        host_id="box-1",
        root_id="app",
        path="/app/log.txt",
        severity="low",
        status="open",
        first_seen=time.time(),
        last_seen=time.time(),
        count=1,
        kinds=["modified"],
        signals=[],
        summary="low severity edit",
    )
    # Low severity is filtered out
    assert notifier.send_alert(alert_low) is False
    assert len(receiver.received) == 0

    # Simulate 1 transient failure on server side
    receiver.fail_attempts = 1

    alert_critical = Alert(
        id=2,
        host_id="box-1",
        root_id="ssh",
        path="/etc/ssh/authorized_keys",
        severity="critical",
        status="open",
        first_seen=time.time(),
        last_seen=time.time(),
        count=1,
        kinds=["modified"],
        signals=["DECOY"],
        summary="SSH key compromised",
    )

    # Critical alert sent: fails once, retried on attempt 2, succeeds
    delivered = notifier.send_alert(alert_critical)
    assert delivered is True
    assert len(receiver.received) == 1
    assert "SSH key compromised" in receiver.received[0]["text"]

