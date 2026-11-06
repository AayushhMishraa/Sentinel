"""Test for Checkpoint F11: Agent Offline Disk Buffering & Reconnect Replay.

F11: Agent offline then back -> buffered events delivered, none lost or duplicated.
"""

import http.server
import json
import threading
import time
import pytest
from sentinel.models import Change, EventEnvelope, Meta
from sentinel.sinks import DiskBufferedHttpSink


class MockServerHandler(http.server.BaseHTTPRequestHandler):
    received_events = []
    return_500 = False

    def do_POST(self):
        if self.path == "/api/v1/events":
            if MockServerHandler.return_500:
                self.send_response(500)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            events = json.loads(body.decode("utf-8"))
            MockServerHandler.received_events.extend(events)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

    def log_message(self, format, *args):
        pass  # Quiet during tests


@pytest.fixture
def mock_server():
    MockServerHandler.received_events = []
    MockServerHandler.return_500 = False
    server = http.server.HTTPServer(("127.0.0.1", 0), MockServerHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}", MockServerHandler

    server.shutdown()
    server.server_close()


def test_f11_offline_buffering_and_reconnect_replay(tmp_path, mock_server):
    """F11: Agent offline then back -> buffered events delivered, none lost or duplicated."""
    server_url, handler = mock_server
    db_path = str(tmp_path / "queue.db")

    sink = DiskBufferedHttpSink(
        queue_db_path=db_path,
        server_url=server_url,
        token="test-token",
    )

    # 1. Simulate server offline (returns 500 error)
    handler.return_500 = True

    # Emit 5 events while server is unreachable
    envelopes = []
    for i in range(5):
        ev = EventEnvelope(
            event_id=f"offline-event-{i}",
            root_id="app",
            path=f"/var/app/file_{i}.txt",
            host_id="box-offline",
            ts=time.time(),
            change=Change(kinds=["modified"]),
            severity="medium",
            summary=f"edit {i}",
        )
        envelopes.append(ev)
        sink.emit(ev)

    # Server received 0 events because it was failing
    assert len(handler.received_events) == 0

    # 2. Server comes back online
    handler.return_500 = False

    # 3. Agent reconnects and flushes queue
    delivered_count = sink.flush()
    assert delivered_count == 5

    # Check server received all 5 unique events
    assert len(handler.received_events) == 5
    delivered_ids = [e["event_id"] for e in handler.received_events]
    assert delivered_ids == [f"offline-event-{i}" for i in range(5)]

    # 4. Another flush should have nothing left to send (no duplicates)
    assert sink.flush() == 0
    assert len(handler.received_events) == 5
