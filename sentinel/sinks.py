"""Event sinks for Sentinel agents.

Follows scaling rules S-1, S-5:
Abstract Sink interface, LocalSink for direct repository access,
HttpSink for distributed remote delivery.
"""

from __future__ import annotations

import abc
from typing import List, Optional

from sentinel.models import Alert, EventEnvelope
from sentinel.server.repo import Repository


class EventSink(abc.ABC):
    """Abstract sink for shipping EventEnvelopes."""

    @abc.abstractmethod
    def emit(self, envelope: EventEnvelope) -> Optional[Alert]:
        """Emit a single event envelope and return the resulting alert if applicable."""
        pass


class LocalSink(EventSink):
    """Direct sink for local/single-process Sentinel runs."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def emit(self, envelope: EventEnvelope) -> Optional[Alert]:
        return self.repo.upsert_alert(envelope)


class HttpSink(EventSink):
    """HTTP client sink that ships batches of EventEnvelopes to a remote Sentinel server.

    Uses standard library urllib (no requests dependency).
    """

    def __init__(self, server_url: str, token: Optional[str] = None, timeout: float = 5.0) -> None:
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def emit(self, envelope: EventEnvelope) -> Optional[Alert]:
        self.emit_batch([envelope])
        return None

    def emit_batch(self, envelopes: List[EventEnvelope]) -> bool:
        if not envelopes:
            return True

        import json
        import urllib.request
        import urllib.error

        url = f"{self.server_url}/api/v1/events"
        payload = json.dumps([e.to_dict() for e in envelopes]).encode("utf-8")

        req = urllib.request.Request(
            url=url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        return False


class DiskBufferedHttpSink(EventSink):
    """Disk-backed persistent queue for offline event buffering and replay."""

    def __init__(self, queue_db_path: str, server_url: str, token: Optional[str] = None) -> None:
        import os
        import sqlite3
        self.queue_db_path = os.path.abspath(os.path.expanduser(queue_db_path))
        os.makedirs(os.path.dirname(self.queue_db_path), exist_ok=True)
        self.http_sink = HttpSink(server_url=server_url, token=token)
        self._init_queue_db()

    def _init_queue_db(self) -> None:
        import sqlite3
        with sqlite3.connect(self.queue_db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.commit()

    def emit(self, envelope: EventEnvelope) -> Optional[Alert]:
        import sqlite3
        import time
        # 1. Enqueue to disk first (durability)
        with sqlite3.connect(self.queue_db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO event_queue (event_id, payload, created_at) VALUES (?, ?, ?)",
                (envelope.event_id, envelope.to_json(), time.time())
            )
            conn.commit()

        # 2. Try flushing queue
        self.flush()
        return None

    def flush(self) -> int:
        """Attempt to flush buffered events to server in order. Returns count delivered."""
        import json
        import sqlite3
        with sqlite3.connect(self.queue_db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT id, payload FROM event_queue ORDER BY id ASC LIMIT 50").fetchall()
            if not rows:
                return 0

            envelopes = [EventEnvelope.from_json(r["payload"]) for r in rows]
            if self.http_sink.emit_batch(envelopes):
                # Delivered! Remove batch from queue
                ids = [r["id"] for r in rows]
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"DELETE FROM event_queue WHERE id IN ({placeholders})", tuple(ids))
                conn.commit()
                return len(ids)

        return 0

