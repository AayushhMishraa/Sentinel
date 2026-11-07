"""Repository abstraction and SQLite implementation.

Follows scaling rule S-3:
Storage sits behind a Repository interface (SQLite now, PostgreSQL later).
"""

from __future__ import annotations

import abc
import contextlib
import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

from sentinel.models import Alert, EventEnvelope


class Repository(abc.ABC):
    """Abstract storage repository for Sentinel."""

    @abc.abstractmethod
    def record_change(self, envelope: EventEnvelope, alert_id: Optional[int] = None) -> None:
        """Store an immutable change event record."""
        pass

    @abc.abstractmethod
    def upsert_alert(self, envelope: EventEnvelope) -> Alert:
        """Create or update an open alert for (host_id, path). Never lowers severity."""
        pass

    @abc.abstractmethod
    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Fetch alert by id."""
        pass

    @abc.abstractmethod
    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        host_id: Optional[str] = None,
    ) -> List[Alert]:
        """List alerts with optional filters."""
        pass

    @abc.abstractmethod
    def resolve_alert(self, alert_id: int, action: str, actor: str, note: str = "") -> bool:
        """Resolve an alert as approved or rejected with an audit trail entry."""
        pass

    @abc.abstractmethod
    def bulk_resolve_alerts(
        self, action: str = "reject", actor: str = "dashboard-admin", note: str = "Bulk acknowledged"
    ) -> int:
        """Resolve all open alerts in bulk with an audit trail entry."""
        pass

    @abc.abstractmethod
    def record_host(self, host_id: str, name: str, token_hash: str = "", agent_version: str = "0.1.0") -> None:
        """Register or heartbeat a host."""
        pass


SEVERITY_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


class SQLiteRepository(Repository):
    """SQLite implementation of the Sentinel Repository."""

    def __init__(self, db_path: str) -> None:
        self.db_path = os.path.abspath(os.path.expanduser(db_path))
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS hosts (
                    host_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token_hash TEXT,
                    last_seen REAL NOT NULL,
                    agent_version TEXT NOT NULL,
                    status TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT NOT NULL,
                    root_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,  -- open, approved, rejected
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    count INTEGER NOT NULL,
                    kinds TEXT NOT NULL,   -- JSON array
                    signals TEXT NOT NULL, -- JSON array
                    summary TEXT NOT NULL,
                    resolution TEXT        -- JSON dict or NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts (host_id, path, status);

                CREATE TABLE IF NOT EXISTS changes (
                    event_id TEXT PRIMARY KEY,
                    alert_id INTEGER,
                    host_id TEXT NOT NULL,
                    ts REAL NOT NULL,
                    json TEXT NOT NULL,
                    FOREIGN KEY (alert_id) REFERENCES alerts(id)
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id INTEGER NOT NULL,
                    action TEXT NOT NULL,  -- approve, reject
                    actor TEXT NOT NULL,
                    ts REAL NOT NULL,
                    note TEXT,
                    FOREIGN KEY (alert_id) REFERENCES alerts(id)
                );

                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT NOT NULL,
                    type TEXT NOT NULL,    -- approve, reject
                    alert_id INTEGER NOT NULL,
                    status TEXT NOT NULL,  -- pending, executed
                    created_at REAL NOT NULL
                );
            """)
            conn.commit()

        if os.path.exists(self.db_path):
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def record_host(self, host_id: str, name: str, token_hash: str = "", agent_version: str = "0.1.0") -> None:
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO hosts (host_id, name, token_hash, last_seen, agent_version, status)
                VALUES (?, ?, ?, ?, ?, 'online')
            """, (host_id, name, token_hash, time.time(), agent_version))
            conn.commit()

    def record_change(self, envelope: EventEnvelope, alert_id: Optional[int] = None) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO changes (event_id, alert_id, host_id, ts, json)
                VALUES (?, ?, ?, ?, ?)
            """, (envelope.event_id, alert_id, envelope.host_id, envelope.ts, envelope.to_json()))
            conn.commit()

    def upsert_alert(self, envelope: EventEnvelope) -> Alert:
        with self._get_connection() as conn:
            # Check for existing OPEN alert for (host_id, path)
            cur = conn.execute("""
                SELECT * FROM alerts
                WHERE host_id = ? AND path = ? AND status = 'open'
                LIMIT 1
            """, (envelope.host_id, envelope.path))
            existing = cur.fetchone()

            if existing:
                alert_id = existing["id"]
                # Never lower severity
                curr_sev = existing["severity"]
                new_sev = envelope.severity
                effective_sev = new_sev if SEVERITY_ORDER.get(new_sev, 0) > SEVERITY_ORDER.get(curr_sev, 0) else curr_sev

                # Union kinds and signals
                existing_kinds = set(json.loads(existing["kinds"]))
                existing_kinds.update(envelope.change.kinds)
                existing_signals = set(json.loads(existing["signals"]))
                existing_signals.update(envelope.signals)
                if envelope.change and hasattr(envelope.change, "signals") and envelope.change.signals:
                    existing_signals.update(envelope.change.signals)

                conn.execute("""
                    UPDATE alerts
                    SET severity = ?, last_seen = ?, count = count + 1,
                        kinds = ?, signals = ?, summary = ?
                    WHERE id = ?
                """, (
                    effective_sev,
                    envelope.ts,
                    json.dumps(sorted(existing_kinds)),
                    json.dumps(sorted(existing_signals)),
                    envelope.summary or existing["summary"],
                    alert_id,
                ))
            else:
                combined_signals = set(envelope.signals)
                if envelope.change and hasattr(envelope.change, "signals") and envelope.change.signals:
                    combined_signals.update(envelope.change.signals)

                cur = conn.execute("""
                    INSERT INTO alerts
                    (host_id, root_id, path, severity, status, first_seen, last_seen, count, kinds, signals, summary, resolution)
                    VALUES (?, ?, ?, ?, 'open', ?, ?, 1, ?, ?, ?, NULL)
                """, (
                    envelope.host_id,
                    envelope.root_id,
                    envelope.path,
                    envelope.severity,
                    envelope.ts,
                    envelope.ts,
                    json.dumps(sorted(envelope.change.kinds)),
                    json.dumps(sorted(combined_signals)),
                    envelope.summary,
                ))
                alert_id = cur.lastrowid

            conn.commit()

        # Record change tied to this alert
        self.record_change(envelope, alert_id=alert_id)
        return self.get_alert(alert_id)  # type: ignore

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if not row:
                return None
            res = json.loads(row["resolution"]) if row["resolution"] else None
            return Alert(
                id=row["id"],
                host_id=row["host_id"],
                root_id=row["root_id"],
                path=row["path"],
                severity=row["severity"],
                status=row["status"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                count=row["count"],
                kinds=json.loads(row["kinds"]),
                signals=json.loads(row["signals"]),
                summary=row["summary"],
                resolution=res,
            )

    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        host_id: Optional[str] = None,
    ) -> List[Alert]:
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if host_id:
            query += " AND host_id = ?"
            params.append(host_id)
        query += " ORDER BY last_seen DESC"

        results: List[Alert] = []
        with self._get_connection() as conn:
            for row in conn.execute(query, tuple(params)):
                res = json.loads(row["resolution"]) if row["resolution"] else None
                results.append(Alert(
                    id=row["id"],
                    host_id=row["host_id"],
                    root_id=row["root_id"],
                    path=row["path"],
                    severity=row["severity"],
                    status=row["status"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    count=row["count"],
                    kinds=json.loads(row["kinds"]),
                    signals=json.loads(row["signals"]),
                    summary=row["summary"],
                    resolution=res,
                ))
        return results

    def resolve_alert(self, alert_id: int, action: str, actor: str, note: str = "") -> bool:
        if action not in ("approve", "reject", "acknowledge"):
            raise ValueError(f"Invalid resolution action: {action}")
        now = time.time()
        res_dict = {"actor": actor, "at": now, "note": note}
        new_status = "approved" if action == "approve" else ("acknowledged" if action == "acknowledge" else "rejected")

        with self._get_connection() as conn:
            cur = conn.execute("""
                UPDATE alerts
                SET status = ?, resolution = ?
                WHERE id = ? AND status = 'open'
            """, (new_status, json.dumps(res_dict), alert_id))
            if cur.rowcount == 0:
                return False

            conn.execute("""
                INSERT INTO approvals (alert_id, action, actor, ts, note)
                VALUES (?, ?, ?, ?, ?)
            """, (alert_id, action, actor, now, note))
            conn.commit()
            return True

    def bulk_resolve_alerts(
        self, action: str = "reject", actor: str = "dashboard-admin", note: str = "Bulk acknowledged"
    ) -> int:
        if action not in ("approve", "reject", "acknowledge"):
            raise ValueError(f"Invalid resolution action: {action}")
        now = time.time()
        res_dict = {"actor": actor, "at": now, "note": note}
        new_status = "approved" if action == "approve" else ("acknowledged" if action == "acknowledge" else "rejected")

        with self._get_connection() as conn:
            rows = conn.execute("SELECT id FROM alerts WHERE status = 'open'").fetchall()
            if not rows:
                return 0
            conn.execute(
                "UPDATE alerts SET status = ?, resolution = ? WHERE status = 'open'",
                (new_status, json.dumps(res_dict))
            )
            for r in rows:
                conn.execute(
                    "INSERT INTO approvals (alert_id, action, actor, ts, note) VALUES (?, ?, ?, ?, ?)",
                    (r["id"], action, actor, now, note)
                )
            conn.commit()
            return len(rows)

