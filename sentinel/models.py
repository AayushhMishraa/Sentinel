"""Data models and serialization contracts for Sentinel.

Adheres to scaling rules S-1, S-2:
Every event carries schema_version=1 and host_id.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

CURRENT_SCHEMA_VERSION = 1


@dataclass
class Meta:
    sha256: str = ""
    size: int = 0
    mode: int = 0
    uid: int = 0
    gid: int = 0
    mtime_ns: int = 0
    entropy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional[Meta]:
        if not d:
            return None
        return cls(
            sha256=str(d.get("sha256", "")),
            size=int(d.get("size", 0)),
            mode=int(d.get("mode", 0)),
            uid=int(d.get("uid", 0)),
            gid=int(d.get("gid", 0)),
            mtime_ns=int(d.get("mtime_ns", 0)),
            entropy=float(d.get("entropy", 0.0)),
        )


@dataclass
class Change:
    kinds: List[str] = field(default_factory=list)  # created, modified, deleted, permissions, owner, renamed
    old: Optional[Meta] = None
    new: Optional[Meta] = None
    diff: Optional[str] = None
    diff_truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kinds": list(self.kinds),
            "old": self.old.to_dict() if self.old else None,
            "new": self.new.to_dict() if self.new else None,
            "diff": self.diff,
            "diff_truncated": self.diff_truncated,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Change:
        return cls(
            kinds=list(d.get("kinds", [])),
            old=Meta.from_dict(d.get("old")),
            new=Meta.from_dict(d.get("new")),
            diff=d.get("diff"),
            diff_truncated=bool(d.get("diff_truncated", False)),
        )


@dataclass
class EventEnvelope:
    root_id: str
    path: str
    host_id: str
    ts: float
    mode: str = "monitor"
    change: Change = field(default_factory=Change)
    signals: List[str] = field(default_factory=list)
    severity: str = "info"  # info | low | medium | high | critical
    pid: Optional[int] = None
    process_name: Optional[str] = None
    summary: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_version: str = "0.1.0"
    schema_version: int = CURRENT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "host_id": self.host_id,
            "agent_version": self.agent_version,
            "ts": self.ts,
            "root_id": self.root_id,
            "path": self.path,
            "mode": self.mode,
            "change": self.change.to_dict(),
            "signals": list(self.signals),
            "severity": self.severity,
            "pid": self.pid,
            "process_name": self.process_name,
            "summary": self.summary,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> EventEnvelope:
        return cls(
            root_id=str(d.get("root_id", "")),
            path=str(d.get("path", "")),
            host_id=str(d.get("host_id", "")),
            ts=float(d.get("ts", 0.0)),
            mode=str(d.get("mode", "monitor")),
            change=Change.from_dict(d.get("change", {})),
            signals=list(d.get("signals", [])),
            severity=str(d.get("severity", "info")),
            pid=d.get("pid"),
            process_name=d.get("process_name"),
            summary=str(d.get("summary", "")),
            event_id=str(d.get("event_id", str(uuid.uuid4()))),
            agent_version=str(d.get("agent_version", "0.1.0")),
            schema_version=int(d.get("schema_version", CURRENT_SCHEMA_VERSION)),
        )

    @classmethod
    def from_json(cls, text: str) -> EventEnvelope:
        return cls.from_dict(json.loads(text))


@dataclass
class Alert:
    id: int
    host_id: str
    root_id: str
    path: str
    severity: str
    status: str  # open | approved | rejected
    first_seen: float
    last_seen: float
    count: int
    kinds: List[str]
    signals: List[str]
    summary: str
    resolution: Optional[Dict[str, Any]] = None  # {actor, at, note}

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
