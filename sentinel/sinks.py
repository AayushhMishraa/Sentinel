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

