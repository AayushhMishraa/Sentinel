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
