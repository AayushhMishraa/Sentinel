"""Sentinel Notification subsystem.

Follows scaling rule S-5:
Pluggable Notifier interface and WebhookNotifier with retry backoff
and Slack-compatible JSON payloads.
"""

from __future__ import annotations

import abc
import json
import time
import urllib.error
import urllib.request
from typing import List, Optional

from sentinel.models import Alert
from sentinel.rules import SEVERITY_ORDER


class Notifier(abc.ABC):
    """Abstract notification delivery interface."""

    @abc.abstractmethod
    def send_alert(self, alert: Alert) -> bool:
        """Deliver alert to notification target."""
        pass


class WebhookNotifier(Notifier):
    """Webhook notifier with retries and severity filtering.

    Payload formatted for Slack/Discord/Teams incoming webhooks.
    """

    def __init__(
        self,
        url: str,
        min_severity: str = "high",
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ) -> None:
        self.url = url
        self.min_severity = min_severity.lower()
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    def _should_notify(self, severity: str) -> bool:
        order_alert = SEVERITY_ORDER.get(severity.lower(), 1)
        order_min = SEVERITY_ORDER.get(self.min_severity, 4)
        return order_alert >= order_min

    def send_alert(self, alert: Alert) -> bool:
        if not self._should_notify(alert.severity):
            return False

        payload = {
            "text": f":warning: *Sentinel Alert [{alert.severity.upper()}]*\n"
                    f"*Path:* `{alert.path}`\n"
                    f"*Host:* `{alert.host_id}`\n"
                    f"*Kinds:* {', '.join(alert.kinds)}\n"
                    f"*Signals:* {', '.join(alert.signals) or 'None'}\n"
                    f"*Summary:* {alert.summary}",
            "attachments": [
                {
                    "color": "#ff4444" if alert.severity == "critical" else "#ff8800",
                    "fields": [
                        {"title": "Alert ID", "value": f"#{alert.id}", "short": True},
                        {"title": "Status", "value": alert.status.upper(), "short": True},
                    ],
                }
            ],
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url=self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        for attempt in range(self.max_retries):
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    if resp.status in (200, 201, 204):
                        return True
            except (urllib.error.URLError, OSError):
                if attempt < self.max_retries - 1:
                    time.sleep(self.backoff_factor * (2 ** attempt))

        return False

