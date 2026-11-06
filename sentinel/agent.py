"""Sentinel Agent runner.

Runs the SentinelEngine, manages disk-backed buffer flushing, periodic heartbeats,
and pulls pending commands (approve/reject) from the central server.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.request
from typing import Optional

from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.settings import SentinelConfig
from sentinel.sinks import DiskBufferedHttpSink, EventSink


class SentinelAgent:
    """Agent process that runs on watched hosts and communicates with the central server."""

    def __init__(
        self,
        config: SentinelConfig,
        baseline_store: BaselineStore,
        sink: EventSink,
    ) -> None:
        self.config = config
        self.baseline_store = baseline_store
        self.sink = sink
        self.engine = SentinelEngine(config=config, baseline_store=baseline_store, sink=sink)
        self._stop_event = threading.Event()
        self._agent_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.engine.start()
        self._stop_event.clear()
        self._agent_thread = threading.Thread(
            target=self._agent_loop, name=f"agent-{self.config.host_id}", daemon=True
        )
        self._agent_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self.engine.stop()
        if self._agent_thread and self._agent_thread.is_alive():
            self._agent_thread.join(timeout=2.0)

    def _agent_loop(self) -> None:
        while not self._stop_event.is_set():
            # 1. Flush disk buffer if using DiskBufferedHttpSink
            if isinstance(self.sink, DiskBufferedHttpSink):
                try:
                    self.sink.flush()
                except Exception:
                    pass

            # 2. Heartbeat to server
            self._send_heartbeat()

            # 3. Pull commands (approve / reject)
            self._pull_commands()

            self._stop_event.wait(5.0)

    def _send_heartbeat(self) -> None:
        server_url = self.config.server.url.rstrip("/")
        token = self.config.server.get_token()
        payload = json.dumps({
            "host_id": self.config.host_id,
            "agent_version": "0.1.0",
        }).encode("utf-8")

        req = urllib.request.Request(
            url=f"{server_url}/api/v1/heartbeat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if token:
            req.add_header("Authorization", f"Bearer {token}")

        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                pass
        except Exception:
            pass

    def _pull_commands(self) -> None:
        server_url = self.config.server.url.rstrip("/")
        token = self.config.server.get_token()
        url = f"{server_url}/api/v1/commands?host_id={self.config.host_id}"

        req = urllib.request.Request(url=url, method="GET")
        if token:
            req.add_header("Authorization", f"Bearer {token}")

        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    cmds = data.get("commands", [])
                    for c in cmds:
                        self._execute_command(c)
        except Exception:
            pass

    def _execute_command(self, cmd: dict) -> None:
        cmd_type = cmd.get("type")
        alert_id = cmd.get("alert_id")
        if cmd_type == "approve":
            self.engine.approve_alert(alert_id, actor="server-sync")
        elif cmd_type == "reject":
            self.engine.reject_alert(alert_id, actor="server-sync")
