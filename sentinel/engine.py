"""Sentinel core engine.

Manages WatchedPath instances, monitors filesystem changes with debouncing,
classifies changes against the persistent baseline, evaluates rules,
and emits versioned EventEnvelopes through the configured Sink.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Callable, Dict, List, Optional, Set

from core.events import FileEvent
from core.logger import log
from sentinel.baseline_store import (
    BaselineEntry,
    BaselineStore,
    hash_file_capped,
    inspect_file,
    scan_and_save_baseline,
)
from sentinel.classifier import classify_file_change
from sentinel.models import EventEnvelope
from sentinel.rules import escalate_with_signals, evaluate_rules
from sentinel.settings import PathSettings, SentinelConfig
from sentinel.sinks import EventSink, LocalSink
from watcher.file_watcher import FileWatcher, get_process_touching_file
from watcher.watcher_control import WatcherControl

DEBOUNCE_QUIET_SECONDS = 0.5


class WatchedPath:
    """Manages monitoring and state for a single configured path."""

    def __init__(
        self,
        config: PathSettings,
        global_config: SentinelConfig,
        baseline_store: BaselineStore,
        sink: EventSink,
        control: WatcherControl,
    ) -> None:
        self.config = config
        self.global_config = global_config
        self.baseline_store = baseline_store
        self.sink = sink
        self.control = control
        self.root_path = config.resolved_path
        self.watcher: Optional[FileWatcher] = None

        # Debouncing per relative path: {relpath: (last_event_time, latest_event)}
        self._debounce_lock = threading.Lock()
        self._pending_events: Dict[str, Tuple[float, FileEvent]] = {}
        self._stop_event = threading.Event()
        self._debounce_thread: Optional[threading.Thread] = None

        # Last reported sha256 to prevent duplicate alerts (G3)
        self._last_reported_hashes: Dict[str, str] = {}

    def start(self) -> None:
        if not os.path.isdir(self.root_path):
            os.makedirs(self.root_path, exist_ok=True)

        self._stop_event.clear()
        self._debounce_thread = threading.Thread(
            target=self._debounce_worker, name=f"debounce-{self.config.id}", daemon=True
        )
        self._debounce_thread.start()

        self.watcher = FileWatcher(
            callback=self._on_fs_event,
            protected_dir=self.root_path,
            idle_callback=None,
            attribute=True,
        )
        self.watcher.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self.watcher:
            self.watcher.stop()
        if self._debounce_thread and self._debounce_thread.is_alive():
            self._debounce_thread.join(timeout=2.0)

    def _on_fs_event(self, event: FileEvent) -> None:
        if self.control.is_paused():
            return

        rel = os.path.relpath(event.path, self.root_path).replace("\\", "/")
        if rel.startswith(".."):
            return

        # Check excludes
        for pat in self.config.exclude:
            import fnmatch
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
                return

        # Check includes if defined
        if self.config.include:
            matched = False
            for pat in self.config.include:
                import fnmatch
                if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
                    matched = True
                    break
            if not matched:
                return

        with self._debounce_lock:
            self._pending_events[rel] = (time.time(), event)

    def _debounce_worker(self) -> None:
        while not self._stop_event.is_set():
            now = time.time()
            ready: List[Tuple[str, FileEvent]] = []

            with self._debounce_lock:
                for rel, (last_ts, ev) in list(self._pending_events.items()):
                    if now - last_ts >= DEBOUNCE_QUIET_SECONDS:
                        ready.append((rel, ev))
                        del self._pending_events[rel]

            for rel, ev in ready:
                self._process_debounced_event(rel, ev)

            time.sleep(0.1)

    def _process_debounced_event(self, rel: str, event: FileEvent) -> None:
        abspath = os.path.join(self.root_path, rel)
        base_entry = self.baseline_store.get_entry(self.config.id, rel)

        change = classify_file_change(
            root_id=self.config.id,
            root_path=self.root_path,
            relpath=rel,
            baseline_entry=base_entry,
            max_hash_bytes=self.global_config.defaults.max_hash_bytes,
            capture_content=self.config.capture_content,
        )

        if not change:
            return

        # Deduplication check: if hash matches last reported, skip (G3)
        curr_hash = change.new.sha256 if change.new else ""
        if "modified" in change.kinds and curr_hash and self._last_reported_hashes.get(rel) == curr_hash:
            return
        if curr_hash:
            self._last_reported_hashes[rel] = curr_hash

        # Base severity from policy rules
        base_sev = evaluate_rules(
            relpath=rel,
            abspath=abspath,
            root_id=self.config.id,
            change=change,
            rules=self.global_config.rules,
            default_new_severity=self.global_config.defaults.new_file_severity,
        )

        # Signals (behavioral layer escalation)
        signals: List[str] = []
        final_sev = escalate_with_signals(base_sev, signals)

        # PID attribution (G6)
        pid = event.pid if event.pid and event.pid > 0 else None
        proc_name = None
        if not pid and os.path.exists(abspath):
            detected_pid = get_process_touching_file(abspath)
            if detected_pid is not None and detected_pid > 0:
                pid = detected_pid
                try:
                    import psutil
                    proc_name = psutil.Process(pid).name()
                except Exception:
                    proc_name = None

        summary_parts = [f"File {', '.join(change.kinds)}: {rel}"]
        if pid:
            summary_parts.append(f"by PID {pid}")
        summary = " ".join(summary_parts)

        envelope = EventEnvelope(
            root_id=self.config.id,
            path=abspath,
            host_id=self.global_config.host_id,
            ts=event.timestamp or time.time(),
            mode=self.config.mode,
            change=change,
            signals=signals,
            severity=final_sev,
            pid=pid,
            process_name=proc_name,
            summary=summary,
        )

        self.sink.emit(envelope)


class SentinelEngine:
    """Top-level Sentinel engine managing all configured paths."""

    def __init__(
        self,
        config: SentinelConfig,
        baseline_store: BaselineStore,
        sink: EventSink,
    ) -> None:
        self.config = config
        self.baseline_store = baseline_store
        self.sink = sink
        self.control = WatcherControl()
        self.watched_paths: Dict[str, WatchedPath] = {}
        self._running = False
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

        for p_cfg in self.config.paths:
            self.watched_paths[p_cfg.id] = WatchedPath(
                config=p_cfg,
                global_config=self.config,
                baseline_store=self.baseline_store,
                sink=self.sink,
                control=self.control,
            )

    def init_baseline(self) -> Dict[str, int]:
        """Scan and populate baseline for all configured paths."""
        counts = {}
        for p_cfg in self.config.paths:
            cnt = scan_and_save_baseline(
                store=self.baseline_store,
                root_id=p_cfg.id,
                root_path=p_cfg.resolved_path,
                includes=p_cfg.include,
                excludes=p_cfg.exclude,
                max_files=p_cfg.max_files or self.config.defaults.max_files,
                max_hash_bytes=self.config.defaults.max_hash_bytes,
                capture_content=p_cfg.capture_content,
                ignore_hidden=False,
            )
            counts[p_cfg.id] = cnt
        return counts

    def approve_alert(self, alert_id: int, actor: str, note: str = "") -> bool:
        """Approve an alert: update agent-side baseline to current file state, record audit."""
        # Resolve alert in repository
        if isinstance(self.sink, LocalSink):
            alert = self.sink.repo.get_alert(alert_id)
            if not alert:
                return False
            resolved = self.sink.repo.resolve_alert(alert_id, "approve", actor, note)
            if not resolved:
                return False

            # Update baseline entry for this path
            wp = self.watched_paths.get(alert.root_id)
            if wp:
                rel = os.path.relpath(alert.path, wp.root_path).replace("\\", "/")
                new_entry = inspect_file(
                    alert.root_id,
                    wp.root_path,
                    rel,
                    self.config.defaults.max_hash_bytes,
                    wp.config.capture_content,
                )
                if new_entry:
                    self.baseline_store.set_entry(new_entry)
                    # Update internal reported hash to prevent repeat alerts
                    wp._last_reported_hashes[rel] = new_entry.sha256
                elif not os.path.exists(alert.path):
                    self.baseline_store.remove_entry(alert.root_id, rel)
            return True
        return False

    def reject_alert(self, alert_id: int, actor: str, note: str = "") -> bool:
        """Reject an alert: marks alert rejected, baseline is NOT updated (drift remains)."""
        if isinstance(self.sink, LocalSink):
            return self.sink.repo.resolve_alert(alert_id, "reject", actor, note)
        return False

    def start(self) -> None:
        self._running = True
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_worker, name="sentinel-heartbeat", daemon=True
        )
        self._heartbeat_thread.start()

        log("sentinel_started", host_id=self.config.host_id, paths=list(self.watched_paths.keys()))
        for wp in self.watched_paths.values():
            wp.start()

    def stop(self) -> None:
        self._running = False
        self._heartbeat_stop.set()
        for wp in self.watched_paths.values():
            wp.stop()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=2.0)
        log("sentinel_stopped", host_id=self.config.host_id)

    def _heartbeat_worker(self) -> None:
        """Write periodic heartbeat log lines (every 30s) to keep dashboard status alive (G5)."""
        while not self._heartbeat_stop.is_set():
            log("sentinel_heartbeat", host_id=self.config.host_id)
            self._heartbeat_stop.wait(30.0)
