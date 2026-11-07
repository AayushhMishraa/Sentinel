"""Sentinel core engine.

Manages WatchedPath instances, monitors filesystem changes with debouncing,
classifies changes against the persistent baseline, evaluates rules,
and emits versioned EventEnvelopes through the configured Sink.
"""

from __future__ import annotations

import os
import stat
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

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
from sentinel.modes import MonitorAdapter, ProtectAdapter
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

        # Debouncing per relative path: {relpath: (last_event_time, events_list, initial_mode)}
        self._debounce_lock = threading.Lock()
        self._pending_events: Dict[str, Tuple[float, List[FileEvent], Optional[int]]] = {}
        self._pending_signals: Dict[str, Set[str]] = {}
        self._stop_event = threading.Event()
        self._debounce_thread: Optional[threading.Thread] = None

        # Last reported sha256 to prevent duplicate alerts (G3)
        self._last_reported_hashes: Dict[str, str] = {}

        # Protect adapter if mode is protect
        self.protect_adapter: Optional[ProtectAdapter] = None
        self.decoy_monitor = None
        if self.config.mode == "protect":
            parent = os.path.dirname(self.root_path)
            safety_dir = os.path.join(parent, f".safety_{self.config.id}")
            try:
                os.makedirs(safety_dir, exist_ok=True)
            except OSError:
                proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                safety_dir = os.path.join(proj_root, f".safety_{self.config.id}")
                try:
                    os.makedirs(safety_dir, exist_ok=True)
                except OSError:
                    safety_dir = f"/tmp/.safety_{self.config.id}"
            self.protect_adapter = ProtectAdapter(
                root_id=self.config.id,
                path=self.root_path,
                safety_dir=safety_dir,
                control=self.control,
                plant_decoys=self.config.decoys,
            )
            self.decoy_monitor = self.protect_adapter.decoys
        elif self.config.decoys:
            from detection.decoy_monitor import DecoyMonitor
            self.decoy_monitor = DecoyMonitor(self.root_path)
            self.decoy_monitor.plant_decoys()

        # Pre-baseline any planted decoys so they are recognized as baselined
        if self.config.decoys and self.decoy_monitor:
            for d_path in self.decoy_monitor.decoys:
                rel_d = os.path.relpath(d_path, self.root_path).replace("\\", "/")
                self._baseline_decoy(rel_d, d_path)

    def _is_decoy_path(self, rel: str) -> bool:
        base = os.path.basename(rel)
        return base.startswith("!DECOY_") or (self.config.decoys and "DECOY" in base)

    def _is_clean_decoy(self, abspath: str) -> bool:
        """Check if file matches clean canary decoy hash."""
        try:
            if not os.path.isfile(abspath):
                return False
            curr_h = hash_file_capped(abspath, self.global_config.defaults.max_hash_bytes)
            return curr_h == "dcf738290fd5a1bf663c2fb27adbdb60cc4d41c2eccf80d7ad4832e082561852"
        except OSError:
            return False

    def _is_own_decoy_planting_event(self, event: FileEvent, abspath: str, rel: str) -> bool:
        """Check if an event matches Sentinel's own decoy planting action."""
        if not self._is_decoy_path(rel):
            return False

        if event.event_type not in ("created", "modified"):
            return False

        # Any file matching clean canary hash is Sentinel's own bait
        if self._is_clean_decoy(abspath):
            return True

        base_entry = self.baseline_store.get_entry(self.config.id, rel)
        if base_entry is not None:
            try:
                curr_hash = hash_file_capped(abspath, self.global_config.defaults.max_hash_bytes)
                if curr_hash == base_entry.sha256:
                    return True
            except OSError:
                pass

        return False

    def _baseline_decoy(self, rel: str, abspath: str) -> None:
        """Auto-baseline a planted decoy file so future changes are tracked against clean canary content."""
        if not os.path.isfile(abspath):
            return
        entry = inspect_file(
            self.config.id,
            self.root_path,
            rel,
            self.global_config.defaults.max_hash_bytes,
            self.config.capture_content,
        )
        if entry:
            self.baseline_store.set_entry(entry)

    def start(self) -> None:
        if not os.path.isdir(self.root_path):
            try:
                os.makedirs(self.root_path, exist_ok=True)
            except OSError:
                pass

        if not os.path.isdir(self.root_path):
            log("watched_path_skipped_nonexistent", path=self.root_path)
            return

        # Cleanly replant and baseline decoys before watcher starts so old modified decoys never false-alarm
        if self.config.decoys and self.decoy_monitor:
            self.decoy_monitor.plant_decoys()
            for d_path in self.decoy_monitor.decoys:
                rel_d = os.path.relpath(d_path, self.root_path).replace("\\", "/")
                self._baseline_decoy(rel_d, d_path)
                try:
                    curr_h = hash_file_capped(d_path, self.global_config.defaults.max_hash_bytes)
                    self._last_reported_hashes[rel_d] = curr_h
                except OSError:
                    pass

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

        target_path = event.dest_path if (event.event_type == "moved" and event.dest_path) else event.path
        rel = os.path.relpath(target_path, self.root_path).replace("\\", "/")
        if rel.startswith(".."):
            return

        abspath = os.path.join(self.root_path, rel)

        # Ignore Sentinel's own decoy planting actions
        if self._is_own_decoy_planting_event(event, abspath, rel):
            self._baseline_decoy(rel, abspath)
            return

        # If protect mode, feed event directly into behavioral pipeline immediately
        if self.protect_adapter:
            if not event.pid or event.pid <= 0:
                try:
                    detected_pid = get_process_touching_file(abspath)
                    if detected_pid and detected_pid > 0:
                        event = FileEvent(
                            path=event.path,
                            action=event.action,
                            timestamp=event.timestamp,
                            pid=detected_pid,
                            cookie=event.cookie,
                        )
                except Exception:
                    pass
            verdict = self.protect_adapter.process_event(event)
            if verdict and verdict.signals:
                with self._debounce_lock:
                    if rel not in self._pending_signals:
                        self._pending_signals[rel] = set()
                    self._pending_signals[rel].update(verdict.signals)

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

        abspath = os.path.join(self.root_path, rel)
        with self._debounce_lock:
            if rel in self._pending_events:
                last_ts, ev_list, init_mode = self._pending_events[rel]
                ev_list.append(event)
                self._pending_events[rel] = (time.time(), ev_list, init_mode)
            else:
                init_mode = None
                if os.path.exists(abspath):
                    try:
                        init_mode = stat.S_IMODE(os.stat(abspath).st_mode)
                    except OSError:
                        init_mode = None
                self._pending_events[rel] = (time.time(), [event], init_mode)

    def _debounce_worker(self) -> None:
        while not self._stop_event.is_set():
            now = time.time()
            ready: List[Tuple[str, List[FileEvent], Optional[int], Set[str]]] = []

            with self._debounce_lock:
                for rel, (last_ts, ev_list, init_mode) in list(self._pending_events.items()):
                    if now - last_ts >= DEBOUNCE_QUIET_SECONDS:
                        sigs = self._pending_signals.pop(rel, set())
                        ready.append((rel, ev_list, init_mode, sigs))
                        del self._pending_events[rel]

            for rel, ev_list, init_mode, sigs in ready:
                self._process_debounced_event(rel, ev_list, init_mode, inherited_signals=sigs)

            time.sleep(0.1)

    def _process_debounced_event(
        self,
        rel: str,
        events: Union[FileEvent, List[FileEvent]],
        initial_mode: Optional[int] = None,
        inherited_signals: Optional[Union[List[str], Set[str]]] = None,
    ) -> None:
        if isinstance(events, list):
            ev_list = events
            event = ev_list[-1]
        else:
            ev_list = [events]
            event = events

        abspath = os.path.join(self.root_path, rel)
        base_entry = self.baseline_store.get_entry(self.config.id, rel)

        change = classify_file_change(
            root_id=self.config.id,
            root_path=self.root_path,
            relpath=rel,
            baseline_entry=base_entry,
            max_hash_bytes=self.global_config.defaults.max_hash_bytes,
            capture_content=self.config.capture_content,
            initial_mode=initial_mode,
            events=ev_list,
        )

        if not change:
            return

        # Ignore Sentinel's own clean decoy files (whether created or replanted)
        if self._is_decoy_path(rel) and self._is_clean_decoy(abspath):
            self._baseline_decoy(rel, abspath)
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
        signals: List[str] = list(inherited_signals or [])
        if self.protect_adapter:
            for ev in ev_list:
                if self.protect_adapter.decoys.was_decoy_touched(ev):
                    signals.append("DECOY")
                    break
            actor_key = event.pid if (event.pid and event.pid > 0) else "default"
            self.protect_adapter.speed.record_event(actor_key, abspath, event.timestamp)
            if self.protect_adapter.speed.get_score(actor_key, event.timestamp):
                signals.append("SPEED")
            if hasattr(self.protect_adapter, "tracker"):
                now_ts = event.timestamp or time.time()
                if self.protect_adapter.tracker.slow_burn(now_ts):
                    signals.append("SLOW_SUSPICION")
                if hasattr(self.protect_adapter.tracker, "is_sustained") and self.protect_adapter.tracker.is_sustained(actor_key, now_ts):
                    signals.append("SUSTAINED")
        elif self.config.decoys and "DECOY" in os.path.basename(rel):
            if any(k in change.kinds for k in ("modified", "deleted", "permissions", "owner")):
                signals.append("DECOY")

        signals = sorted(list(set(signals)))
        final_sev = escalate_with_signals(base_sev, signals)

        # PID attribution (G6)
        pid = None
        for ev in reversed(ev_list):
            if ev.pid and ev.pid > 0:
                pid = ev.pid
                break
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

        # Ensure rollback happens automatically in protect mode before alert status becomes OPEN
        is_attack = any(s in ("DECOY", "SPEED", "SLOW_SUSPICION", "SUSTAINED") for s in signals)
        if self.protect_adapter and is_attack:
            self.protect_adapter.rollback(
                attack_started_at=event.timestamp,
                baseline_store=self.baseline_store,
                pid=pid,
            )

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
            # Cleanly replant clean decoys before scanning baseline so baseline never captures corrupted bait
            if p_cfg.decoys:
                from detection.decoy_monitor import DecoyMonitor
                dm = DecoyMonitor(p_cfg.resolved_path)
                dm.plant_decoys()

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
        repo = self.sink.repo if isinstance(self.sink, LocalSink) else None
        if not repo:
            return False

        alert = repo.get_alert(alert_id)
        if not alert:
            return False
        resolved = repo.resolve_alert(alert_id, "approve", actor, note)
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
                wp._last_reported_hashes[rel] = new_entry.sha256
            elif not os.path.exists(alert.path):
                self.baseline_store.remove_entry(alert.root_id, rel)
                wp._last_reported_hashes.pop(rel, None)
        return True

    def reject_alert(self, alert_id: int, actor: str, note: str = "") -> bool:
        """Reject an alert: marks alert rejected, baseline is NOT updated (drift remains).
        In protect mode, single-file revert restores file from baseline content.
        """
        if isinstance(self.sink, LocalSink):
            alert = self.sink.repo.get_alert(alert_id)
            if not alert:
                return False
            resolved = self.sink.repo.resolve_alert(alert_id, "reject", actor, note)
            if not resolved:
                return False

            wp = self.watched_paths.get(alert.root_id)
            if wp and wp.protect_adapter:
                rel = os.path.relpath(alert.path, wp.root_path).replace("\\", "/")
                entry = self.baseline_store.get_entry(alert.root_id, rel)
                if entry and entry.content is not None:
                    wp.protect_adapter.revert_file(rel, entry.content)
            return True
        return False

    def bulk_reject_alerts(self, actor: str = "dashboard-admin", note: str = "Bulk acknowledged") -> int:
        """Bulk reject/acknowledge all currently open alerts without deleting history."""
        if isinstance(self.sink, LocalSink):
            return self.sink.repo.bulk_resolve_alerts(action="reject", actor=actor, note=note)
        return 0

    def bulk_acknowledge_alerts(self, actor: str = "dashboard-admin", note: str = "Bulk acknowledged") -> int:
        """Alias for bulk_reject_alerts."""
        return self.bulk_reject_alerts(actor=actor, note=note)

    def start(self) -> None:
        self._running = True
        self._heartbeat_stop.clear()

        # Auto-register local host in standalone mode (LocalSink)
        if isinstance(self.sink, LocalSink):
            try:
                import socket
                hostname = socket.gethostname()
                self.sink.repo.record_host(
                    host_id=self.config.host_id,
                    name=hostname,
                    agent_version="0.1.0",
                )
            except Exception:
                pass

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
        """Write periodic heartbeat log lines (every 30s) and update local host heartbeat in standalone mode (G5)."""
        while not self._heartbeat_stop.is_set():
            log("sentinel_heartbeat", host_id=self.config.host_id)
            if isinstance(self.sink, LocalSink):
                try:
                    import socket
                    self.sink.repo.record_host(
                        host_id=self.config.host_id,
                        name=socket.gethostname(),
                        agent_version="0.1.0",
                    )
                except Exception:
                    pass
            self._heartbeat_stop.wait(30.0)
