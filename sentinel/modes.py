"""Execution modes and adapters for Sentinel.

- Monitor Adapter: A pure judge respond function that only reports/alerts, never terminates or reverts.
- Protect Adapter: Opt-in per-path protection wrapping Rewind's Pipeline, DecoyMonitor,
  SpeedChecker, SuspicionTracker, SnapshotManager, and respond_to_attack. Enforces strict safety
  guards (refuses to protect '/', '$HOME', or paths without explicit mode: protect).
"""

from __future__ import annotations

import os
import shutil
import stat
import time
from typing import Any, Callable, Dict, List, Optional

from core.activity import ActivityMonitor
from core.events import FileEvent, Verdict
from core.logger import log
from core.pipeline import Pipeline
from core.state import ThreatState
from detection.decoy_monitor import DecoyMonitor
from detection.entropy_checker import is_suspicious_entropy
from detection.speed_checker import SpeedChecker
from detection.suspicion_tracker import SuspicionTracker
from recovery.known_good import KnownGoodTracker
from recovery.manifest import Manifest, build_manifest, sha256_file
from recovery.restore_engine import _restore_one, restore_all, RestoreResult
from recovery.snapshot_manager import SnapshotManager, take_snapshot, list_complete_snapshots, DATA_DIRNAME
from response.response_engine import ResponseOutcome, respond_to_attack, kill_process_tree, find_suspects
from watcher.watcher_control import WatcherControl


class MonitorAdapter:
    """Monitor mode adapter: pure observation, logs alerts, never kills or restores."""

    def __init__(self, root_id: str, path: str) -> None:
        self.root_id = root_id
        self.path = path

    def respond(self, verdict: Verdict, pid: int, *args: Any, **kwargs: Any) -> ResponseOutcome:
        trace_id = kwargs.get("trace_id", "mon-trace")
        log("sentinel_monitor_alert", root_id=self.root_id, signals=verdict.signals, pid=pid)
        return ResponseOutcome(
            status="ALERTED",
            trace_id=trace_id,
            target_pid=pid if pid > 0 else None,
            killed_pids=[],
            restored_files=[],
            quiet=True,
            details={"verdict": verdict._asdict() if hasattr(verdict, "_asdict") else {}},
        )


def validate_protect_safety(path: str, max_files: int = 10000, max_bytes: int = 1073741824) -> None:
    """Safety guard: refuse to protect root '/', home directory, or directories exceeding size caps."""
    resolved = os.path.abspath(os.path.expanduser(path))
    home = os.path.abspath(os.path.expanduser("~"))

    if resolved == "/":
        raise ValueError("Safety guard: Refusing to enable protect mode on root filesystem '/'")
    if resolved == home:
        raise ValueError(f"Safety guard: Refusing to enable protect mode on user home directory '{home}'")

    if not os.path.exists(resolved):
        return

    # Count files and size
    count = 0
    total_bytes = 0
    for dirpath, dirnames, filenames in os.walk(resolved):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for f in filenames:
            if f.startswith("."):
                continue
            count += 1
            if count > max_files:
                raise ValueError(f"Safety guard: Folder '{resolved}' exceeds file cap of {max_files} files")
            fp = os.path.join(dirpath, f)
            try:
                total_bytes += os.path.getsize(fp)
                if total_bytes > max_bytes:
                    raise ValueError(f"Safety guard: Folder '{resolved}' exceeds size cap of {max_bytes} bytes")
            except OSError:
                pass


class ProtectAdapter:
    """Protect mode adapter: full behavioral pipeline, automated response and recovery."""

    def __init__(
        self,
        root_id: str,
        path: str,
        safety_dir: str,
        control: WatcherControl,
        plant_decoys: bool = True,
    ) -> None:
        validate_protect_safety(path)
        self.root_id = root_id
        self.protected_dir = os.path.abspath(os.path.expanduser(path))
        self.safety_dir = os.path.abspath(os.path.expanduser(safety_dir))
        self.control = control
        self.plant_decoys = plant_decoys

        try:
            os.makedirs(self.protected_dir, exist_ok=True)
            os.makedirs(self.safety_dir, exist_ok=True)
        except OSError:
            pass

        self.state = ThreatState()
        self.activity = ActivityMonitor()
        self.speed = SpeedChecker()
        self.tracker = SuspicionTracker()
        self.known_good = KnownGoodTracker(protected_dir=self.protected_dir, safety_dir=self.safety_dir)
        self.decoys = DecoyMonitor(directory=self.protected_dir)

        # Baseline manifest
        manifest_data = build_manifest(self.protected_dir)
        self.manifest = Manifest(root=self.protected_dir, data=manifest_data)

        # Snapshots
        self.snapshot_mgr = SnapshotManager(
            state=self.state,
            manifest=self.manifest,
            known_good=self.known_good,
            protected_dir=self.protected_dir,
            safety_dir=self.safety_dir,
        )

        if self.plant_decoys:
            self.decoys.plant_decoys()

        # Take initial clean snapshot
        take_snapshot(self.snapshot_mgr)

        # Behavioral pipeline
        self.pipeline = Pipeline(
            manifest=self.manifest,
            decoys=self.decoys,
            known_good=self.known_good,
            protected_dir=self.protected_dir,
            safety_dir=self.safety_dir,
            state=self.state,
            control=self.control,
            activity=self.activity,
            speed=self.speed,
            tracker=self.tracker,
            say=lambda msg: None,
            async_response=True,
            log_incident_fn=lambda **kw: None,
            calm_seconds=0.1,
        )

    def process_event(self, event: FileEvent) -> Optional[Verdict]:
        """Feed event through Rewind behavioral pipeline."""
        return self.pipeline.handle_event(event)

    def rollback(
        self,
        attack_started_at: Optional[float] = None,
        baseline_store: Optional[Any] = None,
        pid: Optional[int] = None,
    ) -> RestoreResult:
        """Execute full snapshot/baseline rollback to revert files to last known clean state."""
        # 1. Kill attacker process and any active suspect processes
        if pid and isinstance(pid, int) and pid > 0:
            kill_process_tree(pid)
        try:
            for s_pid in find_suspects(self.protected_dir):
                if s_pid > 0:
                    kill_process_tree(s_pid)
        except Exception:
            pass

        # 2. Run Rewind restore_all inside watcher pause
        with self.control.paused():
            cutoff_time = (attack_started_at or time.time()) + 1.0
            res = restore_all(
                attack_started_at=cutoff_time,
                protected_dir=self.protected_dir,
                safety_dir=self.safety_dir,
                manifest=self.manifest,
                control=self.control,
                margin_seconds=0.0,
                settle_seconds=0.02,
            )

            # 3. Ensure 100% restoration against baseline_store or snapshot files
            if baseline_store is not None:
                try:
                    if hasattr(baseline_store, "get_all_entries"):
                        entries = list(baseline_store.get_all_entries(self.root_id).values())
                    elif hasattr(baseline_store, "list_entries"):
                        entries = list(baseline_store.list_entries(self.root_id))
                    else:
                        entries = []
                    snapshots = list_complete_snapshots(self.safety_dir)
                    for entry in entries:
                        dest = os.path.join(self.protected_dir, entry.relpath)
                        needs_restore = False
                        if not os.path.exists(dest):
                            needs_restore = True
                        else:
                            try:
                                if sha256_file(dest) != entry.sha256:
                                    needs_restore = True
                            except Exception:
                                needs_restore = True

                        if needs_restore:
                            restored = False
                            for s in snapshots:
                                src = os.path.join(s["path"], DATA_DIRNAME, entry.relpath)
                                if os.path.isfile(src) and sha256_file(src) == entry.sha256:
                                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                                    shutil.copy2(src, dest)
                                    restored = True
                                    break
                            if not restored and entry.content is not None:
                                os.makedirs(os.path.dirname(dest), exist_ok=True)
                                with open(dest, "w", encoding="utf-8") as f:
                                    f.write(entry.content)
                                restored = True
                            if restored and entry.relpath not in res.restored:
                                res.restored.append(entry.relpath)
                except Exception as e:
                    log("protect_baseline_fallback_failed", error=str(e))

            # 4. Replant decoys if enabled
            if self.plant_decoys:
                self.decoys.plant_decoys()

            # 5. Rebuild manifest and reset state
            self.manifest.rebuild()

        self.speed.reset()
        self.tracker.reset()
        self.state.return_to_normal()
        res.verified = not res.failed
        return res

    def revert_file(self, relpath: str, baseline_content: Optional[str]) -> bool:
        """Single-file revert using baseline data or clean snapshot."""
        abspath = os.path.join(self.protected_dir, relpath)
        try:
            if baseline_content is not None:
                with self.control.paused():
                    with open(abspath, "w", encoding="utf-8") as f:
                        f.write(baseline_content)
                return True
        except OSError:
            pass
        return False
