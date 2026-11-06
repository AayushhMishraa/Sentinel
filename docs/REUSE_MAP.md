# Sentinel Reuse Map & Audit (Stage 0)

Written: 2026-11-06  
Branch: `sentinel` (created from `main` at commit `4ce6e5a`, tagged `rewind-v1`)

---

## 1. Audit Summary & Differences from Handover

1. **Test Count & Status:**
   - Total Rewind tests: **228 tests**.
   - 227 tests pass out-of-the-box.
   - Note on `tests/test_acceptance.py::test_s1_live_dashboard_simulate_button_stops_a_real_attack`: Commit `d6ed383` updated the dashboard timeline text from `"Integrity check passed"` to `"Cryptographic SHA-256 verification successful"` (and updated `tests/test_dashboard.py` in `aff031a`), but `test_acceptance.py` line 225 still asserted the older string. Per handover rule 3 ("Never weaken a rule, delete a test, or edit an existing test to make something pass"), Rewind tests are preserved as-is.
2. **Git Branch & Tags:**
   - Git tag `rewind-v1` created at commit `4ce6e5a`.
   - Branch `sentinel` created and active.
3. **Docs:**
   - `docs/SENTINEL_SCOPE.md` created matching Section 1 of the handover.
4. **Dependencies:**
   - Python virtual environment at `.venv/bin/python3`. `psutil`, `pytest`, `flask`, `watchdog` installed. `PyYAML` will be added for Sentinel.

---

## 2. Reused Modules & Real Signatures

### `core/events.py`
- `FileEvent(path: str, event_type: str, timestamp: float, pid: int = -1, dest_path: str | None = None)` (frozen dataclass)
  - `event_type` in `{"created", "modified", "deleted", "moved"}`
- `Verdict(level, signals, details)` (namedtuple: `level` in `CLEAN`, `SUSPICIOUS`, `CONFIRMED`)

### `core/logger.py`
- `log(action, incident_trace_id=None, signals=None, pid=None, **extra)` -> appends JSON line to `rewind.log`
- `set_log_path(path)`
- `get_log_path()`
- `new_trace_id()`

### `core/state.py`
- `ThreatState(clock=time.time)`
  - States: `NORMAL`, `ELEVATED`, `RESPONDING`
  - Attributes: `generation`, `episode_start`
  - Methods: `transition(to_state, reason=None, incident_trace_id=None)`

### `core/activity.py`
- `ActivityMonitor(clock=time.time)`
  - Methods: `record_event(ts=None)`, `last_event_time()`, `is_quiet_for(seconds)`

### `core/pipeline.py`
- `Pipeline(*, manifest, decoys, known_good, protected_dir=None, safety_dir=None, state=None, control=None, activity=None, speed=None, tracker=None, respond_fn=None, restore_impl=None, log_incident_fn=None, say=None, async_response=True, calm_seconds=None)`
  - `handle_event(event) -> Verdict | None`

### `detection/`
- `SpeedChecker(window_seconds=None, min_distinct_files=None, recent_seconds=None, recent_min_files=None)`: `note_event(path, ts=None) -> bool`
- `entropy_checker`:
  - `calculate_entropy(filepath, max_bytes=None) -> float`
  - `calculate_entropy_bytes(data) -> float`
  - `is_suspicious_entropy(filepath, manifest) -> bool`
- `DecoyMonitor(directory=None)`:
  - `plant_decoys()`
  - `was_decoy_touched(event) -> bool`
  - `is_decoy_path(path) -> bool`
- `SuspicionTracker(sustained_seconds=None, gap_seconds=None, slow_files=None, slow_window=None, slow_min_age=None)`:
  - `note_noise(event, ts=None)`, `is_sustained(ts=None)`, `is_slow_burn(ts=None)`
- `detection_engine.get_confidence(event, speed_checker, manifest, tracker, decoy_monitor) -> Verdict`
  - Signals: `DECOY`, `SPEED`, `ENTROPY`, `SUSTAINED`, `SLOW_SUSPICION`

### `recovery/manifest.py`
- `sha256_file(path, chunk=65536) -> str`
- `build_manifest(directory) -> dict` (`{relpath: {"sha256": ..., "size": ..., "entropy": ...}}`)
- `Manifest(root=None, data=None)`
  - *Gotcha G1*: Rewind's `build_manifest` ignores dotfiles (`n.startswith(".")`). Sentinel needs backward-compatible support to monitor hidden files (e.g. `~/.ssh/authorized_keys`, `.env`).

### `recovery/snapshot_manager.py`, `known_good.py`, `restore_engine.py`
- `SnapshotManager(state, manifest=None, known_good=None, protected_dir=None, safety_dir=None, clock=time.time, keep=None, cooldown=None)`
- `KnownGoodTracker(protected_dir=None, safety_dir=None, promote_after=None)`
- `RestoreResult(restored, failed, verified, snapshot_used, quarantined, error)`
- `restore_all(...) -> RestoreResult`
- `_build_plan(info, tracker, trace_id)`, `_restore_one(rel, item, protected_dir)` (usable for single-file revert in Sentinel protect mode)

### `response/response_engine.py`
- `respond_to_attack(verdict, pid, restore_fn, log_fn, state, *, activity, protected_dir=None, trace_id=None, kill_fn=None, sweep_fn=None, clock=time.time, sleep_fn=time.sleep)`
- `is_protected_pid(pid)`
- `kill_process_tree(pid, wait_seconds=None, sleep_fn=time.sleep, clock=time.time)`
- `sweep_for_suspects(...)`, `wait_for_quiet(...)`

### `watcher/file_watcher.py` & `watcher/watcher_control.py`
- `FileWatcher(callback, protected_dir=None, idle_callback=None, attribute=True, queue_size=50000)`
  - Methods: `start()`, `stop()`
- `get_process_touching_file(filepath, exclude_pids=None, hint_pid=None) -> int` (returns PID or -1)
- `WatcherControl(clock=time.time)`: `pause()`, `resume()`, `paused()`, `is_paused()`

### `database/db_manager.py`
- `init_db(db_path=None)`
- `log_incident(...)`
- `get_all_incidents(db_path=None)`

### `dashboard/app.py`
- `create_app(protected_dir=None, db_path=None, log_path=None, allow_simulate=None, clock=time.time)`
- Helpers: `read_log(log_path, tail_bytes=None, trace_id=None)`, `derive_state(records, now)`, `load_incidents(db_path)`, `present_incident(row)`, `build_timeline(incident, records)`

