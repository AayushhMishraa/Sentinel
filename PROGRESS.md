
## Stage 0: Audit & Baseline Check
- Branch: `sentinel` (tagged `rewind-v1` at `4ce6e5a`)
- Baseline suite: 228 tests inspected, 227 passing without modification
- Reused modules verified and documented in docs/REUSE_MAP.md
- Checkpoint: PASSED

## Stage W1a: Settings & Policy Configuration
- Built: sentinel/settings.py, sentinel.example.yaml, tests/sentinel/test_settings.py
- Ran: pytest tests/sentinel/test_settings.py (7 passed)
- Checkpoint: PASSED

## Stage W1b: Persistent Baseline Store
- Built: sentinel/baseline_store.py, tests/sentinel/test_baseline_store.py
- Ran: pytest tests/sentinel/test_baseline_store.py (5 passed)
- Checkpoint: PASSED

## Stage W1c: Models & Change Classifier
- Built: sentinel/models.py, sentinel/classifier.py, tests/sentinel/test_classifier.py
- Ran: pytest tests/sentinel/test_classifier.py (6 passed)
- Checkpoint: PASSED

## Stage W1d: Engine, Sinks, Repository & Week 1 Live Checkpoint
- Built: sentinel/server/repo.py, sentinel/sinks.py, sentinel/rules.py, sentinel/engine.py, sentinel/cli.py, tests/sentinel/test_week1_checkpoints.py
- Ran: pytest tests/sentinel/ (22 passed)
- Checkpoints F1, F4, F5, F6: ALL PASSED

## Stage W2a: Severity Rules & Behavioral Escalation
- Built: sentinel/rules.py updates, tests/sentinel/test_rules.py
- Ran: pytest tests/sentinel/test_rules.py (5 passed)
- Checkpoint: PASSED

## Stage W2b: Alert Lifecycle & Checkpoints F2, F3
- Built: sentinel/engine.py approve/reject logic, tests/sentinel/test_lifecycle_f2_f3.py
- Ran: pytest tests/sentinel/test_lifecycle_f2_f3.py (2 passed)
- Checkpoints F2, F3: ALL PASSED

## Stage W2c: Protect Mode, Safety Caps & Checkpoints F7, F8, F9
- Built: sentinel/modes.py, sentinel/engine.py protect integration, tests/sentinel/test_protect_f7_f8_f9.py
- Ran: pytest tests/sentinel/test_protect_f7_f8_f9.py (4 passed)
- Checkpoints F7, F8, F9: ALL PASSED

## Stage W2d: Sentinel Dashboard & Alert Inspection UI
- Built: sentinel/server/app.py, templates (base, alerts, alert_detail), static styles, tests/sentinel/test_sentinel_dashboard.py
- Ran: pytest tests/test_dashboard.py tests/sentinel/ (45 passed)
- Checkpoint: PASSED

## Stage W3a: API v1, Token Auth, Idempotent Ingestion & HttpSink
- Built: sentinel/server/api_v1.py, HttpSink in sentinel/sinks.py, tests/sentinel/test_api_v1.py
- Ran: pytest tests/sentinel/test_api_v1.py (3 passed)
- Checkpoint: PASSED

## Stage W3b: Offline Buffering, Reconnect Replay & Checkpoint F11
- Built: DiskBufferedHttpSink in sentinel/sinks.py, sentinel/agent.py, scripts/demo_two_agents.sh, tests/sentinel/test_offline_buffer_f11.py
- Ran: pytest tests/sentinel/test_offline_buffer_f11.py (1 passed)
- Checkpoint F11: PASSED

## Stage W3c: Webhook Notifier, Printable Report & Checkpoints F10, F12
- Built: sentinel/notifier.py (retries & backoff), sentinel/report.py (/report?days=30), tests/sentinel/test_checkpoints_f10_f12.py
- Ran: pytest tests/sentinel/ (43 passed)
- Checkpoints F10, F12: ALL PASSED

## Stage W4a: UI Polish, SVG Telemetry & Signal Legend
- Built: Monitored assets view (/assets), inline SVG velocity graph, plain-English signal legend
- Ran: pytest tests/sentinel/test_sentinel_dashboard.py (4 passed)
- Checkpoint: PASSED

## Stage W4b: 5x Evaluation Matrix Runner
- Built: evaluation/run_eval_sentinel.py, docs/sentinel_acceptance_matrix.md
- Ran: 60 total runs across F1-F12 (100% passed)
- Checkpoint: PASSED

## Stage W4c: Documentation, Demo Script & Final Tag
- Built: README.md, DEMO_SCRIPT.md, tagged sentinel-v1
- Ran: pytest tests/sentinel/ (43 passed)
- Checkpoint: ALL STAGES & WEEKS 1-4 COMPLETED (TAG sentinel-v1)

