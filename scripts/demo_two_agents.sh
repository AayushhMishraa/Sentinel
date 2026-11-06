#!/usr/bin/env bash
# Demo script launching 2 Sentinel agents with different host_ids against one central server.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

echo "=== Sentinel Multi-Agent Demonstration ==="
echo "Host 1: web-server-01"
echo "Host 2: db-backup-02"
echo ""

mkdir -p /tmp/sentinel_demo_agent1 /tmp/sentinel_demo_agent2

echo "Initializing Agent 1 (web-server-01)..."
.venv/bin/python3 -c "
from sentinel.settings import load_settings_dict
from sentinel.baseline_store import BaselineStore
from sentinel.server.repo import SQLiteRepository
from sentinel.engine import SentinelEngine
from sentinel.sinks import LocalSink

cfg1 = load_settings_dict({'host_id': 'web-server-01', 'paths': [{'id': 'www', 'path': '/tmp/sentinel_demo_agent1', 'mode': 'monitor'}]})
store1 = BaselineStore('/tmp/sentinel_demo_agent1/baseline.db')
repo = SQLiteRepository('/tmp/sentinel_demo_server.db')
sink = LocalSink(repo)
eng1 = SentinelEngine(cfg1, store1, sink)
eng1.init_baseline()
print('Agent 1 baseline ready.')
"

echo "Initializing Agent 2 (db-backup-02)..."
.venv/bin/python3 -c "
from sentinel.settings import load_settings_dict
from sentinel.baseline_store import BaselineStore
from sentinel.server.repo import SQLiteRepository
from sentinel.engine import SentinelEngine
from sentinel.sinks import LocalSink

cfg2 = load_settings_dict({'host_id': 'db-backup-02', 'paths': [{'id': 'backup', 'path': '/tmp/sentinel_demo_agent2', 'mode': 'monitor'}]})
store2 = BaselineStore('/tmp/sentinel_demo_agent2/baseline.db')
repo = SQLiteRepository('/tmp/sentinel_demo_server.db')
sink = LocalSink(repo)
eng2 = SentinelEngine(cfg2, store2, sink)
eng2.init_baseline()
print('Agent 2 baseline ready.')
"

echo "=== Demonstration Completed Successfully ==="
