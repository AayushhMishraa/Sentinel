"""Sentinel CLI interface.

Commands:
  init-baseline   Scan watched folders and build the initial baseline database
  run             Run Sentinel agent in foreground
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings
from sentinel.sinks import LocalSink


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="Sentinel File Integrity Monitor")
    parser.add_argument("-c", "--config", default="sentinel.yaml", help="Path to sentinel.yaml configuration")
    parser.add_argument("--baseline-db", default="sentinel_baseline.db", help="Path to baseline SQLite database")
    parser.add_argument("--repo-db", default="sentinel_repo.db", help="Path to repository/events SQLite database")

    sub = parser.add_subparsers(dest="command", required=True)

    # init-baseline
    p_init = sub.add_parser("init-baseline", help="Initialize and populate baseline database")

    # run
    p_run = sub.add_parser("run", help="Run Sentinel engine in foreground")

    return parser


def cmd_init_baseline(args: argparse.Namespace) -> int:
    cfg = load_settings(args.config)
    store = BaselineStore(args.baseline_db)
    repo = SQLiteRepository(args.repo_db)
    sink = LocalSink(repo)

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    print(f"Initializing baseline for {len(cfg.paths)} path(s)...")
    counts = engine.init_baseline()
    for root_id, cnt in counts.items():
        print(f"  [{root_id}] Fingerprinted {cnt} file(s)")
    print("Baseline initialization complete.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    import threading
    from sentinel.server.app import create_sentinel_app

    cfg = load_settings(args.config)
    store = BaselineStore(args.baseline_db)
    repo = SQLiteRepository(args.repo_db)
    sink = LocalSink(repo)

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    print(f"Starting Sentinel FIM engine for host '{cfg.host_id}'...")
    engine.start()

    # Start embedded Flask web dashboard on port 5000
    token = cfg.server.get_token()
    app = create_sentinel_app(repo=repo, token=token)
    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False),
        daemon=True,
    )
    server_thread.start()
    print("Dashboard web UI running at: http://127.0.0.1:5000")
    print("Sentinel engine is watching. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping Sentinel engine...")
        engine.stop()
        print("Sentinel stopped.")
    return 0


def main(argv: list = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv or sys.argv[1:])
    if args.command == "init-baseline":
        return cmd_init_baseline(args)
    elif args.command == "run":
        return cmd_run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

