"""Test for auto-registering the local host in standalone mode."""

import socket
import time
import pytest
from sentinel.baseline_store import BaselineStore
from sentinel.engine import SentinelEngine
from sentinel.server.app import create_sentinel_app
from sentinel.server.repo import SQLiteRepository
from sentinel.settings import load_settings_dict
from sentinel.sinks import LocalSink


def test_standalone_engine_auto_registers_local_host(tmp_path):
    """When running in standalone mode (LocalSink), SentinelEngine should

    automatically register the host in the hosts table and show ONLINE
    on the Monitored Assets page.
    """
    watch_dir = tmp_path / "monitored"
    watch_dir.mkdir()

    cfg_dict = {
        "host_id": "test-standalone-host",
        "paths": [
            {
                "id": "vault",
                "path": str(watch_dir),
                "mode": "monitor",
            }
        ],
    }

    cfg = load_settings_dict(cfg_dict)
    store = BaselineStore(str(tmp_path / "baseline.db"))
    repo = SQLiteRepository(str(tmp_path / "repo.db"))
    sink = LocalSink(repo)

    engine = SentinelEngine(config=cfg, baseline_store=store, sink=sink)
    engine.init_baseline()
    engine.start()

    try:
        # 1. Verify host is in SQLiteRepository hosts table
        with repo._get_connection() as conn:
            row = conn.execute("SELECT * FROM hosts WHERE host_id = ?", ("test-standalone-host",)).fetchone()
            assert row is not None, "Host was not auto-registered in hosts table"
            assert row["host_id"] == "test-standalone-host"
            assert row["name"] == socket.gethostname()
            assert row["agent_version"] == "0.1.0"
            assert (time.time() - row["last_seen"]) < 10

        # 2. Verify Monitored Assets view shows the host as ONLINE
        app = create_sentinel_app(repo=repo, engine=engine)
        app.config["TESTING"] = True
        client = app.test_client()

        resp = client.get("/assets")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)

        assert "test-standalone-host" in html
        assert "ONLINE" in html
        assert "No agents registered yet." not in html
        assert "vault" in html
    finally:
        engine.stop()
