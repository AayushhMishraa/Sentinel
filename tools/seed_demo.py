#!/usr/bin/env python3
"""tools/seed_demo.py: Idempotent demo data seeder for Sentinel.

Restores realistic enterprise demo state with ~5 open alerts of mixed severities
(critical, high, medium, low, info) and fleet host agents.

Usage:
  python3 tools/seed_demo.py --reset
"""

from __future__ import annotations

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, REPO_ROOT)

from sentinel.models import Change, EventEnvelope, Meta
from sentinel.server.repo import SQLiteRepository


def seed(repo_path: str, reset: bool = True) -> int:
    repo = SQLiteRepository(repo_path)

    now = time.time()
    hosts = [
        ("box-alpha", "ip-10-0-1-14.ec2.internal (Prod Primary)", "0.1.0-sec", True, now - 12),
        ("prod-web-01", "web-gateway-01.us-east.aws", "0.1.0-sec", True, now - 45),
        ("prod-web-02", "web-gateway-02.us-east.aws", "0.1.0-sec", True, now - 28),
        ("db-replica-03", "db-replica-03.internal.lan", "0.1.0-sec", False, now - 7200),
        ("staging-node-1", "staging-worker-01.local", "0.1.0-sec", True, now - 80),
    ]

    with repo._get_connection() as conn:
        cur = conn.cursor()
        if reset:
            cur.execute("DELETE FROM alerts")
            cur.execute("DELETE FROM changes")
            cur.execute("DELETE FROM approvals")
            cur.execute("DELETE FROM hosts")
            conn.commit()

        for hid, name, ver, online, last_seen in hosts:
            cur.execute(
                """INSERT OR REPLACE INTO hosts (host_id, name, agent_version, status, last_seen)
                   VALUES (?, ?, ?, ?, ?)""",
                (hid, name, ver, 'online' if online else 'offline', last_seen),
            )
        conn.commit()

    # 2. Seed 5 Realistic Alerts with Mixed Severities & Signals
    demo_alerts = [
        # Critical Alert
        EventEnvelope(
            root_id="ssh",
            path="/home/aayush/.ssh/authorized_keys",
            host_id="box-alpha",
            ts=now - 180,
            severity="critical",
            summary="SSH access list changed: unauthorized public key injected",
            signals=["DECOY"],
            change=Change(
                kinds=["modified"],
                old=Meta(sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", size=398, mode=0o600, uid=1000, gid=1000),
                new=Meta(sha256="8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4", size=512, mode=0o600, uid=1000, gid=1000),
                diff=(
                    "--- a/authorized_keys\n"
                    "+++ b/authorized_keys\n"
                    "@@ -1,3 +1,4 @@\n"
                    " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1k7... admin@corp\n"
                    " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6yZ... devops@corp\n"
                    "+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9... unknown_actor@external-host\n"
                ),
            ),
        ),
        # High Alert
        EventEnvelope(
            root_id="sandbox",
            path="/home/aayush/protected_folder/financial_records.xlsx",
            host_id="box-alpha",
            ts=now - 540,
            severity="high",
            summary="Rapid high-entropy file transformation detected",
            signals=["SPEED", "ENTROPY"],
            change=Change(
                kinds=["modified", "entropy"],
                old=Meta(sha256="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945", size=64200, mode=0o644, uid=1000, gid=1000),
                new=Meta(sha256="9a023b1c8f123456789abcdef0123456789abcdef0123456789abcdef0123456", size=64256, mode=0o644, uid=1000, gid=1000),
                diff="Binary file altered (Shannon entropy elevated from 4.12 to 7.98: characteristic of encryption burst).",
            ),
        ),
        # Medium Alert
        EventEnvelope(
            root_id="web",
            path="/var/www/html/wp-config.php",
            host_id="prod-web-01",
            ts=now - 1200,
            severity="medium",
            summary="Configuration directive modified in web root",
            signals=["SUSTAINED"],
            change=Change(
                kinds=["modified"],
                old=Meta(sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", size=3200, mode=0o640, uid=33, gid=33),
                new=Meta(sha256="222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111", size=3284, mode=0o640, uid=33, gid=33),
                diff=(
                    "--- a/wp-config.php\n"
                    "+++ b/wp-config.php\n"
                    "@@ -34,3 +34,4 @@\n"
                    " define('DB_NAME', 'production_db');\n"
                    "-define('WP_DEBUG', false);\n"
                    "+define('WP_DEBUG', true);\n"
                    "+define('WP_DEBUG_LOG', '/tmp/debug.log');\n"
                ),
            ),
        ),
        # Low Alert
        EventEnvelope(
            root_id="docs",
            path="/home/aayush/important/quarterly_roadmap.pdf",
            host_id="box-alpha",
            ts=now - 2800,
            severity="low",
            summary="Document metadata and permission attributes altered",
            signals=[],
            change=Change(
                kinds=["permissions", "modified"],
                old=Meta(sha256="33334444555566667777888899990000aaaabbbbccccddddeeeeffff11112222", size=104520, mode=0o644, uid=1000, gid=1000),
                new=Meta(sha256="4444555566667777888899990000aaaabbbbccccddddeeeeffff111122223333", size=104520, mode=0o777, uid=1000, gid=1000),
                diff="Permissions changed from 0644 to 0777 (world writable). Content hash changed.",
            ),
        ),
        # Info Alert
        EventEnvelope(
            root_id="sandbox",
            path="/home/aayush/protected_folder/backup_manifest.json",
            host_id="prod-web-02",
            ts=now - 4200,
            severity="info",
            summary="Routine daily archive manifest created",
            signals=[],
            change=Change(
                kinds=["created"],
                old=None,
                new=Meta(sha256="555566667777888899990000aaaabbbbccccddddeeeeffff1111222233334444", size=1024, mode=0o644, uid=1000, gid=1000),
                diff="New file created: {\"created_at\": \"2026-11-13T08:00:00Z\", \"archive_id\": \"daily_bak_99\"}",
            ),
        ),
    ]

    for env in demo_alerts:
        repo.upsert_alert(env)

    alerts = repo.list_alerts()
    print(f"Successfully seeded demo data into '{repo_path}':")
    print(f"  Total open alerts: {len(alerts)}")
    for a in alerts:
        print(f"  [{a.severity.upper():<8}] #{a.id} {a.path} ({a.summary})")
    print(f"  Registered hosts: {len(hosts)}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Seed realistic Sentinel demo state.")
    parser.add_argument("--repo-db", default="sentinel_repo.db", help="Path to sentinel repository sqlite database")
    parser.add_argument("--reset", action="store_true", default=True, help="Reset database before seeding (default: True)")
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo_db)
    return seed(repo_path, reset=args.reset)


if __name__ == "__main__":
    sys.exit(main())
