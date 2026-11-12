"""sentinel/demo_data.py: Realistic seed data for Sentinel Enterprise Console."""

import time
from typing import Optional
from sentinel.models import Change, EventEnvelope, Meta
from sentinel.server.repo import SQLiteRepository


DEMO_HOSTS = [
    ("sec-gateway-01", "Linux Bastion / API Gateway", 0),
    ("k8s-worker-node-4", "Kubernetes Node 4 (prod-east)", 15),
    ("db-cluster-primary", "PostgreSQL Primary Instance", 45),
    ("auth-vault-prod", "HashiCorp Vault / Secret Store", 120),
    ("backup-storage-02", "Cold Storage Server", 7200),  # offline (>90s)
]

DEMO_ALERTS = [
    {
        "host_id": "sec-gateway-01",
        "root_id": "ssh",
        "path": "/etc/ssh/authorized_keys",
        "severity": "critical",
        "signals": ["DECOY", "SPEED"],
        "summary": "Unauthorized public key appended to root authorized_keys",
        "diff": "--- /etc/ssh/authorized_keys\n+++ /etc/ssh/authorized_keys\n@@ -1,3 +1,4 @@\n ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADMIN admin@company.internal\n+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC rogue_key@external_proxy\n",
        "pid": 4821,
        "process_name": "curl",
    },
    {
        "host_id": "auth-vault-prod",
        "root_id": "vault",
        "path": "/etc/vault.d/vault.hcl",
        "severity": "high",
        "signals": ["SPEED"],
        "summary": "Vault cluster listener config modified: telemetry egress altered",
        "diff": "--- /etc/vault.d/vault.hcl\n+++ /etc/vault.d/vault.hcl\n@@ -12,2 +12,2 @@\n-tls_min_version = \"tls13\"\n+tls_min_version = \"tls12\"\n",
        "pid": 5102,
        "process_name": "bash",
    },
    {
        "host_id": "k8s-worker-node-4",
        "root_id": "web",
        "path": "/var/www/production/index.html",
        "severity": "medium",
        "signals": ["ENTROPY"],
        "summary": "High entropy content substitution detected in web application bundle",
        "diff": "--- index.html\n+++ index.html\n@@ -4,1 +4,1 @@\n-<script src=\"/bundle.js\"></script>\n+<script src=\"/bundle_obfuscated.js\"></script>\n",
        "pid": 8923,
        "process_name": "node",
    },
    {
        "host_id": "db-cluster-primary",
        "root_id": "system",
        "path": "/etc/hosts",
        "severity": "low",
        "signals": ["SUSTAINED"],
        "summary": "Local hostname resolution table updated with internal proxy address",
        "diff": "--- /etc/hosts\n+++ /etc/hosts\n@@ -3,1 +3,2 @@\n 127.0.0.1 localhost\n+10.0.2.15 telemetry.internal.lan\n",
        "pid": 3211,
        "process_name": "sed",
    },
    {
        "host_id": "backup-storage-02",
        "root_id": "audit",
        "path": "/var/log/audit/audit.log",
        "severity": "info",
        "signals": [],
        "summary": "Log rotation checkpoint initialized and verified",
        "diff": None,
        "pid": 1102,
        "process_name": "logrotate",
    },
]


def seed_demo_data(repo: SQLiteRepository, overwrite: bool = False) -> None:
    """Populates 5 realistic enterprise hosts and mixed severity alerts."""
    now = time.time()

    # 1. Seed Hosts
    for host_id, name, age in DEMO_HOSTS:
        repo.record_host(host_id=host_id, name=name)
        # Update last_seen timestamp
        if hasattr(repo, "_get_connection"):
            with repo._get_connection() as conn:
                conn.execute("UPDATE hosts SET last_seen = ? WHERE host_id = ?", (now - age, host_id))
                conn.commit()

    # 2. Seed Alerts if table has fewer than 5 alerts
    existing_alerts = repo.list_alerts()
    if len(existing_alerts) < 5 or overwrite:
        for item in DEMO_ALERTS:
            meta = Meta(sha256="abc1234567890", size=1024, mode=0o644, uid=0, gid=0)
            change = Change(kinds=["modified"], old=meta, new=meta, diff=item["diff"], signals=item["signals"])
            envelope = EventEnvelope(
                root_id=item["root_id"],
                path=item["path"],
                host_id=item["host_id"],
                ts=now - 120.0,
                change=change,
                severity=item["severity"],
                signals=item["signals"],
                summary=item["summary"],
                pid=item["pid"],
                process_name=item["process_name"],
            )
            repo.upsert_alert(envelope)
