# Sentinel: Mission and Locked Scope

Sentinel records a baseline of watched files, detects every CHANGE (created, modified, deleted,
permissions, owner), rates it by severity, explains it (text diff, which process), and lets a person
APPROVE or REJECT it. A behavioral layer inherited from Rewind (decoy, speed, entropy, sustained,
slow-burn) recognises bulk tampering and ransomware-like activity. An OPTIONAL per-path protect
mode can also stop the attacker and restore files using Rewind's response and recovery engine.

## Locked Decisions
- Reads are NOT monitored, only changes. Decoys fire on tamper (modify/delete/move), never on read.
- Default mode is MONITOR (alert only, never kills or restores). PROTECT is opt-in per path.
- Stack: Python, Flask, SQLite, vanilla JS, inline SVG charts. No Node, no React build step.
- Policy lives in `sentinel.yaml` (PyYAML is the ONE allowed new dependency). Everything else stdlib
  (use urllib, not requests; difflib for diffs; sqlite3; threading).
- Rewind's existing tests must stay green at every commit.
- Linux only (Ubuntu in WSL2, project on the Linux filesystem, never under /mnt/c).
- Roadmap only (design for, do NOT build): React UI, PostgreSQL, Redis/WebSocket push, RBAC,
  multi-tenancy, SIEM connectors, email alerts, Windows/macOS agents, signed baselines,
  container/cgroup awareness, cross-host correlation.
- Out of scope: read/access auditing, eBPF/fanotify, real malware, production hardening.

## Scaling Rules
- **S-1**: Agents send VERSIONED JSON events to `/api/v1/events` with token auth.
- **S-2**: Every record carries `host_id` and `schema_version`.
- **S-3**: Storage sits behind a small Repository interface (SQLite now, PostgreSQL later = new class).
- **S-4**: Policy is data (yaml), not code.
- **S-5**: Alerts leave through a pluggable Notifier interface (webhook now).
- **S-6**: Detectors stay pure judges (Rewind rule R1); modes decide what happens next.

