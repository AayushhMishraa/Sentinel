# Sentinel & Rewind: Autonomous File Integrity Monitoring and Ransomware Defense

**Sentinel** is an enterprise File Integrity Monitoring (FIM) and behavioral defense system built on top of the **Rewind** ransomware response engine.

---

## Architecture Overview

```
                                      +---------------------------------------------+
                                      |             SENTINEL SERVER                 |
                                      |  (Flask Dashboard + API v1 + SQLite Repo)   |
                                      |                                             |
                                      |  * Live Alerts Feed & SVG Velocity Chart    |
                                      |  * Unified Line Diffs & Approval Actions    |
                                      |  * Monitored Assets & Compliance Reporting  |
                                      +---------------------------------------------+
                                                             ^
                                                             | HTTP / Bearer Token
                                                             | (Versioned Envelopes S-1)
                                                             v
+-----------------------------------------------------------------------------------+
|                                 SENTINEL AGENT                                    |
|                                                                                   |
|  +--------------------+    +--------------------+    +-------------------------+  |
|  | FileWatcher        |--->| Debounce Buffer    |--->| Classifier & Diff       |  |
|  | (inotify / psutil) |    | (0.5s quiet window)|    | (vs Local Baseline DB)  |  |
|  +--------------------+    +--------------------+    +-------------------------+  |
|                                                                    |              |
|                                                                    v              |
|  +--------------------+    +--------------------+    +-------------------------+  |
|  | DiskBufferedSink   |<---| Policy Rules Engine|<---| Behavioral Pipeline     |  |
|  | (Durability / F11) |    | (Severity Rating)  |    | (Decoy/Speed/Entropy)   |  |
|  +--------------------+    +--------------------+    +-------------------------+  |
|                                                                                   |
|  Mode: MONITOR (Alert & audit only) | Mode: PROTECT (Automated rollback & isolate)|
+-----------------------------------------------------------------------------------+
```

---

## Comparison with Traditional FIM Tools

| Capability | Sentinel | AIDE | Tripwire | Wazuh |
|---|---|---|---|---|
| **Integrity Baseline** | Cryptographic SHA-256 + permissions + owner + entropy | Cryptographic hash + metadata | Cryptographic hash + metadata | Cryptographic hash + metadata |
| **Real-Time Detection** | Instantaneous filesystem notifications + debouncing | Batch cron jobs | Scheduled polling / agent | Inotify / syscheck module |
| **Behavioral Defense Layer** | Built-in canary decoys, modification velocity, entropy heuristics | None (static check) | None (static check) | Rule correlation engine |
| **Process Attribution** | Kernel open file attribution to PID & process name | None | Best-effort with auditd | Auditd integration |
| **Response & Recovery** | Optional automated attacker isolation (`SIGKILL`) & 100% snapshot rollback | None (alert only) | None | Active response scripts |
| **Operator Experience** | Dark cinematic terminal console, inline SVG charts, one-click Approve/Reject | CLI report text | Enterprise Web UI | Kibana / Opensearch |
| **Content Diffs** | Unified line diffs with sensitive secret deny-list protection | Plain text diffs | Text diffs | Text diffs |

---

## Behavioral Signals Legend

- **`[DECOY]`**: Canary trap tripped — a bait file placed in monitored locations was altered or deleted.
- **`[SPEED]`**: Mass velocity anomaly — 25 or more distinct files changed within a 5-second burst.
- **`[ENTROPY]`**: Content scrambling heuristic — file turned into random-looking data.
- **`[SUSTAINED]`**: Persistent noise — suspicious file tampering continued for 3+ seconds without a break.
- **`[SLOW_SUSPICION]`**: Low-and-slow tampering — subtle, rate-limited file corruption over time.

---

## Configuration Reference (`sentinel.yaml`)

```yaml
host_id: auto            # auto = socket.gethostname()
server:
  url: "http://127.0.0.1:5000"
  token_env: "SENTINEL_TOKEN"

defaults:
  exclude:
    - ".git/**"
    - "node_modules/**"
    - "__pycache__/**"
    - "*.tmp"
  new_file_severity: "info"
  max_files: 50000
  max_hash_bytes: 104857600   # 100 MB cap

paths:
  - id: "ssh"
    path: "~/.ssh"
    mode: "monitor"
    include: ["authorized_keys", "config"]
    decoys: false
    capture_content: true

  - id: "web"
    path: "/var/www/html"
    mode: "monitor"
    decoys: true

  - id: "docs"
    path: "~/important"
    mode: "protect"
    decoys: true

rules:
  - match: "**/authorized_keys"
    severity: "critical"
    reason: "SSH access list changed"
  - match: "/etc/passwd"
    severity: "critical"
  - match: "/etc/shadow"
    severity: "critical"
  - match: "**/index.*"
    under: "web"
    severity: "high"

notify:
  webhooks:
    - url: "http://127.0.0.1:9000/hook"
      min_severity: "high"
```

---

## Quickstart

```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Initialize baseline
python3 -m sentinel.cli -c sentinel.yaml init-baseline

# 3. Run Sentinel in foreground
python3 -m sentinel.cli -c sentinel.yaml run

# 4. Open dashboard
# Visit http://127.0.0.1:5000 in your browser
```

---

## Known Limitations

- **Co-located Storage**: Backups, baselines, and logs reside on the same Linux host; a root-level attacker could tamper with local SQLite stores.
- **Read Operations**: Reads are not audited, only modifications, creations, deletions, and metadata changes.
- **Entropy Heuristics**: Compressed files (zip/tar/mp4) naturally exhibit high entropy; entropy is an indicator, not proof of encryption.
- **Slow Attackers**: Tampering slower than 3 noisy files per 60 seconds evades the slow-burn rule.
- **Process Attribution**: Process attribution is best-effort via `/proc` open file handles; transient processes may report unknown PID.
- **Single Host / Localhost Focus**: Default setup targets single host Linux / WSL2 environments.
