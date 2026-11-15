# Sentinel

*Authored by Aayush Mishra*

Sentinel is a real-time File Integrity Monitoring (FIM) and behavioral defense system for Linux environments. It monitors designated directories for unauthorized modifications, configuration tampering, and mass-encryption attacks, combining persistent cryptographic baselines with behavioral heuristics and an interactive security operations dashboard.

---

## Background and Inspiration: Building on Rewind

Sentinel grew out of an earlier ransomware response project called **Rewind**. 

Rewind was built with a specific operational goal: endpoint ransomware containment. It monitored a protected directory using Linux inotify, detected rapid file tampering through behavioral heuristics (burst velocity, Shannon entropy shifts, and canary decoys), halted the offending process tree, and restored damaged files from local copy-on-write snapshots. It functioned as an active defensive circuit breaker for high-value folders.

While Rewind proved effective at stopping rapid ransomware execution in an isolated folder, enterprise environments face a broader class of integrity threats. Attackers do not only deploy mass-encryption payloads; they also inject SSH keys into `~/.ssh/authorized_keys`, tamper with `/etc/passwd`, modify web application scripts, or alter database configurations low and slow.

Sentinel takes the behavioral detection and recovery mechanics developed for Rewind and expands them into a full-featured File Integrity Monitoring architecture. Where Rewind focused strictly on reactive containment in a single target folder, Sentinel introduces:

- Multi-directory monitoring across arbitrary filesystem paths with independent policies.
- Persistent cryptographic baselines (SHA-256, ownership, permissions, size, entropy) stored in SQLite.
- Structured change classification (added, modified, deleted, metadata changes).
- Unified line diff generation for configuration files, with automatic redaction of sensitive credentials.
- Dual operational modes: passive audit monitoring for system services and active protection for critical assets.
- A dedicated web dashboard with real-time telemetry, live alert feeds, and one-click triage workflows.

Rewind serves as the core response and recovery engine within Sentinel's active protection layer.

---

## Why Sentinel Exists: Moving Beyond Traditional FIM

Traditional File Integrity Monitoring tools such as AIDE, Tripwire, and standard cron-based scanners have long been staples of compliance checklists. However, their architecture introduces critical operational limitations:

1. **High Latency (Periodic Batch Scans)**: Traditional FIM tools typically run as scheduled cron jobs once an hour, once a night, or once a week. If an attacker modifies `/etc/sudoers` or drops a web shell, defenders remain blind until the next scheduled scan runs—often hours after lateral movement has occurred.
2. **Zero Behavioral Context**: When a conventional FIM tool reports that fifty files changed, it cannot tell you whether those changes occurred in fifty milliseconds (a script or encryptor) or across six hours (normal administrative work). It provides no insight into modification velocity or entropy shifts.
3. **No Process Attribution**: Traditional tools inspect the filesystem after the fact. They cannot identify which process or user ID initiated the change while the file handle was open.
4. **Passive Alerting Only**: When unauthorized modifications or destructive encryption attacks occur, traditional tools merely append a line to a log file or send an email. They offer no mechanism to halt an active attack or restore the altered files.

Sentinel addresses these shortcomings by pairing continuous, real-time filesystem observation with behavioral heuristics, process attribution, and optional automated containment.

---

## Comparison: Sentinel vs. Traditional Tools

| Capability | Sentinel | AIDE | Tripwire | Wazuh (FIM / syscheck) |
|---|---|---|---|---|
| **Integrity Baseline** | SHA-256 + permissions + UID/GID + size + Shannon entropy | SHA-256 / SHA-512 + metadata | Cryptographic hash + metadata | Cryptographic hash + metadata |
| **Detection Timing** | Real-time inotify with 0.5s debouncing | Scheduled batch cron jobs | Scheduled polling / agent | Inotify or scheduled checks |
| **Behavioral Signals** | Canary decoys, burst velocity, entropy analysis, sustained tampering | None (static check) | None (static check) | Rule correlation engine |
| **Process Attribution** | Best-effort `/proc` lookup (PID, name, cmdline) | None | Best-effort via auditd | Auditd integration |
| **Response & Recovery** | Optional automated process termination (`SIGKILL`) and snapshot rollback | None (alert only) | None (alert only) | Active response scripts |
| **Content Inspection** | Unified line diffs with sensitive secret deny-list filtering | Text diffs | Text diffs | Text diffs |
| **Operator Console** | Dark-themed SOC dashboard with live feed, SVG velocity charts, and approval workflows | CLI report output | Web console | Kibana / OpenSearch dashboard |

---

## Architecture and Event Pipeline

Sentinel is structured into an agent layer (which observes filesystem activity and evaluates policy) and a server layer (which stores alerts, serves API endpoints, and hosts the operator dashboard).

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
                                                             | (Versioned Envelopes)
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
|  | (SQLite Queue)     |    | (Severity Rating)  |    | (Decoy/Speed/Entropy)   |  |
|  +--------------------+    +--------------------+    +-------------------------+  |
|                                                                                   |
|  Mode: MONITOR (Audit & alert only) | Mode: PROTECT (Automated rollback & isolate)|
+-----------------------------------------------------------------------------------+
```

### How an Event Moves Through the System

1. **Filesystem Observation (`FileWatcher`)**: The watcher attaches inotify hooks to every configured path. It captures file creations, modifications, deletions, moves, and permission changes.
2. **Debounce Buffer**: Many applications—including text editors like Vim or Nano, package managers, and `sed -i`—perform atomic saves by writing to temporary files, renaming, and tweaking permissions. A single file edit can generate up to ten raw inotify events in quick succession. Sentinel holds events in a 0.5-second quiet window per file. Once activity settles, the engine evaluates the final state of the file on disk, eliminating event noise and preventing the hashing of partially written files.
3. **Baseline Classification (`Classifier & Diff`)**: The engine queries the local SQLite baseline database (`~/.sentinel/baseline.db`). It compares the file's current SHA-256 hash, size, mode, and ownership against the recorded baseline entry:
   - `ADDED`: File exists on disk but has no baseline record.
   - `MODIFIED`: Content hash differs from baseline.
   - `DELETED`: File was recorded in baseline but no longer exists.
   - `METADATA`: Content hash is unchanged, but permissions or ownership changed.
   If the file is a readable text file under 64 KB, Sentinel computes a unified line diff showing additions and deletions.
4. **Behavioral Evaluation**: Changes are passed through behavioral heuristics to evaluate threat velocity, entropy shifts, and canary interactions.
5. **Policy Rules & Severity Assignment**: The event is matched against user-defined rules in `sentinel.yaml` (e.g. matching `**/authorized_keys` as `CRITICAL`). If behavioral signals triggered, the severity is escalated automatically.
6. **Durable Delivery (`DiskBufferedSink`)**: Events are packaged into versioned envelopes and committed to a local SQLite buffer before being flushed to the central server over HTTP. If the server is offline or unreachable, events remain queued on disk until connectivity is restored.

---

## Detection Capabilities and Behavioral Signals

Sentinel evaluates file modifications against five distinct behavioral heuristics:

### 1. Canary Decoys (`[DECOY]`)
Canary files with enticing names (such as hidden configuration files or credentials) are placed in monitored directories. Legitimate applications and users have no reason to access or alter these files. Because automated traversal scripts and ransomware encrypt files indiscriminately or alphabetically, touching a decoy provides an immediate, high-confidence indicator of compromise.

### 2. Modification Velocity (`[SPEED]`)
Human administrators edit configuration files one at a time. Ransomware and bulk wiper scripts, by contrast, modify dozens of files per second. Sentinel's speed heuristic tracks modification velocity across watched directories. If 25 or more distinct files are altered within a 5-second sliding window, Sentinel flags a velocity anomaly.

### 3. Entropy Analysis (`[ENTROPY]`)
Shannon entropy quantifies the degree of randomness in a byte stream on a scale from 0 to 8. Normal source code, plain text, and configuration files typically have an entropy score between 3.0 and 5.0. Modern symmetric encryption algorithms (such as AES-256) produce ciphertext whose byte distribution is indistinguishable from random data, with entropy reaching 7.5 or higher. Sentinel calculates file entropy on modification; a sharp jump from a known baseline to $\ge 7.5$ indicates likely encryption.

### 4. Sustained Tampering (`[SUSTAINED]`)
To evade burst-velocity thresholds, some modern ransomware strains throttle their operations, introducing deliberate sleeps between file encryptions. Sentinel's activity monitor tracks persistent tampering over consecutive seconds (e.g. 3+ seconds without a break), flagging sustained tampering even when the instantaneous rate remains below the burst limit.

### 5. Slow-Burn Detection (`[SLOW_SUSPICION]`)
Sophisticated attackers may modify files at very low rates over extended periods to blend into background noise. Sentinel maintains a cumulative suspicion tracker that monitors suspicious file changes across a wider 60-second window, alerting when multiple low-level anomalies accumulate.

---

## Operational Modes: MONITOR vs. PROTECT

Sentinel supports two operating modes configured on a per-path basis in `sentinel.yaml`.

```
                    +------------------------------------+
                    |        Incoming File Event         |
                    +------------------------------------+
                                      |
                      Is path mode 'monitor' or 'protect'?
                                     / \
                                    /   \
                         'monitor' /     \ 'protect'
                                  v       v
           +-----------------------+     +-------------------------------+
           |     MONITOR MODE      |     |         PROTECT MODE          |
           |                       |     |                               |
           | * Classify baseline   |     | * Evaluate Rewind pipeline    |
           | * Generate line diffs |     | * If threat confirmed:        |
           | * Evaluate rules      |     |   1. Identify PID via /proc   |
           | * Ship alert to SOC   |     |   2. Terminate tree (SIGKILL) |
           | * NO processes killed |     |   3. Restore files from       |
           | * NO files modified   |     |      clean snapshot/baseline  |
           +-----------------------+     | * Ship alert & recovery log   |
                                         +-------------------------------+
```

### MONITOR Mode (Audit and Observe)
Designed for system-wide directories such as `/etc`, `/var/www`, `/usr/local/bin`, and `~/.ssh`. 

In monitor mode, Sentinel acts strictly as an auditor. It records modifications, generates unified diffs, classifies changes against the baseline, and delivers alerts to the dashboard and external webhooks. It **never** terminates processes and **never** reverts file contents. This guarantees zero risk of disrupting critical production services or legitimate administrative updates.

### PROTECT Mode (Active Containment and Rollback)
Designed for dedicated document directories, database backups, or high-value data stores.

Protect mode activates the **Rewind** behavioral engine. When a monitored path is initialized under protect mode:
1. An initial clean snapshot and baseline manifest are generated.
2. Canary decoys are deployed.
3. If an event sequence trips behavioral thresholds (e.g., decoy tampering or rapid entropy spikes), the protection engine identifies the offending process tree via `/proc` open file handles, terminates the processes with `SIGKILL`, and rolls back modified or deleted files using the latest verified snapshot.

#### Safety Guards
To prevent catastrophic accidental rollbacks or system instability, Protect mode enforces hard safety constraints:
- It **strictly refuses** to run on the root filesystem (`/`) or the user's root home directory (`~`).
- It enforces a maximum file count cap (default 10,000 files) and directory size cap (default 1 GB) per protected folder to maintain predictable snapshot performance.

---

## Recovery and Response Mechanics

When an active attack is detected in `PROTECT` mode, Sentinel executes a structured response workflow:

```
[Detection Event] 
       │
       ▼
[Identify Offender] ──► Inspect /proc open file handles & parent process trees
       │
       ▼
[Isolate & Terminate] ──► Send SIGSTOP (freeze) then SIGKILL to entire process hierarchy
       │
       ▼
[Revert Damage] ──► Compare disk state against manifest; restore files from snapshots
       │
       ▼
[Notify & Audit] ──► Emit incident report to dashboard repository with killed PIDs and restored paths
```

### Process Attribution
Sentinel correlates filesystem events with the responsible process by reading `/proc` open file descriptors and `/proc/<pid>/stat`. It extracts the process ID (PID), command name, command line arguments, and parent process hierarchy. 

*Engineering Note on Attribution:* Process attribution is best-effort. On Linux, short-lived or transient processes (such as a rapidly invoked bash command or compiler sub-process) may terminate before the `/proc` lookup completes. When a process exits prior to inspection, Sentinel records the event with an unknown PID while still evaluating the integrity change.

---

## The Operator Experience: Web Dashboard

Sentinel includes an embedded security operations console built on Flask and Tailwind CSS, designed for fast alert triage.

- **Live Alerts Feed**: Real-time display of incoming integrity events, sortable and filterable by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), host ID, path, and review status.
- **Unified Line Diff Viewer**: Displays exact line-by-line additions and deletions for text-based configuration files, allowing an analyst to verify changes instantly.
- **Triage and Approval Lifecycle**:
  - **Approve**: Confirms a change was authorized. Approving an alert automatically updates the baseline store to accept the file's new cryptographic hash.
  - **Reject**: Marks an unauthorized modification. The alert remains flagged for incident investigation.
- **Telemetry Visualizations**: Inline dynamic SVG charts showing real-time file modification velocity (changes per second) and alert distribution by severity.
- **Fleet Assets View**: Displays all registered hosts, monitored paths, baseline status, and last heartbeat timestamps.
- **Compliance & Audit Reporting**: Generates a 30-day compliance summary highlighting total modifications, approval rates, and unreviewed critical alerts.
- **Keyboard Navigation & Command Palette**: Operators can press `Ctrl+K` or `/` anywhere in the interface to open the command palette for rapid navigation.

---

## Installation and Setup

### Prerequisites
- Linux or WSL2 (Ubuntu 20.04+ recommended)
- Python 3.9 or newer
- Standard Linux utilities (`inotify-tools`, `gcc` if compiling C dependencies)

### Setup

```bash
# 1. Clone repository
git clone https://github.com/AayushhMishraa/Sentinel.git
cd Sentinel

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Configuration Reference (`sentinel.yaml`)

Sentinel is configured using a single YAML file. Monitored paths, detection modes, exclusion rules, and alert webhooks are defined cleanly:

```yaml
# Host identifier (defaults to system hostname if set to 'auto')
host_id: auto

# Central dashboard server settings
server:
  url: "http://127.0.0.1:5000"
  token_env: "SENTINEL_TOKEN"

# Global monitoring defaults
defaults:
  exclude:
    - ".git/**"
    - "node_modules/**"
    - "__pycache__/**"
    - "*.tmp"
    - "*.swp"
  new_file_severity: "info"
  max_files: 50000
  max_hash_bytes: 104857600   # Cap at 100 MB per file for hashing

# Monitored directory targets
paths:
  # Monitor mode: Audit-only for sensitive system credentials
  - id: "ssh-config"
    path: "~/.ssh"
    mode: "monitor"
    include:
      - "authorized_keys"
      - "config"
    decoys: false
    capture_content: true

  # Monitor mode: Track web server assets with canary traps
  - id: "web-root"
    path: "/var/www/html"
    mode: "monitor"
    decoys: true
    capture_content: true

  # Protect mode: Active defense and automated rollback for critical documents
  - id: "finance-docs"
    path: "~/secure_documents"
    mode: "protect"
    decoys: true

# Severity policy rules
rules:
  - match: "**/authorized_keys"
    severity: "critical"
    reason: "SSH authorized keys modified - potential backdoor"

  - match: "/etc/passwd"
    severity: "critical"
    reason: "System user database modified"

  - match: "/etc/shadow"
    severity: "critical"
    reason: "System password hashes modified"

  - match: "**/index.*"
    under: "web-root"
    severity: "high"
    reason: "Web root index file modified"

# External notification integrations
notify:
  webhooks:
    - url: "http://127.0.0.1:9000/webhook"
      min_severity: "high"
```

---

## Running Sentinel

Sentinel operates via a unified command-line interface.

### 1. Initialize the Baseline Database
Before starting active monitoring, generate a cryptographic baseline of all tracked directories:

```bash
python3 -m sentinel.cli -c sentinel.yaml init-baseline
```

This scans configured paths, computes SHA-256 digests, records permissions and ownership, and writes the baseline records to SQLite (`~/.sentinel/baseline.db`).

### 2. Run Sentinel in the Foreground
Start the monitoring engine and the embedded web dashboard:

```bash
python3 -m sentinel.cli -c sentinel.yaml run
```

Output:
```text
Starting Sentinel FIM engine for host 'sentinel-node-01'...
Dashboard web UI running at: http://127.0.0.1:5000
Sentinel engine is watching. Press Ctrl+C to stop.
```

Open your browser and navigate to `http://127.0.0.1:5000` to access the SOC dashboard.

---

## Testing and Verification

The repository includes test suites covering both the core Rewind ransomware defense engine and Sentinel's FIM platform, along with automated UI audit tools.

```bash
# Run Sentinel test suite (FIM engine, baselines, rules, API, diffs)
pytest tests/sentinel

# Run Rewind test suite (ransomware detection heuristics, response, snapshots)
pytest tests --ignore=tests/sentinel

# Run static UI accessibility and contrast audit
python3 tools/ui_audit.py

# Run headless browser verification (requires Playwright)
python3 tools/ui_browser_check.py
```

---

## Limitations and Security Considerations

Engineering defensive software requires transparency about trade-offs and operational constraints:

- **Co-located Storage**: By default, SQLite baseline stores, snapshot repositories, and logs reside on the monitored host. An attacker who gains root privileges can tamper with local database files or kill monitoring daemons. For hardened deployments, forward event envelopes to an isolated remote Sentinel server.
- **Unmonitored Read Operations**: Sentinel monitors write, create, delete, and attribute modification events. It does not monitor `IN_ACCESS` (read operations). Auditing every read on a Linux filesystem introduces unacceptable I/O overhead and log flooding. Sentinel detects unauthorized changes, not data exfiltration via read-only access.
- **Process Attribution Latency**: Correlating file changes to PIDs relies on reading `/proc` while the file descriptor is open. If an adversary executes an action using a transient one-liner process that exits in under a millisecond, Sentinel detects the file modification but may report an unknown PID.
- **Entropy False Positives on Compressed Files**: Compressed archives (`.zip`, `.tar.gz`, `.xz`) and multimedia formats (`.mp4`, `.png`) are naturally compressed and exhibit high Shannon entropy ($\ge 7.5$). While Sentinel considers entropy a strong signal, archival directories containing compressed data should be excluded from raw entropy alerting.
- **Snapshot Storage Caps**: Protect mode relies on local snapshot copies to perform rollbacks. It is not designed to replace system-wide offsite backup solutions for multi-terabyte filesystems.

---

## Project Status and Roadmap

Sentinel is actively maintained as an independent open-source project. Current areas of development include:

- **eBPF-Based Telemetry**: Implementing an eBPF tracing backend alongside inotify to achieve guaranteed process attribution without polling `/proc`.
- **Remote Cryptographic Baseline Verification**: Signing baseline hashes with asymmetric keys to detect unauthorized local baseline tampering.
- **Multi-Agent Management**: Extending fleet management capabilities with centralized agent configuration push and health monitoring.

---

## Author

Authored by **Aayush Mishra** ([@AayushhMishraa](https://github.com/AayushhMishraa)).

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
