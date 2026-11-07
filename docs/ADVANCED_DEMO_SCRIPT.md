# Sentinel Advanced Live Demo Script (Examiner Guide)

This guide provides the complete set of advanced demonstration tests for **Sentinel** and the autonomous **Rewind Protect Mode engine**. It includes exact terminal commands, expected terminal output, dashboard visibility, and deep explanations of what every observation means for your Viva or examiner demonstration.

---

## Quick Reference Summary

| # | Demo Scenario | Key Command | Signals Caught | Dashboard Visibility | Defense Action |
|---|---|---|---|---|---|
| **1** | **Protect Mode Kill & Auto-Restore** | `ransomware_v1.py --target protected_folder --rate 20 --hold 0.04` | `[DECOY]`, `[SPEED]` | Alert #X `CRITICAL` `OPEN` | `SIGKILL` attacker + 100% rollback |
| **2a** | **Stealth Slow-Burn Attack** | `slow_3s.py --target protected_folder --avoid-decoys --interval 2.5 --limit 3` | `[ENTROPY]`, `[SLOW_SUSPICION]` | Alert escalates `MEDIUM` &rarr; `CRITICAL` | Caught by sliding entropy memory window |
| **2b** | **Stealth XOR Sustained Attack** | `ransomware_v2.py --target protected_folder --avoid-decoys --weak --rate 12` | `[SPEED]`, `[SUSTAINED]` | Alert escalates `HIGH` &rarr; `CRITICAL` | Sustained rule catches low-entropy attacker; SIGKILL + restore |
| **3** | **Distributed Fleet Heartbeat API** | `curl -X POST /api/v1/heartbeat` | Agent telemetry | Monitored Assets shows `aws-prod-web-02` `ONLINE` | Multi-agent centralization |
| **4** | **Single-File Revert on Reject** | Human clicks "Reject" on drift | Drift detection | Alert status changes to `REJECTED` | File reverted from Golden Baseline |
| **5** | **Bulk Acknowledge / SOC Audit** | Recursive `chmod 644` | Policy rules | Counter resets to `0 OPEN`, audit preserved | Mass triage without losing audit trail |

---

## Preparation (Terminal 1 - Engine & Dashboard Server)

Before running any test, ensure Sentinel is running with the current configuration:

```bash
# Terminal 1: Start Sentinel central engine & dashboard
.venv/bin/python3 -m sentinel.cli -c sentinel.yaml run
```

Keep **http://127.0.0.1:5000** open in your browser on the **ALERTS FEED** page.

---

## Advanced Test 1: Autonomous Protect Mode (Process Kill & 100% Auto-Restore)

### What this test does:
Simulates a real, fast ransomware attack attempting to encrypt 20 files per second. It proves Sentinel's autonomous Protect Mode:
1. Catches the process touching a decoy file or exceeding speed thresholds.
2. Sends `SIGKILL` to stop the attacker cold.
3. Automatically rolls back all files to the clean baseline/snapshot **before** the alert is opened.

### Terminal 2 Command:
```bash
.venv/bin/python3 test_ransomware/ransomware_v1.py --target protected_folder --rate 20 --hold 0.04
```

### What You See in Terminal 2:
```text
ransomware_v1 (harmless test tool): attacking 103 files in /home/aayush/rewind_project/protected_folder
Killed
```

### What the Terminal Output Means:
- `attacking 103 files`: The ransomware started scanning and encrypting.
- `Killed`: Sentinel identified the attacker process (via inotify/fanotify PID attribution) and immediately sent `SIGKILL` (signal 9). The process was stopped before it could finish attacking.
- Note: It cleanly exits without hanging or printing `[1]+ Stopped` because the process decouples from terminal job control.

### What You See on the Dashboard (http://127.0.0.1:5000):
1. A new alert pops up immediately at the top of the feed:
   - **Severity Badge**: Red `[CRITICAL]`
   - **Status Badge**: `[OPEN]`
   - **Signals Badge**: Red `[DECOY]` (or `[SPEED]`)
   - **Summary**: `File modified: !DECOY_001.txt by PID <PID>`
2. Click **Inspect &rarr;**:
   - Cryptographic Evidence shows the Unified Diff of the tampering attempt.
   - Target PID attribution correctly identifies the Python simulator PID.

### Verification of Integrity (Terminal 2):
Now prove to the examiner that the files were 100% restored and NOT left encrypted:
```bash
head -n 2 protected_folder/document_000.txt
```
**Expected Output:**
```text
This is a sample document for testing file integrity monitoring.
It contains normal, human-readable text.
```
**What this means:** Even though ransomware attempted to scramble the files, Protect Mode restored every damaged file from the rolling snapshot back to clean text. Zero data loss.

---

## Advanced Test 2: Stealth Slow-Burn Attack (`SLOW_SUSPICION`)

### What this test does:
Demonstrates defense against sophisticated ransomware that tries to evade traditional defenses by:
1. Skipping canary decoy files (`--avoid-decoys`).
2. Pacing itself at 1 file every 2.5 seconds (under the 25 files / 5 sec speed threshold).
3. Using high-entropy random bytes (encryption).

Sentinel detects this using its **Sliding Entropy Window** (detecting 3+ distinct files turned into high-entropy noise within 60 seconds).

### Terminal 2 Command:
```bash
.venv/bin/python3 test_ransomware/slow_3s.py --target protected_folder --avoid-decoys --interval 2.5 --limit 3
```

### What You See in Terminal 2:
```text
slow_3s (harmless test tool): one file every 2.5 s, 100 files in /home/aayush/rewind_project/protected_folder
finished: 3 files overwritten
```

### What You See on the Dashboard (Watch the progression):
1. **File 1 & File 2**:
   - Alerts appear with **Severity**: Yellow `[MEDIUM]`.
   - Signals: `[ENTROPY]`.
   - *Meaning:* Sentinel detects high randomness on an individual file, but because normal software (like saving a `.zip` or `.png`) can create entropy, it raises suspicion without false-alarm escalation.
2. **File 3 (The Escalation)**:
   - The alert for the 3rd file fires with **Severity**: Red **`[CRITICAL]`**!
   - Signals: **`[ENTROPY, SLOW_SUSPICION]`**!
   - *Meaning:* Sentinel's suspicion tracker recognized that 3 distinct files became noise in under 60 seconds. The slow-burn rule escalated the attack to CRITICAL and alerted the SOC.

---

## Advanced Test 2b: Stealth Low-Entropy Sustained Attack (`SUSTAINED`)

### What this test does:
Demonstrates defense against stealth XOR attackers that try to bypass both canary traps and entropy detection:
1. **Avoids decoys** (`--avoid-decoys`), so canary traps don't fire.
2. **Uses weak 4-byte repeating XOR** (`--weak`), keeping file entropy low (~4.5), so individual `[ENTROPY]` alerts do not fire.
3. Rapidly tampers with files. Sentinel initially flags rapid edits as `HIGH [SPEED]` (`SUSPICIOUS`).
4. Because `SPEED` alone could be a legitimate bulk edit (like `git checkout` or batch processing), Sentinel does not kill immediately. Instead, its continuous suspicion tracker observes the activity.
5. Once anomalous activity continues unbroken for 3.0+ seconds, the **`SUSTAINED` rule** fires, escalating the verdict to **`CRITICAL` [SPEED, SUSTAINED]**, terminating the process with `SIGKILL`, and rolling back all tampered files.

### Terminal 2 Command:
```bash
.venv/bin/python3 test_ransomware/ransomware_v2.py --target protected_folder --avoid-decoys --weak --rate 12
```

### What You See in Terminal 2:
```text
ransomware_v2 (harmless test tool, weak (4-byte repeating key)): attacking 100 files in /home/aayush/rewind_project/protected_folder
Killed
```

### What You See on the Dashboard:
1. Initial alerts:
   - **Severity**: Orange/Yellow `[HIGH]`
   - **Signals**: `[SPEED]`
   - *Meaning:* Rapid edits triggered the velocity check, but Sentinel waited to confirm whether it was sustained malicious activity or a quick human bulk operation.
2. The Escalation (at ~3.0-3.5 seconds into attack):
   - **Severity**: Red **`[CRITICAL]`**
   - **Signals**: Red **`[SPEED, SUSTAINED]`**!
   - *Meaning:* Continuous anomalous activity exceeded 3.0 seconds unbroken. Protect Mode confirmed the attack, dispatched `SIGKILL`, and initiated automatic snapshot rollback.

### Verification of Integrity:
```bash
head -n 2 protected_folder/document_000.txt
```
**Expected Output:** Clean, readable English text (100% restored).

---

## Advanced Test 3: Central Agent REST API & Fleet Simulation

### What this test does:
Proves Sentinel's distributed architecture (Rule S-1). Sentinel is not just a local monitor; it is a central Security Information and Event Management (SIEM) server capable of ingesting events and heartbeats from multiple remote servers across a fleet.

### Step 1: Query Live Alerts via REST API
In Terminal 2:
```bash
curl -s http://127.0.0.1:5000/api/v1/alerts | python3 -m json.tool
```
*(Tip: If you only want to inspect the first alert, run: `curl -s http://127.0.0.1:5000/api/v1/alerts | python3 -c "import sys, json; data=json.load(sys.stdin); print(json.dumps(data[0] if data else {}, indent=2))"`)*

**Expected Terminal Output:**
A clean JSON structure representing the alerts:
```json
[
  {
    "id": 1,
    "host_id": "LAPTOP-HEO2HM0R",
    "root_id": "sandbox",
    "path": "/home/aayush/rewind_project/protected_folder/!DECOY_001.txt",
    "severity": "critical",
    "status": "open",
    "signals": ["DECOY"],
    "kinds": ["modified"],
    "summary": "File modified: !DECOY_001.txt by PID 12345",
    "diff": "..."
  }
]
```
**What this means:** Third-party SIEMs (Splunk, Datadog, ELK) or automated orchestration webhooks can query Sentinel programmatically without external dependencies.

### Step 2: Register a Remote Cloud Agent via API Heartbeat
Simulate a secondary cloud server (e.g., `aws-prod-web-02`) checking in from an AWS VPC:
```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/heartbeat \
  -H "Content-Type: application/json" \
  -d '{"host_id": "aws-prod-web-02", "name": "ip-10-0-1-42", "agent_version": "0.1.0"}' | python3 -m json.tool
```
**Expected Terminal Output:**
```json
{
    "ok": true,
    "ts": 1794056000.123
}
```
**What this means:** The central server authenticated the agent and updated its heartbeat registry.

### Step 3: Observe in Dashboard
1. On the dashboard navigation header, click **MONITORED ASSETS** (or open `http://127.0.0.1:5000/assets`).
2. Under **CONNECTED HOST AGENTS**, observe:
   - Your local workstation (`LAPTOP-...`) is `ONLINE`.
   - **`aws-prod-web-02`** is now listed with version `v0.1.0` and green status badge **`ONLINE`**!
3. **What this means:** The examiner can see Sentinel functioning as a multi-host fleet manager.

---

## Advanced Test 4: Single-File Revert on Human Rejection

### What this test does:
Demonstrates human-in-the-loop drift remediation. When an unauthorized modification is rejected by a security analyst, Sentinel does not just dismiss the ticket—it reaches into the Golden Baseline store and automatically reverts that specific file back to its verified clean state.

### Execution:
1. In Terminal 2, inject an unauthorized line into a file:
   ```bash
   echo "unauthorized_backdoor_injection = 1" >> protected_folder/sample.txt
   ```
2. Verify the backdoor exists on disk:
   ```bash
   tail -n 2 protected_folder/sample.txt
   ```
   *Terminal Output:*
   ```text
   unauthorized_backdoor_injection = 1
   ```
3. Look at the Dashboard:
   - Alert appears: `File modified: sample.txt`.
   - Click **Inspect &rarr;**.
   - Review the diff: you see `+unauthorized_backdoor_injection = 1`.
4. Click **`✗ Reject (Keep Drift / Revert)`**:
   - The UI provides friction-free instant rejection (or confirms revert).
   - Alert status updates to `REJECTED`.
5. Check Terminal 2 again:
   ```bash
   tail -n 2 protected_folder/sample.txt
   ```
   **Expected Output:**
   The injected backdoor is **completely gone**!
   **What this means:** Sentinel verified that the path has Golden Baseline content stored, triggered `revert_file()`, and restored the file to its golden state without touching any other files in the directory.

---

## Advanced Test 5: Bulk Acknowledge & SOC Compliance Audit Trail

### What this test does:
Demonstrates high-volume alert triage and regulatory compliance (SOC2 / ISO 27001).
If an operational change (e.g., recursive permission changes or mass file edits) generates dozens of alerts, an administrator needs to triage them without losing the historical audit log.

### Execution:
1. In Terminal 2, run a recursive permission change:
   ```bash
   chmod 644 protected_folder/document_*.txt
   ```
2. Observe the Dashboard:
   - Open alerts counter jumps (e.g. `15 OPEN` or `55 OPEN`).
   - The feed fills with permission alerts.
3. Click the **"Bulk Acknowledge All"** button at the top right of the Alerts Feed:
   - Open alerts counter immediately resets to **`0 OPEN`**.
   - The active feed clears.
4. Click **COMPLIANCE REPORT** in the top navigation:
   - Notice that **all 55 alerts are still listed** with timestamp, path, and resolution status `REJECTED (Bulk acknowledged)`.
   - **What this means:** Bulk triage saves analyst time while strictly preserving the immutability of the audit trail required by compliance auditors.
