# Sentinel Advanced Live Demo Script (Examiner Guide)

This guide covers advanced live demonstration scenarios for Sentinel and the underlying Rewind behavioral response engine, specifically designed for technical evaluation and Viva examinations.

---

## 0. Architecture Context: Why Protect Mode Was Separated from the 7-Test Walkthrough

The primary 7-test walkthrough focuses on **File Integrity Monitoring (FIM)**, policy rule evaluation, and **human-in-the-loop review** (Inspect, Diff, Approve, Reject, Telemetry).

**Protect Mode (Autonomous Defense)** was separated because:
1. **Instant Autonomous Response vs. Human Inspection**: While Monitor Mode holds changes for human review, Protect Mode operates within milliseconds without human intervention—issuing `SIGSTOP`/`SIGKILL` to attacker processes and executing an immediate rolling snapshot restoration.
2. **Strict Guardrails**: Protect Mode leverages Rewind's safety sandbox check (`.REWIND_SANDBOX`). To prevent accidental process termination or data loss on developer machines, ransomware simulators refuse to execute outside explicitly verified sandbox folders.
3. **Specialized Demonstration Flow**: Demonstrating live process death and bulk file restoration is high-impact and requires showcasing the terminal, process tree, and dashboard simultaneously.

---

## Advanced Test 1: Autonomous Protect Mode (Process Kill & Auto-Restore)

**Objective:** Prove that Sentinel actively detects ransomware, kills the attacking process tree with `SIGKILL`, and restores scrambled files back to their baseline state (100% integrity recovery).

### Prerequisites
1. Ensure `sentinel.yaml` has `sandbox` set to `mode: protect` (default).
2. Ensure Sentinel is running in Terminal 1:
   ```bash
   python3 -m sentinel.cli -c sentinel.yaml run
   ```

### Execution (Terminal 2)
1. Verify files exist in `protected_folder/` and note their readable contents:
   ```bash
   head -n 2 protected_folder/sample.txt
   ```
2. Launch the harmless ransomware simulator targeting the sandbox:
   ```bash
   .venv/bin/python3 test_ransomware/ransomware_v1.py --target protected_folder --rate 20 --hold 0.04
   ```

### What You & the Examiner Will Observe:
- **Terminal 2**: The ransomware simulator starts encrypting files, but is almost immediately **terminated** (`Killed` message output by kernel upon receiving `SIGKILL` from Rewind's response engine).
- **Dashboard (http://127.0.0.1:5000)**:
  - An alert fires with **CRITICAL** severity.
  - Behavioral signals display `[DECOY, SPEED]`.
  - Process attribution lists the exact PID of `ransomware_v1.py`.
- **File System**: Inspect `protected_folder/sample.txt` immediately after:
  ```bash
  head -n 2 protected_folder/sample.txt
  ```
  The file is **intact and restored** to clean baseline text—not corrupted binary bytes.

---

## Advanced Test 2: Stealth Slow-Burn Attack (`SLOW_SUSPICION`)

**Objective:** Demonstrate that Sentinel cannot be fooled by slow, low-volume ransomware that evades speed thresholds and skips decoy traps.

### Background
Fast ransomware is caught by high file-modification speed (>25 files / 5s) or touching canary files (`!DECOY_*`). A "Slow-Burn" attacker writes one encrypted file every 2.5–3 seconds and avoids decoys. Sentinel uses a multi-file entropy memory tracker to confirm the attack once 3+ distinct files become random noise over time.

### Execution (Terminal 2)
1. Run the slow ransomware simulator with `--avoid-decoys`:
   ```bash
   .venv/bin/python3 test_ransomware/slow_3s.py --target protected_folder --avoid-decoys --interval 2.5 --limit 4
   ```

### What You & the Examiner Will Observe:
- During the first 1-2 files, the attacker operates under the speed radar and does not touch decoys.
- Upon the 3rd file turning into high-entropy noise, the **Slow-Burn Rule** triggers.
- **Dashboard**:
  - Alert escalates to **CRITICAL**.
  - Signals show `[ENTROPY, SLOW_SUSPICION]`.
  - The attacker process is suspended and terminated before completing its target list.

---

## Advanced Test 3: Central Agent REST API & Fleet Simulation

**Objective:** Prove Sentinel's distributed architecture (Rule S-1) by querying the REST API and simulating a remote agent checking in from the cloud.

### 1. Query Current Live Alerts via CLI
```bash
curl -s http://127.0.0.1:5000/api/v1/alerts | jq .
```
*Returns JSON list of all versioned alerts, severities, diffs, and attribution.*

### 2. Query Connected Hosts
```bash
curl -s http://127.0.0.1:5000/api/v1/hosts | jq .
```
*Returns the registered host registry.*

### 3. Register a Remote Cloud Agent via API Heartbeat
Simulate a secondary server (e.g. `aws-prod-web-02`) reporting to your Sentinel central server:
```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/heartbeat \
  -H "Content-Type: application/json" \
  -d '{"host_id": "aws-prod-web-02", "name": "ip-10-0-1-42", "agent_version": "0.1.0"}' | jq .
```
*Expected response: `{"ok": true, "ts": ...}`*

### 4. Verify in Dashboard
Open **http://127.0.0.1:5000/assets**:
- Under **Connected Host Agents**, `aws-prod-web-02` immediately appears alongside your local machine with an **`ONLINE`** status badge.

---

## Advanced Test 4: Single-File Revert on Human Rejection

**Objective:** Demonstrate Sentinel's precise human-in-the-loop rollback: rejecting an unauthorized drift reverts that specific file from baseline without affecting other concurrent work.

### Execution
1. Modify a legitimate file in `protected_folder`:
   ```bash
   echo "unauthorized_backdoor_injection = 1" >> protected_folder/sample.txt
   ```
2. Wait 1 second for the alert to pop up in **http://127.0.0.1:5000**.
3. Click **Inspect &rarr;** on the alert.
4. Click **Reject (Keep Drift / Revert)**.
5. In Terminal 2, inspect `sample.txt`:
   ```bash
   tail -n 3 protected_folder/sample.txt
   ```
   Notice the injected line `unauthorized_backdoor_injection = 1` is **gone**—Sentinel automatically restored the file from its stored baseline content.
