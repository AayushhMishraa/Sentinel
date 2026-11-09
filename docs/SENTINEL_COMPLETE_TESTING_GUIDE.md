# Sentinel: Enterprise File Integrity Monitoring (FIM) & Autonomous Defense
## Complete Testing & Demonstration Showcase Guide

This document is the master testing guide for **Sentinel**, designed for enterprise evaluators, examiners, and security teams. It brings together all foundational (normal) tests, advanced behavioral defense tests, and automated regression suites into a single, structured runbook.

---

## Executive Summary: What is Sentinel and Why Enterprise Grade?

Traditional File Integrity Monitoring (FIM) tools (such as OSSEC or Tripwire) only alert security teams *after* files have been modified or encrypted. In an enterprise environment facing modern ransomware or insider threats, alert fatigue and delayed human reaction cause massive data loss.

**Sentinel bridges the gap between passive FIM and active endpoint defense:**
1. **Cryptographic Baseline Integrity (NIST 800-53 / PCI-DSS 4.0 / SOC 2):** Computes SHA-256 hashes, POSIX file modes, ownership, and text diffs across critical directories, maintaining a tamper-evident golden baseline in a secured database.
2. **Behavioral Heuristic Escalation:** Detects Canary Trap violations (`[DECOY]`), high-speed tampering bursts (`[SPEED]`), content transformation into encrypted noise (`[ENTROPY]`), prolonged anomalous activity (`[SUSTAINED]`), and low-and-slow evasion attacks (`[SLOW_SUSPICION]`).
3. **Autonomous Protect Mode (Zero Data Loss):** For critical paths, Sentinel links directly with the low-level engine to freeze the malicious process tree (`SIGSTOP`), terminate the attacker (`SIGKILL`), and restore damaged files from a rolling clean snapshot back to 100% data integrity within milliseconds.
4. **Human-in-the-Loop Remediation:** Security analysts can review unified diffs, approve valid patches (updating the golden baseline), or reject unauthorized drift (triggering instant rollback to the verified clean baseline).
5. **Distributed Multi-Cloud Fleet Architecture:** Central REST API (`/api/v1/`) ingesting events and heartbeats from distributed agents across Linux servers, cloud instances, and developer machines.

---

## Pre-Test Setup & Starting Sentinel

Run all demonstration tests in **two separate terminal tabs** while keeping the web dashboard open.

### Terminal 1: Start Central Sentinel Engine & Server
```bash
cd ~/rewind_project
source .venv/bin/activate
# Start Sentinel engine and web dashboard on 127.0.0.1:5000
python3 -m sentinel.cli -c sentinel.yaml run
```

### Browser Dashboard
Open in your browser:
* **Alerts Feed:** `http://127.0.0.1:5000`
* **Monitored Assets:** `http://127.0.0.1:5000/assets`
* **Compliance Audit Report:** `http://127.0.0.1:5000/report?days=30`

---

# PART 1: Foundational Tests (Core FIM Capabilities)

---

### Test 1: Content Modification & Live Unified Diff
* **Objective:** Verify Sentinel captures text file edits, computes cryptographic diffs, and reflects the change in real-time.
* **Terminal 2 Command:**
  ```bash
  echo "CRITICAL_PAYLOAD = True" >> protected_folder/sample.txt
  ```
* **Terminal 2 Output:** None (clean append).
* **Terminal Meaning:** A file within the watched folder had a line appended by a background process or user.
* **Dashboard Visibility:**
  * Browser tab title dynamically shifts from `Sentinel` to `(1) Alerts - Sentinel`.
  * **Open Alerts** counter highlights and plays the bounce animation, turning yellow (`--warn`).
  * A new alert appears: **Target Path:** `.../sample.txt`, **Severity:** `[MEDIUM]`, **Kinds:** `[modified]`, **Signals:** `—`.
* **Inspection View (Click "Inspect →"):**
  * Displays old SHA-256 vs. new SHA-256.
  * Displays the unified diff highlighting the added line in green: `+CRITICAL_PAYLOAD = True`.
* **Enterprise Meaning:** Proves continuous integrity monitoring without polling lag. Analysts can review exact line-by-line changes rather than just a vague "file touched" alert.

---

### Test 2: Administrator Approval Workflow (Golden Baseline Update)
* **Objective:** Prove an administrator can approve a legitimate operational change, updating the Golden Baseline so repeat alerts never fire.
* **Execution:**
  1. On the inspection page for `sample.txt`, click **"✓ Approve (Update Baseline)"**.
  2. Confirm the security confirmation modal dialog.
* **Dashboard Visibility:**
  * Alert badge transitions to green **`[APPROVED]`**.
  * Open alerts count decrements back to `0`.
* **Terminal 2 Verification:**
  ```bash
  echo "# Routine administrative maintenance" >> protected_folder/sample.txt
  ```
* **Observation:** Sentinel compares this next change against the **approved state** (`+CRITICAL_PAYLOAD = True`), not the old baseline from days ago.
* **Enterprise Meaning:** Establishes compliance with change management policies (ITIL / SOC 2). Legitimate software updates do not generate continuous false alarms.

---

### Test 3: Unauthorized Tampering Rejection & Drift Enforcement
* **Objective:** Demonstrate that rejecting an alert keeps the security incident flagged as unauthorized drift.
* **Terminal 2 Command:**
  ```bash
  echo "UNAUTHORIZED_BACKDOOR = 1" >> protected_folder/sample.txt
  ```
* **Dashboard Visibility:**
  * New alert generated for `sample.txt`.
  * Click **"Inspect →"**, then click **"✗ Reject (Keep Drift / Revert)"**.
  * Badge changes to orange **`[REJECTED]`**.
* **Observation:** The baseline is **not** updated. The change remains documented in the immutable audit log as rejected drift.
* **Enterprise Meaning:** Prevents unauthorized changes from accidentally becoming the new accepted standard.

---

### Test 4: File Deletion & Metadata Retention
* **Objective:** Ensure file deletions are flagged as high-severity incidents, preserving previous metadata and hash evidence.
* **Terminal 2 Command:**
  ```bash
  rm protected_folder/sample.txt
  ```
* **Dashboard Visibility:**
  * New alert with **Severity:** Red/Orange **`[HIGH]`**, **Kinds:** **`[deleted]`**.
  * Status: `[OPEN]`.
* **Inspection View:**
  * Shows the deleted file's previous SHA-256 hash, size, and POSIX permissions.
* **Enterprise Meaning:** Ensures malicious deletion of system logs, configuration files, or database dumps is immediately surfaced with complete evidentiary history.

---

### Test 5: Canary Decoy Trap (Instant Behavioral Escalation to CRITICAL)
* **Objective:** Demonstrate canary traps planted in critical folders that trigger an immediate threat escalation upon contact.
* **Terminal 2 Command:**
  ```bash
  echo "tampering" >> protected_folder/\!DECOY_001.txt
  ```
* **Dashboard Visibility:**
  * **CRITICAL** counter increments in bright red.
  * Browser toast slides in: `New [CRITICAL] Alert: File modified.`
  * Alert row shows **Severity:** `[CRITICAL]`, **Signals:** `[DECOY]`.
* **Enterprise Meaning:** Legitimate users and applications never access hidden canary trap files (`!DECOY_*.txt`). Any read or write indicates an autonomous scanner or ransomware script traversing the directory.

---

### Test 6: Permission Tampering & Privilege Escalation (`chmod 777`)
* **Objective:** Detect dangerous file permission drift even if the file content is untouched.
* **Terminal 2 Command:**
  ```bash
  touch protected_folder/runner.sh
  chmod 777 protected_folder/runner.sh
  ```
* **Dashboard Visibility:**
  * Alert flags **Severity:** `[HIGH]`, **Kinds:** `[created, permissions]`.
* **Inspection View:**
  * Details show mode change: `0644` (or `0755`) &rarr; `0777` (`rwxrwxrwx`).
* **Enterprise Meaning:** Catches privilege escalation attempts, SUID bit abuse, or misconfigurations that allow untrusted users to execute malicious binaries.

---

### Test 7: Fleet Inventory & Compliance Audit Report
* **Objective:** Demonstrate multi-asset management and executive compliance reporting.
* **Execution:**
  1. In the dashboard top bar, click **"Monitored Assets"** (`/assets`).
     * Observe the **Connected Host Agents** table showing agent heartbeat, version `v0.1.0`, and status `ONLINE`.
     * Observe the **Monitored Folders & Protection Modes** table specifying which folders are in `PROTECT (AUTO-RESTORE)` vs. `MONITOR ONLY`.
  2. Click **"Compliance Report"** (`/report?days=30`).
     * Displays a clean, printable executive summary table showing total incidents, approvals, rejections, and resolution notes.
     * Press `Ctrl+P` to view print-optimized CSS for executive PDF presentation.
* **Enterprise Meaning:** Satisfies compliance auditors by delivering immutable 30-day reporting ready for SOC 2, HIPAA, and ISO 27001 evidence packages.

---

# PART 2: Advanced Behavioral & Autonomous Protect Tests

---

### Test 8: Autonomous Protect Mode (Process Kill & 100% Auto-Restore)
* **Objective:** Simulate a full-speed ransomware outbreak. Prove that Sentinel kills the attacker process and restores all files to 100% integrity with zero data loss.
* **Terminal 2 Command:**
  ```bash
  .venv/bin/python3 test_ransomware/ransomware_v1.py --target protected_folder --rate 20 --hold 0.04
  ```
* **Terminal 2 Output:**
  ```text
  ransomware_v1 (harmless test tool): attacking 103 files in /home/aayush/rewind_project/protected_folder
  Killed
  ```
* **What the Output Means:**
  * The ransomware began attacking files.
  * As soon as it struck a canary decoy or exceeded velocity thresholds, the engine issued `SIGKILL` (signal 9) directly to the attacker's PID.
  * The process was terminated immediately.
* **Dashboard Visibility:**
  * Alert fires with **Severity:** `[CRITICAL]`, **Signals:** `[DECOY, SPEED]`.
  * Summary: `File modified: !DECOY_001.txt by PID <PID>`.
* **Terminal 2 Integrity Verification:**
  ```bash
  head -n 2 protected_folder/document_000.txt
  ```
  **Expected Output:**
  ```text
  This is a sample document for testing file integrity monitoring.
  It contains normal, human-readable text.
  ```
* **Enterprise Meaning:** Unlike standard FIMs that merely watch disasters unfold, Sentinel's autonomous Protect Mode actively terminates the malicious process and reverses the attack. No backups need to be manually pulled from tapes or cold storage.

---

### Test 9: Stealth Slow-Burn Evasion Attack (`SLOW_SUSPICION`)
* **Objective:** Prove defense against sophisticated attackers who pace file encryption to avoid burst rate limits and avoid decoys.
* **Terminal 2 Command:**
  ```bash
  .venv/bin/python3 test_ransomware/slow_3s.py --target protected_folder --avoid-decoys --interval 2.5 --limit 3
  ```
* **Terminal 2 Output:**
  ```text
  slow_3s (harmless test tool): one file every 2.5 s, 100 files in /home/aayush/rewind_project/protected_folder
  finished: 3 files overwritten
  ```
* **Dashboard Visibility Progression:**
  * **File 1 & File 2:** Flagged as `[MEDIUM]` with signal `[ENTROPY]`. (Normal single-file encryption or compression does not trigger panic).
  * **File 3 (The Escalation):** As the 3rd file crosses the entropy threshold within the rolling memory window, the alert escalates to **`[CRITICAL]`** with signals:
    ```text
    [ENTROPY, SLOW_SUSPICION]
    ```
* **Enterprise Meaning:** Sophisticated ransomware (e.g., LockBit, BlackCat) frequently uses slow pacing to evade simple velocity checks. Sentinel's sliding window memory tracks cumulative behavioral suspicion over time.

---

### Test 10: Stealth XOR Sustained Attack (`SUSTAINED`)
* **Objective:** Catch low-entropy ransomware (e.g., repeating XOR keys) that bypasses both canary traps and entropy thresholds.
* **Terminal 2 Command:**
  ```bash
  .venv/bin/python3 test_ransomware/ransomware_v2.py --target protected_folder --avoid-decoys --weak --rate 12
  ```
* **Terminal 2 Output:**
  ```text
  ransomware_v2 (harmless test tool, weak (4-byte repeating key)): attacking 100 files in /home/aayush/rewind_project/protected_folder
  Killed
  ```
* **Dashboard Visibility Progression:**
  * Initial edits appear as `[HIGH]` with signal `[SPEED]`.
  * After anomalous activity continues unbroken for $\ge 3.0$ seconds, the alert escalates to **`[CRITICAL]`** with signals:
    ```text
    [SPEED, SUSTAINED]
    ```
  * Sentinel confirms the attack, sends `SIGKILL`, and rolls back files.
* **Integrity Verification:**
  ```bash
  head -n 2 protected_folder/document_000.txt
  ```
  Files are intact human-readable text.

---

### Test 11: Distributed Multi-Cloud REST API & Remote Heartbeat
* **Objective:** Prove Sentinel functions as a central security event manager for a distributed fleet.
* **Step 1: Query Active Alerts Programmatically via REST API**
  ```bash
  curl -s http://127.0.0.1:5000/api/v1/alerts | python3 -m json.tool | head -n 25
  ```
  *Output:* Formatted JSON showing alert ID, host, path, severity, and behavioral signals.
* **Step 2: Register a Remote Cloud Agent (e.g., AWS VPC Instance)**
  ```bash
  curl -s -X POST http://127.0.0.1:5000/api/v1/heartbeat \
    -H "Content-Type: application/json" \
    -d '{"host_id": "aws-prod-web-02", "name": "ip-10-0-1-42", "agent_version": "0.1.0"}' | python3 -m json.tool
  ```
  *Output:* `{"ok": true, "ts": ...}`
* **Dashboard Verification:**
  * Open `http://127.0.0.1:5000/assets`.
  * Under **Connected Host Agents**, `aws-prod-web-02` appears with green badge **`ONLINE`**.
* **Enterprise Meaning:** Proves that Sentinel can be deployed across on-premise servers and multi-cloud environments (AWS, GCP, Azure) reporting back to a centralized dashboard.

---

### Test 12: High-Volume Bulk Triage & Audit Trail Preservation
* **Objective:** Demonstrate that a SOC analyst can triage dozens of alerts from mass maintenance without destroying audit logs.
* **Terminal 2 Command:**
  ```bash
  chmod 644 protected_folder/document_*.txt
  ```
* **Dashboard Visibility:**
  * Open alerts count spikes to 20+.
  * Click the orange **"✓ Bulk Acknowledge (X)"** button.
  * The Open Alerts counter resets to **0** and animates.
* **Compliance Report Verification:**
  * Visit `/report?days=30`.
  * Every single permission change remains logged with its timestamp, actor `dashboard-admin`, and resolution note `Bulk acknowledged`.
* **Enterprise Meaning:** Solves SOC analyst alert fatigue while satisfying strict regulatory requirements where every event must be retained.

---

# PART 3: Automated Quality & Regression Test Suite

To prove code reliability and regression resistance to examiners, Sentinel includes a test suite covering all architecture checkpoints:

```bash
# In Terminal 2:
cd ~/rewind_project
.venv/bin/pytest tests/sentinel/
```

### Expected Output:
```text
============================= test session starts ==============================
collected 61 items

tests/sentinel/test_api_v1.py ...                                        [  4%]
tests/sentinel/test_baseline_store.py .....                              [ 13%]
tests/sentinel/test_bulk_acknowledge.py ..                               [ 16%]
tests/sentinel/test_checkpoints_f10_f12.py ..                            [ 19%]
tests/sentinel/test_classifier.py ......                                 [ 29%]
tests/sentinel/test_clean_slate_decoys.py ...                            [ 34%]
tests/sentinel/test_debounce_permissions.py ..                           [ 37%]
tests/sentinel/test_decoy_no_self_alert.py ..                            [ 40%]
tests/sentinel/test_lifecycle_f2_f3.py ..                                [ 44%]
tests/sentinel/test_local_host_autoregister.py .                         [ 45%]
tests/sentinel/test_offline_buffer_f11.py .                              [ 47%]
tests/sentinel/test_protect_f7_f8_f9.py ....                             [ 54%]
tests/sentinel/test_protect_live_subprocess.py .                         [ 55%]
tests/sentinel/test_protect_ransomware_restore.py ..                     [ 59%]
tests/sentinel/test_reflag_after_approval.py .                           [ 60%]
tests/sentinel/test_rules.py .....                                       [ 68%]
tests/sentinel/test_sentinel_dashboard.py ......                         [ 78%]
tests/sentinel/test_settings.py .......                                  [ 90%]
tests/sentinel/test_slow_burn_alert.py ..                                [ 93%]
tests/sentinel/test_week1_checkpoints.py ....                            [100%]

======================== 61 passed in 63.46s =========================
```

### What This Proves:
1. **F1–F6 Core Baselines:** Cryptographic hashes, hidden files, permission debouncing, and exclude glob matching are verified.
2. **F7–F9 Protect Engine:** Process freezing (`SIGSTOP`), termination (`SIGKILL`), and rolling snapshot restoration operate reliably across edge cases.
3. **F10–F12 Distributed Resiliency:** Offline buffering queues events during network partitions and re-transmits them automatically upon reconnect without duplicate records.
4. **UI & Dashboard Integrity:** Dynamic tab titles, rate-limited toast notifications, non-destructive live DOM updates, and prominent 1.5s counter bounce animations function as designed.

---

## Quick Reference Summary Table for Demonstrations

| Test # | Title | Terminal 2 Command | Primary Signal | Dashboard Impact | Defense Outcome |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **1** | Content Modification | `echo "CRITICAL_PAYLOAD = True" >> protected_folder/sample.txt` | `—` | `[MEDIUM]` modified | Unified diff highlighted in green |
| **2** | Baseline Approval | UI Button Click: *Approve* | `—` | `[APPROVED]` badge | Baseline updated; no repeat alerts |
| **3** | Drift Rejection | `echo "UNAUTHORIZED" >> protected_folder/sample.txt` & UI *Reject* | `—` | `[REJECTED]` badge | Baseline preserved; drift flagged |
| **4** | File Deletion | `rm protected_folder/sample.txt` | `—` | `[HIGH]` deleted | Historical metadata preserved |
| **5** | Canary Decoy Trap | `echo "tampering" >> protected_folder/\!DECOY_001.txt` | `[DECOY]` | `[CRITICAL]` decoy | Toast notification & canary alert |
| **6** | Privilege Escalation | `chmod 777 protected_folder/runner.sh` | `—` | `[HIGH]` permissions | Detects `0777` mode change |
| **7** | Monitored Assets | Dashboard Navigation: `/assets` & `/report` | Telemetry | Host `ONLINE` | Executive printable report |
| **8** | Protect Mode Kill | `.venv/bin/python3 test_ransomware/ransomware_v1.py ...` | `[DECOY, SPEED]` | `[CRITICAL]` open | Process `Killed`; 100% rollback |
| **9** | Stealth Slow-Burn | `.venv/bin/python3 test_ransomware/slow_3s.py ...` | `[SLOW_SUSPICION]` | Escalates to `CRITICAL` | Caught by sliding entropy window |
| **10** | Stealth XOR Sustained | `.venv/bin/python3 test_ransomware/ransomware_v2.py ...` | `[SPEED, SUSTAINED]` | Escalates to `CRITICAL` | Sustained rule fires; `SIGKILL` + restore |
| **11** | Fleet REST API | `curl -X POST /api/v1/heartbeat ...` | Heartbeat | `aws-prod-web-02` `ONLINE` | Multi-host cloud fleet visibility |
| **12** | Bulk Acknowledge | `chmod 644 ...` & UI *Bulk Acknowledge* | Bulk policy | Resets to `0 OPEN` | Complete 30-day compliance retention |
