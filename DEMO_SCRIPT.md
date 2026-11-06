# Sentinel Demo Walkthrough (3-Minute Script)

This script guides an examiner through the key capabilities of **Sentinel**: file integrity monitoring, behavioral defense escalation, process attribution, unified text diffs, and approval/rejection workflows.

---

## 0. Preparation & Starting Sentinel

In your WSL2 Ubuntu terminal:

```bash
cd ~/rewind_project
source .venv/bin/activate
cp sentinel.example.yaml sentinel.yaml

# 1. Initialize the cryptographic baseline
python3 -m sentinel.cli -c sentinel.yaml init-baseline

# 2. Start the Sentinel FIM engine & server
python3 -m sentinel.cli -c sentinel.yaml run
```

Open the dashboard in your browser at: **`http://127.0.0.1:5000`**

---

## 1. Scenario 1: Unauthorized SSH Key Injection (Checkpoint F1)

**Story:** An attacker sneaks a rogue SSH public key into `~/.ssh/authorized_keys`.

1. In a second terminal, append an attacker key:
   ```bash
   echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKERKEY evil@darknet" >> ~/.ssh/authorized_keys
   ```
2. Switch to the Sentinel Dashboard:
   - Notice the status counter immediately increments under **CRITICAL**.
   - An alert appears with target `~/.ssh/authorized_keys` and severity `CRITICAL`.
3. Click **Inspect &rarr;**:
   - The unified diff highlights the added line in bright green: `+ssh-ed25519 AAAAC3...`.
   - Process attribution indicates the PID and process that modified the file.

---

## 2. Scenario 2: Administrator Review & Approval (Checkpoint F2)

**Story:** A system administrator reviews the change and approves legitimate configuration updates.

1. On the alert inspection page, click **Approve (Update Baseline)**.
2. Confirm the prompt.
3. The alert status transitions to `APPROVED`.
4. The agent automatically updates the local SQLite baseline for this file. No further repeat alerts will trigger for this state.

---

## 3. Scenario 3: Privilege Escalation & Rogue Tampering Rejection (Checkpoint F3, F5)

**Story:** An attacker tampers with script permissions (`chmod 777`).

1. Change permissions on a watched script:
   ```bash
   chmod 777 ~/important/deploy.sh
   ```
2. The Sentinel dashboard flags a **HIGH** severity alert: `permissions changed`.
3. Click **Inspect &rarr;** and choose **Reject (Keep Drift / Revert)**.
4. The baseline is **not** updated; the drift remains flagged as a security violation. In protect mode, Sentinel automatically rolls the file back.

---

## 4. Scenario 4: Bulk Behavioral Tampering & Decoy Defense (Checkpoints F7, F8, F9)

**Story:** Ransomware attempts rapid bulk file encryption across a protected vault.

1. Watch the dashboard's **Live Change Velocity** graph.
2. If ransomware touches a decoy canary file (`!DECOY_*.txt`), Sentinel's behavioral layer trips instantly:
   - Threat escalated to **CRITICAL**.
   - Signals show: `[DECOY]`, `[SPEED]`, `[ENTROPY]`.
   - In protect mode, the attacker process tree is frozen with `SIGSTOP`, terminated with `SIGKILL`, and scrambled files are restored to clean baseline state 100/100.

---

## 5. Compliance Audit Report

1. Click **Compliance Report** in the top navigation or visit `http://127.0.0.1:5000/report?days=30`.
2. Inspect the clean audit summary showing total incidents, approval resolutions, and violation history ready for printing (`Ctrl+P` formatted with `@media print`).

