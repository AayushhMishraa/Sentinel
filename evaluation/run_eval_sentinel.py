"""Sentinel Acceptance Matrix 5x Evaluation Runner.

Runs scenarios F1 through F12 five times each, measures runtimes,
and outputs a markdown acceptance table.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Dict, List

SCENARIOS = [
    ("F1", "tests/sentinel/test_week1_checkpoints.py::test_f1_authorized_keys_appended_critical_with_diff", "Key appended to watched authorized_keys -> CRITICAL alert with diff"),
    ("F2", "tests/sentinel/test_lifecycle_f2_f3.py::test_f2_approve_updates_baseline_and_no_repeat_alert", "Config file edited, then Approved -> baseline updated, no repeat alert"),
    ("F3", "tests/sentinel/test_lifecycle_f2_f3.py::test_f3_reject_keeps_drift_flagged_without_updating_baseline", "Config file edited, then Rejected -> drift stays flagged"),
    ("F4", "tests/sentinel/test_week1_checkpoints.py::test_f4_watched_file_deleted", "Watched file deleted -> alert"),
    ("F5", "tests/sentinel/test_week1_checkpoints.py::test_f5_chmod_permissions_changed", "chmod 777 on watched file -> HIGH 'permissions changed'"),
    ("F6", "tests/sentinel/test_week1_checkpoints.py::test_f6_new_file_in_watched_folder_info", "New file in watched folder -> INFO alert"),
    ("F7", "tests/sentinel/test_protect_f7_f8_f9.py::test_f7_speed_rule_bulk_edits", "25+ files edited within 5 s -> HIGH (SPEED)"),
    ("F8", "tests/sentinel/test_protect_f7_f8_f9.py::test_f8_decoy_tampered_critical", "Decoy tampered with -> CRITICAL alert"),
    ("F9", "tests/sentinel/test_protect_f7_f8_f9.py::test_f9_ransomware_stopped_and_restored", "Ransomware simulator vs protect path -> stopped & restored 100/100"),
    ("F10", "tests/sentinel/test_checkpoints_f10_f12.py::test_f10_legitimate_zip_tar_only_raises_info", "Legitimate zip or tar created -> INFO only, zero false alarms"),
    ("F11", "tests/sentinel/test_offline_buffer_f11.py::test_f11_offline_buffering_and_reconnect_replay", "Agent offline then back -> buffered events delivered in order"),
    ("F12", "tests/sentinel/test_checkpoints_f10_f12.py::test_f12_webhook_delivered_with_retries", "Webhook alert to local receiver -> delivered with retries"),
]

RUNS_PER_SCENARIO = 5


def run_single(test_target: str) -> float:
    start = time.time()
    res = subprocess.run(
        [sys.executable, "-m", "pytest", test_target, "-q"],
        capture_output=True,
        text=True,
    )
    elapsed = time.time() - start
    if res.returncode != 0:
        raise RuntimeError(f"Test {test_target} failed:\n{res.stdout}\n{res.stderr}")
    return elapsed


def main():
    print(f"=== Starting Sentinel 5x Evaluation ({len(SCENARIOS)} scenarios x {RUNS_PER_SCENARIO} runs) ===")
    results = []

    for sid, target, desc in SCENARIOS:
        print(f"Running Scenario {sid}: {desc}...")
        times = []
        for r in range(RUNS_PER_SCENARIO):
            t = run_single(target)
            times.append(t)
            print(f"  Run {r+1}/{RUNS_PER_SCENARIO}: {t:.2f}s")
        times.sort()
        median_s = times[len(times) // 2]
        worst_s = times[-1]
        results.append({
            "id": sid,
            "desc": desc,
            "runs": RUNS_PER_SCENARIO,
            "passed": RUNS_PER_SCENARIO,
            "median_s": median_s,
            "worst_s": worst_s,
        })

    # Generate Markdown Table
    md = [
        "# Sentinel Acceptance Matrix (5x Evaluation Runs)",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "| ID | Scenario & Description | Runs | Passed | Median (s) | Worst (s) | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        md.append(f"| {r['id']} | {r['desc']} | {r['runs']}/5 | {r['passed']}/{r['runs']} | {r['median_s']:.2f} | {r['worst_s']:.2f} | PASSED |")

    md.append("")
    md.append("**Result:** ALL 12 ACCEPTANCE SCENARIOS GREEN (100% Pass Rate Across 60 Runs)")

    out_content = "\n".join(md) + "\n"
    matrix_path = os.path.abspath("docs/sentinel_acceptance_matrix.md")
    with open(matrix_path, "w", encoding="utf-8") as f:
        f.write(out_content)

    print("\n" + out_content)
    print(f"Saved evaluation matrix to {matrix_path}")


if __name__ == "__main__":
    main()

