# Sentinel Acceptance Matrix (5x Evaluation Runs)

Generated: 2026-11-06 12:53:48

| ID | Scenario & Description | Runs | Passed | Median (s) | Worst (s) | Status |
|---|---|---|---|---|---|---|
| F1 | Key appended to watched authorized_keys -> CRITICAL alert with diff | 5/5 | 5/5 | 2.32 | 2.39 | PASSED |
| F2 | Config file edited, then Approved -> baseline updated, no repeat alert | 5/5 | 5/5 | 3.32 | 3.48 | PASSED |
| F3 | Config file edited, then Rejected -> drift stays flagged | 5/5 | 5/5 | 2.07 | 2.12 | PASSED |
| F4 | Watched file deleted -> alert | 5/5 | 5/5 | 2.08 | 2.11 | PASSED |
| F5 | chmod 777 on watched file -> HIGH 'permissions changed' | 5/5 | 5/5 | 2.07 | 2.08 | PASSED |
| F6 | New file in watched folder -> INFO alert | 5/5 | 5/5 | 2.09 | 2.11 | PASSED |
| F7 | 25+ files edited within 5 s -> HIGH (SPEED) | 5/5 | 5/5 | 2.55 | 2.57 | PASSED |
| F8 | Decoy tampered with -> CRITICAL alert | 5/5 | 5/5 | 2.04 | 2.05 | PASSED |
| F9 | Ransomware simulator vs protect path -> stopped & restored 100/100 | 5/5 | 5/5 | 2.78 | 2.79 | PASSED |
| F10 | Legitimate zip or tar created -> INFO only, zero false alarms | 5/5 | 5/5 | 3.36 | 3.38 | PASSED |
| F11 | Agent offline then back -> buffered events delivered in order | 5/5 | 5/5 | 1.21 | 1.21 | PASSED |
| F12 | Webhook alert to local receiver -> delivered with retries | 5/5 | 5/5 | 1.36 | 1.40 | PASSED |

**Result:** ALL 12 ACCEPTANCE SCENARIOS GREEN (100% Pass Rate Across 60 Runs)
