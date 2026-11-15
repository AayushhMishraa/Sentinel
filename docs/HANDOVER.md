# Rewind + Sentinel: Project Handover

Written 2026-11-15 for ANY AI coding agent (Antigravity, Claude Code, others) or a human taking over.

- Trust the code over this file. Where they disagree, add a line to section 9 and continue.
- This file is a LIVING document: after every finished item in section 7, tick it and update section 6.
- The owner is a beginner. Explain in plain English, short, no unexplained jargon.

---

## 1. What this project is

**Rewind** (finished, 228 tests): a real-time ransomware defense for one Linux folder. It watches the folder, detects
ransomware-like behavior, kills the attacking process tree, and restores damaged files from clean backups.
Tagline: "Detected. Stopped. Undone."

**Sentinel** (in progress, branch `sentinel`): a file integrity monitor (FIM) built on top of Rewind. It records a
baseline of watched files, detects every change (created, modified, deleted, permissions, owner), rates it by
severity, explains it (text diff, which process), and lets a person APPROVE or REJECT it. Rewind's behavioral
detectors (decoy, speed, entropy, sustained, slow-burn) add ransomware-style signals. An OPTIONAL per-path
"protect" mode reuses Rewind's kill-and-restore engine.

Deliverable: a college capstone project with a viva/live demo. The UI matters a lot to the examiner.

## 2. Environment and how to run

- Windows 11 + WSL2 Ubuntu. Code lives at `~/rewind_project` (Linux filesystem). NEVER work under `/mnt/c`
  (the file watcher does not work there).
- A Git Bash clone exists at `C:\Users\Aayush\rewind`. It is a read-only mirror: do not run or edit there.
- GitHub: `AayushhMishraa/rewind` (public). Branches: `main` = final Rewind, `sentinel` = current work.
  Tag `rewind-v1` was requested for the final Rewind (verify with `git tag --list`).
- Python venv: `.venv` (`source .venv/bin/activate`). The owner's shell has `alias rsudo='sudo -E env "PATH=$PATH"'`
  (aliases do not exist in an agent's terminal: write the expansion out).
- The demo browser is Chrome/Edge on Windows 11. The server runs in WSL and is reached at http://127.0.0.1:5000.
- Antigravity is configured with Turbo (auto-run) and a deny list: `git push`, `git reset --hard`, `git clean`,
  `rm -rf`, `sudo`, `dd`, `mkfs`, `shutdown`, `reboot`. You cannot type a sudo password: give the owner exact
  commands for any root step and wait.

Commands (run from `~/rewind_project` with the venv active):

```
python3 -m pytest tests --ignore=tests/sentinel -q; echo EXIT=$?   # Rewind: expect 228 passed (~3 min)
python3 -m pytest tests/sentinel -q; echo EXIT=$?                   # Sentinel: expect 71 passed (~1 min)
python3 tools/ui_audit.py; echo EXIT=$?                             # static UI audit, 9 checks
python3 tools/ui_browser_check.py; echo EXIT=$?                     # real Chromium check (Playwright), 120 checks
python3 tools/seed_demo.py --reset                                  # demo data (add --loop to keep hosts ONLINE)
python3 -m sentinel.cli -c sentinel.yaml run                        # Sentinel at http://127.0.0.1:5000
rsudo python3 main.py                                               # Rewind itself (needs root to see processes)
```

Playwright note: Chromium needed system libraries that `sudo -n` could not install. A previous run extracted `.deb`
libraries into the workspace and used `LD_LIBRARY_PATH`. Those files must stay UNTRACKED. The clean fix is for the owner
to run `sudo env "PATH=$PATH" python -m playwright install-deps chromium` once.

## 3. Rules (follow all of them)

### 3.1 Truth protocol (the agent has repeatedly over-claimed; these exist for that reason)
- T1 After EVERY pytest run paste the LITERAL last line and `echo EXIT=$?`. Never write "all tests pass" without it.
  Non-zero exit = failure, whatever you believe the cause is.
- T2 Before any test run: `pgrep -af "sentinel.cli|ransomware_|wiper_v1|slow_3s|python3 main.py|pytest"` must print
  nothing (ignore itself). Never run two suites at once: the live tests are timing-sensitive.
- T3 Record collect counts at the start and end of each phase. Rewind must stay 228. Counts may only go up, except for
  tests deleted on purpose in item R1 (list each by name first).
- T4 Never edit, delete, skip or loosen an existing test to make something pass. A test may change only when the product
  behavior was deliberately changed; then show old vs new and keep the assertion equally strong.
- T5 Never claim PASS for something you did not run or see. Unverified items are "NOT VERIFIED" and go on the human
  checklist. Since `tools/ui_browser_check.py` exists, every UI item must be covered by a check in it.
- T6 Git: commit per item with explicit paths (never `git add -A`). Never push. Never print or store tokens. No `sudo`,
  `rm -rf`, `pip`, `npm` or new network downloads without asking (one line: what and why).
- T7 Rewind code (`dashboard/`, `detection/`, `recovery/`, `response/`, `watcher/`, `core/`, `main.py`) and
  `tests/test_dashboard.py` stay unchanged. `git diff --stat main -- dashboard tests/test_dashboard.py` must be empty.
  Exception: repairing a regression, shown as a diff in the report.
- T8 Report every item as DONE / PARTIAL / NOT DONE with `file:line` evidence. An item that depends on something you
  could not do is PARTIAL, never DONE.

### 3.2 Rewind rules (keep them true)
R1 detection only judges, response only acts. R2 response only on CONFIRMED (runtime guard raises RuntimeError).
R3 every action is logged with its signals. R4 never kill without positive attribution. R5 never kill self,
ancestors, PID 1; ignore own writes. R6 backups never poisoned. R7 simulators only touch a marked sandbox
(`.REWIND_SANDBOX`). R8 behavior over names (no process-name allow-lists).

### 3.3 Sentinel scaling rules
S-1 agents send versioned JSON events to `/api/v1/events` (token auth). S-2 every record has `host_id` and
`schema_version`. S-3 storage behind a repository interface (SQLite now, PostgreSQL later). S-4 policy is data
(`sentinel.yaml`). S-5 alerts leave through a pluggable notifier (webhook now). S-6 detectors stay pure judges.

### 3.4 Security constraints
- Server binds 127.0.0.1. Keep the Host-header guard. Everything from the filesystem (paths, diffs) is attacker-controlled:
  `textContent` only, never `innerHTML` (audit check 4 enforces it).
- Agent tokens compared with `hmac.compare_digest`; never logged. No `shell=True` with user-controlled strings.
- Content/diff capture only for text files up to 64 KB, never for a deny list (shadow, *.pem, id_*, *.key ...).
- Protect mode refuses `/`, `$HOME`, or a folder over the size cap, and requires explicit `mode: protect`.

### 3.5 Locked decisions
Reads are NOT monitored (only changes; decoys fire on tamper, not on read). Default mode is monitor; protect is
opt-in per path. Stack: Python, Flask, SQLite, vanilla JS (native ES modules), Tailwind v4 browser build vendored
locally, CSS-variable tokens. No Node, no runtime CDN (works offline). Linux only. Config in YAML.
Sidebar follows the theme (light sidebar in light theme). Logo = the original mark in `static/brand/logo.svg`
(hexagon with a squared S): do NOT replace it with any traced or copied artwork. The owner uploaded two logo images
earlier; one was traced by mistake and removed: never trace third-party artwork.

## 4. Rewind: what exists (final, tagged `rewind-v1`)

Pipeline: watchdog events -> debounce/attribution -> detection (verdict) -> if CONFIRMED: response (freeze + kill the
tree, wait for quiet, restore, verify, log incident).

- Signals: DECOY (bait `!DECOY_*` file modified/deleted/moved: instant CONFIRMED); SPEED (>=25 distinct pre-existing
  files in 5 s and >=3 in the last second); ENTROPY (file was <6.5 and is now >=7.5, size >=4096 B); SUSTAINED (one
  weak signal unbroken for 3 s, a gap >2 s resets); SLOW_SUSPICION (>=3 distinct files turned to noise within 60 s,
  oldest >=5 s old). SPEED+ENTROPY = CONFIRMED; one signal = SUSPICIOUS.
- Response: SIGSTOP then SIGKILL on the tree; protected PIDs (self, ancestors, PID 1) refused; attribution sweep (20
  looks over ~1 s; more than 3 suspects = no kill, status UNATTRIBUTED_ALERT); wait for 2 s of quiet (max 10 s);
  restore; statuses RESOLVED / PARTIAL / UNATTRIBUTED_ALERT / STILL_ACTIVE.
- Recovery: snapshots every 30 s (keep 5), skipped when not NORMAL or within 10 s of an alert, discarded if an alert
  happens mid-copy, refused if files already look encrypted; known-good copies with 10 s delayed promotion and a
  snapshot cross-check (entropy shift >0.5 or size shift >5% rejects); restore uses the newest snapshot finished >=1 s
  before the attack and not "poisoned" (>20% noisy files), overlays trusted known-good copies, quarantines alien files,
  verifies SHA-256.
- Key code: `config.py` (all thresholds), `core/` (events, pipeline, state, activity, logger), `detection/`,
  `response/response_engine.py` (`respond_to_attack(verdict, pid, restore_fn, log_fn, state, *, activity, ...)`),
  `recovery/` (manifest, snapshot_manager, known_good, restore_engine), `watcher/`, `database/db_manager.py`,
  `dashboard/` (Rewind's own Flask dashboard), `main.py` (`RewindApp`).
- Simulators (harmless, sandbox-guarded): `test_ransomware/ransomware_v1.py`, `ransomware_v2.py` (`--weak`),
  `slow_3s.py`, `wiper_v1_zerofill.py`. Flags: `--target --rate --hold --limit --avoid-decoys`.
- Tests: 228 passed. Live scenarios S1a, S1b, S1-live, S2, S3a-S3f, S4, S5, S6 plus slow-burn/wiper/false-positive
  tests. `docs/acceptance_matrix.md` maps them. `evaluation/run_eval.py` runs live scenarios N times.
- Known limits (state them honestly in the report): backups and logs live on the same host; entropy cannot judge
  already-compressed files or encryption after the first 64 KB; attackers slower than 3 noisy files per 60 s evade
  slow-burn; attribution is best-effort; protect mode can misfire on legitimate bulk edits; Linux only.

## 5. Sentinel: what exists on the `sentinel` branch

Package `sentinel/` [verify names against the code]: settings (YAML), models, baseline store, classifier (+ diff), rules
(severity by path glob and by signal), engine (monitor and protect modes per path), sinks (local + HTTP with offline
buffer), agent, notifier (webhook), report (`/report` printable page), CLI (`python -m sentinel.cli`), and
`sentinel/server/` (Flask app, `api_v1.py`, `repo.py` SQLiteRepository, templates, static). Also
`scripts/demo_two_agents.sh`, `sentinel.yaml`, `tools/seed_demo.py`.

Config in use (`sentinel.yaml`): paths `sandbox` (./protected_folder, protect), `web` (./web_root, monitor),
`ssh` (./ssh_keys, monitor, decoys disabled), `docs` (~/important, protect). `ssh_keys/` and `web_root/` are demo
fixtures (git-ignored; recreate with the DEMO_SCRIPT one-liner or the seeder).

Features built: persistent baseline, change classifier with text diff, severity rules, alert lifecycle (open,
approved, rejected), approve/reject with audit trail, bulk action (see issue below), optional protect mode, agent to
server REST (`/api/v1`: events, heartbeat, commands, hosts, alerts, changes, stats, search), webhook notifier,
compliance report page, one source of truth for hosts (`get_fleet_hosts(repo, ttl=90)`: ONLINE if heartbeat <90 s).
Tests: 71 in `tests/sentinel/`.

UI state (Tailwind 4.3.5 vendored in `static/vendor/` with `VERSIONS.md`; tokens in `static/tokens.css`):
- Three themes via `data-theme` on `<html>`: dark, light, contrast (Demo contrast for projectors). Blocking inline
  anti-flicker script in `<head>`. Inter + JetBrains Mono self-hosted. Contrast ratios computed by the audit.
- Shell: sidebar (grouped nav, collapsible, rail mode, follows theme), top bar (breadcrumb, wide search, host selector,
  theme switch, user menu), pages: Alerts (stat tiles, 24 h change-velocity chart, alerts table with filters and row
  menu), Assets (hosts, monitored folders), Alert detail, Compliance report, UI Kit (TO BE REMOVED, item R1).
- Search: Ctrl/Cmd+K or `/` opens a native `<dialog>` palette backed by `GET /api/v1/search?q=` (alerts, hosts, paths),
  grouped results, arrows + Enter, recents (typed queries only), actions (go to pages, toggle theme, demo contrast).
- Popover menus (host selector, severity/status filters, row "..." menu) on the native `popover` attribute with
  JS positioning; toasts (aria-live, max 3, 3 s, solid background); 32 px table rows with middle-truncated mono paths
  and click-to-copy; chips and severity rails; copy diet applied (no explanatory text, definitions in a "?" popover).
- Brand: inline SVG macros in `templates/_brand.html` (logo mark, wordmark, lockup, fingerprint motif). The wordmark is
  outlined from "Ethnocentric Light" by `tools/make_wordmark.py` (needs fontTools). The font file is kept OUTSIDE git
  in `~/brand_src/`. Its zip licence says "Free for Personal Use" (source: exfont.com): fine for this college project;
  replace before any commercial use. `brand/FONT_NOTICE.md` records it.
- Verification tools: `tools/ui_audit.py` (9 static checks: routes/assets 200, no external URLs, theme script order, no
  innerHTML, tailwind sha256, contrast table, no font files in git, static colour/layout checks, dialog/popover
  attributes) and `tools/ui_browser_check.py` (real headless Chromium at 1366x768 and 1914x962, 3 themes, console
  errors, overlay-blocking via `elementFromPoint`, popover geometry within 8 px of its trigger, toast dismissal;
  120 checks, screenshots to `docs/screens/`).

Known issues to fix (see section 7):
- "Bulk Acknowledge" currently marks alerts REJECTED (the report shows "Bulk acknowledged" with status REJECTED). The
  label and the effect disagree. Make the action honest and confirmable.
- The Alerts chart is a simple curve; fine for now.
- `/ui-kit` must go.

## 6. Done so far (commits on `sentinel`)

- [x] Rewind complete, 228 tests, 13-row acceptance matrix, 5x evaluation harness, README, DEMO_SCRIPT.
- [x] Sentinel weeks 1-3 functionality (baseline, classifier, rules, lifecycle, protect mode, agent/server API,
      webhook, report) with 71 tests.
- [x] G `b6b140c` fix regressions (simulator wrapper removed, one test string updated)
- [x] A `22019f6` UI audit tool; U1 `0003f71` shell/components; U1-FIX-2 `368f4e2`; U1-FIX-3 `e550ffa`;
      U1-FIX-4 `d120fec` (inline brand SVGs, fonttools wordmark, working search endpoint)
- [x] U2 `328322d` palette upgrade, popover menu primitive, toasts, motion tokens, 24 h chart data;
      U2-FIX `14f83db` host consistency, seed loop; U2-FIX-2 `bdde598` real-browser check, JS syntax error fixed
      (a duplicate code tail in `base.html` had killed every page script: this caused the "stuck buttons" and the
      menus opening at the top-left)

Lessons that must not be repeated:
1. Python tests cannot catch JavaScript errors. Use `tools/ui_browser_check.py` for every UI change.
2. An SVG loaded through `<img>` cannot inherit `currentColor` (it renders black). Logos/wordmarks are INLINE SVG.
3. Sticky table headers inside cards float over the data. Only the main table header sticks, at `top: 0`.
4. A stale Flask server shows old templates with new CSS. Restart after Python changes; templates auto-reload in dev.
5. A GitHub token once leaked in a remote URL: never print `git remote -v`; use `gh auth login` credentials.
6. The agent once reported "all pass" while a suite exited non-zero: always paste literal lines (T1).

## 7. Remaining work (do in order; tick each when DONE and committed)

Each item: write or extend a Playwright check for any UI change, keep Rewind at 228, keep `ui_audit` and
`ui_browser_check` at EXIT=0, run the suites (T1/T2), commit, update this file.

- [ ] **R0 Baseline.** Verify the current state before changing anything: branch `sentinel`, clean `git status`,
  Rewind 228 passed, sentinel 71 passed, audit EXIT=0, browser check EXIT=0. Print the literal lines. Check
  `git tag --list` for `rewind-v1` and create it locally on the last Rewind commit if missing (never push).

- [ ] **R1 Remove the UI Kit (the owner does not want to show it to the examiner).** Delete the `/ui-kit` route, the
  `ui_kit.html` template, its sidebar entry, its palette and search entries, breadcrumbs/links to it, its pages in
  `tools/ui_audit.py` and `tools/ui_browser_check.py`, its screenshots in `docs/screens/`, and every mention in README
  and docs. Keep tokens, brand macros and the sidebar logo. Delete only tests that exist solely to assert `/ui-kit`
  (list them by name before deleting; show the diff); keep every other assertion. Acceptance: `GET /ui-kit` returns 404;
  `grep -rniE "ui-kit|ui_kit|UI Kit" --include=* .` outside `.git` finds nothing except this section; add a browser
  check that the sidebar logo and wordmark have a contrast ratio >= 3:1 against the sidebar background in all 3
  themes (computed styles); Rewind 228; sentinel passed; both tools EXIT=0.

- [ ] **R2 Repo hygiene.** Nothing from the Playwright library workaround is tracked (`.so`, `.deb`, `ms-playwright`,
  extracted libs); `.gitignore` covers `brand_src/`, extracted libs, `*.db`, `*.log`, `sentinel.yaml` secrets,
  `.safety_*`, `ssh_keys/`, `web_root/`; no font files in git; secret scan of the working tree AND history
  (`ghp_`, `github_pat_`, `PRIVATE KEY`, `AKIA`); `.git` size sane. Print results.

- [ ] **R3 Alert detail page = the core FIM workflow.** Header (severity chip, status chip, mono path with copy), meta
  (host, process/pid or "unknown", signals as chips with tooltips, first/last seen, count), metadata table old vs new
  (sha256 short, size, mode, uid/gid, mtime, entropy) with changed values highlighted, diff viewer (line numbers,
  unified/split toggle, +/- colours from tokens, word-level highlight, "truncated" notice, copy button), timeline of
  the alert (detected, signals, approved/rejected with actor and time). Actions: Approve and Reject, each with a
  confirmation dialog and an optional note; approve updates the baseline and shows "baseline updated"; reject keeps the
  drift flagged and, for protect-mode paths, shows the revert result. Toast on success/failure; keyboard `a`/`r` with the
  same confirmation. Playwright checks: approve flow and reject flow on seeded alerts, diff view toggle, copy. API tests
  for approve/reject including a repeat-alert check (approved state does not re-alert).
  **Fix "Bulk Acknowledge":** relabel it to what it does, with a confirmation that states the count and the resulting
  status; it must never silently mark alerts REJECTED.

- [ ] **R4 Live table behavior.** Keyed row updates (never `replaceChildren` on poll); selection kept as a Set of ids;
  focus and scroll preserved across polls; new-row highlight (~200 ms, no layout jump); shift-click range select;
  `j/k` move, `x` select, `a/r` act on the selection with confirmation; bulk bar appears when something is selected;
  filters reflected in the URL query; loading, empty and error states (empty state text max 8 words). Playwright check:
  select 3 rows, wait for 3 polls, selection/focus/scroll unchanged.

- [ ] **R5 Acceptance matrix F1-F12 (Sentinel).** Map each row of `docs/SENTINEL_SCOPE.md` to an automated test
  (`file::function`); write missing tests; any row without a real test is "NOT TESTED" (never green). F1 key appended to
  `authorized_keys` -> CRITICAL with diff; F2 edit then approve -> baseline updated, no repeat alert; F3 edit then reject
  -> stays flagged (protect mode reverts); F4 delete -> alert; F5 chmod/chown -> HIGH; F6 new file -> INFO per policy;
  F7 25+ files in 5 s -> HIGH (SPEED); F8 decoy tampered -> CRITICAL; F9 ransomware simulator vs protect path ->
  stopped and restored 100/100; F10 legitimate zip/tar -> no alarm beyond INFO new-file; F11 agent offline then back ->
  buffered events delivered once; F12 webhook delivered and retried. Fill `docs/sentinel_acceptance_matrix.md` from JUnit
  XML exactly like `docs/acceptance_matrix.md`.

- [ ] **R6 Evaluation.** Extend `evaluation/run_eval.py` (or add `run_eval_sentinel.py`) to run the F-scenarios 5 times
  each (separate processes, median and worst runtime, include the harmless scenarios so false positives are measured);
  save `evaluation/results.md` and `results.json`. Optional: overhead benchmark (CPU % and RSS of the engine for 2
  minutes of normal writes).

- [ ] **R7 Documentation.** Root `README.md` for both projects (what they are, how Sentinel builds on Rewind, architecture
  diagram in Mermaid or ASCII, quick start, the exact commands from section 2, monitor vs protect, config reference,
  4 screenshots from `docs/screens/`, tests and evaluation table, limitations, roadmap). `docs/ARCHITECTURE.md`.
  `docs/COMPARISON.md`: Sentinel vs AIDE, Tripwire and Wazuh FIM, stating only well-known general capabilities, with an
  honest "what they do better" column (maturity, scale, compliance reporting, ecosystems) and "what Sentinel adds"
  (behavioral layer, process attribution, optional auto-recovery, approval UI). `DEMO_SCRIPT.md` (Sentinel 3-5 min and
  Rewind 2 min, exact commands and what to see at each step, pre-demo checklist: seed, browser zoom 100%, theme,
  fallback). `docs/VIVA_QA.md` (the 20 most likely examiner questions with short honest answers, including threat model
  and limits). `THIRD_PARTY.md` (Tailwind MIT, Inter and JetBrains Mono OFL, icon licence, wordmark note).

- [ ] **R8 Polish (only after R0-R7).** Theme switch via a scoped ~400 ms transition or View Transitions (feature-detected,
  never a global `*` transition); keyboard cheat sheet on `?`; skeleton states; collapsed rail keeps the logo mark;
  chart tooltip; round Integrity Score badge if it is small. Each with a browser check.

- [ ] **R9 Release.** Both suites and both tools green (literal lines), `git status` clean, tag `sentinel-v1` locally,
  print `git log --oneline | head -20`, write the final report. NEVER push: the owner pushes
  (`git push origin sentinel --tags`) after reading the secret-scan output.

STOP points (otherwise work autonomously): STOP A after R3 (the owner checks the alert detail page by eye and by
recording); STOP B after R7 (documentation review); final report after R9. Stop and ask at any time if blocked, if this
file contradicts the code, or if a decision is needed.

## 8. Report format (every item)

Done / Literal outputs (pytest last lines + EXIT, audit, browser check) / NOT VERIFIED / Diffs to non-Sentinel files /
Next. Maximum 250 words plus the outputs.

## 9. Open decisions and discrepancies

Owner decisions: whether to merge `sentinel` into `main` (suggest a pull request after R9); confirm the old GitHub token
was revoked; wordmark licence is personal-use only; sidebar stays theme-following; the logo is the original mark in
`static/brand/logo.svg`.

Discrepancies found between this file and the code: (add lines here)

## 10. Where things are

`docs/SENTINEL_SCOPE.md` (locked scope, F1-F12), `docs/acceptance_matrix.md` (Rewind), `docs/screens/` (Playwright
screenshots), `brand/FONT_NOTICE.md`, `static/vendor/VERSIONS.md`, `PROGRESS.md` (running log), `DEMO_SCRIPT.md`,
`README.md`, `evaluation/`.
