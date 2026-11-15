#!/usr/bin/env python3
"""tools/ui_browser_check.py: Headless Chromium real-browser interaction & layout verification.

Runs against temporary seeded SQLite database using Playwright at:
  - 1366x768 (standard laptop)
  - 1914x962 (high-res demo window)
Tests Alerts, Assets, UI Kit, and Report across Dark, Light, and Contrast themes.

Verifies:
  (a) Zero console errors or pageerrors.
  (b) Saves screenshots to docs/screens/.
  (c) Runs full interaction script:
      - Click Light, Dark, Contrast -> assert html[data-theme] updates.
      - Collapse / expand sidebar twice -> assert width changes.
      - Open / close palette via click, Ctrl+K, and "/" -> assert state and overlay clearing.
      - Open host, severity, status, row "..." popovers -> assert bounding box within 8px and inside viewport.
      - Trigger toast -> assert dismissal from DOM within 4s.
      - After EVERY step assert document.elementFromPoint at controls returns control itself (no invisible overlay).
  (d) Prints table of checks and exits 1 on any failure.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, REPO_ROOT)

# Ensure local runtime libraries are discoverable by Chromium subprocesses
libs_dir = os.path.join(REPO_ROOT, ".libs")
if os.path.isdir(libs_dir):
    extra_paths = []
    for root, dirs, files in os.walk(libs_dir):
        if any(f.endswith(".so") or ".so." in f for f in files):
            extra_paths.append(root)
    if extra_paths:
        cur_ld = os.environ.get("LD_LIBRARY_PATH", "")
        os.environ["LD_LIBRARY_PATH"] = ":".join(extra_paths) + (f":{cur_ld}" if cur_ld else "")

from werkzeug.serving import make_server
from playwright.sync_api import sync_playwright

from sentinel.server.app import create_sentinel_app
from sentinel.server.repo import SQLiteRepository
from tools.seed_demo import seed

VIEWPORTS = [
    {"width": 1366, "height": 768, "label": "1366x768"},
    {"width": 1914, "height": 962, "label": "1914x962"},
]

THEMES = ["dark", "light", "contrast"]

PAGES = [
    {"name": "Alerts", "path": "/"},
    {"name": "Assets", "path": "/assets"},
    {"name": "UI_Kit", "path": "/ui-kit"},
    {"name": "Report", "path": "/report"},
]


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BrowserChecker:
    def __init__(self, base_url: str, screen_dir: str):
        self.base_url = base_url
        self.screen_dir = screen_dir
        os.makedirs(self.screen_dir, exist_ok=True)
        self.results: List[Dict[str, Any]] = []

    def log_check(self, name: str, passed: bool, detail: str = ""):
        self.results.append({"name": name, "passed": passed, "detail": detail})
        status = "PASS" if passed else "FAIL"
        print(f"[{status:<4}] {name}" + (f" - {detail}" if detail else ""))

    def check_overlay(self, page, context_name: str) -> bool:
        """Assert document.elementFromPoint at control centres returns the control itself."""
        script = """
        (function() {
            const selectors = [
                '#theme-btn-dark',
                '#theme-btn-light',
                '#theme-btn-contrast',
                '.sidebar-toggle-btn',
                '#cmd-k-trigger'
            ];
            const issues = [];
            for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (!el) continue;
                // If element is hidden or collapsed away, skip
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) continue;
                const cx = Math.floor(rect.left + rect.width / 2);
                const cy = Math.floor(rect.top + rect.height / 2);
                if (cx < 0 || cy < 0 || cx >= window.innerWidth || cy >= window.innerHeight) continue;

                const topEl = document.elementFromPoint(cx, cy);
                if (!topEl) {
                    issues.push(sel + ' has no element at (' + cx + ',' + cy + ')');
                    continue;
                }
                if (el !== topEl && !el.contains(topEl) && !topEl.contains(el)) {
                    const desc = topEl.tagName + (topEl.id ? '#' + topEl.id : '') + (topEl.className ? '.' + String(topEl.className).replace(/\\s+/g, '.') : '');
                    issues.push(sel + ' blocked by ' + desc + ' at (' + cx + ',' + cy + ')');
                }
            }
            return issues;
        })()
        """
        try:
            issues = page.evaluate(script)
            if issues:
                self.log_check(f"Overlay check ({context_name})", False, "; ".join(issues))
                return False
            return True
        except Exception as e:
            self.log_check(f"Overlay check exception ({context_name})", False, str(e))
            return False

    def test_popover_position(self, page, trigger_sel: str, popover_sel: str, name: str) -> Tuple[bool, str]:
        """Click trigger, check popover bounding box is within 8px of trigger bottom-left and inside viewport."""
        try:
            trigger = page.query_selector(trigger_sel)
            if not trigger:
                return False, f"Trigger '{trigger_sel}' not found"

            trigger.click()
            page.wait_for_timeout(100)

            popover = page.query_selector(popover_sel)
            if not popover:
                return False, f"Popover '{popover_sel}' not found"

            # Check visibility
            is_visible = page.evaluate(f"""
                (function() {{
                    const el = document.querySelector('{popover_sel}');
                    if (!el) return false;
                    try {{
                        if (el.matches(':popover-open')) return true;
                    }} catch(e) {{}}
                    const style = window.getComputedStyle(el);
                    return style.display !== 'none' && style.visibility !== 'hidden';
                }})()
            """)

            if not is_visible:
                return False, f"Popover '{popover_sel}' not open/visible after trigger click"

            metrics = page.evaluate(f"""
                (function() {{
                    const tr = document.querySelector('{trigger_sel}').getBoundingClientRect();
                    const po = document.querySelector('{popover_sel}').getBoundingClientRect();
                    return {{
                        trigger: {{ left: tr.left, right: tr.right, top: tr.top, bottom: tr.bottom, width: tr.width, height: tr.height }},
                        popover: {{ left: po.left, right: po.right, top: po.top, bottom: po.bottom, width: po.width, height: po.height }},
                        viewport: {{ width: window.innerWidth, height: window.innerHeight }}
                    }};
                }})()
            """)

            t = metrics["trigger"]
            p = metrics["popover"]
            vp = metrics["viewport"]

            # Inside viewport check
            in_viewport = (p["left"] >= 0 and p["top"] >= 0 and p["right"] <= vp["width"] + 1 and p["bottom"] <= vp["height"] + 1)

            # Alignment check:
            # Normal: popover top is near trigger bottom (within 8px); left near trigger left (or right-aligned if clamped)
            dx = abs(p["left"] - t["left"])
            dy_down = abs(p["top"] - t["bottom"])
            dy_up = abs(p["bottom"] - t["top"])  # flipped above

            # Is it flipped above or below?
            is_near_y = (dy_down <= 8) or (dy_up <= 8)

            # Horizontal alignment: left aligned within 8px OR right aligned within 8px
            dx_right_aligned = abs(p["right"] - t["right"])
            is_near_x = (dx <= 8) or (dx_right_aligned <= 8)

            detail = (
                f"trigger=({t['left']:.1f}, {t['bottom']:.1f}), "
                f"popover=({p['left']:.1f}, {p['top']:.1f}), "
                f"dx={dx:.1f}px, dy_down={dy_down:.1f}px, dy_up={dy_up:.1f}px, in_vp={in_viewport}"
            )

            # Close popover
            page.keyboard.press("Escape")
            page.wait_for_timeout(50)

            passed = is_near_y and is_near_x and in_viewport
            return passed, detail
        except Exception as e:
            return False, f"Exception: {e}"

    def run(self) -> int:
        print("\n=== Sentinel Real-Browser Headless Chromium Verification ===")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            for vp in VIEWPORTS:
                print(f"\n--- Viewport: {vp['label']} ---")
                context = browser.new_context(viewport={"width": vp["width"], "height": vp["height"]})

                for page_info in PAGES:
                    page_name = page_info["name"]
                    page_path = page_info["path"]
                    url = f"{self.base_url}{page_path}"

                    for theme in THEMES:
                        context_id = f"{page_name}_{theme}_{vp['label']}"
                        page = context.new_page()

                        console_errors: List[str] = []
                        page.on("console", lambda msg: console_errors.append(f"CONSOLE {msg.type}: {msg.text}") if msg.type in ("error",) else None)
                        page.on("pageerror", lambda err: console_errors.append(f"PAGEERROR: {err}"))

                        # Navigate
                        page.goto(url, wait_until="networkidle")

                        # Check (a): Console errors immediately
                        if console_errors:
                            self.log_check(f"Console errors ({context_id})", False, "; ".join(console_errors))
                        else:
                            self.log_check(f"Console errors ({context_id})", True, "Zero console/page errors")

                        # Set theme
                        page.evaluate(f"""
                            (function() {{
                                if (typeof setSentinelTheme === 'function') {{
                                    setSentinelTheme('{theme}');
                                }} else {{
                                    document.documentElement.setAttribute('data-theme', '{theme}');
                                    document.documentElement.className = '{theme}';
                                }}
                            }})()
                        """)

                        # Check (b): Screenshot
                        screen_path = os.path.join(self.screen_dir, f"{context_id}.png")
                        page.screenshot(path=screen_path)
                        self.log_check(f"Screenshot ({context_id})", True, f"Saved {screen_path}")

                        # Initial overlay check
                        self.check_overlay(page, f"init_{context_id}")

                        # Run Interaction script on Alerts page
                        if page_name == "Alerts":
                            # 1. Theme switching interaction
                            page.click("#theme-btn-light")
                            t_light = page.evaluate("document.documentElement.getAttribute('data-theme')")
                            self.log_check(f"Theme switch Light ({context_id})", t_light == "light", f"theme={t_light}")
                            self.check_overlay(page, f"after_light_{context_id}")

                            page.click("#theme-btn-dark")
                            t_dark = page.evaluate("document.documentElement.getAttribute('data-theme')")
                            self.log_check(f"Theme switch Dark ({context_id})", t_dark == "dark", f"theme={t_dark}")
                            self.check_overlay(page, f"after_dark_{context_id}")

                            page.click("#theme-btn-contrast")
                            t_contrast = page.evaluate("document.documentElement.getAttribute('data-theme')")
                            self.log_check(f"Theme switch Contrast ({context_id})", t_contrast == "contrast", f"theme={t_contrast}")
                            self.check_overlay(page, f"after_contrast_{context_id}")

                            # Return to target theme
                            page.evaluate(f"""
                                (function() {{
                                    if (typeof setSentinelTheme === 'function') {{
                                        setSentinelTheme('{theme}');
                                    }} else {{
                                        document.documentElement.setAttribute('data-theme', '{theme}');
                                        document.documentElement.className = '{theme}';
                                    }}
                                }})()
                            """)

                            # 2. Sidebar collapse & expand twice
                            sb = page.query_selector("#app-sidebar")
                            toggle = page.query_selector(".sidebar-toggle-btn")
                            if sb and toggle:
                                w_init = sb.bounding_box()["width"]
                                toggle.click()
                                page.wait_for_timeout(100)
                                w_col1 = sb.bounding_box()["width"]
                                self.check_overlay(page, f"sb_col1_{context_id}")

                                toggle.click()
                                page.wait_for_timeout(100)
                                w_exp1 = sb.bounding_box()["width"]
                                self.check_overlay(page, f"sb_exp1_{context_id}")

                                toggle.click()
                                page.wait_for_timeout(100)
                                w_col2 = sb.bounding_box()["width"]
                                self.check_overlay(page, f"sb_col2_{context_id}")

                                toggle.click()
                                page.wait_for_timeout(100)
                                w_exp2 = sb.bounding_box()["width"]
                                self.check_overlay(page, f"sb_exp2_{context_id}")

                                sb_ok = (w_col1 <= 70 and w_col2 <= 70 and w_exp1 > 150 and w_exp2 > 150)
                                self.log_check(f"Sidebar collapse/expand twice ({context_id})", sb_ok, f"w_col={w_col1:.0f}, w_exp={w_exp1:.0f}")

                            # 3. Palette open / close via click, Ctrl+K, and "/"
                            # Click
                            page.click("#cmd-k-trigger")
                            page.wait_for_timeout(50)
                            p_open_click = page.evaluate("document.getElementById('cmd-palette-dialog').open")
                            page.keyboard.press("Escape")
                            page.wait_for_timeout(50)
                            p_closed_click = not page.evaluate("document.getElementById('cmd-palette-dialog').open")
                            self.check_overlay(page, f"palette_after_click_esc_{context_id}")

                            # Ctrl+K
                            page.keyboard.press("Control+k")
                            page.wait_for_timeout(50)
                            p_open_ctrlk = page.evaluate("document.getElementById('cmd-palette-dialog').open")
                            page.keyboard.press("Escape")
                            page.wait_for_timeout(50)
                            p_closed_ctrlk = not page.evaluate("document.getElementById('cmd-palette-dialog').open")
                            self.check_overlay(page, f"palette_after_ctrlk_esc_{context_id}")

                            # "/"
                            page.keyboard.press("/")
                            page.wait_for_timeout(50)
                            p_open_slash = page.evaluate("document.getElementById('cmd-palette-dialog').open")
                            page.keyboard.press("Escape")
                            page.wait_for_timeout(50)
                            p_closed_slash = not page.evaluate("document.getElementById('cmd-palette-dialog').open")
                            self.check_overlay(page, f"palette_after_slash_esc_{context_id}")

                            pal_ok = (p_open_click and p_closed_click and p_open_ctrlk and p_closed_ctrlk and p_open_slash and p_closed_slash)
                            self.log_check(f"Command palette open/close triggers ({context_id})", pal_ok, "click, Ctrl+K, / tested")

                            # 4. Popovers positioning checks (PRIORITY ONE)
                            # Host selector popover
                            ok_host, det_host = self.test_popover_position(page, "#host-selector-btn", "#host-popover", "Host Selector")
                            self.log_check(f"Popover: Host selector ({context_id})", ok_host, det_host)
                            self.check_overlay(page, f"after_host_pop_{context_id}")

                            # Severity filter popover
                            ok_sev, det_sev = self.test_popover_position(page, "#filter-sev-btn", "#filter-sev-popover", "Severity Filter")
                            self.log_check(f"Popover: Severity filter ({context_id})", ok_sev, det_sev)
                            self.check_overlay(page, f"after_sev_pop_{context_id}")

                            # Status filter popover
                            ok_st, det_st = self.test_popover_position(page, "#filter-status-btn", "#filter-status-popover", "Status Filter")
                            self.log_check(f"Popover: Status filter ({context_id})", ok_st, det_st)
                            self.check_overlay(page, f"after_status_pop_{context_id}")

                            # Row "..." more menu popover
                            row_btn = page.query_selector(".row-more-btn")
                            if row_btn:
                                row_pop_id = row_btn.get_attribute("popovertarget")
                                ok_row, det_row = self.test_popover_position(page, ".row-more-btn", f"#{row_pop_id}", "Row More Menu")
                                self.log_check(f"Popover: Row more menu ({context_id})", ok_row, det_row)
                                self.check_overlay(page, f"after_row_pop_{context_id}")

                            # 5. Toast system: trigger and verify leaves DOM within 4s
                            page.evaluate("showToast('info', 'Real-browser automated test toast', 2000)")
                            toast_present = page.query_selector(".toast") is not None
                            self.log_check(f"Toast appears ({context_id})", toast_present)
                            page.wait_for_timeout(3000)
                            toast_left = page.query_selector(".toast") is None
                            self.log_check(f"Toast leaves DOM <= 4s ({context_id})", toast_left)
                            self.check_overlay(page, f"after_toast_{context_id}")

                        elif page_name == "Assets":
                            # Host selector popover on Assets page
                            ok_host, det_host = self.test_popover_position(page, "#host-selector-btn", "#host-popover", "Host Selector (Assets)")
                            self.log_check(f"Popover: Host selector ({context_id})", ok_host, det_host)
                            self.check_overlay(page, f"after_host_pop_{context_id}")

                        page.close()
                context.close()
            browser.close()

        # Summary
        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])
        failed = total - passed

        print("\n=== Browser Check Summary ===")
        print(f"Total checks: {total} | Passed: {passed} | Failed: {failed}")

        return 0 if failed == 0 else 1


def main():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    server = None
    try:
        # 1. Seed temp DB
        seed(db_path, reset=True)
        repo = SQLiteRepository(db_path)
        app = create_sentinel_app(repo)
        app.config["TESTING"] = False  # Real runtime mode

        port = find_free_port()
        server = make_server("127.0.0.1", port, app)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        time.sleep(0.5)

        base_url = f"http://127.0.0.1:{port}"
        screen_dir = os.path.join(REPO_ROOT, "docs", "screens")

        checker = BrowserChecker(base_url, screen_dir)
        exit_code = checker.run()
        return exit_code

    finally:
        if server:
            server.shutdown()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
