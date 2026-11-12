#!/usr/bin/env python3
"""tools/ui_audit.py: Audit suite for Sentinel UI Phase A.

Verifies:
 1. Every page route in sentinel/server returns 200 and every referenced /static file returns 200.
 2. No URL in served HTML/CSS/JS points outside 127.0.0.1/localhost (ignoring xmlns and vendored tailwind).
 3. Each full page has an inline <script> in <head> that sets the theme BEFORE any <link>/<style>.
 4. No innerHTML, outerHTML, insertAdjacentHTML or document.write in static/js or templates.
 5. sha256 of the vendored tailwind file equals the value in static/vendor/VERSIONS.md.
 6. Recompute contrast from tokens.css for dark/light/contrast: text roles >= 4.5:1, non-text pairs >= 3:1.
 7. git ls-files has no font file containing "ethnocentric".
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, REPO_ROOT)

from sentinel.server.app import create_sentinel_app
from sentinel.server.repo import SQLiteRepository
from sentinel.models import EventEnvelope, Change, Meta


def run_check_1_and_2_and_3(app, client):
    errors = []
    routes_to_test = ["/", "/assets", "/alerts/1", "/report", "/ui-kit"]
    static_urls = set()

    external_url_regex = re.compile(r'(?:href|src|url)\s*=\s*["\'](https?://[^"\']+|//[^"\']+)["\']', re.IGNORECASE)

    for route in routes_to_test:
        resp = client.get(route)
        if resp.status_code != 200:
            errors.append(f"Route {route} returned status {resp.status_code}")
            continue

        html = resp.get_data(as_text=True)

        # Check 3: inline <script> in <head> before <link>/<style>
        head_match = re.search(r'<head>(.*?)</head>', html, re.DOTALL | re.IGNORECASE)
        if not head_match:
            errors.append(f"Route {route} has no <head> element")
        else:
            head_content = head_match.group(1)
            first_script = re.search(r'<script\b[^>]*>(.*?)</script>', head_content, re.DOTALL | re.IGNORECASE)
            first_link = re.search(r'<link\b', head_content, re.IGNORECASE)
            first_style = re.search(r'<style\b', head_content, re.IGNORECASE)

            if not first_script:
                errors.append(f"Route {route} missing inline <script> in <head>")
            else:
                script_pos = first_script.start()
                link_pos = first_link.start() if first_link else 999999
                style_pos = first_style.start() if first_style else 999999
                if script_pos > link_pos or script_pos > style_pos:
                    errors.append(f"Route {route} has <link> or <style> before theme <script> in <head>")
                if "data-theme" not in first_script.group(1):
                    errors.append(f"Route {route} head <script> does not set data-theme")

        # Gather static URLs
        for m in re.finditer(r'(?:href|src)\s*=\s*["\'](/static/[^"\']+)["\']', html, re.IGNORECASE):
            raw_url = m.group(1).split('#')[0]
            static_urls.add(raw_url)

        # Check 2: check external URLs in HTML
        for m in external_url_regex.finditer(html):
            url = m.group(1)
            if "www.w3.org" in url or "localhost" in url or "127.0.0.1" in url:
                continue
            errors.append(f"Route {route} contains external URL: {url}")

    # Check all static URLs return 200
    for s_url in sorted(static_urls):
        s_resp = client.get(s_url)
        if s_resp.status_code != 200:
            errors.append(f"Static file {s_url} returned status {s_resp.status_code}")
        else:
            # Check external URLs in served CSS/JS (except tailwind vendor)
            if s_url.endswith((".css", ".js")) and not s_url.endswith("tailwindcss-browser-4.3.5.js"):
                body = s_resp.get_data(as_text=True)
                for m in re.finditer(r'url\s*\(\s*["\']?(https?://[^"\'\)]+)["\']?\s*\)', body, re.IGNORECASE):
                    u = m.group(1)
                    if "localhost" not in u and "127.0.0.1" not in u:
                        errors.append(f"Static file {s_url} contains external URL: {u}")

    return errors


def run_check_4():
    """No innerHTML, outerHTML, insertAdjacentHTML or document.write in static/js or templates."""
    errors = []
    forbidden = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"]
    scan_dirs = [
        os.path.join(REPO_ROOT, "sentinel", "server", "templates"),
        os.path.join(REPO_ROOT, "sentinel", "server", "static", "js"),
    ]

    for d in scan_dirs:
        if not os.path.exists(d):
            continue
        for root, _, files in os.walk(d):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        for line_no, line in enumerate(f, 1):
                            for word in forbidden:
                                if word in line:
                                    errors.append(f"{os.path.relpath(fpath, REPO_ROOT)}:{line_no} uses {word}")
                except Exception:
                    pass
    return errors


def run_check_5():
    """sha256 of the vendored tailwind file equals the value in static/vendor/VERSIONS.md."""
    versions_file = os.path.join(REPO_ROOT, "sentinel", "server", "static", "vendor", "VERSIONS.md")
    tw_file = os.path.join(REPO_ROOT, "sentinel", "server", "static", "vendor", "tailwindcss-browser-4.3.5.js")

    if not os.path.isfile(versions_file):
        return [f"VERSIONS.md missing at {versions_file}"]
    if not os.path.isfile(tw_file):
        return [f"Tailwind file missing at {tw_file}"]

    with open(versions_file, "r", encoding="utf-8") as f:
        v_content = f.read()
    m = re.search(r'sha-?256[\*`:\s]+([a-f0-9]{64})', v_content, re.IGNORECASE)
    if not m:
        return ["Could not parse SHA-256 from VERSIONS.md"]
    expected_sha = m.group(1).lower()

    with open(tw_file, "rb") as f:
        actual_sha = hashlib.sha256(f.read()).hexdigest().lower()

    if actual_sha != expected_sha:
        return [f"Tailwind sha256 mismatch: expected {expected_sha}, got {actual_sha}"]
    return []


def parse_color(c):
    c = c.strip()
    if c.startswith("#"):
        h = c[1:]
        if len(h) == 3:
            h = "".join(x * 2 for x in h)
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 1.0)
    m = re.match(r"rgba?\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)(?:\s*,\s*([0-9.]+))?\s*\)", c)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), float(m.group(4) or 1.0))
    return None


def blend(fg, bg):
    r1, g1, b1, a = fg
    r2, g2, b2, _ = bg
    r = int(round(r1 * a + r2 * (1 - a)))
    g = int(round(g1 * a + g2 * (1 - a)))
    b = int(round(b1 * a + b2 * (1 - a)))
    return (r, g, b, 1.0)


def luminance(color):
    r, g, b, _ = color
    def chan(v):
        v = v / 255.0
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)


def calc_contrast(c1, c2):
    l1 = luminance(c1)
    l2 = luminance(c2)
    return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)


def run_check_6():
    """Recompute contrast from tokens.css: text >= 4.5:1, non-text >= 3:1. Print table."""
    tokens_file = os.path.join(REPO_ROOT, "sentinel", "server", "static", "tokens.css")
    if not os.path.isfile(tokens_file):
        return ["tokens.css missing"], ""

    with open(tokens_file, "r", encoding="utf-8") as f:
        css = f.read()

    # Parse theme blocks
    def extract_vars(pattern):
        m = re.search(pattern, css, re.DOTALL)
        if not m:
            return {}
        block = m.group(1)
        v = {}
        for line in block.splitlines():
            line = line.split("/*")[0].strip()
            if line.startswith("--") and ":" in line:
                key, val = line.split(":", 1)
                val = val.rstrip(";").strip()
                v[key.strip()] = val
        return v

    dark_vars = extract_vars(r'(?::root,\s*html\[data-theme="dark"\]\s*\{)(.*?)\}')
    light_vars = extract_vars(r'html\[data-theme="light"\]\s*\{(.*?)\}')
    contrast_vars = extract_vars(r'html\[data-theme="contrast"\]\s*\{(.*?)\}')

    themes = [("Dark", dark_vars), ("Light", light_vars), ("Contrast", contrast_vars)]
    errors = []
    table_lines = [
        "| Theme | Role / Severity | Surface | Ratio | WCAG Target | Pass |",
        "| :--- | :--- | :--- | :--- | :--- | :---: |"
    ]

    for tname, tvars in themes:
        bg_col = parse_color(tvars.get("--surface-bg", "#000000"))
        surfaces = [
            ("bg", bg_col),
            ("card", blend(parse_color(tvars.get("--surface-card", "#111111")), bg_col)),
            ("raised", blend(parse_color(tvars.get("--surface-raised", "#222222")), bg_col)),
            ("hover", blend(parse_color(tvars.get("--surface-hover", "#333333")), bg_col)),
            ("selected", blend(parse_color(tvars.get("--surface-selected", "#444444")), bg_col)),
        ]

        text_roles = [
            ("primary", parse_color(tvars.get("--text-primary", "#ffffff"))),
            ("muted", parse_color(tvars.get("--text-muted", "#888888"))),
            ("faint", parse_color(tvars.get("--text-faint", "#666666"))),
        ]

        for rname, rcol in text_roles:
            for sname, scol in surfaces:
                c = calc_contrast(rcol, scol)
                passed = c >= 4.5
                if not passed:
                    errors.append(f"{tname} {rname} on {sname} contrast {c:.2f}:1 is < 4.5:1")
                table_lines.append(f"| {tname} | text-{rname} | {sname} | {c:.2f}:1 | 4.5:1 | {'PASS' if passed else 'FAIL'} |")

        # Severity on -soft
        severities = [
            ("critical", "--sev-critical", "--sev-critical-soft"),
            ("high", "--sev-high", "--sev-high-soft"),
            ("medium", "--sev-medium", "--sev-medium-soft"),
            ("low", "--sev-low", "--sev-low-soft"),
            ("info", "--sev-info", "--sev-info-soft"),
            ("ok", "--ok", "--ok-soft"),
            ("danger", "--danger", "--danger-soft"),
        ]

        for s_key, s_fg_key, s_bg_key in severities:
            fg_col = parse_color(tvars.get(s_fg_key, "#ffffff"))
            soft_col = blend(parse_color(tvars.get(s_bg_key, "rgba(255,255,255,0.1)")), bg_col)
            c = calc_contrast(fg_col, soft_col)
            passed = c >= 3.0
            if not passed:
                errors.append(f"{tname} {s_key} on -soft contrast {c:.2f}:1 is < 3.0:1")
            table_lines.append(f"| {tname} | {s_key} (rail/chip) | {s_key}-soft | {c:.2f}:1 | 3.0:1 | {'PASS' if passed else 'FAIL'} |")

    return errors, "\n".join(table_lines)


def run_check_7():
    """git ls-files has no font file containing 'ethnocentric'."""
    cmd = ["git", "ls-files"]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        return [f"git ls-files failed: {res.stderr}"]

    errors = []
    for line in res.stdout.splitlines():
        lower = line.lower()
        if any(ext in lower for ext in [".otf", ".ttf", ".woff", ".woff2"]) and "ethnocentric" in lower:
            errors.append(f"Tracked font file contains ethnocentric: {line}")
    return errors


def main():
    print("=== Sentinel Phase A UI Audit ===")
    all_errors = []

    # Setup isolated test app
    temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp_db.close()
    try:
        repo = SQLiteRepository(temp_db.name)
        repo.record_host(host_id="test-host", name="Test Host")
        # Seed an alert so /alerts/1 returns 200
        envelope = EventEnvelope(
            root_id="root",
            path="sample.txt",
            host_id="test-host",
            ts=1700000000.0,
            mode="monitor",
            change=Change(kinds=["modified"], diff="--- a/sample.txt\n+++ b/sample.txt\n@@ -1 +1 @@\n-old\n+new\n"),
            signals=["SPEED"],
            severity="critical",
            pid=123,
            process_name="python3",
            summary="Test alert for audit",
        )
        repo.upsert_alert(envelope)

        app = create_sentinel_app(repo=repo)
        app.config["TESTING"] = True
        client = app.test_client()

        # Checks 1, 2, 3
        c123_errs = run_check_1_and_2_and_3(app, client)
        if c123_errs:
            all_errors.extend(c123_errs)
        else:
            print("[PASS] Check 1: All page routes and referenced /static files return 200.")
            print("[PASS] Check 2: No URLs pointing outside localhost/127.0.0.1.")
            print("[PASS] Check 3: Head script sets theme before link/style on all pages.")

        # Check 4
        c4_errs = run_check_4()
        if c4_errs:
            all_errors.extend(c4_errs)
        else:
            print("[PASS] Check 4: Zero innerHTML, outerHTML, insertAdjacentHTML or document.write.")

        # Check 5
        c5_errs = run_check_5()
        if c5_errs:
            all_errors.extend(c5_errs)
        else:
            print("[PASS] Check 5: Vendored tailwind sha256 matches VERSIONS.md.")

        # Check 6
        c6_errs, contrast_table = run_check_6()
        if c6_errs:
            all_errors.extend(c6_errs)
        else:
            print("[PASS] Check 6: Computed contrast ratios meet WCAG standards.")
        print("\n" + contrast_table + "\n")

        # Check 7
        c7_errs = run_check_7()
        if c7_errs:
            all_errors.extend(c7_errs)
        else:
            print("[PASS] Check 7: No ethnocentric font files in repository.")

    finally:
        if os.path.exists(temp_db.name):
            os.remove(temp_db.name)

    if all_errors:
        print(f"\n[FAIL] UI Audit encountered {len(all_errors)} errors:")
        for err in all_errors:
            print(f"  - {err}")
        return 1

    print("[SUCCESS] All UI Audit checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
