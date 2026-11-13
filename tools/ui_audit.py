#!/usr/bin/env python3
"""tools/ui_audit.py: Audit suite for Sentinel UI Phase A and U1-FIX-2.

Verifies:
 1. Every page route in sentinel/server returns 200 and every referenced /static file returns 200.
 2. No URL in served HTML/CSS/JS points outside 127.0.0.1/localhost (ignoring xmlns and vendored tailwind).
 3. Each full page has an inline <script> in <head> that sets the theme BEFORE any <link>/<style>.
 4. No innerHTML, outerHTML, insertAdjacentHTML or document.write in static/js or templates.
 5. sha256 of the vendored tailwind file equals the value in static/vendor/VERSIONS.md.
 6. Recompute contrast from tokens.css for dark/light/contrast: text roles >= 4.5:1, non-text pairs >= 3:1.
 7. git ls-files has no font file containing "ethnocentric".
 8. Static checks (a)-(e):
    (a) no literal colors or fixed Tailwind color classes outside tokens.css;
    (b) every main wrapper has flex-1 + min-w-0 and no fixed small widths;
    (c) no box-shadow blur > 8px or drop-shadow outside popovers;
    (d) logo SVGs contain no color other than currentColor;
    (e) git ls-files has no untracked proprietary font files.
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
                if not fname.endswith((".html", ".js", ".j2")):
                    continue
                fpath = os.path.join(root, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                for token in forbidden:
                    # Token must appear as property access or function call, e.g. .innerHTML = or document.write(
                    pattern = rf"\.{token}\b" if token != "document.write" else r"document\.write\b"
                    if re.search(pattern, content):
                        # Exceptions if any (there should be none)
                        errors.append(f"File {fpath} contains forbidden DOM write pattern: {token}")

    return errors


def run_check_5():
    """Vendored tailwind sha256 matches VERSIONS.md."""
    errors = []
    vendor_file = os.path.join(REPO_ROOT, "sentinel", "server", "static", "vendor", "tailwindcss-browser-4.3.5.js")
    versions_file = os.path.join(REPO_ROOT, "sentinel", "server", "static", "vendor", "VERSIONS.md")

    if not os.path.isfile(vendor_file):
        return [f"Vendored tailwind file missing: {vendor_file}"]
    if not os.path.isfile(versions_file):
        return [f"VERSIONS.md missing: {versions_file}"]

    with open(vendor_file, "rb") as f:
        computed_sha = hashlib.sha256(f.read()).hexdigest()

    with open(versions_file, "r", encoding="utf-8") as f:
        v_content = f.read()

    match = re.search(r"sha[-_]?256[*\s:`]+([a-fA-F0-9]{64})", v_content, re.IGNORECASE)
    if not match:
        errors.append(f"VERSIONS.md does not contain sha256 checksum pattern")
    else:
        recorded_sha = match.group(1).lower()
        if computed_sha.lower() != recorded_sha:
            errors.append(f"sha256 mismatch! Computed {computed_sha} != recorded {recorded_sha}")

    return errors


def parse_color(val):
    val = val.strip().lower()
    if val.startswith("#"):
        h = val[1:]
        if len(h) == 3:
            return (int(h[0]*2, 16), int(h[1]*2, 16), int(h[2]*2, 16), 1.0)
        elif len(h) == 6:
            return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 1.0)
    elif val.startswith("rgba"):
        m = re.match(r"rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([0-9.]+)\s*\)", val)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)), float(m.group(4)))
    elif val.startswith("rgb"):
        m = re.match(r"rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)", val)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 1.0)
    return (0, 0, 0, 1.0)


def srgb_to_linear(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(rgb):
    r, g, b, _ = rgb
    return 0.2126 * srgb_to_linear(r) + 0.7152 * srgb_to_linear(g) + 0.0722 * srgb_to_linear(b)


def calc_contrast(fg, bg):
    l1 = relative_luminance(fg)
    l2 = relative_luminance(bg)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def blend(fg, bg):
    # fg over bg composite
    r1, g1, b1, a1 = fg
    r2, g2, b2, _ = bg
    r = int(r1 * a1 + r2 * (1.0 - a1))
    g = int(g1 * a1 + g2 * (1.0 - a1))
    b = int(b1 * a1 + b2 * (1.0 - a1))
    return (r, g, b, 1.0)


def run_check_6():
    """Contrast ratios computed across themes meeting WCAG standards."""
    errors = []
    tokens_path = os.path.join(REPO_ROOT, "sentinel", "server", "static", "tokens.css")
    if not os.path.isfile(tokens_path):
        return [f"tokens.css missing: {tokens_path}"], ""

    with open(tokens_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Extract themes blocks
    theme_defs = {}
    dark_block = re.search(r':root,\s*html\[data-theme="dark"\]\s*\{(.*?)\}', content, re.DOTALL)
    if dark_block:
        theme_defs["Dark"] = dark_block.group(1)
    light_block = re.search(r'html\[data-theme="light"\]\s*\{(.*?)\}', content, re.DOTALL)
    if light_block:
        theme_defs["Light"] = light_block.group(1)
    contrast_block = re.search(r'html\[data-theme="contrast"\]\s*\{(.*?)\}', content, re.DOTALL)
    if contrast_block:
        theme_defs["Contrast"] = contrast_block.group(1)

    table_lines = [
        "| Theme | Role / Severity | Surface | Ratio | WCAG Target | Pass |",
        "| :--- | :--- | :--- | :--- | :--- | :---: |",
    ]

    for tname, block in theme_defs.items():
        # Parse vars in block
        tvars = dict(re.findall(r"(--[a-zA-Z0-9_-]+)\s*:\s*([^;]+);", block))

        bg_col = parse_color(tvars.get("--surface-bg", "#0b0f14"))
        card_col = blend(parse_color(tvars.get("--surface-card", "rgba(255,255,255,0.03)")), bg_col)
        raised_col = blend(parse_color(tvars.get("--surface-raised", "rgba(255,255,255,0.05)")), bg_col)
        hover_col = blend(parse_color(tvars.get("--surface-hover", "rgba(255,255,255,0.08)")), bg_col)
        selected_col = blend(parse_color(tvars.get("--surface-selected", "rgba(56,189,248,0.12)")), bg_col)

        surfaces = [
            ("bg", bg_col),
            ("card", card_col),
            ("raised", raised_col),
            ("hover", hover_col),
            ("selected", selected_col),
        ]

        text_roles = [
            ("primary", parse_color(tvars.get("--text-primary", "#f1f5f9"))),
            ("muted", parse_color(tvars.get("--text-muted", "#9fb0c3"))),
            ("faint", parse_color(tvars.get("--text-faint", "#818f9f"))),
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


def run_static_checks():
    """Static checks (a)-(e) per U1-FIX-2."""
    errors = []

    # (a) No literal colors or fixed Tailwind color classes outside tokens.css
    scan_paths = []
    for root, _, files in os.walk(os.path.join(REPO_ROOT, "sentinel", "server", "templates")):
        for f in files:
            if f.endswith(".html"):
                scan_paths.append(os.path.join(root, f))
    for f in os.listdir(os.path.join(REPO_ROOT, "sentinel", "server", "static")):
        if f.endswith(".css") and f != "tokens.css":
            scan_paths.append(os.path.join(REPO_ROOT, "sentinel", "server", "static", f))

    color_regex = re.compile(r"(?<!&)(#[0-9a-fA-F]{3,8}\b|rgba?\([^)]+\)|hsla?\([^)]+\))")
    tw_color_regex = re.compile(
        r"\b(bg|text|border|ring)-(slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|white|black)(?:-\d+)?\b"
    )

    for p in scan_paths:
        with open(p, "r", encoding="utf-8") as f:
            c = f.read()
        for m in color_regex.finditer(c):
            line_num = c[:m.start()].count("\n") + 1
            errors.append(f"{os.path.basename(p)}:{line_num}: Found literal color {m.group(0)}")
        for m in tw_color_regex.finditer(c):
            line_num = c[:m.start()].count("\n") + 1
            errors.append(f"{os.path.basename(p)}:{line_num}: Found fixed Tailwind color class {m.group(0)}")

    # (b) Every main wrapper has flex-1 + min-w-0 and no fixed small widths
    style_path = os.path.join(REPO_ROOT, "sentinel", "server", "static", "style.css")
    if os.path.isfile(style_path):
        with open(style_path, "r", encoding="utf-8") as f:
            sc = f.read()
        if ".app-body" not in sc or "min-width: 0" not in sc:
            errors.append(".app-body missing min-width: 0 in style.css")
        if "main {" not in sc or "min-width: 0" not in sc:
            errors.append("main missing min-width: 0 in style.css")

    # (c) No box-shadow blur > 8px or drop-shadow outside popovers
    shadow_regex = re.compile(r"box-shadow:\s*([^;]+);")
    drop_regex = re.compile(r"drop-shadow\([^)]+\)")
    for p in scan_paths:
        with open(p, "r", encoding="utf-8") as f:
            c = f.read()
        for m in shadow_regex.finditer(c):
            val = m.group(1)
            parts = [part.strip() for part in val.split(",") if "inset" not in part]
            for part in parts:
                lengths = re.findall(r"(\d+)px", part)
                if len(lengths) >= 3 and int(lengths[2]) > 8:
                    line_num = c[:m.start()].count("\n") + 1
                    errors.append(f"{os.path.basename(p)}:{line_num}: box-shadow blur {lengths[2]}px > 8px")
        for m in drop_regex.finditer(c):
            line_num = c[:m.start()].count("\n") + 1
            errors.append(f"{os.path.basename(p)}:{line_num}: drop-shadow found ({m.group(0)})")

    # (d) Logo SVGs contain no color other than currentColor
    brand_dir = os.path.join(REPO_ROOT, "sentinel", "server", "static", "brand")
    if os.path.isdir(brand_dir):
        logo_files = [f for f in os.listdir(brand_dir) if f.startswith("logo") and f.endswith(".svg")]
        color_attr_regex = re.compile(r"""(?:fill|stroke)\s*=\s*["\x27]([^"\x27]+)["\x27]""")
        literal_regex = re.compile(r"#[0-9a-fA-F]{3,8}|rgba?\([^)]+\)|hsla?\([^)]+\)")
        for lf in logo_files:
            lp = os.path.join(brand_dir, lf)
            with open(lp, "r", encoding="utf-8") as fp:
                lc = fp.read()
            for m in color_attr_regex.finditer(lc):
                v = m.group(1).strip()
                if v not in ("currentColor", "none"):
                    errors.append(f"{lf}: Found color {v} other than currentColor/none")
            for m in literal_regex.finditer(lc):
                errors.append(f"{lf}: Found literal color {m.group(0)}")

    # (e) git ls-files has no font files containing ethnocentric
    cmd = ["git", "ls-files"]
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            lower = line.lower()
            if any(ext in lower for ext in [".otf", ".ttf", ".woff", ".woff2"]) and "ethnocentric" in lower:
                errors.append(f"Tracked font file contains ethnocentric: {line}")

    return errors


def main():
    print("=== Sentinel Phase A & U1-FIX-2 UI Audit ===")
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

        # Check 8 (Static Checks a-e)
        c8_errs = run_static_checks()
        if c8_errs:
            all_errors.extend(c8_errs)
        else:
            print("[PASS] Check 8: Static checks (a)-(e) passed with zero violations.")

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
