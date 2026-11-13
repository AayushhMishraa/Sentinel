#!/usr/bin/env python3
"""tools/make_wordmark.py: Generates Sentinel brand wordmark SVG using fontTools.

Converts the word SENTINEL from Ethnocentric-Light.otf into outlined SVG paths
(uppercase, tracking +0.08em, skewX(-8deg), fill currentColor, role="img", aria-label="Sentinel").
Font files are kept strictly out of git.
"""

from __future__ import annotations

import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)

OUTPUT_SVG = os.path.join(REPO_ROOT, "sentinel", "server", "static", "brand", "sentinel-wordmark.svg")
NOTICE_PATH = os.path.join(REPO_ROOT, "brand", "FONT_NOTICE.md")
STATIC_NOTICE = os.path.join(REPO_ROOT, "sentinel", "server", "static", "brand", "FONT_NOTICE.md")

FONT_CANDIDATES = [
    os.path.expanduser("~/brand_src/Ethnocentric-Light.otf"),
    os.path.expanduser("~/brand_src/Ethnocentric-Regular.otf"),
    os.path.expanduser("~/brand_src/ethnocentric rg.otf"),
    os.path.join(REPO_ROOT, "brand_src", "Ethnocentric-Light.otf"),
    os.path.join(REPO_ROOT, "brand_src", "Ethnocentric-Regular.otf"),
]


def write_notice():
    notice_text = (
        "# Font Notice\n\n"
        "Outlined graphic generated from Ethnocentric font (`Ethnocentric-Light.otf`) "
        "using fontTools `SVGPathPen`.\n"
        "Font binaries are kept strictly outside git version control.\n\n"
        "## Archive File List (`ethnocentric-light-1794528777-0.zip`)\n\n"
        "- `Ethnocentric-Light.otf` (90,064 bytes)\n"
        "- `exFont-License.txt` (80 bytes)\n\n"
        "## License Text (`exFont-License.txt`)\n\n"
        "```\n"
        "License: Free for Personal Use\n"
        "Link: https://exfont.com/ethnocentric-light.font\n"
        "```\n"
    )
    for p in [NOTICE_PATH, STATIC_NOTICE]:
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(notice_text)
        except OSError:
            pass


def make_fallback_svg():
    svg_content = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 135 24" fill="currentColor" '
        'role="img" aria-label="Sentinel">\n'
        '  <text x="0" y="18" font-family="\'Inter\', -apple-system, sans-serif" '
        'font-weight="600" font-size="15" letter-spacing="0.08em" fill="currentColor">SENTINEL</text>\n'
        '</svg>\n'
    )
    try:
        os.makedirs(os.path.dirname(OUTPUT_SVG), exist_ok=True)
        with open(OUTPUT_SVG, "w", encoding="utf-8") as f:
            f.write(svg_content)
    except OSError:
        pass
    print("WORDMARK FONT PENDING")


def main() -> int:
    write_notice()

    font_path = None
    for cand in FONT_CANDIDATES:
        if os.path.isfile(cand):
            font_path = cand
            break

    if not font_path:
        make_fallback_svg()
        return 0

    try:
        from fontTools.ttLib import TTFont
        from fontTools.pens.svgPathPen import SVGPathPen
        from fontTools.pens.boundsPen import BoundsPen
    except ImportError:
        print("fontTools not installed in environment. Using fallback wordmark.")
        make_fallback_svg()
        return 0

    # Convert font glyphs to outlined SVG paths using fontTools
    try:
        font = TTFont(font_path)
        glyph_set = font.getGlyphSet()
        cmap = font.getBestCmap()
        word = "SENTINEL"

        units_per_em = font["head"].unitsPerEm
        tracking_units = int(units_per_em * 0.08)

        paths = []
        cur_x = 0
        all_x, all_y = [], []
        skew_angle = math.radians(8)

        for char in word:
            code = ord(char)
            gname = cmap.get(code)
            if not gname:
                continue

            glyph = glyph_set[gname]
            bp = BoundsPen(glyph_set)
            glyph.draw(bp)
            b = bp.bounds
            if b:
                for x, y in [(b[0], b[1]), (b[2], b[1]), (b[0], b[3]), (b[2], b[3])]:
                    sx = cur_x + x - y * math.tan(skew_angle)
                    all_x.append(sx)
                    all_y.append(y)

            char_pen = SVGPathPen(glyph_set)
            glyph.draw(char_pen)
            d = char_pen.getCommands()
            if d:
                paths.append(f'<path d="{d}" transform="translate({cur_x}, 0)" />')
            cur_x += glyph.width + tracking_units

        min_x, max_x = min(all_x), max(all_x)
        min_y, max_y = min(all_y), max(all_y)
        w = int(math.ceil(max_x - min_x))
        h = int(math.ceil(max_y - min_y))

        svg_content = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
            f'fill="currentColor" role="img" aria-label="Sentinel">\n'
            f'  <g transform="translate({-min_x:.1f}, {max_y:.1f}) scale(1, -1) skewX(-8)">\n'
            f'    {"".join(paths)}\n'
            f'  </g>\n'
            f'</svg>\n'
        )
        try:
            with open(OUTPUT_SVG, "w", encoding="utf-8") as f:
                f.write(svg_content)
        except OSError:
            pass
        print("Generated outlined SVG wordmark successfully from Ethnocentric-Light.otf using fontTools.")
    except Exception as e:
        print(f"Error outlining font: {e}. Falling back to text wordmark.")
        make_fallback_svg()

    return 0


if __name__ == "__main__":
    sys.exit(main())
