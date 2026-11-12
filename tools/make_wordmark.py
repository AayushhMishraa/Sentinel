#!/usr/bin/env python3
"""tools/make_wordmark.py: Generates Sentinel brand wordmark SVG.

If Ethnocentric font is found in ~/brand_src/ or brand_src/, and fontTools is installed,
it converts the word SENTINEL to outlined SVG paths.
Otherwise, generates a clean Inter 600 uppercase fallback wordmark SVG and reports
'WORDMARK FONT PENDING'.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)

OUTPUT_SVG = os.path.join(REPO_ROOT, "sentinel", "server", "static", "brand", "sentinel-wordmark.svg")
NOTICE_PATH = os.path.join(REPO_ROOT, "brand", "FONT_NOTICE.md")
STATIC_NOTICE = os.path.join(REPO_ROOT, "sentinel", "server", "static", "brand", "FONT_NOTICE.md")

FONT_CANDIDATES = [
    os.path.expanduser("~/brand_src/Ethnocentric-Regular.otf"),
    os.path.expanduser("~/brand_src/ethnocentric rg.otf"),
    os.path.join(REPO_ROOT, "brand_src", "Ethnocentric-Regular.otf"),
]


def write_notice():
    notice_text = (
        "# Font Notice\n\n"
        "Outlined graphic from Ethnocentric by Typodermic Fonts under the Typodermic Desktop License; "
        "font files not included.\n"
    )
    for p in [NOTICE_PATH, STATIC_NOTICE]:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(notice_text)


def make_fallback_svg():
    svg_content = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 135 24" fill="currentColor" '
        'role="img" aria-label="Sentinel">\n'
        '  <text x="0" y="18" font-family="\'Inter\', -apple-system, sans-serif" '
        'font-weight="600" font-size="15" letter-spacing="0.08em" fill="currentColor">SENTINEL</text>\n'
        '</svg>\n'
    )
    os.makedirs(os.path.dirname(OUTPUT_SVG), exist_ok=True)
    with open(OUTPUT_SVG, "w", encoding="utf-8") as f:
        f.write(svg_content)
    print("WORDMARK FONT PENDING")


def main():
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
    except ImportError:
        print("fontTools not installed in environment. Using fallback wordmark.")
        make_fallback_svg()
        return 0

    # Convert font glyphs to outlined SVG paths
    try:
        font = TTFont(font_path)
        glyph_set = font.getGlyphSet()
        cmap = font.getBestCmap()
        word = "SENTINEL"
        pen = SVGPathPen(glyph_set)
        
        # Calculate horizontal positions with +0.08em tracking
        units_per_em = font["head"].unitsPerEm
        tracking_units = int(units_per_em * 0.08)
        
        paths = []
        cur_x = 0
        for char in word:
            code = ord(char)
            gname = cmap.get(code)
            if not gname:
                continue
            char_pen = SVGPathPen(glyph_set)
            glyph = glyph_set[gname]
            glyph.draw(char_pen)
            d = char_pen.getCommands()
            if d:
                paths.append(f'<path d="{d}" transform="translate({cur_x}, 0)" />')
            cur_x += glyph.width + tracking_units

        # Render full outlined SVG with optional skewX(-8deg)
        total_width = cur_x
        scale_y = -1  # Font coordinates are bottom-up
        svg_content = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total_width} {units_per_em}" '
            f'fill="currentColor" role="img" aria-label="Sentinel">\n'
            f'  <g transform="scale(1, {scale_y}) translate(0, -{units_per_em * 0.85}) skewX(-8)">\n'
            f'    {"".join(paths)}\n'
            f'  </g>\n'
            f'</svg>\n'
        )
        with open(OUTPUT_SVG, "w", encoding="utf-8") as f:
            f.write(svg_content)
        print("Generated outlined SVG wordmark successfully.")
    except Exception as e:
        print(f"Error outlining font: {e}. Falling back to text wordmark.")
        make_fallback_svg()

    return 0


if __name__ == "__main__":
    sys.exit(main())
