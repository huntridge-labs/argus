"""
Generate full truecolor ASCII art from argus_brandmark_color.png.

ascii_magic's `to_file()` maps colors to the nearest ANSI 16-color code
which collapses the gradient to ~2 visible tones.  This script uses
`to_character_list(full_color=True)` instead, which surfaces the true
24-bit hex value (`full_hex_color`) for every cell, and emits it as a
real truecolor escape sequence (\033[38;2;R;G;Bm).

Usage (from the img/ directory):
    python make_logo_ascii.py

Output:
    argus_logo.txt  – raw ANSI-escape file you can `cat` in any truecolor
                      terminal (iTerm2, macOS Terminal ≥ 3.6, etc.)
"""

import os
import sys
import ascii_magic

# ── tuneable ─────────────────────────────────────────────────────────────────
IMAGE_PATH  = os.path.join(os.path.dirname(__file__), 'argus_brandmark_color.png')
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), 'argus_logo.txt')

# Width in terminal columns.  100–120 fits most 80/120-col terminals when
# scrolled; increase to 160 for wider, cinematic look.
COLUMNS = 110

# Terminal font aspect-ratio correction (monospace chars are ~2× taller than
# wide).  2.2 is the ascii_magic default.  Increase slightly (e.g. 2.4) if
# the image looks squashed vertically.
WIDTH_RATIO = 2.2

# Boost contrast/saturation before conversion.  Helps the gradient pop.
ENHANCE = True
# ─────────────────────────────────────────────────────────────────────────────


def hex_to_rgb(hex_color: str):
    """'#a1b2c3' → (161, 178, 195)"""
    h = hex_color.lstrip('#')
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def render_truecolor(char_grid) -> str:
    """
    Walk the character-list returned by to_character_list() and emit
    24-bit truecolor ANSI escape sequences instead of the 16-color codes
    that to_ascii()/to_file() would use.
    """
    RESET = '\033[0m'
    lines = []

    for row in char_grid:
        line_parts = []
        prev_color = None

        for cell in row:
            ch    = cell['character']
            color = cell['full-hex-color']   # true RGB as '#rrggbb'

            # Skip invisible (transparent/white) cells – keep as spaces
            if color in ('#ffffff', '#FFFFFF') or ch == ' ':
                # If we were in a colored run, close it first
                if prev_color is not None:
                    line_parts.append(RESET)
                    prev_color = None
                line_parts.append(' ')
                continue

            if color != prev_color:
                r, g, b = hex_to_rgb(color)
                line_parts.append(f'\033[38;2;{r};{g};{b}m')
                prev_color = color

            line_parts.append(ch)

        # End of row: reset color and add newline
        if prev_color is not None:
            line_parts.append(RESET)

        lines.append(''.join(line_parts))

    return '\n'.join(lines)


def main():
    print(f'Loading {IMAGE_PATH} …')
    art = ascii_magic.AsciiArt.from_image(IMAGE_PATH)

    print(f'Converting at {COLUMNS} columns, width_ratio={WIDTH_RATIO}, enhance={ENHANCE} …')
    char_grid = art.to_character_list(
        columns=COLUMNS,
        width_ratio=WIDTH_RATIO,
        full_color=True,        # ← populates 'full-hex-color' with true RGB
    )

    output = render_truecolor(char_grid)

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as fh:
        fh.write(output)

    print(f'Saved → {OUTPUT_PATH}')
    print()
    print('Preview:')
    print(output)


if __name__ == '__main__':
    main()
