#!/usr/bin/env python3
"""Measure every colour pairing in tokens.css against WCAG AA.

The same script as LycheePot's, pointed at Archibald's copy of the shared
Havarti SecOps palette.

Run it after touching the palette: `python3 scripts/check_contrast.py`. Exits
non-zero on a failure, so it can go in CI.

The pairings are listed explicitly rather than discovered, because which token is
drawn on which surface is a fact about the CSS that no amount of parsing will
tell you.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TOKENS = Path(__file__).resolve().parents[1] / "src/archibald/web/tokens.css"
AA = 4.5
AA_LARGE = 3.0


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")

    def channel(pair: str) -> float:
        c = int(pair, 16) / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * channel(h[0:2]) + 0.7152 * channel(h[2:4]) + 0.0722 * channel(h[4:6])


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def parse_blocks(css: str) -> dict[str, dict[str, str]]:
    """Pull the light and dark token sets out of the stylesheet."""
    blocks: dict[str, dict[str, str]] = {"light": {}, "dark": {}}
    light_match = re.search(r':root,\s*\[data-theme="light"\]\s*\{(.*?)\n\}', css, re.S)
    dark_match = re.search(r'\[data-theme="dark"\]\s*\{(.*?)\n\}', css, re.S)
    for name, match in (("light", light_match), ("dark", dark_match)):
        if match:
            for var, value in re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})", match.group(1)):
                blocks[name][var] = value
    return blocks


# (foreground, background, minimum). Small text and UI chrome need AA; a 3px row
# rail and a chart fill are non-text and need only AA_LARGE.
PAIRINGS = [
    ("text", "bg", AA),
    ("text", "bg-raised", AA),
    ("text", "bg-sunken", AA),
    ("text-dim", "bg", AA),
    ("text-dim", "bg-raised", AA),
    ("text-faint", "bg", AA),
    ("text-faint", "bg-raised", AA),
    ("accent", "bg", AA),
    ("accent", "bg-raised", AA),
    ("on-accent", "accent", AA),
    ("alert", "bg", AA),
    ("alert", "bg-raised", AA),
    ("ok", "bg", AA),
    ("ok", "bg-raised", AA),
    # Archibald colours the "likely" verdict with the deepest ramp step.
    ("ramp-5", "bg-raised", AA),
    ("focus", "bg", AA),
    ("focus", "bg-raised", AA),
    # Severity badges carry 11px text, so they need full AA.
    ("ramp-1-text", "ramp-1", AA),
    ("ramp-2-text", "ramp-2", AA),
    ("ramp-3-text", "ramp-3", AA),
    ("ramp-4-text", "ramp-4", AA),
    ("ramp-5-text", "ramp-5", AA),
    ("on-accent", "alert", AA),
    # Non-text: bar fills and gridlines only need to be perceptible.
    ("ramp-4", "bg-sunken", AA_LARGE),
    ("grid", "bg-raised", 1.2),
]


def main() -> int:
    css = TOKENS.read_text(encoding="utf-8")
    blocks = parse_blocks(css)
    failures: list[str] = []

    for theme, tokens in blocks.items():
        print(f"\n{theme.upper()}")
        for fg, bg, minimum in PAIRINGS:
            if fg not in tokens or bg not in tokens:
                failures.append(f"{theme}: missing token {fg} or {bg}")
                continue
            r = contrast(tokens[fg], tokens[bg])
            ok = r >= minimum
            mark = "ok  " if ok else "FAIL"
            print(f"  {mark} {fg:>14} on {bg:<14} {r:5.2f}:1  (need {minimum})")
            if not ok:
                failures.append(f"{theme}: {fg} on {bg} is {r:.2f}:1, need {minimum}")

        # The ramp must be monotonic in luminance, which is what makes it survive
        # greyscale and colour vision deficiency. Direction differs by theme: in
        # light "more" is darker, in dark "more" is brighter.
        ramp = [tokens.get(f"ramp-{i}") for i in range(1, 6)]
        if all(ramp):
            lums = [luminance(c) for c in ramp]  # type: ignore[arg-type]
            increasing = all(lums[i] < lums[i + 1] for i in range(4))
            decreasing = all(lums[i] > lums[i + 1] for i in range(4))
            if increasing or decreasing:
                direction = "increasing" if increasing else "decreasing"
                print(f"  ok   ramp luminance is monotonic ({direction})")
            else:
                failures.append(f"{theme}: ramp luminance is not monotonic")
                print("  FAIL ramp luminance is not monotonic")

    if failures:
        print(f"\n{len(failures)} failure(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nAll pairings pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
