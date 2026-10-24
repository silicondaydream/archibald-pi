"""Just enough CSS to decide whether text is visible.

Not a layout engine. It answers one question per element — "would a person see
this text?" — from the declarations that commonly hide it: display, visibility,
opacity, font-size, colour against background, off-screen positioning, clipping
and zero-size boxes. Anything it cannot decide, it treats as visible, so a miss
here is a missed escalation, never a false alarm.
"""

from __future__ import annotations

import re

RELEVANT = {
    "display",
    "visibility",
    "opacity",
    "font-size",
    "color",
    "background",
    "background-color",
    "position",
    "left",
    "top",
    "right",
    "text-indent",
    "clip",
    "clip-path",
    "width",
    "height",
    "max-height",
    "overflow",
    "transform",
    "fill",
    "fill-opacity",
}

_NAMED = {
    "white": (255, 255, 255),
    "black": (0, 0, 0),
    "snow": (255, 250, 250),
    "ivory": (255, 255, 240),
    "whitesmoke": (245, 245, 245),
    "ghostwhite": (248, 248, 255),
    "floralwhite": (255, 250, 240),
    "linen": (250, 240, 230),
    "beige": (245, 245, 220),
    "seashell": (255, 245, 238),
    "mintcream": (245, 255, 250),
    "azure": (240, 255, 255),
    "aliceblue": (240, 248, 255),
    "honeydew": (240, 255, 240),
    "oldlace": (253, 245, 230),
    "gainsboro": (220, 220, 220),
    "lightgray": (211, 211, 211),
    "lightgrey": (211, 211, 211),
    "silver": (192, 192, 192),
    "gray": (128, 128, 128),
    "grey": (128, 128, 128),
    "red": (255, 0, 0),
    "green": (0, 128, 0),
    "blue": (0, 0, 255),
    "yellow": (255, 255, 0),
    "navy": (0, 0, 128),
}

_HEX = re.compile(r"#([0-9a-f]{3,8})\b")
_RGB = re.compile(r"rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)(?:[\s,/]+([\d.]+%?))?\s*\)")
_LEN = re.compile(r"^(-?[\d.]+)\s*(px|pt|em|rem|%|vw|vh)?$")

Color = tuple[int, int, int]


def parse_declarations(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in style.split(";"):
        if ":" not in part:
            continue
        prop, _, value = part.partition(":")
        prop = prop.strip().lower()
        if prop in RELEVANT:
            out[prop] = value.replace("!important", "").strip().lower()
    return out


def parse_color(value: str | None) -> tuple[Color | None, bool]:
    """(rgb, transparent). Unknown values come back as (None, False)."""
    if not value:
        return None, False
    value = value.strip().lower()
    if value == "transparent":
        return None, True
    if value in _NAMED:
        return _NAMED[value], False
    m = _HEX.search(value)
    if m:
        h = m.group(1)
        if len(h) in (3, 4):
            rgb = tuple(int(c * 2, 16) for c in h[:3])
            alpha = int(h[3] * 2, 16) / 255 if len(h) == 4 else 1.0
        else:
            rgb = tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))
            alpha = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        return rgb, alpha < 0.05  # type: ignore[return-value]
    m = _RGB.search(value)
    if m:
        rgb = tuple(min(255, int(float(m.group(i)))) for i in (1, 2, 3))
        a = m.group(4)
        alpha = 1.0
        if a:
            alpha = float(a[:-1]) / 100 if a.endswith("%") else float(a)
        return rgb, alpha < 0.05  # type: ignore[return-value]
    return None, False


def background_color(decls: dict[str, str]) -> Color | None:
    for prop in ("background-color", "background"):
        if prop in decls:
            for token in re.split(r"\s+(?![^(]*\))", decls[prop]):
                rgb, _ = parse_color(token)
                if rgb:
                    return rgb
    return None


def _luminance(rgb: Color) -> float:
    def ch(c: int) -> float:
        x = c / 255
        return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4

    r, g, b = rgb
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: Color, b: Color) -> float:
    la, lb = _luminance(a), _luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


def _length(value: str) -> tuple[float, str] | None:
    m = _LEN.match(value.strip())
    if not m:
        return None
    return float(m.group(1)), m.group(2) or "px"


def hiding_reason(d: dict[str, str]) -> str | None:
    """Why these declarations hide an element's text, or None."""
    if d.get("display") == "none":
        return "display:none"
    if d.get("visibility") in ("hidden", "collapse"):
        return "visibility:hidden"
    for prop in ("opacity", "fill-opacity"):
        if prop in d:
            try:
                if float(d[prop].rstrip("%")) / (100 if d[prop].endswith("%") else 1) <= 0.05:
                    return f"{prop}:{d[prop]}"
            except ValueError:
                pass
    if "font-size" in d:
        ln = _length(d["font-size"])
        if ln:
            size, unit = ln
            limit = {"px": 1.5, "pt": 1.0, "em": 0.1, "rem": 0.1, "%": 10, "vw": 0.1, "vh": 0.1}
            if size <= limit.get(unit, 0):
                return f"font-size:{d['font-size']}"
    _, transparent = parse_color(d.get("color"))
    if transparent:
        return "transparent text colour"
    if d.get("fill") in ("none", "transparent"):
        return f"fill:{d['fill']}"
    if "transform" in d and re.search(r"scale[xy]?\(\s*0(\.0+)?\s*[,)]", d["transform"]):
        return "transform:scale(0)"
    if d.get("position") in ("absolute", "fixed"):
        for prop in ("left", "top", "right"):
            ln = _length(d.get(prop, ""))
            if ln and ln[0] <= -500:
                return f"positioned off-screen ({prop}:{d[prop]})"
        clip = d.get("clip", "") + " " + d.get("clip-path", "")
        if re.search(r"rect\(\s*0[^)]*\)|inset\(\s*(50%|100%)|circle\(\s*0", clip):
            return "clipped to nothing"
    ln = _length(d.get("text-indent", ""))
    if ln and ln[0] <= -500:
        return f"text-indent:{d['text-indent']}"
    if "hidden" in d.get("overflow", ""):
        for prop in ("width", "height", "max-height"):
            ln = _length(d.get(prop, ""))
            if ln and ln[0] <= 1:
                return f"zero-size box ({prop}:{d[prop]})"
    return None


# Class names that mean "hide this", in the frameworks that use them.
HIDING_CLASSES = {
    "sr-only": "screen-reader-only class",
    "visually-hidden": "screen-reader-only class",
    "screen-reader-text": "screen-reader-only class",
    "screen-reader-only": "screen-reader-only class",
    "hidden": "'hidden' class",
    "d-none": "'d-none' class",
    "invisible": "'invisible' class",
    "offscreen": "'offscreen' class",
    "hide": "'hide' class",
}


_RULE_RE = re.compile(r"([^{}@]+)\{([^{}]*)\}")
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)


def stylesheet_rules(css: str, limit: int = 2000) -> list[tuple[str, dict[str, str]]]:
    """(selector, relevant declarations) pairs from a <style> block.

    Rules inside @media blocks are included: their inner `sel { … }` text still
    matches. Specificity is ignored; later rules win, as they usually do.
    """
    out: list[tuple[str, dict[str, str]]] = []
    for sel, body in _RULE_RE.findall(_COMMENT_RE.sub("", css)):
        decls = parse_declarations(body)
        if not decls:
            continue
        for s in sel.split(","):
            s = s.strip()
            if s and not s.startswith(("from", "to")) and not s.endswith("%"):
                out.append((s, decls))
        if len(out) >= limit:
            break
    return out
