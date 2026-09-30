"""Undo the tricks that hide an instruction from a regex — then scan again.

Every transform here produces a *variant* of the text. The detector scans the
original and each variant, so an instruction written in look-alike Cyrillic,
split by zero-width spaces, or smuggled as invisible Unicode tag characters still
matches, and the finding says which transform exposed it.

The presence of the trick is itself a finding: nobody puts zero-width joiners in
the middle of "instructions" by accident.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

ZERO_WIDTH = "​‌‍⁠﻿᠎­"
BIDI = "‪‫‬‭‮⁦⁧⁨⁩"
_ZW_RE = re.compile(f"[{ZERO_WIDTH}]")
_BIDI_RE = re.compile(f"[{BIDI}]")

# Unicode "tag" characters (U+E0000–U+E007F) mirror ASCII but render as nothing.
# They are the basis of "ASCII smuggling": an instruction that is invisible on
# screen and perfectly legible to a model's tokenizer.
_TAG_RE = re.compile("[\U000e0000-\U000e007f]+")

# The confusables that matter in practice: Cyrillic and Greek letters that are
# visually identical to Latin ones. Not the full Unicode confusables table — the
# point is to catch "іgnore" with a Cyrillic і, not to be a font.
_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
        "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "ո": "n",
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
        "С": "C", "Т": "T", "Х": "X", "І": "I",
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u",
        "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
        "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
    }
)
_MIXED_WORD_RE = re.compile(r"\b\w*[A-Za-z]\w*\b")
_NON_LATIN_LETTER_RE = re.compile(r"[Ͱ-ϿЀ-ӿ]")

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")


@dataclass(frozen=True)
class Variant:
    text: str
    # Human description of the transform, e.g. "base64-decoded". None = original.
    decoded_from: str | None


@dataclass(frozen=True)
class Trick:
    """An obfuscation technique found in the text, reported as its own finding."""

    rule: str
    severity: str
    message: str
    evidence: str


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\n\t")
    return ok / len(s)


def decode_tags(text: str) -> str:
    """Map Unicode tag characters back to the ASCII they shadow."""
    return _TAG_RE.sub(lambda m: "".join(chr(ord(c) - 0xE0000) for c in m.group()), text)


def fold(text: str) -> str:
    """Canonical form: NFKC, no zero-width or bidi controls, confusables folded."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZW_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    return text.translate(_CONFUSABLES)


def variants(text: str) -> tuple[list[Variant], list[Trick]]:
    """Every readable form of `text`, plus the concealment tricks that were used."""
    out = [Variant(text, None)]
    tricks: list[Trick] = []

    tags = _TAG_RE.findall(text)
    if tags:
        smuggled = decode_tags("".join(tags))
        out.append(Variant(decode_tags(text), "Unicode tag characters (ASCII smuggling)"))
        tricks.append(
            Trick(
                "obfuscation.unicode_tags", "high",
                "Invisible Unicode tag characters carry hidden ASCII text",
                smuggled[:200],
            )
        )

    zw = _ZW_RE.findall(text)
    if zw:
        # A stray BOM or soft hyphen is common; several inside words is not.
        inside_words = len(re.findall(rf"\w[{ZERO_WIDTH}]+\w", text))
        if inside_words >= 2 or len(zw) >= 5:
            tricks.append(
                Trick(
                    "obfuscation.zero_width", "medium",
                    f"{len(zw)} zero-width characters, {inside_words} splitting words",
                    _ZW_RE.sub("␣", text)[:200],
                )
            )

    if _BIDI_RE.search(text):
        tricks.append(
            Trick(
                "obfuscation.bidi_controls", "medium",
                "Bidirectional control characters can make text display in a different order "
                "than it is read",
                _BIDI_RE.sub("␣", text)[:200],
            )
        )

    mixed = [
        w for w in _MIXED_WORD_RE.findall(text)
        if _NON_LATIN_LETTER_RE.search(w) and re.search(r"[A-Za-z]", w)
    ]
    if mixed:
        tricks.append(
            Trick(
                "obfuscation.mixed_script", "medium",
                "Words mix Latin with look-alike Cyrillic/Greek letters",
                ", ".join(mixed[:8]),
            )
        )

    folded = fold(decode_tags(text))
    if folded != text:
        out.append(Variant(folded, "normalised (NFKC, invisible characters removed, "
                                    "look-alike letters folded)"))

    for blob in _B64_RE.findall(text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if len(decoded) >= 12 and _printable_ratio(decoded) > 0.95 and " " in decoded:
            out.append(Variant(decoded, "base64-decoded"))

    if len(_PCT_RE.findall(text)) >= 4:
        decoded = unquote(text)
        if decoded != text:
            out.append(Variant(decoded, "URL-decoded"))

    return out, tricks
