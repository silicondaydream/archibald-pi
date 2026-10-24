"""Plain text and Markdown.

Markdown has its own places to hide text that a renderer drops but a model reading
the raw file sees: HTML comments, link-reference "comments" like `[//]: # (…)`,
and image alt text.
"""

from __future__ import annotations

import re

from archibald.models import Segment

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_REF_COMMENT = re.compile(r"^\s*\[(?://|comment|_)\]:\s*(?:#|<>)\s*[(\"'](.*?)[)\"']\s*$", re.M)
_IMG_ALT = re.compile(r"!\[([^\]]{3,})\]\(([^)\s]+)(?:\s+\"([^\"]*)\")?\)")


def extract_text(text: str, name: str = "input") -> tuple[list[Segment], list[str]]:
    segments = [Segment(text=text, source="text", location=name)]
    for m in _HTML_COMMENT.finditer(text):
        segments.append(
            Segment(
                text=m.group(1),
                source="markdown.comment",
                location=f"{name} › HTML comment",
                hidden=True,
                hidden_reason="comment (not rendered)",
            )
        )
    for m in _REF_COMMENT.finditer(text):
        segments.append(
            Segment(
                text=m.group(1),
                source="markdown.comment",
                location=f"{name} › link-reference comment",
                hidden=True,
                hidden_reason="Markdown link-reference comment (not rendered)",
            )
        )
    for m in _IMG_ALT.finditer(text):
        segments.append(
            Segment(
                text=m.group(1),
                source="markdown.alt",
                location=f"{name} › image alt text",
                hidden=True,
                hidden_reason="image alt text",
                routine=True,
            )
        )
        if m.group(3):
            segments.append(
                Segment(
                    text=m.group(3),
                    source="markdown.title",
                    location=f"{name} › image title",
                    hidden=True,
                    hidden_reason="image title",
                    routine=True,
                )
            )
    return segments, []
