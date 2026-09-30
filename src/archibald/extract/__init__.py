"""Turn any supported input into Segments.

The format is decided by content, not by name: magic bytes first, then a look at
the text. A file called report.pdf that is really HTML is scanned as HTML.
"""

from __future__ import annotations

from archibald.extract.docx import extract_docx
from archibald.extract.html import extract_html, looks_like_html
from archibald.extract.image import extract_image
from archibald.extract.pdf import extract_pdf
from archibald.extract.text import extract_text
from archibald.models import Segment

MAX_BYTES = 25_000_000

_IMAGE_MAGIC = (
    b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"II*\x00", b"MM\x00*",
)


def sniff(data: bytes, filename: str | None = None) -> str:
    name = (filename or "").lower()
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "docx" if name.endswith((".docx", ".docm")) or b"word/" in data[:4000] else "zip"
    if data.startswith(_IMAGE_MAGIC) or (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
        return "image"
    text = _decode(data[:20_000])
    head = text.lstrip()[:300].lower()
    if "<svg" in head:
        return "svg"
    if name.endswith((".html", ".htm", ".xhtml")) or looks_like_html(text):
        return "html"
    if name.endswith((".md", ".markdown")):
        return "markdown"
    return "text"


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def extract_bytes(
    data: bytes, filename: str | None = None
) -> tuple[list[Segment], list[str], str]:
    """(segments, notes, kind) for an uploaded or fetched file."""
    notes: list[str] = []
    if len(data) > MAX_BYTES:
        return [], [f"Refused: larger than {MAX_BYTES // 1_000_000} MB"], "unknown"
    kind = sniff(data, filename)
    label = filename or "input"
    if kind == "pdf":
        segs, notes = extract_pdf(data, label)
    elif kind == "docx":
        segs, notes = extract_docx(data, label)
    elif kind == "image":
        segs, notes = extract_image(data, label)
    elif kind in ("html", "svg"):
        segs, notes = extract_html(_decode(data), prefix=label if filename else "")
    elif kind == "zip":
        return [], ["Zip archives other than .docx are not scanned yet"], kind
    else:
        segs, notes = extract_text(_decode(data), label)
    return segs, notes, kind


def extract_string(text: str, kind: str = "auto") -> tuple[list[Segment], list[str], str]:
    """For pasted content: plain text, Markdown, or HTML."""
    if kind == "auto":
        kind = "html" if looks_like_html(text) else "text"
    if kind == "html":
        segs, notes = extract_html(text)
    else:
        segs, notes = extract_text(text)
    return segs, notes, kind


__all__ = ["extract_bytes", "extract_string", "sniff"]
