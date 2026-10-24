"""The public API: scan a string, a file's bytes, or a URL."""

from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urlsplit

from archibald.detect import scan_segments
from archibald.extract import extract_bytes, extract_string
from archibald.fetch import fetch
from archibald.models import Verdict


def scan_string(text: str, kind: str = "auto") -> Verdict:
    """Pasted content. `kind` is "text", "html", or "auto" to decide from the content."""
    segments, notes, resolved = extract_string(text, kind)
    return scan_segments(segments, resolved, notes)


def scan_bytes(data: bytes, filename: str | None = None) -> Verdict:
    """A file: PDF, DOCX, image, HTML/SVG, Markdown or plain text — sniffed by content."""
    segments, notes, kind = extract_bytes(data, filename)
    return scan_segments(segments, kind, notes)


def scan_url(url: str, *, any_port: bool = False) -> Verdict:
    """Fetch a public page (see fetch.py for the guard rails) and scan it."""
    body, content_type, final = fetch(url, any_port=any_port)
    name = PurePosixPath(urlsplit(final).path).name or None
    if "html" in content_type and name and "." not in name:
        name = None  # a bare path like /about is a page, not a file name
    segments, notes, kind = extract_bytes(body, name)
    note = f"Fetched {final}" + (f" ({content_type.split(';')[0]})" if content_type else "")
    return scan_segments(segments, f"url:{kind}", [note, *notes])
