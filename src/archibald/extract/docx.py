"""Word documents (.docx): hidden runs, white text, comments and properties.

A .docx is a zip of XML. Word hides text with the `vanish` run property; people
hide it with white-on-white or a 1pt font. Comments, headers, footers, footnotes
and document properties are all read by text extractors and rarely by people.

XML is parsed with defusedxml, and the archive is size-checked before anything
is decompressed, so a zip bomb or an entity-expansion document cannot take the
process down.
"""

from __future__ import annotations

import io
import zipfile
from xml.etree.ElementTree import Element  # the type only; parsing is defusedxml

from defusedxml import ElementTree

from archibald.models import Segment

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
MAX_UNCOMPRESSED = 60_000_000
MAX_MEMBERS = 3000
WHITES = ("FFFFFF", "FEFEFE", "FFFFFE")

PARTS = {
    "word/document.xml": "body",
    "word/footnotes.xml": "footnotes",
    "word/endnotes.xml": "endnotes",
    "word/comments.xml": "comments",
}


def _run_hidden(run: Element) -> str | None:
    props = run.find(f"{W}rPr")
    if props is None:
        return None
    if props.find(f"{W}vanish") is not None or props.find(f"{W}specVanish") is not None:
        return "Word hidden text"
    color = props.find(f"{W}color")
    if color is not None and str(color.get(f"{W}val", "")).upper() in WHITES:
        return "white text"
    size = props.find(f"{W}sz")
    if size is not None:
        try:
            if int(size.get(f"{W}val", "24")) <= 2:  # half-points: ≤ 1pt
                return "font size ≤ 1pt"
        except ValueError:
            pass
    return None


def extract_docx(data: bytes, name: str = "document.docx") -> tuple[list[Segment], list[str]]:
    segments: list[Segment] = []
    notes: list[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return [], ["Not a valid .docx (zip) file"]
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS or sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
        return [], ["Refused: the archive expands to more than the size limit"]
    names = set(zf.namelist())

    parts = dict(PARTS)
    for n in names:
        if n.startswith("word/header") and n.endswith(".xml"):
            parts[n] = "header"
        elif n.startswith("word/footer") and n.endswith(".xml"):
            parts[n] = "footer"

    for part, label in parts.items():
        if part not in names:
            continue
        try:
            root = ElementTree.fromstring(zf.read(part))
        except Exception:  # noqa: BLE001 — defusedxml raises its own types for attacks
            notes.append(f"Could not parse {part}")
            continue
        for p_index, para in enumerate(root.iter(f"{W}p"), start=1):
            runs: list[tuple[str, str | None]] = []
            for run in para.iter(f"{W}r"):
                text = "".join(t.text or "" for t in run.iter(f"{W}t"))
                if text:
                    runs.append((text, _run_hidden(run)))
            # Merge adjacent runs with the same visibility into one segment.
            merged: list[tuple[str, str | None]] = []
            for text, reason in runs:
                if merged and merged[-1][1] == reason:
                    merged[-1] = (merged[-1][0] + text, reason)
                else:
                    merged.append((text, reason))
            for text, reason in merged:
                if not text.strip():
                    continue
                if label == "comments":
                    reason = reason or "Word comment"
                segments.append(Segment(
                    text=text, source=f"docx.{label}",
                    location=f"{name} › {label} paragraph {p_index}",
                    hidden=reason is not None, hidden_reason=reason,
                    routine=label == "comments" and reason == "Word comment",
                ))

    for part in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
        if part not in names:
            continue
        try:
            root = ElementTree.fromstring(zf.read(part))
        except Exception:  # noqa: BLE001
            continue
        for el in root.iter():
            if el.text and el.text.strip() and len(el.text.strip()) >= 3:
                key = el.tag.split("}")[-1]
                segments.append(Segment(
                    text=el.text.strip(), source="docx.properties",
                    location=f"{name} › property {key}", hidden=True,
                    hidden_reason="document properties", routine=True,
                ))
    return segments, notes
