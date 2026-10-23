"""PDFs: metadata, annotations, form fields, and text a reader never sees.

Invisible text is found by watching the content stream while text is extracted:
text render mode 3 ("neither fill nor stroke"), a white fill colour, or a font so
small it cannot be read. That is how instructions get into a résumé or a paper
without anyone noticing — the text is there for a model's text extractor, and
nowhere on the printed page.

White text is judged against white, the overwhelmingly common page colour;
coloured page backgrounds are not modelled.
"""

from __future__ import annotations

import io

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from archibald.models import Segment

MAX_PAGES = 200


class _HiddenTextTracker:
    """Follows the graphics state while pypdf walks one page's content stream.

    pypdf calls `operator` before each content-stream operator and `text` for each
    run it decodes, so the render mode and fill colour seen by `text` are the ones
    in force when that run was drawn.
    """

    def __init__(self) -> None:
        self.mode = 0
        self.white = False
        self.runs: list[tuple[str, str]] = []

    def operator(self, op: bytes, args: list, cm: object, tm: object) -> None:  # noqa: ARG002
        try:
            if op == b"Tr" and args:
                self.mode = int(args[0])
            elif op in (b"rg", b"sc", b"scn") and len(args) >= 3:
                self.white = all(float(a) >= 0.97 for a in args[:3])
            elif op == b"g" and args:
                self.white = float(args[0]) >= 0.97
            elif op == b"k" and len(args) >= 4:
                self.white = all(float(a) <= 0.03 for a in args[:4])
        except (TypeError, ValueError):
            pass  # a pattern name or other non-numeric operand: not a plain colour

    def text(self, text: str, cm: object, tm: object, font: object, size: float) -> None:  # noqa: ARG002
        if not text.strip():
            return
        reason = None
        if self.mode == 3:
            reason = "invisible text render mode"
        elif self.white:
            reason = "white text"
        elif size and 0 < abs(size) < 1.0:
            reason = f"font size {abs(size):.2f}pt"
        if reason:
            self.runs.append((text, reason))


def extract_pdf(data: bytes, name: str = "document.pdf") -> tuple[list[Segment], list[str]]:
    segments: list[Segment] = []
    notes: list[str] = []
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted and not reader.decrypt(""):
            return [], ["PDF is encrypted with a password; nothing could be read"]
    except (PdfReadError, ValueError, OSError) as exc:
        return [], [f"Could not read PDF: {exc.__class__.__name__}"]

    def add(
        text: str, source: str, where: str, reason: str | None = None, routine: bool = False
    ) -> None:
        if text and text.strip():
            segments.append(
                Segment(
                    text=text.strip(),
                    source=source,
                    location=f"{name} › {where}",
                    hidden=reason is not None,
                    hidden_reason=reason,
                    routine=routine,
                )
            )

    meta = reader.metadata or {}
    for key in ("/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer"):
        value = meta.get(key)
        if value:
            add(
                str(value), "pdf.metadata", f"metadata {key[1:]}", "document metadata", routine=True
            )

    pages = reader.pages
    if len(pages) > MAX_PAGES:
        notes.append(f"Only the first {MAX_PAGES} of {len(pages)} pages were scanned")
    for number, page in enumerate(pages[:MAX_PAGES], start=1):
        tracker = _HiddenTextTracker()
        try:
            visible = page.extract_text(
                visitor_operand_before=tracker.operator, visitor_text=tracker.text
            )
        except Exception as exc:  # noqa: BLE001 — malformed pages must not stop the scan
            notes.append(f"Page {number}: text could not be extracted ({exc.__class__.__name__})")
            continue
        add(visible or "", "pdf.text", f"page {number}")

        by_reason: dict[str, list[str]] = {}
        for text, reason in tracker.runs:
            by_reason.setdefault(reason, []).append(text)
        for reason, parts in by_reason.items():
            add(" ".join(parts), "pdf.hidden", f"page {number}", reason)

        for annot in page.get("/Annots") or []:
            try:
                obj = annot.get_object()
            except Exception:  # noqa: BLE001
                continue
            for key in ("/Contents", "/TU", "/T"):
                if obj.get(key):
                    add(
                        str(obj[key]),
                        "pdf.annotation",
                        f"page {number} annotation {key[1:]}",
                        "annotation",
                        routine=True,
                    )

    try:
        fields = reader.get_fields() or {}
    except Exception:  # noqa: BLE001
        fields = {}
    for field_name, field in fields.items():
        for key in ("/V", "/TU"):
            value = field.get(key)
            if value and isinstance(value, str):
                add(
                    value,
                    "pdf.form",
                    f"form field '{field_name}' {key[1:]}",
                    "form field value" if key == "/V" else "form field tooltip",
                    routine=True,
                )
    if fields:
        notes.append(f"{len(fields)} PDF form field{'s' if len(fields) != 1 else ''} scanned")
    return segments, notes
