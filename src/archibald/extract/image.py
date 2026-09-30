"""Image metadata — and bytes smuggled after the end of the image.

Reads EXIF (including UserComment and the Windows XP* tags), PNG text chunks,
XMP, JPEG/GIF comments, and anything appended after the image's end marker.

Pixels are never decoded: Image.open() only parses headers until load() is
called, and nothing here calls it. That keeps decompression bombs out of reach
and keeps this module about text, not vision. Text *drawn* in the pixels needs
OCR and is listed as a planned capability.
"""

from __future__ import annotations

import io
import re
import warnings

from PIL import ExifTags, Image, UnidentifiedImageError

from archibald.models import Segment

Image.MAX_IMAGE_PIXELS = 80_000_000

_XML_TAG = re.compile(r"<[^>]+>")
_INTERESTING_EXIF = {
    "ImageDescription", "Artist", "Copyright", "Software", "Make", "Model",
    "UserComment", "XPTitle", "XPComment", "XPAuthor", "XPKeywords", "XPSubject",
    "DocumentName", "HostComputer",
}


def _decode(value: object, tag_name: str) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        if tag_name.startswith("XP"):
            return value.decode("utf-16-le", errors="ignore").rstrip("\x00")
        if tag_name == "UserComment" and len(value) >= 8:
            charset, body = value[:8], value[8:]
            codec = "utf-16" if charset.startswith(b"UNICODE") else "utf-8"
            return body.decode(codec, errors="ignore").rstrip("\x00")
        return value.decode("utf-8", errors="ignore").rstrip("\x00")
    if isinstance(value, tuple) and value and all(isinstance(v, int) for v in value):
        # XP* tags sometimes arrive as a tuple of byte values.
        return _decode(bytes(value), tag_name)
    return None


def _trailing(data: bytes, fmt: str | None) -> bytes:
    """Bytes after the format's end marker, where a payload can be appended."""
    if fmt == "PNG":
        i = data.rfind(b"IEND")
        return data[i + 8 :] if i != -1 else b""
    if fmt == "JPEG":
        i = data.rfind(b"\xff\xd9")
        return data[i + 2 :] if i != -1 else b""
    # GIF's trailer is a single 0x3B byte that also occurs inside image data, so
    # "after the end" cannot be found reliably without walking every block.
    return b""


def extract_image(data: bytes, name: str = "image") -> tuple[list[Segment], list[str]]:
    segments: list[Segment] = []
    notes: list[str] = ["Text drawn in the image's pixels is not read yet (needs OCR)."]

    def add(text: str | None, source: str, where: str, reason: str, routine: bool = True) -> None:
        if text and text.strip():
            segments.append(Segment(text=text.strip(), source=source,
                                    location=f"{name} › {where}", hidden=True,
                                    hidden_reason=reason, routine=routine))

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            img = Image.open(io.BytesIO(data))
        except (UnidentifiedImageError, Image.DecompressionBombError,
                Image.DecompressionBombWarning, OSError) as exc:
            return [], [f"Could not read image: {exc.__class__.__name__}"]

        fmt = img.format
        notes.append(f"{fmt} image, {img.width}×{img.height}")

        exif = img.getexif()
        ifds = [exif]
        try:
            ifds.append(exif.get_ifd(ExifTags.IFD.Exif))
        except (KeyError, AttributeError, OSError):
            pass
        for ifd in ifds:
            for tag_id, value in ifd.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if tag_name in _INTERESTING_EXIF:
                    add(_decode(value, tag_name), "image.exif", f"EXIF {tag_name}",
                        "image metadata")

        for key, value in (img.info or {}).items():
            if key in ("exif", "icc_profile", "dpi", "gamma", "transparency", "duration",
                       "loop", "background", "version", "extension", "interlace", "aspect"):
                continue
            if key in ("xmp", "XML:com.adobe.xmp"):
                raw = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) \
                    else str(value)
                text = re.sub(r"\s+", " ", _XML_TAG.sub(" ", raw))
                add(text, "image.xmp", "XMP metadata", "image metadata")
            elif key == "comment":
                add(_decode(value, "comment"), "image.comment", "comment", "image metadata")
            elif isinstance(value, (str, bytes)):
                # PNG tEXt / zTXt / iTXt chunks land here under their keyword.
                add(_decode(value, key), "image.text-chunk", f"text chunk '{key}'",
                    "image metadata")

    tail = _trailing(data, fmt)
    if len(tail) >= 8:
        text = tail[:100_000].decode("utf-8", errors="ignore")
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
        if text and printable / len(text) > 0.85:
            add(text, "image.trailing-data", f"{len(tail)} bytes after end of image",
                "data appended after the image ends", routine=False)
        else:
            notes.append(f"{len(tail)} non-text bytes appended after the end of the image")
    return segments, notes
