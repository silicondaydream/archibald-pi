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
import zlib

from PIL import ExifTags, Image, UnidentifiedImageError

from archibald.models import Segment

Image.MAX_IMAGE_PIXELS = 80_000_000

_XML_TAG = re.compile(r"<[^>]+>")
_INTERESTING_EXIF = {
    "ImageDescription",
    "Artist",
    "Copyright",
    "Software",
    "Make",
    "Model",
    "UserComment",
    "XPTitle",
    "XPComment",
    "XPAuthor",
    "XPKeywords",
    "XPSubject",
    "DocumentName",
    "HostComputer",
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


def _png_end(data: bytes) -> int | None:
    """Offset just past the IEND chunk, found by walking chunk lengths."""
    i = 8  # signature
    while i + 8 <= len(data):
        length = int.from_bytes(data[i : i + 4], "big")
        kind = data[i + 4 : i + 8]
        end = i + 12 + length  # length, type, data, CRC
        if end > len(data):
            return None
        if kind == b"IEND":
            return end
        i = end
    return None


def _jpeg_end(data: bytes) -> int | None:
    """Offset just past the real EOI, found by walking markers and scans.

    After a start-of-scan the entropy-coded data can contain 0xFF only as
    0xFF00 (stuffing) or 0xFFD0-D7 (restart markers), so the next other marker is
    a real one — and the first real EOI is the end, whatever comes after it.
    """
    i = 2  # SOI
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            return None
        marker = data[i + 1]
        if marker == 0xD9:
            return i + 2
        if marker == 0xFF:  # fill byte
            i += 1
            continue
        length = int.from_bytes(data[i + 2 : i + 4], "big")
        i += 2 + length
        if marker == 0xDA:  # start of scan: skip entropy-coded data
            while i + 1 < n:
                if data[i] == 0xFF and data[i + 1] not in (0x00, *range(0xD0, 0xD8)):
                    break
                i += 1
    return None


def _gif_end(data: bytes) -> int | None:
    """Offset just past the 0x3B trailer, found by walking blocks.

    The trailer byte also occurs inside image data, so searching for it finds the
    wrong one; walking the block structure finds the real one.
    """
    n = len(data)
    if n < 13:
        return None
    i = 13
    if data[10] & 0x80:  # global colour table
        i += 3 * (2 ** ((data[10] & 0x07) + 1))

    def skip_sub_blocks(j: int) -> int | None:
        while j < n:
            size = data[j]
            j += 1
            if size == 0:
                return j
            j += size
        return None

    while i < n:
        introducer = data[i]
        if introducer == 0x3B:
            return i + 1
        if introducer == 0x21:  # extension: label, then sub-blocks
            nxt = skip_sub_blocks(i + 2)
        elif introducer == 0x2C:  # image descriptor
            if i + 10 > n:
                return None
            packed = data[i + 9]
            j = i + 10
            if packed & 0x80:  # local colour table
                j += 3 * (2 ** ((packed & 0x07) + 1))
            nxt = skip_sub_blocks(j + 1)  # +1: LZW minimum code size
        else:
            return None
        if nxt is None:
            return None
        i = nxt
    return None


def _webp_end(data: bytes) -> int | None:
    """RIFF says how long it is; anything past that is not part of the image."""
    if len(data) < 12 or data[:4] != b"RIFF":
        return None
    size = int.from_bytes(data[4:8], "little")
    end = 8 + size + (size & 1)  # chunks are padded to even length
    return end if end <= len(data) else None


MAX_PNG_TEXT = 1_000_000  # decompressed bytes per zTXt/iTXt chunk


def _inflate(blob: bytes) -> bytes:
    """Bounded zlib: a compressed text chunk cannot become a decompression bomb."""
    try:
        return zlib.decompressobj().decompress(blob, MAX_PNG_TEXT)
    except zlib.error:
        return b""


def _png_metadata(data: bytes) -> tuple[list[tuple[str, str]], bytes | None]:
    """Text chunks and the eXIf payload, from anywhere in the file.

    Read by walking chunks rather than through Pillow, because Pillow only sees
    chunks after the image data by decoding the pixels — which this module never
    does. Text placed after IDAT is exactly where someone hiding it would put it.
    """
    texts: list[tuple[str, str]] = []
    exif: bytes | None = None
    i = 8
    while i + 8 <= len(data):
        length = int.from_bytes(data[i : i + 4], "big")
        kind = data[i + 4 : i + 8]
        body = data[i + 8 : i + 8 + length]
        if len(body) < length:
            break
        if kind == b"tEXt":
            key, _, value = body.partition(b"\x00")
            texts.append((key.decode("latin-1"), value.decode("latin-1")))
        elif kind == b"zTXt":
            key, _, rest = body.partition(b"\x00")
            texts.append((key.decode("latin-1"), _inflate(rest[1:]).decode("latin-1")))
        elif kind == b"iTXt":
            key, _, rest = body.partition(b"\x00")
            if len(rest) >= 2:
                compressed, rest = rest[0], rest[2:]
                _lang, _, rest = rest.partition(b"\x00")
                _translated, _, value = rest.partition(b"\x00")
                raw = _inflate(value) if compressed else value
                texts.append((key.decode("latin-1"), raw.decode("utf-8", errors="ignore")))
        elif kind == b"eXIf":
            exif = body
        elif kind == b"IEND":
            break
        i += 12 + length
    return texts, exif


_END_OF = {"PNG": _png_end, "JPEG": _jpeg_end, "GIF": _gif_end, "WEBP": _webp_end}


def _trailing(data: bytes, fmt: str | None) -> bytes:
    """Bytes after the image's real end, where a payload can be appended.

    Found by walking the format's structure, not by searching for an end marker.
    A search from the right can be fooled by a payload that ends with a fake
    marker; a search from the left, by one that occurs inside the image data.
    TIFF is not covered: its offsets point anywhere in the file, so "the end"
    has no single answer.
    """
    finder = _END_OF.get(fmt or "")
    if finder is None:
        return b""
    end = finder(data)
    return data[end:] if end is not None else b""


def extract_image(data: bytes, name: str = "image") -> tuple[list[Segment], list[str]]:
    segments: list[Segment] = []
    notes: list[str] = ["Text drawn in the image's pixels is not read yet (needs OCR)."]

    def add(text: str | None, source: str, where: str, reason: str, routine: bool = True) -> None:
        if text and text.strip():
            segments.append(
                Segment(
                    text=text.strip(),
                    source=source,
                    location=f"{name} › {where}",
                    hidden=True,
                    hidden_reason=reason,
                    routine=routine,
                )
            )

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            img = Image.open(io.BytesIO(data))
        except (
            UnidentifiedImageError,
            Image.DecompressionBombError,
            Image.DecompressionBombWarning,
            OSError,
            # Pillow's own guards: ValueError for an oversized text chunk,
            # SyntaxError for a malformed one. A hostile file is a verdict
            # about the file, not a crash.
            ValueError,
            SyntaxError,
        ) as exc:
            return [], [f"Could not read image: {exc.__class__.__name__}"]

        fmt = img.format
        notes.append(f"{fmt} image, {img.width}×{img.height}")

        if fmt == "PNG":
            # Pillow's getexif() on a PNG calls load() — decoding every pixel —
            # to look for an eXIf chunk after the image data. Read it ourselves.
            png_texts, png_exif = _png_metadata(data)
            exif = Image.Exif()
            if png_exif:
                try:
                    exif.load(png_exif)
                except (OSError, ValueError, SyntaxError):
                    notes.append("PNG eXIf chunk could not be parsed")
            info_items: list[tuple[str, object]] = list(png_texts)
        else:
            try:
                exif = img.getexif()
            except (OSError, ValueError, SyntaxError):
                exif = Image.Exif()
                notes.append("EXIF block could not be parsed")
            info_items = list((img.info or {}).items())
        ifds = [exif]
        try:
            ifds.append(exif.get_ifd(ExifTags.IFD.Exif))
        except (KeyError, AttributeError, OSError):
            pass
        for ifd in ifds:
            for tag_id, value in ifd.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if tag_name in _INTERESTING_EXIF:
                    add(
                        _decode(value, tag_name), "image.exif", f"EXIF {tag_name}", "image metadata"
                    )

        for key, value in info_items:
            if key in (
                "exif",
                "icc_profile",
                "dpi",
                "gamma",
                "transparency",
                "duration",
                "loop",
                "background",
                "version",
                "extension",
                "interlace",
                "aspect",
            ):
                continue
            if key in ("xmp", "XML:com.adobe.xmp"):
                raw = (
                    value.decode("utf-8", errors="ignore")
                    if isinstance(value, bytes)
                    else str(value)
                )
                text = re.sub(r"\s+", " ", _XML_TAG.sub(" ", raw))
                add(text, "image.xmp", "XMP metadata", "image metadata")
            elif key == "comment":
                add(_decode(value, "comment"), "image.comment", "comment", "image metadata")
            elif isinstance(value, (str, bytes)):
                # PNG tEXt / zTXt / iTXt chunks land here under their keyword.
                add(
                    _decode(value, key), "image.text-chunk", f"text chunk '{key}'", "image metadata"
                )

    tail = _trailing(data, fmt)
    if len(tail) >= 8:
        text = tail[:100_000].decode("utf-8", errors="ignore")
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in text)
        if text and printable / len(text) > 0.85:
            add(
                text,
                "image.trailing-data",
                f"{len(tail)} bytes after end of image",
                "data appended after the image ends",
                routine=False,
            )
        else:
            notes.append(f"{len(tail)} non-text bytes appended after the end of the image")
    return segments, notes
