# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **URL fetches are pinned to the checked address.** The fetcher used to check a
  name's addresses and then let httpx resolve it again to connect, which a
  DNS-rebinding server could exploit. The connection now goes to the vetted IP,
  with the name as Host and TLS server name; each redirect hop is re-checked and
  re-pinned. Ports are 80 and 443 unless `scan --any-port`.
- **The server enforces loopback itself**, peer and Host header, so starting it
  with uvicorn directly no longer bypasses the CLI's check, and a DNS-rebinding
  page in the operator's browser cannot drive it. `serve --allow-remote` opts out.
- **Appended image data could hide behind a fake end marker.** Trailing data is
  now found by walking each format's structure (PNG, JPEG, GIF, WebP).
- **A file that could not be scanned read as clean.** Over 25 MB, a zip other
  than DOCX, or a corrupt or oversized DOCX produced a verdict with no segments —
  score 0, level `clean` — so `scan` exited 0 and a pipeline gate passed it. These
  now raise `NotScannedError`: `scan` exits 2 and the API answers `415`.

### Fixed

- PNG pixels were decoded after all: Pillow's `getexif()` loads the image to find
  a late eXIf chunk. PNG metadata is now read by walking chunks, anywhere in the
  file, with compressed text capped at 1 MB. A truncated PNG no longer crashes.
- An oversized `zTXt` chunk crashed the scan with an uncaught `ValueError`.
- Six `mypy --strict` errors.

### Added

- `archibald eval --min-precision / --min-recall`, so the corpus can gate a build.
- GIF and WebP trailing-data detection.
- Tests for the fetcher, the server and the CLI (84 tests, from 10).
- LICENSE (MIT, as pyproject always declared), SECURITY.md, CONTRIBUTING.md, a
  Makefile with `make check`, and strict mypy.

### Known gaps

- No OCR: text drawn in an image's pixels is not read.
- Archives other than DOCX are not scanned; trailing data after a TIFF is not
  detected.
- PDFs are scanned to 200 pages; "white text" is judged against a white page only.
- `eval` scores raw corpus strings; it does not exercise the extractors.

## [0.1.0]

### Added

First release. Scans text, Markdown, HTML and SVG, web pages by URL, PDF, DOCX,
and image metadata for instructions aimed at an AI, including hidden ones;
decodes Unicode tag smuggling, zero-width splitting, bidi controls, homoglyphs,
base64 and URL encoding; scores 0–100 with escalation for hidden and decoded
content and de-escalation for quoted discussion. CLI (`scan`, `eval`, `serve`)
and a static web UI. A labelled corpus of 52 examples.
