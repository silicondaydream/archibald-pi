# Security Policy

## Reporting a vulnerability

Report security issues privately through [GitHub Security
Advisories](https://github.com/silicondaydream/archibald-pi/security/advisories/new),
not in a public issue. This is a small open-source project, not a product with an
on-call rotation: expect an acknowledgement within a few days and a fix or a
mitigation within 30 days for confirmed issues.

A **missed injection** — some text that should have scored higher — is usually
not a vulnerability. Open an ordinary issue with the example, or better, a pull
request adding it to `corpus/`. It *is* a vulnerability if Archibald can be made
to do something: fetch where it should not, crash, hang, exhaust memory, or render
what it was given.

## The assumption

**Everything Archibald reads was written by someone trying to steer an AI.** Text,
pages, PDFs, documents and images arrive precisely because somebody suspects them.
Archibald classifies and reports; it never follows, runs, renders or forwards what
it reads. Every control below falls out of that.

## In scope

| Threat | Control | Test |
|---|---|---|
| Server-side request forgery through "scan this URL" | http(s) only; ports 80/443 unless `--any-port`; every resolved address must be public (no loopback, RFC 1918, link-local, multicast or reserved); no credentials in URLs; no proxy settings from the environment | `tests/test_fetch.py` |
| DNS rebinding between the check and the connection | The connection is **pinned** to the address that was checked, with the name sent as Host and as the TLS server name; each redirect hop is re-resolved, re-checked and re-pinned; no connection reuse across names | `tests/test_fetch.py` |
| Exposing the scanner to the network | The app refuses any non-loopback peer **and** any Host header that does not name loopback, whether started by `archibald serve` or by uvicorn directly. `--allow-remote` is an explicit opt-out | `tests/test_server.py` |
| A web page in the operator's browser driving the local server | The Host-header check above: a rebinding page reaches 127.0.0.1 but carries its own name | `tests/test_server.py` |
| Oversized input | 25 MB per file, 2,000,000 characters per pasted text, 5 MB per fetched page, 5 MB of HTML, 200 PDF pages | `tests/test_server.py` |
| Decompression bombs | DOCX: member count and total uncompressed size checked before unzipping. PNG text chunks: inflation capped at 1 MB. Images: pixels are never decoded, and Pillow's pixel limit stands behind that | `tests/test_image_trailing.py` |
| XML entity expansion | DOCX XML is parsed with `defusedxml` | |
| Executing or rendering hostile content | HTML is parsed, never rendered; scripts never run; the UI writes every value with `textContent` under a CSP with no inline script and no third-party origin | |
| Hiding text from the scanner | Hidden-content extraction (CSS, attributes, metadata, comments), decoding of tag-smuggling, zero-width, bidi, homoglyph, base64 and URL encodings, and structural detection of data appended after an image | `tests/test_detect.py`, `tests/test_image_trailing.py` |
| A crafted file crashing the scan | Extractors skip a malformed part and carry on; Pillow's own guard exceptions become notes | `tests/test_image_trailing.py` |

## Out of scope

- **Detection is not a guarantee.** Archibald is a deterministic rule set. It
  will miss phrasings it has no rule for, and the corpus evaluation (`archibald
  eval`) says how often on the examples it has. It is a filter that raises the
  cost of an attack, not a proof that a document is safe to give an agent.
- **Text drawn in an image's pixels.** Reading it needs OCR, which is not built.
- **Archive formats other than DOCX**, and appended data after a TIFF.
- **Authentication.** The server has none; loopback is the boundary. If you pass
  `--allow-remote`, put it behind something that authenticates.
- **A malicious Python dependency.** Dependencies are few and pinned in
  `pyproject.toml` by minimum version; `make audit` runs `pip-audit`.

## Design commitments

These are contracts, not aspirations.

1. **Nothing read is ever followed, executed or rendered.** Archibald has no code
   path that acts on the content it scans.
2. **Nothing leaves the host except the one fetch you asked for.** No telemetry,
   no update check, no LLM call. The URL scanner is the only outbound request, and
   it runs only when you give it a URL.
3. **Every finding says why.** A rule id, a location and the evidence, never a bare
   score.
4. **A hostile file is a verdict, not a crash.**
5. **Loopback unless told otherwise**, enforced by the server itself.

## Supported versions

Until 1.0, only the latest release receives security fixes.
