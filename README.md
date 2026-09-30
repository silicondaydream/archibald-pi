# Archibald

**A prompt-injection inspector.** Point it at text, a web page, or a file, and it
finds instructions aimed at an AI — including the ones a person was never meant
to see — and shows you exactly where they are.

Prompt injection (OWASP LLM01) is what happens when text a model *reads* gets
treated as text a model *obeys*. The dangerous version is indirect: the
instruction sits in a web page, an email, a PDF or an image's metadata that an
AI agent later processes, usually hidden from the human who shared it. Archibald
takes that content apart, finds every place an instruction could hide, and scores
each piece.

It classifies and reports. It never follows, runs, renders or forwards what it
reads.

## What it inspects

| Input | Where it looks |
|---|---|
| **Text / Markdown** | The text itself, HTML comments, `[//]: # (…)` link-reference comments, image alt text and titles |
| **Web pages (URL or pasted HTML)** | Visible text · **hidden text** (`display:none`, `visibility:hidden`, `opacity:0`, zero font size, off-screen positioning, clipping, zero-size boxes, `hidden` attribute, `<template>`, screen-reader-only classes, **text coloured to match its background**) · **form fields** (placeholders, default values, hidden inputs, labels) · alt / title / aria-* / data-* attributes · `<title>`, `<meta>` and JSON-LD **metadata** · HTML comments · `<noscript>` · non-JS `<script>` blocks · iframe `srcdoc` and `data:` URIs (scanned recursively) |
| **SVG** | Everything above, plus `<desc>`, `<title>`, `<metadata>` and presentation attributes (`opacity="0"`, `fill="none"`) |
| **PDF** | Page text · **invisible text** (render mode 3, white fill, sub-1pt fonts) · document metadata · annotations · form field values and tooltips |
| **DOCX** | Body, headers, footers, footnotes, comments · **hidden runs** (`vanish`), white text, 1pt text · document properties |
| **Images** (PNG, JPEG, GIF, WebP, TIFF) | EXIF (incl. UserComment and XP* tags) · PNG text chunks · XMP · comments · **data appended after the end of the image** |

Every piece of text — and each *decoded* form of it — is checked against the
rule set:

- **Rules:** instruction override, role and chat-template impersonation,
  exfiltration (system-prompt leaks, markdown-image beacons, "send the
  conversation to…"), tool-call hijacking, delimiter confusion, text addressed to
  an AI, and secrecy ("don't tell the user").
- **Decoding:** Unicode tag-character "ASCII smuggling", zero-width splitting,
  bidirectional controls, Cyrillic/Greek look-alike letters, base64 and
  URL-encoding. The text is normalised or decoded, then scanned again.
- **Context:** an instruction in hidden content is escalated one step. An
  instruction that only appears after decoding is escalated one step. One that
  appears inside quotation marks (someone *writing about* injection) is
  de-escalated one step.

The result is a score from 0 to 100 and a level: **clean**, **suspicious**,
**likely** or **injection**. Every finding comes with its rule, location and
evidence.

## Run it

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

.venv/bin/archibald serve          # UI at http://127.0.0.1:8741
.venv/bin/archibald scan page.html # or a .pdf, .docx, .png, .md, a URL, or - for stdin
.venv/bin/archibald scan https://example.com --json
.venv/bin/archibald eval           # precision / recall against corpus/
.venv/bin/pytest -q
```

`scan` exits 1 at or above `--fail-at` (default `likely`), so it can gate a
pipeline that feeds untrusted documents to an agent.

The UI has built-in samples for each capability: a poisoned product page, a
clean page, an email with smuggled text, an image with metadata, a résumé PDF
with invisible text, and a Word report with hidden runs.

## Safety

- **Loopback only.** `serve` refuses to bind anywhere else unless you pass
  `--allow-remote`, because the URL scanner fetches pages on request.
- **The URL fetcher is SSRF-guarded:** http(s) only, public addresses only
  (every resolved address is checked, including each redirect hop), no proxy
  settings from the environment, 10 s and 5 MB limits.
- **Nothing is rendered or run.** HTML is parsed with the standard library
  parser, and scripts are never executed. Image pixels are never decoded. DOCX
  XML goes through `defusedxml`, with the archive size-checked before it is
  unzipped.
- **The UI treats every result as hostile text.** Everything is written with
  `textContent`, and the CSP allows no inline script and no third-party origins.
- **The corpus is defensive test data.** Every example is a harmless
  demonstration ("reply with PWNED"). Addresses use the reserved `.example`
  domain, and each technique cites its public source.

## Layout

```
src/archibald/
  models.py      Segment → Finding → Verdict: the one JSON envelope
  rules.py       the rule set
  normalize.py   decoding and de-obfuscation variants
  detect.py      scoring, escalation, verdicts
  extract/       html (+css), text, pdf, docx, image — each turns input into Segments
  fetch.py       the SSRF-guarded URL fetcher
  scan.py        public API: scan_string / scan_bytes / scan_url
  evaluate.py    corpus precision / recall
  samples.py     built-in demo inputs (binaries generated in memory)
  server.py      FastAPI backend for the UI
  web/           the UI — static HTML, CSS and JS, no build step
corpus/          labelled injection and benign examples
tests/
```
