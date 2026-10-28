# Threat model

Why Archibald is built the way it is. The summary table is in
[SECURITY.md](../SECURITY.md); this is the reasoning behind it.

## Who we are defending against

1. **The author of the content.** Whoever wrote the page, PDF, email or image
   wants an AI that reads it to do something its user did not ask for. They know
   Archibald exists, can read its rules, and will try to hide from it.
2. **The author of a URL.** "Scan this URL" makes Archibald fetch from somewhere
   an attacker chose — the classic server-side request forgery shape.
3. **A web page in the operator's own browser.** It cannot see Archibald, but it
   can make requests to `127.0.0.1` if it can get a name to point there.

The operator is trusted. The controls exist to keep the *tool* from being turned
against the person running it.

## Why Archibald never acts on what it reads

The only safe way to inspect an instruction is to treat it as data all the way
through. So there is no code path that follows, executes, renders or forwards
scanned content: HTML is parsed with the standard-library parser and never
rendered, scripts never run, image pixels are never decoded, and nothing is sent
to a model. This is also why classification is a deterministic rule set rather
than an LLM: a model asked "is this a prompt injection?" can itself be prompt-
injected by the text it is judging.

## Why hidden text gets extra weight

Indirect prompt injection is defined by an asymmetry: the model sees text the
person does not. So extraction records, for every piece of text, whether a person
could see it — CSS that hides it, a colour that matches the background, a
zero-size box, a PDF render mode, a DOCX `vanish` run, metadata, data after the
end of an image. A rule match in hidden text is escalated one step, and a large
block of hidden text is a finding on its own. See [rules.md](rules.md).

The extractors work from structure, not from searching for markers, because an
attacker controls the bytes: data appended after an image is found by walking
the format to its real end, since a search for the end marker can be fooled by a
payload that ends with a fake one.

## Why the URL fetcher is pinned

Checking that a name resolves to a public address is not enough if the library
then resolves it *again* to connect: a DNS-rebinding server answers the check
with a public address and the connection with `169.254.169.254`. So the fetcher
resolves once, refuses if any answer is not public, and connects to the address
it checked — sending the name as the Host header and as the TLS server name, so
the certificate is still verified against the name. Every redirect hop goes
through the same steps. Connections are not reused, because a pool keyed by IP
would let a connection opened for one name serve another.

## Why the server checks the Host header

`archibald serve` refuses to bind anything but loopback, but the app can be
started other ways, so it checks every request itself. The peer address alone is
not enough: a page in the operator's browser can rebind a name it owns to
`127.0.0.1`, and its requests then arrive from a loopback peer. They still carry
that name as the Host header, so the server answers only to `127.0.0.1`,
`localhost` and `[::1]`.

## Why every input is bounded before it is parsed

Files are capped at 25 MB, pasted text at 2,000,000 characters, fetched pages and
HTML at 5 MB, PDFs at 200 pages. A DOCX archive's member count and total
uncompressed size are checked before anything is unzipped; compressed PNG text is
inflated to at most 1 MB per chunk. Checking a size after the work is done is a
post-mortem, not a limit.

## Known gaps

- **No OCR.** Text drawn in an image's pixels is not read.
- **Archives other than DOCX are not opened**, and data appended after a TIFF is
  not detected (TIFF offsets can point anywhere in the file).
- **PDF white text** is judged against a white page only.
- **The rule set misses phrasings it has no rule for.** `make eval` measures how
  often on the corpus; recall is 83% today.
- **`eval` measures the rules, not the extractors**: it scores raw strings.
- **Python's `re` backtracks.** Rules use bounded repetition and no nested
  quantifiers, and segments are capped at 200,000 characters, but there is no
  linear-time guarantee as there is in Lincoln.
