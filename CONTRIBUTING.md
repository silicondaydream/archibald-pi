# Contributing

Archibald is part of the Havarti SecOps tools, and follows the same standards.
Issues and pull requests are welcome; there is no process to speak of beyond what
is written here, and no promises about response time.

## Getting set up

```console
make setup        # venv + pip install -e ".[dev]"
make serve        # UI at http://127.0.0.1:8741
make check        # ruff, mypy --strict, tests, and the eval floors
```

Python 3.11+. No Docker, no build step for the UI.

## The rules that are not negotiable

Most of this codebase is open to opinion. These are not, because each one is a
safety property that a well-meaning change could quietly remove.

1. **Archibald never acts on what it reads.** No code path follows, executes,
   renders or forwards scanned content. A feature that needs to is a different
   tool.
2. **The only outbound request is the one the user asked for**, and it goes
   through `fetch.py`. No other module imports an HTTP client.
3. **`fetch.py` connects to the address it checked.** Resolve once, check every
   answer, pin the connection, repeat per redirect hop. Do not hand httpx a
   hostname to resolve on its own.
4. **The server answers loopback only unless `ARCHIBALD_ALLOW_REMOTE=1`**, checked
   in the app, peer and Host header both.
5. **Pixels are never decoded.** Image extraction reads structure and metadata.
   `tests/test_image_trailing.py` patches `Image.load` to fail; keep it passing.
6. **Every limit is a constant at the top of its module** and is checked before
   the work, not after.
7. **The UI writes text with `textContent`.** No `innerHTML`, no inline script,
   no third-party origin. No hex colour outside `web/tokens.css`.

## Adding a rule

`src/archibald/rules.py`. A rule is an id (`category.name`), a category, a
severity and a message that says in plain words what the text is trying to do.

- **Specific beats broad.** "Please ignore my previous email" must stay clean.
  Run `make eval` before and after; a new rule that costs precision needs a very
  good reason.
- **Add corpus examples in the same PR**: at least one injection it catches and
  one benign sentence near it that it must not.
- **Linear-time patterns only in spirit**: bounded repetition (`{0,40}`), no
  nested quantifiers. Python's `re` backtracks, and the input is hostile.

## Adding corpus examples

`corpus/injections/<technique>.yaml` and `corpus/benign/<kind>.yaml`. Every
injection file carries a `source:` citing the public write-up of the technique.
Examples are harmless demonstrations ("reply with PWNED"); addresses use the
reserved `.example` domain. Never paste a real victim's text or a working
payload against a named product.

## Adding an extractor

`src/archibald/extract/`. An extractor turns bytes into `Segment`s — text plus
where it was and whether a person could see it — and returns notes for anything
it skipped. Size-check before parsing, catch the parser's own exceptions as
notes, and add a test with a malformed file as well as a well-formed one.

## Testing

```console
make test         # pytest
make eval         # precision/recall against corpus/, failing below the floors
```

A fix for something an attacker could trigger comes with a test that fails
without it. Say so in the commit message.

## Commits and pull requests

Small, with one goal each. The subject says what changed in the imperative; the
body says why, what was verified, and — for a bug — how it was found. Stacked PRs
are fine and preferred over one large one. The Arboria Foundation's full
standards are the source of truth and are linked from the README.

## Things that will be declined

Not because they are bad ideas in general, but because they are wrong *here*.

- **Calling an LLM to classify.** It would send the scanned content off the host,
  make verdicts unreproducible, and put a model that can be prompt-injected in
  charge of detecting prompt injection.
- **Rendering pages in a headless browser.** It would run the scripts Archibald
  exists to avoid running. Hidden-text detection stays static.
- **Following or acting on found instructions**, even "safely", even in a sandbox.
- **Telemetry, update checks, or any second outbound call.**
- **Auto-remediation that rewrites the user's document.** Archibald reports; a
  separate tool can strip.
- **A plugin system for rules.** Rules are reviewed code with tests and corpus
  examples, not something loaded at runtime.

If you think one of these is wrong, open an issue and argue the case before
writing the patch.

## Style

`ruff` (line length 100) and `mypy --strict`. Comments explain **why**, not what.
