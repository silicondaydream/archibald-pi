# Rules and scoring

How Archibald turns text into a verdict. Everything here is deterministic: the
same input always gets the same score, and every point of it is attributable to a
named rule.

## The pipeline

1. **Extract.** An extractor (`src/archibald/extract/`) turns the input into
   *segments*: a piece of text, where it was (`page 3 › annotation`, `div.sr-only`,
   `EXIF UserComment`), and whether a person could see it.
2. **Decode.** `normalize.variants()` produces every readable form of each
   segment: the original; the text with Unicode tag characters decoded (ASCII
   smuggling); one *normalised* form (NFKC, invisible characters removed,
   Cyrillic/Greek look-alikes folded to Latin); and each base64 or URL-encoded
   run, decoded. Each concealment trick it had to undo is itself a finding.
3. **Match.** Every rule runs against every variant, at most
   5 matches per rule per segment.
4. **Adjust.** Each match's severity moves one step on the scale
   `info → low → medium → high → critical`:
   - **up** if the segment is hidden from people — the defining shape of
     indirect injection;
   - **up** if the match only appears after decoding — someone encoded it on
     purpose;
   - **down** if the match sits inside quotation marks on its line — someone
     *writing about* injection, which a security blog is full of.

   Every adjustment is written into the finding's message, never applied
   silently.
5. **Score.** Findings combine like independent probabilities:
   `score = 100 × (1 − Π(1 − w))`, with weights

   | Severity | Weight |
   |---|---|
   | info | 0.02 |
   | low | 0.06 |
   | medium | 0.2 |
   | high | 0.45 |
   | critical | 0.7 |

   so findings compound, but no number of weak signals alone reaches 100.
6. **Level.**

   | Score | Level |
   |---|---|
   | ≥ 70 | **injection** |
   | ≥ 40 | **likely** |
   | ≥ 12 | **suspicious** |
   | below that | **clean** |

   `archibald scan` exits 1 at or above `--fail-at` (default `likely`).

## The rule set

21 rules in seven categories, following the publicly documented
prompt-injection families (OWASP LLM01; Greshake et al., arXiv:2302.12173; Perez &
Ribeiro, arXiv:2211.09527).

| Rule | Category | Base severity | What it means |
|---|---|---|---|
| `override.ignore_previous` | override | high | Tells the model to discard its existing instructions |
| `override.new_instructions` | override | medium | Announces replacement instructions |
| `override.from_now_on` | override | medium | Tries to change the model's behaviour for the rest of the conversation |
| `override.priority_claim` | override | high | Claims its instructions outrank the model's own |
| `role.template_token` | role | high | Contains chat-template control tokens used to fake a conversation turn |
| `role.fake_turn` | role | medium | Starts a line as if it were a system or assistant message |
| `role.you_are_now` | role | medium | Tries to reassign the model's identity |
| `role.jailbreak_mode` | role | high | Invokes a known jailbreak persona or 'mode' |
| `exfil.reveal_prompt` | exfiltration | high | Asks the model to disclose its hidden instructions |
| `exfil.repeat_above` | exfiltration | high | Asks the model to reproduce its context verbatim |
| `exfil.markdown_beacon` | exfiltration | high | Markdown image whose URL carries a query parameter — a classic data-exfiltration beacon |
| `exfil.send_to` | exfiltration | high | Instructs sending data to an external address |
| `exfil.credential_request` | exfiltration | high | Tells the model to ask the user for secrets |
| `tool.fake_call_markup` | tool_hijack | high | Contains tool-call markup, as if the model had already decided to call a tool |
| `tool.fake_call_json` | tool_hijack | medium | Contains JSON shaped like a function/tool call |
| `tool.invoke_instruction` | tool_hijack | medium | Tells the model to use one of its tools |
| `delimiter.end_of_context` | delimiter | medium | Pretends the document has ended so what follows reads as instructions |
| `delimiter.begin_instructions` | delimiter | high | Opens a fake block of system or admin instructions |
| `addressed.to_ai` | addressed | medium | Written to an AI reader rather than a human one |
| `addressed.output_hijack` | addressed | medium | Dictates the model's exact output |
| `secrecy.hide_from_user` | secrecy | high | Asks the model to keep something from the user |

## Concealment and obfuscation findings

These come from extraction and decoding rather than from `rules.py`. They report
*how* text was hidden, independently of what it says.

| Finding | When |
|---|---|
| `concealment.hidden_text` | 20+ characters of non-routine text people cannot see (hidden CSS, white text, invisible PDF text, data after an image) |
| `obfuscation.unicode_tags` | Invisible Unicode tag characters carrying ASCII (high) |
| `obfuscation.zero_width` | Zero-width characters splitting words, not just a stray BOM |
| `obfuscation.bidi_controls` | Bidirectional control characters that reorder what is displayed |
| `obfuscation.mixed_script` | Cyrillic or Greek look-alikes mixed into Latin words |

"Routine" hidden text — an image's camera model, a PDF's producer string — is
scanned but does not raise `concealment.hidden_text` on its own.

## Measuring it

`archibald eval` runs the corpus in `corpus/` (injections by technique, and benign
text that deliberately looks close) and reports precision, recall, F1, per-group
results and every mistake. `make eval` fails below precision 0.90 or recall 0.80.

The corpus scores raw strings, so it measures the rules, not the extractors;
`tests/` covers extraction.
