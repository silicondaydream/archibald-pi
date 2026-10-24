# HTTP API

`archibald serve` starts this on `127.0.0.1:8741`, with the web UI at `/`. The UI
is a client of exactly these routes.

## Access

Loopback only. Every request must come from a loopback peer **and** carry a Host
header naming loopback (`127.0.0.1`, `localhost`, `[::1]`, with any port);
anything else is a `403`. `archibald serve --allow-remote` sets
`ARCHIBALD_ALLOW_REMOTE=1`, which lifts both checks — put it behind something
that authenticates if you do. There is no other authentication.

## Headers

Every response, refusals included: a CSP with `default-src 'none'` and `'self'`
only for scripts, styles, images, fonts and fetches; `X-Content-Type-Options:
nosniff`; `Referrer-Policy: no-referrer`; `Cache-Control: no-store`. The OpenAPI
and docs routes are disabled.

## Routes

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/api/health` | | `{"status": "ok", "version": …}` |
| POST | `/api/scan/text` | `{"text": "…", "kind": "auto"\|"text"\|"html"}` | a Verdict. `400` if the text is blank; text is capped at 2,000,000 characters |
| POST | `/api/scan/url` | `{"url": "…"}` | a Verdict. `400` with the reason if the fetcher refuses the URL (see [threat-model.md](threat-model.md#why-the-url-fetcher-is-pinned)) |
| POST | `/api/scan/file` | multipart `file` | a Verdict. `413` over 25 MB, `400` if empty. Type is sniffed from content, not the name |
| GET | `/api/samples` | | the built-in demo inputs |
| POST | `/api/scan/sample/{id}` | | a Verdict for one sample; `404` if unknown |

Errors are `{"detail": "…"}`.

## The Verdict

The same JSON as `archibald scan --json` (abridged):

```json
{
  "score": 88,
  "level": "injection",
  "summary": "…",
  "input_kind": "html",
  "segments_scanned": 14,
  "findings": [
    {
      "rule": "override.ignore_previous",
      "category": "override",
      "severity": "critical",
      "message": "Tells the model to discard its existing instructions — in content hidden from people (display:none)",
      "location": "reviews.html › div.review-note",
      "evidence": "…ignore all previous instructions…",
      "match": "ignore all previous instructions",
      "source": "html.hidden",
      "hidden": true,
      "hidden_reason": "display:none",
      "decoded_from": null
    }
  ],
  "hidden": [{ "text": "…", "source": "…", "location": "…", "reason": "…" }],
  "notes": ["…"]
}
```

`level` is one of `clean`, `suspicious`, `likely`, `injection`; see
[rules.md](rules.md) for how the score is built.
