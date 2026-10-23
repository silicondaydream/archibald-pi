"""Segments in, Verdict out.

Three adjustments sit on top of the raw rule matches, and all three are
explained in the finding's message rather than applied silently:

* **Hidden content is escalated one step.** An instruction a person cannot see
  but a model can read is the defining shape of indirect prompt injection.
* **Decoded content is escalated one step.** Base64 or tag-smuggled text that
  turns out to be an instruction was encoded on purpose.
* **Quoted content is de-escalated one step.** "Attackers write 'ignore previous
  instructions'" is a sentence *about* injection, which a security blog is full
  of. It still reports — just lower.
"""

from __future__ import annotations

import re

from archibald.models import (
    Finding,
    HiddenText,
    Level,
    Segment,
    Severity,
    Verdict,
    bump,
)
from archibald.normalize import variants
from archibald.rules import RULES

# Probability-style weights: the score is 1 - Π(1 - w), so findings compound
# without any number of weak signals ever reaching 100 on their own.
WEIGHTS: dict[Severity, float] = {
    "info": 0.02,
    "low": 0.06,
    "medium": 0.20,
    "high": 0.45,
    "critical": 0.70,
}
LEVELS: tuple[tuple[int, Level], ...] = ((70, "injection"), (40, "likely"), (12, "suspicious"))

MAX_SEGMENT_CHARS = 200_000
MAX_MATCHES_PER_RULE = 5
CONTEXT = 80
_QUOTES_OPEN = '"“«'
_QUOTES_CLOSE = '"”»'


def _evidence(text: str, start: int, end: int) -> str:
    lo, hi = max(0, start - CONTEXT), min(len(text), end + CONTEXT)
    snippet = text[lo:hi].replace("\n", " ")
    return ("…" if lo else "") + snippet + ("…" if hi < len(text) else "")


def _is_quoted(text: str, start: int, end: int) -> bool:
    """True when the match sits between an opening and a closing quote on its line."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end == -1 else line_end
    before = text[max(line_start, start - 120) : start]
    after = text[end : min(line_end, end + 120)]
    opens = sum(before.count(q) for q in _QUOTES_OPEN)
    closes_before = sum(before.count(q) for q in "”»")
    # Straight quotes open and close with the same character: an odd count before
    # the match means we are inside a pair.
    straight_open = before.count('"') % 2 == 1
    curly_open = (opens - before.count('"')) > closes_before
    return (straight_open or curly_open) and any(q in after for q in _QUOTES_CLOSE)


def _scan_segment(seg: Segment) -> list[Finding]:
    text = seg.text[:MAX_SEGMENT_CHARS]
    found: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    forms, tricks = variants(text)

    for trick in tricks:
        severity: Severity = trick.severity  # type: ignore[assignment]
        found.append(
            Finding(
                rule=trick.rule,
                category="obfuscation",
                severity=bump(severity) if seg.hidden else severity,
                message=trick.message,
                evidence=trick.evidence,
                match=trick.evidence[:80],
                source=seg.source,
                location=seg.location,
                hidden=seg.hidden,
                hidden_reason=seg.hidden_reason,
            )
        )

    for form in forms:
        for rule in RULES:
            count = 0
            for m in rule.pattern.finditer(form.text):
                key = (rule.id, re.sub(r"\s+", " ", m.group().lower()).strip())
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                if count > MAX_MATCHES_PER_RULE:
                    break

                severity = rule.severity
                notes: list[str] = []
                if _is_quoted(form.text, m.start(), m.end()):
                    severity = bump(severity, -1)
                    notes.append("appears quoted, so it may be discussion rather than an attack")
                if seg.hidden:
                    severity = bump(severity)
                    notes.append(f"in content hidden from people ({seg.hidden_reason})")
                if form.decoded_from:
                    severity = bump(severity)
                    notes.append(f"only visible after decoding: {form.decoded_from}")

                message = rule.message + ("; " + "; ".join(notes) if notes else "")
                found.append(
                    Finding(
                        rule=rule.id,
                        category=rule.category,
                        severity=severity,
                        message=message,
                        evidence=_evidence(form.text, m.start(), m.end()),
                        match=m.group(),
                        source=seg.source,
                        location=seg.location,
                        hidden=seg.hidden,
                        hidden_reason=seg.hidden_reason,
                        decoded_from=form.decoded_from,
                    )
                )

    if seg.hidden and not seg.routine and len(text.strip()) >= 20:
        long = len(text.strip()) >= 120
        found.append(
            Finding(
                rule="concealment.hidden_text",
                category="concealment",
                severity="medium" if long else "low",
                message=f"Text that people cannot see ({seg.hidden_reason})",
                evidence=_evidence(text.strip(), 0, min(len(text.strip()), 120)),
                match=text.strip()[:80],
                source=seg.source,
                location=seg.location,
                hidden=True,
                hidden_reason=seg.hidden_reason,
            )
        )
    return found


def score(findings: list[Finding]) -> int:
    remaining = 1.0
    for f in findings:
        remaining *= 1.0 - WEIGHTS[f.severity]
    return round(100 * (1.0 - remaining))


def level_for(value: int) -> Level:
    for threshold, level in LEVELS:
        if value >= threshold:
            return level
    return "clean"


def _summary(level: Level, findings: list[Finding], hidden: list[HiddenText]) -> str:
    attacks = [f for f in findings if f.category not in ("concealment", "obfuscation")]
    in_hidden = sum(1 for f in attacks if f.hidden)
    if level == "clean" and not findings:
        return "Nothing here reads like an instruction to a model."
    if not attacks:
        parts = []
        if hidden:
            parts.append(f"{len(hidden)} piece{'s' if len(hidden) != 1 else ''} of hidden content")
        tricks = sum(1 for f in findings if f.category == "obfuscation")
        if tricks:
            parts.append(f"{tricks} concealment trick{'s' if tricks != 1 else ''}")
        return "No injection language, but worth a look: " + " and ".join(parts) + "."
    label = {
        "clean": "Low-signal matches only",
        "suspicious": "Suspicious",
        "likely": "Likely prompt injection",
        "injection": "Prompt injection",
    }[level]
    extra = f", {in_hidden} of them hidden from people" if in_hidden else ""
    return f"{label} · {len(attacks)} instruction pattern{'s' if len(attacks) != 1 else ''}{extra}."


def scan_segments(
    segments: list[Segment], input_kind: str, notes: list[str] | None = None
) -> Verdict:
    findings: list[Finding] = []
    hidden: list[HiddenText] = []
    for seg in segments:
        if not seg.text or not seg.text.strip():
            continue
        seg_findings = _scan_segment(seg)
        findings.extend(seg_findings)
        # Routine non-visible text (metadata, alt text) is only surfaced when it
        # actually tripped something.
        if seg.hidden and len(seg.text.strip()) >= 3 and (not seg.routine or seg_findings):
            hidden.append(
                HiddenText(
                    text=seg.text.strip()[:2000],
                    source=seg.source,
                    location=seg.location,
                    reason=seg.hidden_reason or "hidden",
                )
            )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order[f.severity], not f.hidden, f.location))
    value = score(findings)
    level = level_for(value)
    return Verdict(
        score=value,
        level=level,
        summary=_summary(level, findings, hidden),
        input_kind=input_kind,
        findings=findings,
        hidden=hidden,
        segments_scanned=len(segments),
        notes=notes or [],
    )


def scan_text(text: str) -> Verdict:
    """The simplest entry point: one block of plain text."""
    return scan_segments([Segment(text=text, source="text", location="input")], "text")
