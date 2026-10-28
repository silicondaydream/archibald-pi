"""The one JSON envelope shared by the library, the CLI and the HTTP API.

Extractors turn an input into Segments — a piece of text plus where it came from
and whether a human would have seen it. The detector turns Segments into
Findings, and the scorer turns Findings into a Verdict.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Level = Literal["clean", "suspicious", "likely", "injection"]

SEVERITY_ORDER: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")


class NotScannedError(Exception):
    """The input was refused whole: too large, corrupt, or a format not opened.

    Raised, never returned as a note: a verdict built from no segments scores 0
    and reads as clean, and a gate would wave through exactly the file an
    attacker padded past the limit or wrapped in an archive.
    """


def bump(severity: Severity, steps: int = 1) -> Severity:
    """Move a severity up (or down, with a negative step), clamped to the scale."""
    i = SEVERITY_ORDER.index(severity) + steps
    return SEVERITY_ORDER[max(0, min(i, len(SEVERITY_ORDER) - 1))]


class Segment(BaseModel):
    """A piece of text pulled out of an input, with its provenance."""

    text: str
    # Machine-readable origin, e.g. "html.visible", "form.placeholder", "image.exif".
    source: str
    # Human-readable place, e.g. "form#signup > input[name=email] @placeholder".
    location: str
    # True when a person looking at the rendered page or document would not see it.
    hidden: bool = False
    hidden_reason: str | None = None
    # Not visible *by nature* — metadata, alt text, comments. An instruction found
    # here is still escalated, but its mere presence is not reported as concealment,
    # or every page with a meta description would be flagged.
    routine: bool = False


class Finding(BaseModel):
    rule: str
    category: str
    severity: Severity
    message: str
    # The matched text, and up to ~80 characters either side of it.
    evidence: str
    match: str
    source: str
    location: str
    hidden: bool = False
    hidden_reason: str | None = None
    # Set when the text only matched after decoding (base64, Unicode tags, …).
    decoded_from: str | None = None


class HiddenText(BaseModel):
    """Concealed content, surfaced so a person can read what was hidden."""

    text: str
    source: str
    location: str
    reason: str


class Verdict(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Level
    summary: str
    input_kind: str
    findings: list[Finding]
    hidden: list[HiddenText]
    segments_scanned: int
    notes: list[str] = []
