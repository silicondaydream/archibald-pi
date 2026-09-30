"""Score the detector against the labelled corpus.

An example counts as *flagged* when its verdict is "likely" or "injection"
(score ≥ 40). "Suspicious" is deliberately not a positive: it is the level for a
single medium-strength signal, which ordinary writing produces now and then.

The numbers this prints are the honest baseline to improve against — misses are
listed, not hidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from archibald.detect import scan_text

POSITIVE_AT = 40


@dataclass
class Example:
    text: str
    label: str  # "injection" | "benign"
    group: str  # technique or benign set name


@dataclass
class Report:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    by_group: dict[str, list[int]] = field(default_factory=dict)  # group -> [hit, total]
    mistakes: list[tuple[Example, int, str]] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


def load_corpus(root: Path) -> list[Example]:
    examples: list[Example] = []
    for path in sorted(root.glob("*/*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        label = doc["label"]
        group = doc.get("technique") or path.stem
        for text in doc["examples"]:
            examples.append(Example(text=text, label=label, group=f"{label}/{group}"))
    return examples


def evaluate(root: Path) -> Report:
    report = Report()
    for ex in load_corpus(root):
        verdict = scan_text(ex.text)
        flagged = verdict.score >= POSITIVE_AT
        stats = report.by_group.setdefault(ex.group, [0, 0])
        stats[1] += 1
        correct = flagged == (ex.label == "injection")
        stats[0] += int(correct)
        if ex.label == "injection":
            report.tp += int(flagged)
            report.fn += int(not flagged)
        else:
            report.fp += int(flagged)
            report.tn += int(not flagged)
        if not correct:
            report.mistakes.append((ex, verdict.score, verdict.level))
    return report


def format_report(report: Report) -> str:
    total = report.tp + report.fp + report.tn + report.fn
    lines = [
        f"Archibald corpus evaluation — {total} examples (flagged = score ≥ {POSITIVE_AT})",
        "",
        "                 predicted injection   predicted clean",
        f"  injection      {report.tp:>10}            {report.fn:>10}",
        f"  benign         {report.fp:>10}            {report.tn:>10}",
        "",
        f"  precision {report.precision:.2%}   recall {report.recall:.2%}   F1 {report.f1:.2%}",
        "",
        "  per group (correct / total):",
    ]
    for group, (hit, n) in sorted(report.by_group.items()):
        lines.append(f"    {group:<34} {hit:>2} / {n:<2}")
    if report.mistakes:
        lines += ["", "  mistakes:"]
        for ex, score, level in report.mistakes:
            kind = "missed" if ex.label == "injection" else "false alarm"
            preview = ex.text.encode("unicode_escape").decode()[:90]
            lines.append(f"    [{kind}, score {score}, {level}] {ex.group}: {preview}")
    return "\n".join(lines)
