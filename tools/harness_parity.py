"""Compare two harness logs section by section, and say plainly whether they agree.

WHY THIS EXISTS
    `tools/harness_ledger.py` measures **one** log at a time: what a run printed, counted from the log itself. The
    question that actually decides whether a change is finished is comparative — the `.sh` and `.ps1` harnesses are two
    implementations of one spec, so a run that passes 288 assertions on one side and 287 on the other is not two
    green runs, it is one assertion that only exists in one implementation. Answering that by eye means reading two
    ledgers and diffing per-section counts in your head, which is exactly the kind of measurement a document cannot
    keep true (see `docs/CHANGE_POLICY.md`).

WHAT IT COMPARES
    Two things, and only these: the section headings (number **and** title text) and the per-section PASS counts. A
    missing section, an extra section, a renamed heading, and a count that differs by one are four different defects
    and this tool names each as its own divergence rather than collapsing them into "totals disagree".

WHAT IT DELIBERATELY DOES NOT DO
    It does not re-derive the ledger `tools/harness_ledger.py` already writes, and it does not judge whether a
    divergence is *acceptable* — a harness legitimately gaining an assertion on one side before the other catches up is
    a real state of this project, and the tool's job is to report it, not to excuse it. FAIL/WARN counts are printed so
    a reader can see which side carries them, but parity here means "the two logs describe the same run shape", which
    is decided by headings and PASS counts.

USAGE
    python3 tools/harness_parity.py LOG_A LOG_B            # table + verdict
    python3 tools/harness_parity.py LOG_A LOG_B --quiet    # verdict line only

Exit codes: 0 parity · 1 divergence · 2 not exactly two usable logs given.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

SECTION_MARK = "§"

#: Byte-identical to `tools/harness_ledger.py`'s patterns on purpose: two tools that parse a harness log differently
#: would produce two answers to one question, and the disagreement between the tools would be harder to read than the
#: divergence they are reporting. The `.ps1` builds its headings from `$script:SectionMark`, so the mark is a literal
#: section sign in both logs.
HEADING_RE = re.compile(rf"^{SECTION_MARK}(?P<number>\d+)\s+(?P<title>.*\S)\s*$")
OUTCOME_RE = re.compile(r"^\s*(?P<kind>PASS|FAIL|WARN)\s+(?P<label>.*\S)\s*$")
SUMMARY_RE = re.compile(r"^== summary: (?P<pass>\d+) pass, (?P<fail>\d+) fail, (?P<warn>\d+) warn ==\s*$")


class ParityError(Exception):
    """A log cannot be read, or does not look like a harness log at all."""


@dataclass
class Section:
    number: int
    title: str
    passed: int = 0
    failed: int = 0
    warned: int = 0

    @property
    def heading(self) -> str:
        return f"{SECTION_MARK}{self.number} {self.title}"


@dataclass
class RunShape:
    """The part of one harness log this tool compares: its headings and their PASS counts."""

    label: str
    log_path: Path
    lines: int
    sections: list[Section] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    warned: int = 0
    printed: tuple[int, int, int] | None = None

    def totals(self) -> str:
        return f"{self.passed} / {self.failed} / {self.warned}"


def read_shape(path: Path, label: str) -> RunShape:
    """Count what one log printed. Same reading rules as `tools/harness_ledger.py`, applied to one log."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ParityError(f"{path} cannot be read: {exc}") from exc

    lines = text.splitlines()
    shape = RunShape(label=label, log_path=path, lines=len(lines))
    current: Section | None = None

    for number, raw in enumerate(lines, start=1):
        heading = HEADING_RE.match(raw)
        if heading:
            current = Section(number=int(heading.group("number")), title=heading.group("title"))
            shape.sections.append(current)
            continue

        outcome = OUTCOME_RE.match(raw)
        if outcome:
            if current is None:
                raise ParityError(f"{path}:{number}: an assertion line appears before any section heading")
            kind = outcome.group("kind")
            if kind == "PASS":
                current.passed += 1
            elif kind == "FAIL":
                current.failed += 1
            else:
                current.warned += 1
            continue

        summary = SUMMARY_RE.match(raw)
        if summary:
            shape.printed = (int(summary.group("pass")), int(summary.group("fail")), int(summary.group("warn")))

    if not shape.sections:
        raise ParityError(f"{path} has no {SECTION_MARK}<N> section headings - is it a harness log?")

    shape.passed = sum(section.passed for section in shape.sections)
    shape.failed = sum(section.failed for section in shape.sections)
    shape.warned = sum(section.warned for section in shape.sections)
    return shape


def compare(left: RunShape, right: RunShape) -> list[str]:
    """Every way the two logs disagree about the run they describe, as one line each."""
    findings: list[str] = []

    by_number = {section.number: section for section in right.sections}
    left_numbers = [section.number for section in left.sections]
    right_numbers = [section.number for section in right.sections]

    for missing in sorted(set(left_numbers) - set(right_numbers)):
        findings.append(f"{left.label} has {SECTION_MARK}{missing}, {right.label} does not")
    for extra in sorted(set(right_numbers) - set(left_numbers)):
        findings.append(f"{right.label} has {SECTION_MARK}{extra}, {left.label} does not")

    for section in left.sections:
        other = by_number.get(section.number)
        if other is None:
            continue
        if section.title != other.title:
            findings.append(
                f"{SECTION_MARK}{section.number} heading differs: {left.label} says {section.title!r}, "
                f"{right.label} says {other.title!r}"
            )
        if section.passed != other.passed:
            findings.append(
                f"{SECTION_MARK}{section.number} PASS count differs: {left.label} {section.passed}, "
                f"{right.label} {other.passed}"
            )

    if left.printed is not None and right.printed is not None and left.printed != right.printed:
        findings.append(f"summary lines differ: {left.label} {left.totals()}, {right.label} {right.totals()}")

    return findings


def render_table(left: RunShape, right: RunShape) -> str:
    """One row per section, both sides' PASS counts side by side, with the mismatch marked in the verdict column."""
    right_by_number = {section.number: section for section in right.sections}
    numbers = sorted({section.number for section in left.sections} | set(right_by_number))

    headings = [section.heading for section in left.sections + right.sections] + [f"{SECTION_MARK}?", "log lines"]
    width = max(len(heading) for heading in headings)

    out = [
        f"{'section':<{width}}  {left.label:>12}  {right.label:>12}  verdict",
        f"{'-' * width}  {'-' * 12}  {'-' * 12}  -------",
    ]

    for number in numbers:
        left_section = next((s for s in left.sections if s.number == number), None)
        right_section = right_by_number.get(number)
        present = [s for s in (left_section, right_section) if s is not None]
        name = max((s.heading for s in present), key=len, default=f"{SECTION_MARK}{number}")
        left_count = "—" if left_section is None else str(left_section.passed)
        right_count = "—" if right_section is None else str(right_section.passed)

        same_heading = (
            left_section is not None and right_section is not None and left_section.title == right_section.title
        )
        agree = left_count == right_count and same_heading
        out.append(f"{name:<{width}}  {left_count:>12}  {right_count:>12}  {'ok' if agree else 'DIFFERS'}")

    out.append(f"{'-' * width}  {'-' * 12}  {'-' * 12}  -------")
    out.append(f"{'counted pass / fail / warn':<{width}}  {left.totals():>12}  {right.totals():>12}")
    out.append(f"{'log lines':<{width}}  {left.lines:>12}  {right.lines:>12}")
    out.append(f"{'sections':<{width}}  {len(left.sections):>12}  {len(right.sections):>12}")
    return "\n".join(out)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two smoke-harness logs section by section.")
    parser.add_argument("logs", nargs="*", help="exactly two harness log paths (one per harness implementation)")
    parser.add_argument("--label", action="append", default=[], help="name for a side, repeated once per log in order")
    parser.add_argument("--quiet", action="store_true", help="print the verdict only, not the table")
    args = parser.parse_args(argv)

    if len(args.logs) != 2:
        print(f"exactly two logs are required (got {len(args.logs)}); this tool compares one pair", file=sys.stderr)
        return 2

    labels = list(args.label)
    shapes: list[RunShape] = []
    for index, raw in enumerate(args.logs):
        path = Path(raw)
        label = labels[index] if index < len(labels) else path.parent.name
        try:
            shapes.append(read_shape(path, label))
        except ParityError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    left, right = shapes
    if not args.quiet:
        print(render_table(left, right))

    findings = compare(left, right)
    for finding in findings:
        print(f"DIVERGES {finding}", file=sys.stderr)

    if findings:
        print(f"parity: NO ({len(findings)} divergence(s)) between {left.label} and {right.label}")
        return 1

    print(
        f"parity: OK - {len(left.sections)} sections match heading-for-heading, "
        f"{left.passed}/{left.failed}/{left.warned} on both sides ({left.label}, {right.label})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
