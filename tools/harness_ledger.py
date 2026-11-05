"""Turn a smoke-harness log into a machine-readable ledger.

WHY THIS EXISTS
    SMOKE_TESTING.md used to restate, by hand, everything a harness run already prints: the pass/fail/warn totals, how
    many lines each log held, the line number of the summary, the line number of every section heading, and the
    per-section assertion counts. Those are measurements **of one log**, so every change to either harness shifted
    dozens of sentences across two documents — a documentation cost with no engineering content. This tool makes the
    measurement a generated artifact instead: run a harness, point this at its log, and the ledger is written out.
    Documents then link to the ledger rather than copying it (see docs/CHANGE_POLICY.md).

WHAT IT READS
    A harness log exactly as both scripts print it: section headings beginning `§<N>`, assertion lines prefixed
    `  PASS  `, `  FAIL  ` or `  WARN  `, and a closing `== summary: N pass, M fail, K warn ==`. Nothing is inferred
    from the harness source, so the ledger describes the run that happened rather than the script that could have.

WHAT IT CHECKS
    The counted PASS/FAIL/WARN lines are compared against the harness's own summary line, and the per-section counts
    are summed against that total. A disagreement is reported as a finding and makes `--check` exit non-zero: the tool
    is only useful because it can say "this log does not add up".

USAGE
    python3 tools/harness_ledger.py LOG [LOG...] [--label NAME ...]      # one entry per log, labels in order
    python3 tools/harness_ledger.py --write                              # write reports/harness-ledger.{md,json}
    python3 tools/harness_ledger.py --print                              # print the markdown instead of writing
    python3 tools/harness_ledger.py --check                              # exit 1 on any inconsistency

Exit codes: 0 clean · 1 inconsistent (--check) or unreadable log · 2 no usable log given.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

SECTION_MARK = "§"

#: Both harnesses print headings as `§<N> <title>`; the `.ps1` builds them from `$script:SectionMark`, so the mark is a
#: literal section sign in both logs (MEASURED: bytes C2 A7 at column 1 of line 1 of each log).
HEADING_RE = re.compile(rf"^{SECTION_MARK}(?P<number>\d+)\s+(?P<title>.*\S)\s*$")
OUTCOME_RE = re.compile(r"^\s*(?P<kind>PASS|FAIL|WARN)\s+(?P<label>.*\S)\s*$")
SUMMARY_RE = re.compile(r"^== summary: (?P<pass>\d+) pass, (?P<fail>\d+) fail, (?P<warn>\d+) warn ==\s*$")


class LedgerError(Exception):
    """A log cannot be read, or does not look like a harness log at all."""


@dataclass
class Section:
    number: int
    title: str
    heading_line: int
    passed: int = 0
    failed: int = 0
    warned: int = 0

    def total(self) -> int:
        return self.passed + self.failed + self.warned

    def as_dict(self) -> dict[str, object]:
        return {
            "section": self.number,
            "title": self.title,
            "heading_line": self.heading_line,
            "pass": self.passed,
            "fail": self.failed,
            "warn": self.warned,
        }


@dataclass
class RunLedger:
    """Everything one harness log states about itself."""

    label: str
    log_path: Path
    lines: int
    sections: list[Section] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    warned: int = 0
    summary_line: int | None = None
    printed: tuple[int, int, int] | None = None
    findings: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.warned

    def as_dict(self) -> dict[str, object]:
        printed = (
            None
            if self.printed is None
            else {"pass": self.printed[0], "fail": self.printed[1], "warn": self.printed[2]}
        )
        return {
            "label": self.label,
            "log": str(self.log_path),
            "log_lines": self.lines,
            "summary_line": self.summary_line,
            "counted": {"pass": self.passed, "fail": self.failed, "warn": self.warned},
            "printed_summary": printed,
            "headings_line_numbers": [section.heading_line for section in self.sections],
            "per_section": {section.number: section.total() for section in self.sections},
            "sections": [section.as_dict() for section in self.sections],
            "findings": self.findings,
        }


def parse_log(path: Path, label: str) -> RunLedger:
    """Read one harness log and count what it actually printed."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise LedgerError(f"{path} cannot be read: {exc}") from exc

    lines = text.splitlines()
    ledger = RunLedger(label=label, log_path=path, lines=len(lines))
    current: Section | None = None

    for number, raw in enumerate(lines, start=1):
        heading = HEADING_RE.match(raw)
        if heading:
            current = Section(
                number=int(heading.group("number")),
                title=heading.group("title"),
                heading_line=number,
            )
            ledger.sections.append(current)
            continue

        outcome = OUTCOME_RE.match(raw)
        if outcome:
            kind = outcome.group("kind")
            if current is None:
                ledger.findings.append(f"line {number}: a {kind} line appears before any section heading")
            elif kind == "PASS":
                current.passed += 1
            elif kind == "FAIL":
                current.failed += 1
            else:
                current.warned += 1
            continue

        summary = SUMMARY_RE.match(raw)
        if summary:
            if ledger.summary_line is not None:
                ledger.findings.append(f"line {number}: a second summary line (first at {ledger.summary_line})")
            ledger.summary_line = number
            ledger.printed = (int(summary.group("pass")), int(summary.group("fail")), int(summary.group("warn")))

    if not ledger.sections:
        raise LedgerError(f"{path} has no {SECTION_MARK}<N> section headings - is it a harness log?")

    ledger.passed = sum(section.passed for section in ledger.sections)
    ledger.failed = sum(section.failed for section in ledger.sections)
    ledger.warned = sum(section.warned for section in ledger.sections)

    counted = (ledger.passed, ledger.failed, ledger.warned)
    if ledger.printed is None:
        ledger.findings.append(f"no '== summary: … ==' line found ({ledger.total} assertions counted instead)")
    elif ledger.printed != counted:
        ledger.findings.append(
            f"summary says {ledger.printed[0]}/{ledger.printed[1]}/{ledger.printed[2]} but the log carries "
            f"{counted[0]}/{counted[1]}/{counted[2]} PASS/FAIL/WARN lines"
        )
    return ledger


def _line_list(ledger: RunLedger) -> str:
    if not ledger.sections:
        return "none"
    return " / ".join(str(section.heading_line) for section in ledger.sections)


def render_markdown(ledgers: Sequence[RunLedger]) -> str:
    """The markdown half of the artifact: one block per run, with headings and per-section counts."""
    out: list[str] = [
        "# Harness ledger (generated)",
        "",
        "Generated by `tools/harness_ledger.py` from the logs named below. **Do not copy these numbers into a",
        "document** - link to this file, and re-run the tool after each harness run. Numbers written into",
        "SMOKE_TESTING.md or CHANGELOG.md are hand-copied measurements, and every change to either harness shifts",
        "them; docs/CHANGE_POLICY.md states the rule.",
        "",
    ]
    for ledger in ledgers:
        printed = (
            "none printed"
            if ledger.printed is None
            else f"{ledger.printed[0]} / {ledger.printed[1]} / {ledger.printed[2]}"
        )
        summary_at = "" if ledger.summary_line is None else f" (log line {ledger.summary_line})"
        per_section = " · ".join(f"{SECTION_MARK}{section.number} {section.total()}" for section in ledger.sections)
        out += [
            f"## {ledger.label}",
            "",
            f"- log: `{ledger.log_path}` ({ledger.lines} lines)",
            f"- counted from the log: **{ledger.passed} pass / {ledger.failed} fail / {ledger.warned} warn**",
            f"- harness summary line: {printed}{summary_at}",
            f"- section headings at log lines: {_line_list(ledger)}",
            f"- per-section totals: {per_section}",
        ]
        if ledger.findings:
            out.append("- **inconsistencies:**")
            out += [f"  - {finding}" for finding in ledger.findings]
        out.append("")
    return "\n".join(out)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a machine-readable ledger from smoke-harness logs.")
    parser.add_argument("logs", nargs="*", help="paths to harness log files (one ledger entry per log)")
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="name for a ledger entry, repeated once per log in order; defaults to the log's parent directory name",
    )
    parser.add_argument("--out-dir", default="reports", help="where to write the ledger files (default: reports/)")
    parser.add_argument("--write", action="store_true", help="write reports/harness-ledger.md and .json")
    parser.add_argument("--print", action="store_true", dest="to_stdout", help="print the markdown ledger")
    parser.add_argument("--check", action="store_true", help="exit 1 if any log is internally inconsistent")
    args = parser.parse_args(argv)

    if not args.logs:
        print("no logs given; pass one or more harness log paths", file=sys.stderr)
        return 2

    labels = list(args.label)
    ledgers: list[RunLedger] = []
    for index, raw in enumerate(args.logs):
        path = Path(raw)
        label = labels[index] if index < len(labels) else path.parent.name
        try:
            ledgers.append(parse_log(path, label))
        except LedgerError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    markdown = render_markdown(ledgers)

    if args.write or not args.to_stdout:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "harness-ledger.md").write_text(markdown + "\n", encoding="utf-8")
        payload = {"runs": [ledger.as_dict() for ledger in ledgers]}
        (out_dir / "harness-ledger.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"ledger written to {out_dir}/harness-ledger.md and {out_dir}/harness-ledger.json")

    if args.to_stdout:
        print(markdown)

    inconsistent = [ledger for ledger in ledgers if ledger.findings]
    for ledger in inconsistent:
        for finding in ledger.findings:
            print(f"{ledger.label}: {finding}", file=sys.stderr)
    if args.check and inconsistent:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
