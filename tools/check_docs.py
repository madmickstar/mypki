"""Keep the living documentation free of hand-copied measurements and positional citations.

WHY THIS EXISTS
    Every change to a harness, a template or a test file shifts line numbers and assertion counts. While those values
    were written into SMOKE_TESTING.md and CHANGELOG.md as prose, each small code edit forced a sweep through both
    documents to restate them. The sweep was serial, cross-checked by eye, and it still produced stale citations: a
    changelog that names a test by its line number goes wrong the moment a docstring is rewrapped. This gate makes the
    rule mechanical so the sweep stops happening.

THE RULES (ids are what `--lint-allow` names)
    1. file-line-citation          a source file followed by a line number - cite the function, class, test or label.
    2. bare-anchor-citation        a bare `:NNN` anchor with no name attached to it.
    3. log-position-prose          "line NN before MM", "lines NNN-MM", or a slash-separated list of heading line
                                   numbers - all measurements of one log, which reports/harness-ledger.md carries.
    4. copied-harness-measurement  a harness summary line, an assertion count, or a per-section ledger written into
                                   prose; link to the generated ledger instead.

EXEMPTIONS
    Frozen, append-only regions are not policed: anything under `docs/history/`, plus `docs/measurement-history.md`,
    plus generated artifacts under `reports/`. Those exist to record what a past run measured; restating a past
    measurement is their purpose. A line carrying `<!-- lint-allow: <rule-id> -->` (or `lint-allow: all`) is skipped,
    and the escape hatch stays visible in the document it excuses so it cannot become invisible furniture.

USAGE
    python3 tools/check_docs.py                 police the living docs; 0 clean, 1 findings
    python3 tools/check_docs.py --self-test     prove each rule fires and that clean prose does not trip it
    python3 tools/check_docs.py --print-exempt  list the exempt regions

Exit codes: 0 clean · 1 findings or a failed self-test · 2 usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

BUILD_ROOT = Path(__file__).resolve().parent.parent

#: Documents that describe the current build, and are therefore policed.
LIVE_DOCS = [
    "README.md",
    "SMOKE_TESTING.md",
    "CHANGELOG.md",
    "docs/page-map.md",
    "docs/CHANGE_POLICY.md",
]

#: Frozen or generated regions. A measurement recorded once is history; the same measurement restated by hand is drift.
EXEMPT_PREFIXES = ("docs/history/", "docs/measurement-history.md", "reports/")

SOURCE_NAMES = r"[A-Za-z0-9_\-/]+\.(?:py|pyi|sh|ps1|md|html|css|js|toml|yml|yaml|json)"

RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "file-line-citation",
        re.compile(SOURCE_NAMES + r":\d+"),
        "names a line number in a source file; name the function, class, test or label instead",
    ),
    (
        "bare-anchor-citation",
        re.compile(r"\(:\s?\d{2,4}\)|(?<= ):\d{3,4}\b"),
        "names a position with nothing attached to it; the position moves and the reader is left holding arithmetic",
    ),
    (
        "log-position-prose",
        re.compile(r"\blines? \d{2,4}(?:-\d{2,4})?\b|\b\d{1,4}(?: / \d{1,4}){3,}\b"),
        "restates a position inside one log or script; reports/harness-ledger.md carries log positions",
    ),
    (
        "copied-harness-measurement",
        re.compile(
            r"== summary: \d+ pass, \d+ fail, \d+ warn =="
            r"|\b\d{2,4} assertions\b"
            r"|§\d+\s+\d+(?:\s*[·,]\s*§\d+\s+\d+)+"
        ),
        "copies a harness measurement into prose; link to reports/harness-ledger.md instead",
    ),
)

ALLOW_MARKER = re.compile(r"<!--\s*lint-allow:\s*([a-z\-]+)\s*-->")


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    detail: str
    text: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.detail}\n    {self.text.strip()}"


def is_exempt(relative: str) -> bool:
    return relative.startswith(EXEMPT_PREFIXES)


def policed_documents(root: Path = BUILD_ROOT) -> list[Path]:
    """The named living documents, plus any other top-level `docs/*.md` that is not frozen history."""
    found: list[Path] = []
    for entry in LIVE_DOCS:
        path = root / entry
        if path.is_file():
            found.append(path)
    docs_dir = root / "docs"
    if docs_dir.is_dir():
        for path in sorted(docs_dir.glob("*.md")):
            if not is_exempt(path.relative_to(root).as_posix()) and path not in found:
                found.append(path)
    return found


def check_text(relative: str, text: str) -> list[Finding]:
    """Apply every rule to one document. Deciding whether the document is policed is the caller's job."""
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        allowed = set(ALLOW_MARKER.findall(line))
        if "all" in allowed:
            continue
        for rule, pattern, detail in RULES:
            if rule in allowed:
                continue
            if pattern.search(line):
                findings.append(Finding(relative, number, rule, detail, line))
    return findings


def check_documents(root: Path = BUILD_ROOT) -> list[Finding]:
    findings: list[Finding] = []
    for path in policed_documents(root):
        relative = path.relative_to(root).as_posix()
        if is_exempt(relative):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(Finding(relative, 0, "unreadable", str(exc), ""))
            continue
        findings.extend(check_text(relative, text))
    return findings


# --------------------------------------------------------------------------------------------- mutation self-test
#: One synthetic violation per rule. A gate that matches nothing passes forever, so each pattern is shown to fire
#: (STYLE §8: mutate one thing, prove the check sees it).
SELF_TEST_SAMPLES = [
    ("file-line-citation", "the handler `app.py:609` re-renders the form"),
    ("bare-anchor-citation", "the splats are `@probeArgs` (:312) and `@all` (:403)"),
    ("log-position-prose", "both logs put their headings at 1 / 9 / 30 / 32 / 36"),
    ("log-position-prose", "the block precedes the label (line 83 before 89)"),
    ("copied-harness-measurement", "== summary: 288 pass, 0 fail, 0 warn =="),
    ("copied-harness-measurement", "the harness prints 288 assertions"),
    ("copied-harness-measurement", "per-section §1 8 · §7 6 · §11 76 sums the total"),
]

#: Prose that must NOT be flagged, so no rule can win by matching everything.
SELF_TEST_CLEAN = [
    "the harness exits 2 when nothing was checked, which is not a pass",
    "serve on `http://127.0.0.1:8443` and open the sign page",
    "`mypki serve --port 8443` writes its log under `<data>/logs/`",
    "the `.form-errors.refused` block renders above the paste label",
    "read the totals from `reports/harness-ledger.md`, which regenerates on every run",
    "`test_a_refused_paste_is_named_on_the_sign_page_above_the_box_it_belongs_to` asserts the order",
]


def self_test() -> int:
    failures: list[str] = []

    for rule, sample in SELF_TEST_SAMPLES:
        fired = {finding.rule for finding in check_text("synthetic.md", sample)}
        if rule not in fired:
            failures.append(f"rule {rule!r} did NOT fire on {sample!r} (saw {sorted(fired)})")

    for clean in SELF_TEST_CLEAN:
        flagged = [finding.rule for finding in check_text("synthetic.md", clean)]
        if flagged:
            failures.append(f"clean prose flagged: {clean!r} -> {flagged}")

    for frozen in ("docs/history/0.6.0.md", "docs/measurement-history.md", "reports/harness-ledger.md"):
        if not is_exempt(frozen):
            failures.append(f"{frozen!r} is not recognised as exempt")
    for living in LIVE_DOCS:
        if is_exempt(living):
            failures.append(f"{living!r} would escape policing")

    allowed = check_text(
        "synthetic.md",
        "the handler `app.py:609` re-renders <!-- lint-allow: file-line-citation -->",
    )
    if allowed:
        failures.append("the lint-allow marker did not suppress its rule")

    # End-to-end on a throwaway tree: the same text must be silent in an exempt file and loud in a living one.
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        (root / "docs" / "history").mkdir(parents=True)
        violations = "\n".join(sample for _, sample in SELF_TEST_SAMPLES)
        (root / "docs" / "history" / "0.6.0.md").write_text(violations + "\n", encoding="utf-8")
        (root / "CHANGELOG.md").write_text(violations + "\n", encoding="utf-8")
        if any(finding.path.startswith("docs/history/") for finding in check_documents(root)):
            failures.append("an exempt file was policed end-to-end")
        living_hits = [finding for finding in check_documents(root) if finding.path == "CHANGELOG.md"]
        if len(living_hits) < len(SELF_TEST_SAMPLES):
            failures.append(
                f"check_documents() reported {len(living_hits)} of {len(SELF_TEST_SAMPLES)} violations in a living file"
            )

    if failures:
        for failure in failures:
            print(f"self-test FAILED: {failure}", file=sys.stderr)
        return 1

    print(
        f"self-test ok: {len(SELF_TEST_SAMPLES)} violations caught, {len(SELF_TEST_CLEAN)} clean lines passed, "
        "exemption and lint-allow both honoured"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Police mypki's living documentation against hand-copied measurements."
    )
    parser.add_argument(
        "--self-test", action="store_true", help="verify each rule fires and clean prose does not trip it"
    )
    parser.add_argument("--print-exempt", action="store_true", help="list the exempt (frozen or generated) regions")
    parser.add_argument("--root", default=str(BUILD_ROOT), help="repository root to police (default: this checkout)")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.print_exempt:
        for prefix in EXEMPT_PREFIXES:
            print(f"exempt: {prefix}")
        return 0

    root = Path(args.root)
    findings = check_documents(root)
    documents = policed_documents(root)

    if findings:
        for finding in findings:
            print(finding)
        print(f"\n{len(findings)} finding(s) across {len(documents)} living document(s)")
        return 1

    sizes = ", ".join(
        f"{path.relative_to(root).as_posix()} ({len(path.read_text(encoding='utf-8').splitlines())} lines)"
        for path in documents
    )
    print(f"docs clean: {sizes}; exempt: {', '.join(EXEMPT_PREFIXES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
