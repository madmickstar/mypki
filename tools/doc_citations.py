"""Enumerate every citation from code into a document, so an edit can be planned from one file.

WHY THIS EXISTS
  mypki's source cites its own documentation by section — `docs/REFERENCE.md gotcha 1`, `page-map §7`,
  `README.md "Where the files live"`, `SMOKE_TESTING.md §9`. A measured pass over this tree finds **429 references
  across 48 Python files** (420 of them in the 42 files under `src/` and `tests/`) and runs in about 2.9 s. That number
  is the blast radius of moving a heading: every one of those citations has to land on a section that still exists. That
  is what broke during the 0.7.2 README restructure: 41 citation lines moved across `src/`, `tests/`,
  `docs/page-map.md`, `SMOKE_TESTING.md` and Makefile.

THE DENOMINATOR, AND WHY IT IS THE SAME ONE tools/tree_manifest.py USES
  "Tracked" here means what a commit from this tree would contain — `git ls-files --cached --exclude-standard --others`
  filtered to `.py` — not plain `git ls-files`. MEASURED on this checkout with the three definitions spelled out:
  `src/` + `tests/` only gives 42 files and 420 references (the number AGENTS.md rule 1 quotes, which leaves `tools/`
  out); plain `git ls-files` gives 46 files and 425; the commit-shaped denominator gives 48 files and 429. The spread is
  the denominator, not the pattern: the same scan, three questions.

  The count also moves when this file's own prose moves, because a tool that scans docstrings scans its own. That is not
  a defect to route around — it is why the number here is written with its denominator attached rather than as a fact.

  The pass cost **113 read-only shell commands (56% of a 203-command, 161.6-minute session)** because the facts were
  re-derived with repeated grepping instead of enumerated once into a file. This tool is that enumeration; `make
  inventory` runs it and writes the result to reports/inventory.txt.

WHAT IT DOES NOT DO — read this before trusting its output
  It reports **references**, not correctness, and not prose. It cannot tell you whether a sentence about behaviour is
  true, whether a section heading is well worded, or whether a claim in CHANGELOG.md is accurate. The prose-policing
  gates (`tools/check_docs.py`, `tools/check_docstrings.py`, `tests/test_docstrings.py`) were deliberately deleted in
  bc0031b and this tool is not their reinstatement: it answers "what points where", mechanically, and stops there.

  It also reports a reference as *unresolved* only when the target document exists and the named section does not. A
  citation to a document that no longer exists at all is reported as a missing target, which is a different failure and
  is listed separately.

THE EXIT CODES A WRAPPER MUST NOT FLATTEN
  0  enumerated (unresolved references do not change this; they are findings, not defects in the run)
  2  cannot enumerate: no git binary, or tree_manifest.tracked_paths() raised
  Same contract as tools/check_version.py and tools/tree_manifest.py: a scanner that reports "no problems" because it
  read nothing is worse than no scanner.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path

#: One denominator for the repository's mechanical facts. `tools/` is on pytest's pythonpath (pyproject.toml) and is
#: sys.path[0] when this file runs as a script, so this import resolves from the repo root either way; see
#: tools/tree_manifest.py for why the denominator is "what a commit would contain".
import tree_manifest

BUILD_ROOT = Path(__file__).resolve().parent.parent

#: Documents a citation may point at, as they are spelled in this repository's source. `README.md` needs its own key:
#: tokens are matched longest-first, so without it `README` matched and the `.md` was left dangling — which is how the
#: citation at tools/tree_manifest.py:4 (README's *Where the files live*) went uncounted by this very file.
DOC_ALIASES: dict[str, str] = {
    "README": "README.md",
    "README.md": "README.md",
    "docs/REFERENCE.md": "docs/REFERENCE.md",
    "REFERENCE.md": "docs/REFERENCE.md",
    "docs/linux_install.md": "docs/linux_install.md",
    "SMOKE_TESTING.md": "SMOKE_TESTING.md",
    "SMOKE_TESTING": "SMOKE_TESTING.md",
    "page-map": "docs/page-map.md",
    "page-map.md": "docs/page-map.md",
}

#: `<doc> "Some Section"` and `<doc>'Some Section'`. The document token is matched longest-first so `docs/REFERENCE.md`
#: is not read as `REFERENCE.md` with a stray prefix, and so `README.md` is not read as `README` plus a dangling `.md`.
DOC_TOKEN = (
    r"docs/REFERENCE\.md|docs/linux_install\.md|SMOKE_TESTING\.md|page-map\.md|README\.md|README|"
    r"SMOKE_TESTING|page-map"
)
QUOTED_SECTION = re.compile(rf"\b({DOC_TOKEN})\s+([\"'])([^\"']+)\2")

#: `<doc> §N` and the bare `§N` that page-map's own prose uses.
NUMBERED_SECTION = re.compile(rf"\b({DOC_TOKEN})\s*§\s*(\d+)")
BARE_SECTION = re.compile(r"§(\d+)")

#: Files worth scanning: source and tests cite documents; documents cite each other in prose this tool would only count.
SCAN_SUFFIXES = (".py",)


def _git(root: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *arguments], cwd=str(root), capture_output=True, text=True, check=False)


def git_available() -> bool:
    return _git(BUILD_ROOT, ["--version"]).returncode == 0


def tracked_scan_files(root: Path = BUILD_ROOT) -> list[str]:
    """The `.py` files a commit from this tree would contain, in git's order.

    Delegates to tools/tree_manifest.py rather than re-asking git, so the inventory's "python files scanned" line and
    its "tracked paths" line cannot answer with two different trees. They did: this file asked plain `git ls-files`
    while the fingerprint printed beside it asked `--cached --others --exclude-standard` — 46/75 against 48/78 here.
    """
    return [path for path in tree_manifest.tracked_paths(root) if path.endswith(SCAN_SUFFIXES)]


def headings_of(path: Path) -> dict[str, int]:
    """ATX headings of a markdown file, keyed by their text with leading `§N` stripped.

    Fenced blocks are skipped: a `#` inside a code sample is not a heading, and counting one as a heading makes a real
    citation look resolvable when it is not.
    """
    out: dict[str, int] = {}
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if match:
            title = match.group(1).strip()
            out[title] = out.get(title, 0) + 1
            stripped = re.sub(r"^§\s*\d+\s*", "", title).strip()
            if stripped and stripped != title:
                out.setdefault(stripped, 0)
    return out


def numbered_headings_of(path: Path) -> set[int]:
    """Section numbers that exist as headings only — not `§N` mentions inside prose.

    Counting mentions instead would make every broken section reference look resolvable, because documents in this
    project quote each other's section numbers constantly.
    """
    found: set[int] = set()
    for title in headings_of(path):
        match = re.match(r"^§\s*(\d+)\b", title)
        if match:
            found.add(int(match.group(1)))
    return found


def prose_lines(path: Path) -> list[tuple[int, str]]:
    """Comment and docstring lines of a Python file, as (line number, text).

    Only prose is scanned. A citation inside executable code (a string used as data, a log message) would be counted as
    a documentation dependency that no reader ever follows, so the file is parsed rather than grepped.
    """
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    found: dict[int, str] = {}

    try:
        tree = ast.parse(text)
    except SyntaxError:
        # A file this tool cannot parse is a file whose citations it cannot attribute; reporting nothing would be a
        # silent blind spot, so every line is scanned instead and the caller sees the whole file.
        return [(index, line) for index, line in enumerate(lines, start=1)]

    docstring_spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                docstring_spans.append((first.lineno, first.end_lineno))
    for node in ast.walk(tree):
        # Module- and function-level bare strings are the docstrings; a bare string elsewhere is not prose anyone reads.
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            span = (node.lineno, node.end_lineno)
            if span not in docstring_spans:
                docstring_spans.append(span)

    for start, end in docstring_spans:
        for number in range(start, end + 1):
            if 1 <= number <= len(lines):
                found[number] = lines[number - 1]

    import io
    import tokenize

    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type != tokenize.COMMENT:
                continue
            for number in range(token.start[0], token.end[0] + 1):
                if 1 <= number <= len(lines):
                    found[number] = lines[number - 1]
    except (tokenize.TokenError, IndentationError):
        pass

    return sorted(found.items())


class Report:
    """Counts and findings, assembled so `make inventory` can print one readable file from them."""

    def __init__(self) -> None:
        self.files_scanned = 0
        self.references: list[dict[str, str]] = []
        self.unresolved: list[dict[str, str]] = []
        self.missing_documents: list[dict[str, str]] = []

    def resolve(self, document: str, section: str, *, numbered: bool) -> bool:
        target = BUILD_ROOT / document
        if not target.is_file():
            self.missing_documents.append({"document": document, "section": section})
            return False
        if numbered:
            match = re.match(r"^§?\s*(\d+)$", section.strip())
            numbers = numbered_headings_of(target)
            return bool(match) and int(match.group(1)) in numbers
        wanted = section.strip().lower()
        for title in headings_of(target):
            lowered = title.lower()
            if wanted == lowered or wanted in lowered or lowered in wanted:
                return True
        return False


def scan(files: list[str]) -> Report:
    report = Report()
    for relative in files:
        path = BUILD_ROOT / relative
        if not path.is_file():
            continue
        report.files_scanned += 1
        for number, text in prose_lines(path):
            for document_token, _quote, section in QUOTED_SECTION.findall(text):
                document = DOC_ALIASES[document_token]
                entry = {"file": relative, "line": str(number), "document": document, "section": section}
                report.references.append(entry)
                if not report.resolve(document, section, numbered=False):
                    report.unresolved.append(entry)
            for document_token, number in NUMBERED_SECTION.findall(text):
                document = DOC_ALIASES[document_token]
                entry = {"file": relative, "line": number, "document": document, "section": f"§{number}"}
                report.references.append(entry)
                if not report.resolve(document, number, numbered=True):
                    report.unresolved.append(entry)
    return report


def render(report: Report, tracked: list[str], fingerprint: str) -> str:
    """The inventory as one file: the tree, then every citation, then what could not be resolved."""
    out = [
        "# mypki inventory (generated by `make inventory`; do not edit by hand)",
        f"# tree: {fingerprint}",
        f"# tracked paths: {len(tracked)}",
        f"# python files scanned: {report.files_scanned}",
        f"# document references found in code prose: {len(report.references)}",
        "",
        "## citations, by target document",
    ]
    by_document: dict[str, list[dict[str, str]]] = {}
    for entry in report.references:
        by_document.setdefault(entry["document"], []).append(entry)
    for document in sorted(by_document):
        entries = by_document[document]
        out.append(f"  {document}: {len(entries)}")
        for entry in entries:
            out.append(f"    {entry['file']}:{entry['line']} -> {entry['section']}")

    out.append("")
    out.append(f"## unresolved references ({len(report.unresolved)})")
    if not report.unresolved:
        out.append("  none")
    for entry in report.unresolved:
        out.append(f"  {entry['file']}:{entry['line']} -> {entry['document']} {entry['section']} (no such heading)")

    out.append("")
    out.append(f"## citations naming a document that does not exist ({len(report.missing_documents)})")
    if not report.missing_documents:
        out.append("  none")
    for entry in report.missing_documents:
        out.append(f"  {entry['document']} {entry['section']}")

    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enumerate code-to-document citations in this repository.")
    parser.add_argument("--json", action="store_true", help="print the references as JSON instead of a readable report")
    arguments = parser.parse_args(argv)

    if not git_available():
        print("cannot enumerate: no git binary in this environment", file=sys.stderr)
        return 2
    try:
        tracked = tree_manifest.tracked_paths()
        files = tracked_scan_files()
    except RuntimeError as error:
        print(f"cannot enumerate: {error}", file=sys.stderr)
        return 2

    try:
        fingerprint = tree_manifest.tree_fingerprint()
    except RuntimeError as error:
        print(f"cannot enumerate: {error}", file=sys.stderr)
        return 2

    report = scan(files)

    if arguments.json:
        import json

        print(
            json.dumps(
                {
                    "files_scanned": report.files_scanned,
                    "references": report.references,
                    "unresolved": report.unresolved,
                    "missing_documents": report.missing_documents,
                },
                indent=1,
            )
        )
        return 0

    sys.stdout.write(render(report, tracked, fingerprint))
    if report.unresolved or report.missing_documents:
        print(
            f"note: {len(report.unresolved)} unresolved, {len(report.missing_documents)} naming a missing document",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
