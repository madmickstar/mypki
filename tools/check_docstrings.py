"""Keep release-time prose out of `src/` docstrings and comments.

WHY THIS EXISTS
    A docstring that cites a released version, or records how one probe run went, is a sentence about the past inside a
    file that outlives it. It goes stale the moment behaviour moves, it drags every later edit into renegotiating a
    version number the code no longer means, and a probe note names a scratch file nobody kept. Living code states an
    invariant and how it fails; `docs/history/` is where a release-specific claim belongs. This gate makes that split
    mechanical rather than a review convention.

THE RULES (ids are what a line's `# allow-docstring-rule:` marker names)
    1. version-citation        a `0.x.y` token, or a `pre-0.x.y` phrasing. RFC section numbers, dotted-quad addresses
                               and any dependency pin whose major version is not `0` are not citations: the pattern is
                               scoped to a leading `0.` plus an explicit `pre-0.x.y`, so `cryptography 50.0.2`,
                               `pydantic-settings 2.16.1`, `RFC 5280 §5.2.1` and `127.0.0.1` stay legal prose. A pin
                               whose major version is itself `0.` does read as a citation, and src/ prose states such a
                               fact by the behaviour it pins rather than by the number.
    2. one-run-probe           the marker `MEASURED`, or a `/tmp/...` probe path. Both describe one run rather than the
                               invariant, and a probe path is a file that no longer exists by the time it is read.
    3. release-plan-tag        `answer N` or `(0.x.y)`. Both point at a planning document's numbering rather than at
                               code. Kept deliberately narrow: `U<N>` and `plan §` appear in far more lines than the
                               inventory this pass worked from, so policing them would flag prose that says nothing
                               about a release.

WHAT IS POLICED
    Docstring lines and full-line comments under `src/`. Code lines are not read: a version or a limit inside a string
    literal is behaviour rather than prose, and two such literals exist in this package on purpose (a settings help
    string and an inspect-page row). A line carrying `# allow-docstring-rule: <rule-id>` (or `all`) is skipped, and the
    escape hatch stays visible in the file it excuses.

USAGE
    python3 tools/check_docstrings.py                 police src/; 0 clean, 1 findings
    python3 tools/check_docstrings.py --self-test     prove each rule fires and that clean prose survives it
    python3 tools/check_docstrings.py --print-rules   list the rules and their patterns

Exit codes: 0 clean · 1 findings or a failed self-test · 2 usage error.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

BUILD_ROOT = Path(__file__).resolve().parent.parent

#: The package this gate reads. Nothing else: `tests/` and `tools/` are allowed to discuss releases, because a test
#: name or a checker's own note about a pinned dependency is exactly the kind of fact that has to be written down.
POLICED_DIRECTORY = "src"

#: A `0.x.y` citation, plus the `pre-0.x.y` phrasing that means the same thing in prose. Deliberately NOT a general
#: version pattern: it is scoped to a leading `0.` and bounded so a match cannot be a fragment of a longer dotted chain,
#: which keeps a dotted-quad address (`127.0.0.1`, `10.0.0.1`, the wildcard bind `0.0.0.0`) legal prose — those names
#: appear in this package's docstrings on purpose, and an unbounded pattern flags them as releases.
VERSION_PATTERN = re.compile(r"(?<![\d.])0\.\d+\.\d+(?![\d]|\.\d)|pre-0\.\d+\.\d+")

#: A one-run probe marker, or the path of a scratch file a probe was written into.
PROBE_PATTERN = re.compile(r"MEASURED|/tmp/")

#: A planning-document tag. Narrow on purpose -- see rule 3 in the module docstring.
TAG_PATTERN = re.compile(r"\banswer \d+|\(0\.\d+\.\d+\)")

RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "version-citation",
        VERSION_PATTERN,
        "names a released version in living code; state the invariant here and put the release claim in docs/history/",
    ),
    (
        "one-run-probe",
        PROBE_PATTERN,
        "reports one probe run rather than the invariant; say what breaks and how, not what was measured",
    ),
    (
        "release-plan-tag",
        TAG_PATTERN,
        "points at a planning document's numbering instead of at this file's own behaviour",
    ),
)

ALLOW_MARKER = re.compile(r"#\s*allow-docstring-rule:\s*([a-z\-]+)")


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    detail: str
    text: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.detail}\n    {self.text.strip()}"


def docstring_spans(tree: ast.AST) -> list[tuple[int, int]]:
    """Line ranges occupied by docstrings. Deciding that from the AST is what keeps a version inside a string
    literal out of the count: only a node's leading expression statement is a docstring."""
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if ast.get_docstring(node, clean=False) is None:
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        spans.append((first.lineno, first.end_lineno))
    return spans


def prose_lines(text: str) -> Iterable[tuple[int, str]]:
    """The lines this gate reads: docstring lines and full-line comments.

    A trailing comment on a code line is not read either -- it sits beside an expression whose own text may legitimately
    contain a limit or a version, and splitting one line into two verdicts is how a gate gets worked around."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    spans = docstring_spans(tree)
    out: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if any(start <= number <= end for start, end in spans) or line.strip().startswith("#"):
            out.append((number, line))
    return out


def check_text(relative: str, text: str) -> list[Finding]:
    """Apply every rule to one file's prose. Deciding whether the file is policed is the caller's job."""
    findings: list[Finding] = []
    for number, line in prose_lines(text):
        allowed = set(ALLOW_MARKER.findall(line))
        if "all" in allowed:
            continue
        for rule, pattern, detail in RULES:
            if rule in allowed:
                continue
            if pattern.search(line):
                findings.append(Finding(relative, number, rule, detail, line))
    return findings


def policed_files(root: Path = BUILD_ROOT) -> list[Path]:
    directory = root / POLICED_DIRECTORY
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.rglob("*.py") if path.is_file())


def check_package(root: Path = BUILD_ROOT) -> list[Finding]:
    findings: list[Finding] = []
    for path in policed_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(Finding(relative, 0, "unreadable", str(exc), ""))
            continue
        findings.extend(check_text(relative, text))
    return findings


# --------------------------------------------------------------------------------------------- mutation self-test
#: One synthetic violation per rule. A gate whose patterns match nothing passes forever, so each pattern is shown
#: firing on text that is otherwise plausible prose for this package.
SELF_TEST_SAMPLES = [
    ("version-citation", "    The CA page shows the certificate itself next to the facts about it (as of 0.5.0)."),
    ("version-citation", "    # this bind refusal predates 0.6.0's spelling of the same answer, in pre-0.7 wording."),
    ("one-run-probe", "        # The write is what touches this host's filesystem. MEASURED defect found by a test."),
    ("one-run-probe", "    Probed on this box (/tmp/ssl_probe2.py, against an interpreter version) for the failure:"),
    ("release-plan-tag", "    called. Raising would report a revoke that worked as a failure (plan §4, answer 2)."),
]

#: Prose that must NOT be flagged, so no rule can win by matching everything. These are the near-misses this gate is
#: calibrated against: a dependency pin, an RFC section number, a dotted-quad address, a limit inside a literal.
SELF_TEST_CLEAN = [
    "    `cert.fingerprint(hashes.SHA256()) -> bytes` is the API on cryptography 50.0.2; the newer-looking",
    "    # `keyEncipherment` is asserted bit-by-bit in `test_csr_validate.py` against `openssl req -text`.",
    "        # `ssl.SSLError` **is** an OSError, so this arm has to precede the bind arm or a bad certificate is",
    "          * body over `OCSP_MAX_REQUEST_BYTES` -> MALFORMED_REQUEST. A real request is tens of bytes, so this",
    "    # Serving on 127.0.0.1 rather than 0.0.0.0 is the default; a wildcard bind has to be asked for out loud.",
    "    # Four dot-separated numeric groups `ipaddress` refused: almost certainly a mistyped IPv4 (a leading zero,",
    "        §5). That is exactly what `CRLNumber` needs — RFC 5280 §5.2.1 wants a number that only increases for a",
]


def self_test() -> int:
    failures: list[str] = []

    for rule, sample in SELF_TEST_SAMPLES:
        fired = {finding.rule for finding in check_text("synthetic.py", f'"""\n{sample}\n"""\n')}
        if rule not in fired:
            failures.append(f"rule {rule!r} did NOT fire on {sample!r} (saw {sorted(fired)})")

    for clean in SELF_TEST_CLEAN:
        flagged = [finding.rule for finding in check_text("synthetic.py", f'"""\n{clean}\n"""\n')]
        if flagged:
            failures.append(f"clean prose flagged: {clean!r} -> {flagged}")

    # A code line is not prose, and a trailing comment on one is not read either.
    code_only = check_text("synthetic.py", 'value = "0.1.0"  # MEASURED in (0.1.0)\nanswer 7 = 3\n')
    if code_only:
        failures.append(f"a code line was policed: {code_only}")

    # The marker excuses the line it sits on, and only that line.
    allowed = check_text(
        "synthetic.py",
        '"""\n    # MEASURED defect found by driving the app  # allow-docstring-rule: one-run-probe\n"""\n',
    )
    if allowed:
        failures.append("the allow marker did not suppress its rule")

    leaky = check_text(
        "synthetic.py",
        '"""\n'
        "    # One probe note  # allow-docstring-rule: all\n"
        "    # The next line is not excused: MEASURED again\n"
        '"""\n',
    )
    if len(leaky) != 1:
        failures.append(f"the allow marker reached beyond its own line: {[str(item) for item in leaky]}")

    # End-to-end on a throwaway tree: src/ is policed, tests/ and tools/ are not.
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        (root / POLICED_DIRECTORY / "mypki").mkdir(parents=True)
        (root / "tests").mkdir()
        (root / "tools").mkdir()
        violations = '"""\n' + "\n".join(sample for _, sample in SELF_TEST_SAMPLES) + '\n"""\n'
        (root / POLICED_DIRECTORY / "mypki" / "mod.py").write_text(violations, encoding="utf-8")
        (root / "tests" / "test_mod.py").write_text(violations, encoding="utf-8")
        (root / "tools" / "helper.py").write_text(violations, encoding="utf-8")

        reported = check_package(root)
        if len(reported) < len(SELF_TEST_SAMPLES):
            failures.append(
                f"check_package() reported {len(reported)} of {len(SELF_TEST_SAMPLES)} violations "
                f"under {POLICED_DIRECTORY}/"
            )
        escaped = sorted({finding.path for finding in reported if not finding.path.startswith(POLICED_DIRECTORY + "/")})
        if escaped:
            failures.append(f"files outside the policed directory were read: {escaped}")

    if failures:
        for failure in failures:
            print(f"self-test FAILED: {failure}", file=sys.stderr)
        return 1

    print(
        f"self-test ok: {len(SELF_TEST_SAMPLES)} violations caught, {len(SELF_TEST_CLEAN)} clean lines passed, "
        "code lines ignored and the allow marker honoured"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Police mypki's src/ docstrings against release-time prose.")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="verify each rule fires and clean prose does not trip it",
    )
    parser.add_argument("--print-rules", action="store_true", help="list the rules this gate applies")
    parser.add_argument("--root", default=str(BUILD_ROOT), help="repository root to police (default: this checkout)")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.print_rules:
        for rule, pattern, detail in RULES:
            print(f"{rule}: {pattern.pattern} :: {detail}")
        print(f"policed directory: {POLICED_DIRECTORY}/ (docstrings and full-line comments only)")
        return 0

    root = Path(args.root)
    findings = check_package(root)
    files = policed_files(root)

    if findings:
        for finding in findings:
            print(finding)
        print(f"\n{len(findings)} finding(s) across {len(files)} file(s) under {POLICED_DIRECTORY}/")
        return 1

    print(
        f"docstrings clean: {len(files)} file(s) under {POLICED_DIRECTORY}/ read for "
        f"{len(RULES)} rule(s); docstring lines and full-line comments only"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a script, not as an import
    sys.exit(main())
