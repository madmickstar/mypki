"""The fast lane: the gates worth running on every edit, and only those.

WHY THIS EXISTS
    A small change should cost minutes, not an hour. Naming the cheap gate set in prose is how it gets skipped: under
    time pressure the honest options are "spend four minutes of gates on a CSS edit" or "run nothing". This file makes
    the cheap option one command (`make fast K=...` wraps it), so the fast lane is the default rather than a discipline
    to remember.

WHAT IT RUNS, AND WHY THOSE
    ruff check + ruff format --check (scoped)   ~0.1 s   the two things an edit breaks most often
    tools/check_version.py                       ~0.1 s   four lines, and the only gate that reads the version chain
    pytest -q --no-cov -k PATTERN                1-20 s   the tests for what you actually changed

WHAT IT DELIBERATELY OMITS
    mypy, coverage and the e2e harness. Those belong to a commit or a release, not to an edit: `mypy src` is half
    a second but answers a question an unchanged signature did not raise; coverage needs the whole suite to mean
    anything; a harness run costs minutes and only earns its cost when a user-visible string or a status code moved.
    The omission is asserted in `tests/test_fast_lane.py`, because "the fast lane is fast" decays the first time
    someone adds a slow step to it for convenience.

THE EXIT CODES A WRAPPER MUST NOT FLATTEN
    pytest exits **5** when its `-k` pattern matched nothing. A wrapper that reads any non-zero exit as "tests failed"
    and any zero as "fine" would report success for every mistyped pattern, which is worse than running no tests. Exit 5
    is reported here as a failure, with the reason spelled out.

    pytest also exits **4** when the expression cannot be parsed at all (`-k "a or or b"` - MEASURED on this tree). Same
    reasoning: it is a mistake in the command and nothing about the tree, and naming it is the only clue a reader has.

HOW THE PATTERN IS READ, AND WHY BOTH SPELLINGS WORK
    `make fast K=csr_generate ca_page` and `make fast K="csr_generate or ca_page"` reach this tool as the same
    three words, because make expands `$(K)` unquoted and the shell splits on whitespace. They used to be treated
    identically - joined with `' or '` whatever the caller wrote - which made the second spelling produce `-k "a
    or or or b"`, and pytest refuses that with exit 4 after the lane has already paid for lint and the version
    chain.

    So the words are read looking for operators. Bare keywords are ORed, because pytest accepts no space-separated
    list of names (`-k "csr_generate ca_page"` exits 4, MEASURED). If the caller wrote `or`, `and` or `not` at
    all, those belong to pytest and the words are rejoined with single spaces so the expression arrives as
    written. An expression that cannot be valid - a leading binary operator, an operator at the end, two binary
    operators side by side - is rejected here with exit 2 before any step runs, rather than found by pytest at the
    most expensive moment in the run.

A SECOND INVOCATION BUG, AND THE NASTIER ONE
    Run this through an interpreter that does not have mypki installed — the system `python3` of a checkout whose
    virtualenv sits in `.venv/`, for instance — and pytest aborts at conftest with `ModuleNotFoundError: No module
    named 'mypki'`. Scoped ruff and the version-chain gate still pass - they are stdlib-only - so the run
    comes back half-green with one failure that reads to whoever just edited a stylesheet as "my change broke
    the suite". It did
    not break anything: no test of the changed behaviour ever ran.

    The interpreter is therefore chosen rather than inherited. Every step runs under this checkout's `.venv`
    interpreter when one exists, and the choice is printed on its own line before any step runs, so a switch is
    visible instead of inferred. With no `.venv` — a CI container that installs into the system interpreter — the
    invoking interpreter is used unchanged, and the printed line says that too rather than leaving it assumed.

STOPS AT THE FIRST FAILING STEP
    Steps are ordered cheapest-first, so an early failure is information about everything later. `make gate` has
    always short-circuited this way (lint -> types -> version -> cov -> e2e, and a lint break ends the run); a lane
    that kept going was the inconsistent half of one gate set. Until now it did keep going: with an over-long comment
    injected into `app.py`, the lane printed `[exit 1] ruff check (0.06s)` and then ran
    `pytest -k csr_generate or ca_page` for 24.84s anyway, finishing at 25.06s to report a failure that had already
    been known in 60ms. That is this file's own argument inverted: spending minutes on a tree a 0.06s check had
    already refused.

    The steps it did not reach are named as *not run* rather than left unstated, because "ruff failed" and "no test
    ever ran" are different facts and a reader has to be able to tell which one they are holding. Fix the first
    failure and re-run: the later steps are uncollected evidence, not passed evidence.

USAGE
    python3 tools/fast_lane.py KEYWORD [KEYWORD...]   # lint + version chain + pytest -k <keywords ORed>
    python3 tools/fast_lane.py csr_sign and not csr_generate   # an expression, passed through as written
    python3 tools/fast_lane.py --dry-run              # print the plan, run nothing
    python3 tools/fast_lane.py --no-docs              # skip the version-chain gate

Exit codes: 0 all steps passed · 1 a step failed (its reason printed, later steps not run) · 2 usage error (no pattern
and not --dry-run, or a -k expression that could not be valid).

ONE FLAG DECLARED ELSEWHERE ON PURPOSE
    The pytest step carries no `-q`. `pyproject.toml`'s `addopts = "-q --strict-markers"` already asks for quiet,
    and a second `-q` stacks to `-qq`, which suppresses pytest's summary line - no pass count, no duration. That
    is the number this lane exists to produce, and it is the same evidence exit 5 protects: without it, a run that
    deselected everything looks like a run that passed something.
"""

from __future__ import annotations

import argparse
import itertools
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

#: The doc/version gate this lane runs, named once so `build_steps` and the test that pins this lane agree on it.
#: Invoked by path rather than as a module import: `tools/` is not part of the installed package, and CI plus the
#: pre-commit hooks already call it by path, so the lane cannot pass on an import route the real gates do not use.
DOC_TOOLS: tuple[str, ...] = ("tools/check_version.py",)

#: This checkout's virtualenv, named as a directory so the existence test below and the interpreter path built from it
#: come from one fact. `mypki` is installed here and not system-wide, which is exactly why inheriting `sys.executable`
#: is the bug this file's own docstring names: the stdlib-only gates pass and pytest is the only step that can tell you
#: nothing was tested.
VENV_DIR = ".venv"
BUILD_ROOT = Path(__file__).resolve().parent.parent
VENV_PYTHON = BUILD_ROOT / VENV_DIR / "bin" / "python"

#: Steps that run on every edit, ordered to fail cheapest first. Data rather than inline calls in `main` so
#: `tests/test_fast_lane.py` can assert what this lane is *not*: mypy, coverage, the src/ prose gate and the e2e
#: harness all stay out.
LINT_STEPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ruff check", ("-m", "ruff", "check", "src", "tests", "tools")),
    ("ruff format --check", ("-m", "ruff", "format", "--check", "src", "tests", "tools")),
)

#: Everything this lane refuses to run, spelled out so `--dry-run` can name it and the test that pins the lane can
#: assert each entry stayed out. Keeping this list honest is the point: if a slow gate vanished from it, the tool would
#: stop telling anyone that mypy, coverage and the end-to-end harness are still owed at commit.
COMMIT_ONLY_STEPS: tuple[str, ...] = (
    "mypy src",
    "pytest --cov",
    "tools/e2e_harness.py",
)


#: Words that are pytest's own operators rather than test names. Lower-cased on purpose: `-k` is case-sensitive about
# them, so `OR` is a substring to match and not an operator.
PYTEST_OPERATORS: frozenset[str] = frozenset({"or", "and", "not"})

#: Operators that are legal with nothing before them. `not sign` is a whole expression; `or sign` is not.
_UNARY_OPERATORS: frozenset[str] = frozenset({"not"})


def flatten_patterns(patterns: Sequence[str]) -> list[str]:
    """Split every argument on whitespace, so quoting is the caller's choice and not a change of behaviour.

    `fast_lane.py "csr_generate ca_page"` arrives as one argument and `make fast K="csr_generate ca_page"` arrives
    as two, because make expands `$(K)` unquoted. Both mean the same request. Flattening is what makes them behave
    alike: the single-argument spelling used to go straight to pytest as `-k "csr_generate ca_page"`, which exits
    4.
    """
    return [word for pattern in patterns for word in pattern.split()]


def expression_operators(words: Sequence[str]) -> list[str]:
    """The operator words in a flattened pattern list, in order."""
    return [word for word in words if word in PYTEST_OPERATORS]


def validate_expression(words: Sequence[str]) -> str | None:
    """Why this expression cannot be valid, or None when it can.

    Checked here rather than left to pytest because the lane runs lint and the version chain first: a malformed pattern
    discovered by pytest is one discovered after everything cheap has been paid for. Three shapes are caught - a leading
    binary operator, an operator with nothing after it, and two binary operators side by side. `and not` / `or not` are
    allowed because that is how a negation is written, and so is a leading `not`.
    """
    if not words:
        return "no pattern words remain after splitting the arguments"

    first = words[0]
    if first in PYTEST_OPERATORS and first not in _UNARY_OPERATORS:
        return f"the expression starts with {first!r}, which needs something before it"

    last = words[-1]
    if last in PYTEST_OPERATORS:
        return f"the expression ends with the operator {last!r} and nothing after it"

    for previous, current in itertools.pairwise(words):
        binary_after_binary = previous in PYTEST_OPERATORS and current in PYTEST_OPERATORS
        if binary_after_binary and current not in _UNARY_OPERATORS:
            return f"{previous!r} and {current!r} are adjacent operators - pytest has nothing between them"

    return None


def pytest_expression(patterns: Sequence[str]) -> str:
    """The `-k` expression this lane hands to pytest, from however the caller spelled the request.

    Bare keywords are ORed because pytest accepts no space-separated list of names. An expression the caller wrote is
    rejoined with single spaces and passed through, because its operators belong to pytest - joining them again is what
    turned `K="a or b"` into `-k "a or or or b"`. The two readings cannot be told apart any other way, since make splits
    both into the same words, so an operator word present at all is the signal. It is a fair one: a test named literally
    `or`, `and` or `not` would already match every test in the suite.
    """
    words = flatten_patterns(patterns)
    if expression_operators(words):
        return " ".join(words)
    return " or ".join(words)


def build_steps(patterns: Sequence[str], *, include_docs: bool) -> list[tuple[str, tuple[str, ...]]]:
    """The exact commands this lane will run, in order.

    `--no-cov` is not an optimisation: coverage measurement is what makes pytest slow, and a partial run measures a
    partial denominator, so any percentage printed here would mean nothing. Coverage belongs to the full-suite gate.

    No `-q`: `pyproject.toml`'s `addopts` already declares it, and a second one stacks to `-qq`, which deletes pytest's
    summary line - the pass count and duration this lane exists to report.
    """
    steps = list(LINT_STEPS)
    if include_docs:
        steps.extend(("version chain", (tool,)) for tool in DOC_TOOLS)
    if patterns:
        expression = pytest_expression(patterns)
        steps.append(
            (f"pytest -k {expression}", ("-m", "pytest", "-p", "no:cacheprovider", "--no-cov", "-k", expression))
        )
    return steps


def step_interpreter() -> str:
    """The interpreter every step runs under: this checkout's venv python when it exists, else the invoking one.

    Checked by existence rather than by trusting that a directory named `.venv` is a usable environment — a half-created
    or deleted venv whose `bin/python` is missing must fall back to an interpreter that at least runs something, and the
    fallback gets stated out loud by `interpreter_note` rather than passing silently.
    """
    return str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable


def step_command(interpreter: str, cmd: Sequence[str]) -> list[str]:
    """One step as spawned: the chosen interpreter first, then the step's own arguments.

    Steps are stored without an interpreter (`LINT_STEPS` and `DOC_TOOLS` hold `-m ruff …` and tool paths), which is
    what lets one definition serve both a CI container with no venv and this checkout that has one. The prefix is added
    here, once.
    """
    return [interpreter, *cmd]


def interpreter_note(interpreter: str) -> str:
    """Say which interpreter was picked and why, so the choice is a printed fact rather than a hidden one.

    The branch is `step_interpreter`'s own test - does this checkout's venv python exist - and not a comparison against
    `sys.executable`. That distinction is the bug this sentence used to get wrong: run the lane *through* the venv
    (`make fast`, which resolves `PY` to `.venv/bin/python`) and the two paths are equal, so the note printed "no
    .venv/bin/python in this checkout" about a checkout that demonstrably has one, while naming it as the interpreter. A
    reader comparing this run with a CI container could conclude only that the line meant nothing, which is what it did.
    """
    if VENV_PYTHON.exists():
        same = "the same interpreter" if interpreter == sys.executable else "a different one"
        return f"interpreter: {interpreter} — this checkout's {VENV_DIR}; invoked through {sys.executable} ({same})"
    return (
        f"interpreter: {sys.executable} — no {VENV_DIR}/bin/python in this checkout, "
        f"so the invoking interpreter is used unchanged"
    )


def emit(line: str, *, to_stderr: bool = False) -> None:
    """Print one line of the lane's own report and flush it immediately.

    Python block-buffers stdout whenever it is not a terminal. Redirect the lane to a file with `> log 2>&1` and
    stderr - unbuffered - arrives ahead of the status lines that caused it: measured on this tree, `FAILED ruff
    check` and the skipped-steps line printed *before* `[exit 1] ruff check (0.06s)`, so a reader of a merged log
    sees the conclusion before the step that produced it. Flushing each line makes the file read in the order
    things happened.
    """
    print(line, file=sys.stderr if to_stderr else sys.stdout, flush=True)


def run(interpreter: str, args: Sequence[str]) -> tuple[int, float]:
    """Run one step under `interpreter`, let its own output through, and report (exit code, seconds)."""
    started = time.monotonic()
    completed = subprocess.run(step_command(interpreter, args), check=False)
    return completed.returncode, time.monotonic() - started


def describe(returncode: int) -> str:
    """Translate the exit codes a wrapper must not flatten into 'failed'.

    pytest 5 means the pattern matched nothing — a mistake in the command, not a failing test. Flattening it hides the
    only clue a reader has, and a green "tests passed" for a run that collected zero tests is the failure mode this
    tool exists to avoid.
    """
    if returncode == 0:
        return "ok"
    if returncode == 5:
        return "NO TESTS RAN - the -k pattern matched nothing, so this proves nothing"
    if returncode == 4:
        return "BAD EXPRESSION - pytest could not parse the -k expression, so no test ran"
    return f"exit {returncode}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the fast-lane gates: lint, doc gates, targeted pytest.")
    parser.add_argument(
        "patterns",
        nargs="*",
        help="test keywords (ORed) or a pytest -k expression using or/and/not; omit with --dry-run to see the plan",
    )
    parser.add_argument("--dry-run", action="store_true", help="print the steps without running them")
    parser.add_argument("--no-docs", action="store_true", help=f"skip {' and '.join(DOC_TOOLS)}")
    args = parser.parse_args(argv)

    if not args.patterns and not args.dry_run:
        emit("no -k pattern given; pass one, or use --dry-run to see what the fast lane runs", to_stderr=True)
        return 2

    # Rejected before any step runs. The alternative is paying for scoped ruff and the version chain and only then
    # handing pytest an expression it refuses with exit 4 - a mistake in the command found at its most expensive moment.
    words = flatten_patterns(args.patterns)
    if args.patterns:
        problem = validate_expression(words)
        if problem is not None:
            emit(f"bad -k expression: {problem}", to_stderr=True)
            emit(
                f"as read by this lane: {pytest_expression(args.patterns)!r} "
                f"(bare keywords are ORed; or/and/not are passed to pytest as written)",
                to_stderr=True,
            )
            return 2

    steps = build_steps(args.patterns, include_docs=not args.no_docs)
    interpreter = step_interpreter()

    if args.dry_run:
        emit(interpreter_note(interpreter))
        emit("fast lane would run:")
        for name, cmd in steps:
            emit(f"  {' '.join(step_command(interpreter, cmd))}   # {name}")
        emit("deliberately not in the fast lane (commit/release only):")
        for name in COMMIT_ONLY_STEPS:
            emit(f"  {name}")
        return 0

    emit(interpreter_note(interpreter))
    total = 0.0
    for index, (name, cmd) in enumerate(steps):
        code, elapsed = run(interpreter, cmd)
        total += elapsed
        status = describe(code)
        emit(f"[{status}] {name} ({elapsed:.2f}s)")
        if code == 0:
            continue

        # What it cost, then what it found: the ordering `make gate` already gives a reader. The steps after the
        # failure are named as unproven rather than quietly omitted from the report.
        emit(f"fast lane total: {total:.2f}s")
        emit(f"FAILED {name}: {status}", to_stderr=True)
        skipped = [step for step, _ in steps[index + 1 :]]
        if skipped:
            emit(
                f"stopped at the first failing step: {len(skipped)} later step(s) never ran "
                f"({', '.join(skipped)}) - unproven, not passed",
                to_stderr=True,
            )
        emit(
            "the fast lane is the floor, not the whole gate set: mypy, coverage and (when a visible string or status "
            "code moved) tools/e2e_harness.py still runs before a commit - see the Makefile gate target",
            to_stderr=True,
        )
        return 1

    emit(f"fast lane total: {total:.2f}s")
    emit("fast lane clean. Full gates remain required at commit.")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a script, not as an import
    sys.exit(main())
