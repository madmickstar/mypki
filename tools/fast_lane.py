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

ONE FAILURE MODE WORTH NAMING
    pytest exits **5** when its `-k` pattern matched nothing. A wrapper that reads any non-zero exit as "tests failed"
    and any zero as "fine" would report success for every mistyped pattern, which is worse than running no tests. Exit 5
    is reported here as a failure, with the reason spelled out.

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
    python3 tools/fast_lane.py KEYWORD [KEYWORD...]   # lint + version chain + pytest -k KEYWORD
    python3 tools/fast_lane.py --dry-run              # print the plan, run nothing
    python3 tools/fast_lane.py --no-docs              # skip the version-chain gate

Exit codes: 0 all steps passed · 1 a step failed (its reason printed, later steps not run) · 2 usage error
(no pattern and not --dry-run).
"""

from __future__ import annotations

import argparse
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


def build_steps(patterns: Sequence[str], *, include_docs: bool) -> list[tuple[str, tuple[str, ...]]]:
    """The exact commands this lane will run, in order.

    `--no-cov` is not an optimisation: coverage measurement is what makes pytest slow, and a partial run measures a
    partial denominator, so any percentage printed here would mean nothing. Coverage belongs to the full-suite gate.
    """
    steps = list(LINT_STEPS)
    if include_docs:
        steps.extend(("version chain", (tool,)) for tool in DOC_TOOLS)
    if patterns:
        expression = " or ".join(patterns)
        steps.append(
            (f"pytest -k {expression}", ("-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-cov", "-k", expression))
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
    """Say which interpreter was picked and why, so the choice is a printed fact rather than a hidden one."""
    if interpreter == sys.executable:
        return (
            f"interpreter: {sys.executable} — no {VENV_DIR}/bin/python in this checkout, "
            f"so the invoking interpreter is used unchanged"
        )
    return f"interpreter: {interpreter} — this checkout's {VENV_DIR}; invoked through {sys.executable}"


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
    return f"exit {returncode}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the fast-lane gates: lint, doc gates, targeted pytest.")
    parser.add_argument(
        "patterns", nargs="*", help="pytest -k expression(s), ORed; omit with --dry-run to see the plan"
    )
    parser.add_argument("--dry-run", action="store_true", help="print the steps without running them")
    parser.add_argument("--no-docs", action="store_true", help=f"skip {' and '.join(DOC_TOOLS)}")
    args = parser.parse_args(argv)

    if not args.patterns and not args.dry_run:
        print("no -k pattern given; pass one, or use --dry-run to see what the fast lane runs", file=sys.stderr)
        return 2

    steps = build_steps(args.patterns, include_docs=not args.no_docs)
    interpreter = step_interpreter()

    if args.dry_run:
        print(interpreter_note(interpreter))
        print("fast lane would run:")
        for name, cmd in steps:
            print(f"  {' '.join(step_command(interpreter, cmd))}   # {name}")
        print("deliberately not in the fast lane (commit/release only):")
        for name in COMMIT_ONLY_STEPS:
            print(f"  {name}")
        return 0

    print(interpreter_note(interpreter))
    total = 0.0
    for index, (name, cmd) in enumerate(steps):
        code, elapsed = run(interpreter, cmd)
        total += elapsed
        status = describe(code)
        print(f"[{status}] {name} ({elapsed:.2f}s)")
        if code == 0:
            continue

        # What it cost, then what it found: the ordering `make gate` already gives a reader. The steps after the
        # failure are named as unproven rather than quietly omitted from the report.
        print(f"fast lane total: {total:.2f}s")
        print(f"FAILED {name}: {status}", file=sys.stderr)
        skipped = [step for step, _ in steps[index + 1 :]]
        if skipped:
            print(
                f"stopped at the first failing step: {len(skipped)} later step(s) never ran "
                f"({', '.join(skipped)}) - unproven, not passed",
                file=sys.stderr,
            )
        print(
            "the fast lane is the floor, not the whole gate set: mypy, coverage and (when a visible string or status "
            "code moved) tools/e2e_harness.py still runs before a commit - see the Makefile gate target",
            file=sys.stderr,
        )
        return 1

    print(f"fast lane total: {total:.2f}s")
    print("fast lane clean. Full gates remain required at commit.")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a script, not as an import
    sys.exit(main())
