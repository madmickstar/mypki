"""The fast lane is pinned to the cheap half of the gate list.

`tools/fast_lane.py` claims in its own docstring that "the omission is asserted in `tests/test_fast_lane.py`". That
claim was written before this file existed, which is the failure mode the claim itself warns about: a tool that says it
is checked, and is not. A lane advertised as fast decays the first time someone adds a slow step to it for convenience —
`mypy src` costs half a second and reads harmless, a harness run costs minutes and reads thorough — and nothing in the
lane itself can notice, because the lane has no opinion about its own contents.

So the assertions here are negative by design. They do not check that the fast lane runs the gates it should (the steps
print themselves, and running them from a test would nest one pytest inside another). They check what stays **out**:
coverage measurement, mypy, and both harness scripts. That is the only property worth locking, because every other
property of this tool is visible in its output the moment you run it.

Why the constants are read rather than the source text: `LINT_STEPS`, `DOC_TOOLS` and `COMMIT_ONLY_STEPS` are data in
the tool precisely so this file can assert over them. A test that grepped `fast_lane.py` for the string "mypy" would
pass against a lane that runs mypy (the word appears in its docstring explaining why it does not) and fail against one
that renamed a step while running exactly the same commands.

The two exit codes are asserted by calling `main` directly rather than by spawning the script: `main([])` and
`main(["--dry-run"])` both decide before any subprocess starts, so these tests cost milliseconds and cannot recurse.
Exit 2 is the usage error, and it matters for the same reason exit 5 does — a wrapper that reads "no arguments" as a
successful run has silently run no gates at all.
"""

from __future__ import annotations

import sys
from pathlib import Path

import fast_lane


# --------------------------------------------------------------------------------------------- what the lane runs
def test_the_lint_steps_are_only_scoped_ruff() -> None:
    """The two steps every edit pays for are `ruff check` and `ruff format --check`, both scoped.

    Scoped, not `.`: `docs/CHANGE_POLICY.md` states that the scoped form is the gate whose file counts mean anything,
    and a fast lane that ran a different ruff invocation would produce a result the commit gate cannot be compared to.
    """
    assert fast_lane.LINT_STEPS, "a fast lane with no lint steps is not a fast lane"

    for name, cmd in fast_lane.LINT_STEPS:
        assert "ruff" in name, f"non-ruff step {name!r} sits in LINT_STEPS"
        assert cmd[:2] == ("-m", "ruff"), f"{name!r} does not invoke ruff as a module: {cmd}"
        assert cmd[2] in {"check", "format"}, f"{name!r} runs an unexpected ruff subcommand: {cmd}"
        assert cmd[-3:] == ("src", "tests", "tools"), f"{name!r} is not the scoped gate the commit gate uses: {cmd}"

    names = [name for name, _ in fast_lane.LINT_STEPS]
    assert names == ["ruff check", "ruff format --check"], f"unexpected lint steps: {names}"


def test_the_doc_gates_are_the_two_tools_by_path() -> None:
    """`DOC_TOOLS` names the version chain and the docs gate, invoked the way CI invokes them.

    The paths matter as much as the pair: `tools/` is not part of the installed package, so `-m tools.check_docs` would
    be a route the real gates never take, and a lane that passes only on an import route CI does not use is a lane that
    hides a broken gate.
    """
    assert fast_lane.DOC_TOOLS == ("tools/check_version.py", "tools/check_docs.py")


def test_the_commit_only_steps_name_everything_the_fast_lane_drops() -> None:
    """The list the tool prints as "deliberately not in the fast lane" has to name the real slow gates.

    If one of these disappeared from `COMMIT_ONLY_STEPS` the tool would stop telling anyone that mypy, coverage and the
    harnesses are still required at commit — a silent omission is how "fast" turns into "incomplete".
    """
    committed = fast_lane.COMMIT_ONLY_STEPS
    assert "mypy src" in committed
    assert "pytest --cov" in committed
    assert "scripts/smoke_test.sh" in committed
    assert "scripts/smoke_test.ps1" in committed


# ------------------------------------------------------------------------------------------------ what it must not
def test_no_build_step_is_a_slow_gate() -> None:
    """The load-bearing assertion in this file: no step `build_steps` can produce mentions mypy, coverage or a harness.

    Coverage is checked as "no `-cov` token except the literal `--no-cov`", because disabling coverage *is* spelled
    with that substring and a rule that flagged it would forbid the very flag that keeps pytest fast. The patterns
    argument is varied rather than fixed so a slow gate hidden behind one particular code path still shows up.
    """
    variants = [
        fast_lane.build_steps([], include_docs=True),
        fast_lane.build_steps([], include_docs=False),
        fast_lane.build_steps(["sign"], include_docs=True),
        fast_lane.build_steps(["csr", "nav"], include_docs=False),
    ]

    for steps in variants:
        for name, cmd in steps:
            rendered = f"{name} {' '.join(cmd)}"
            assert "mypy" not in rendered, f"a type gate entered the fast lane: {rendered}"
            assert "smoke_test" not in rendered, f"a harness run entered the fast lane: {rendered}"
            assert "harness_ledger" not in rendered, f"a ledger run entered the fast lane: {rendered}"
            for token in cmd:
                if token.startswith("-cov") or token.startswith("--cov"):
                    raise AssertionError(f"coverage measurement entered the fast lane: {rendered}")


def test_coverage_is_off_in_every_pytest_step_rather_than_merely_absent() -> None:
    """When the lane does run pytest, it runs it with `--no-cov`.

    A partial suite measures a partial denominator, so any percentage printed from a targeted run would be a number
    nobody can compare against the commit gate's. `--no-cov` is what stops the lane printing one.
    """
    steps = fast_lane.build_steps(["sign"], include_docs=True)
    pytest_steps = [cmd for name, cmd in steps if "pytest" in name or "pytest" in cmd]
    assert pytest_steps, "a lane given a pattern must run pytest"
    for cmd in pytest_steps:
        assert "--no-cov" in cmd, f"targeted pytest without --no-cov measures nothing comparable: {cmd}"


def test_a_lane_with_no_pattern_runs_gates_but_not_pytest() -> None:
    """`--dry-run` with no pattern is lint plus the doc gates, and nothing else.

    This is the shape that would otherwise drift: someone adds a blanket pytest step for convenience, and every
    `--dry-run` in the project quietly becomes a full-suite run that still advertises itself as the fast lane.
    """
    steps = fast_lane.build_steps([], include_docs=True)
    names_and_cmds = [f"{name} {' '.join(cmd)}" for name, cmd in steps]
    assert not any("pytest" in entry for entry in names_and_cmds), (
        f"a pytest step appeared with no pattern given: {names_and_cmds}"
    )
    assert len(steps) == len(fast_lane.LINT_STEPS) + len(fast_lane.DOC_TOOLS), (
        f"no-pattern lane is not lint + the two doc gates: {names_and_cmds}"
    )
    head = [cmd for _, cmd in steps[: len(fast_lane.LINT_STEPS)]]
    assert head == [cmd for _, cmd in fast_lane.LINT_STEPS]


def test_no_docs_skips_exactly_the_two_named_tools() -> None:
    """`--no-docs` removes `DOC_TOOLS` and nothing else, so the lint half is never optional."""
    with_docs = fast_lane.build_steps([], include_docs=True)
    without_docs = fast_lane.build_steps([], include_docs=False)

    doc_cmds = [cmd for _, cmd in with_docs if any(tool in " ".join(cmd) for tool in fast_lane.DOC_TOOLS)]
    assert len(doc_cmds) == 2, f"expected one step per DOC_TOOLS entry, saw {doc_cmds}"
    assert all(" ".join(cmd) in fast_lane.DOC_TOOLS for cmd in doc_cmds), doc_cmds

    assert [cmd for _, cmd in without_docs] == [cmd for _, cmd in fast_lane.LINT_STEPS]


# ------------------------------------------------------------------------------------- exit codes a wrapper flattens
def test_no_pattern_without_dry_run_is_a_usage_error() -> None:
    """`main([])` returns 2 rather than running the lint gates and calling that a pass.

    The distinction is the whole point of the exit code: "you asked for nothing" and "everything you asked for passed"
    are different facts, and a script that reads both as success runs no tests for every mistyped invocation.
    """
    assert fast_lane.main([]) == 2


def test_dry_run_returns_zero_without_running_anything() -> None:
    """`--dry-run` prints the plan and exits 0 without spawning a single step."""
    assert fast_lane.main(["--dry-run"]) == 0


# ------------------------------------------------------------------------ which interpreter the steps run under
def test_the_steps_are_stored_without_an_interpreter_prefix() -> None:
    """`build_steps` emits arguments, not commands: the interpreter is added at spawn time and nowhere else.

    That separation is what keeps one lane definition usable in two environments — this checkout, where mypki lives in
    `.venv`, and a CI container that installs into the system interpreter. If an interpreter path were baked into
    `LINT_STEPS` or `DOC_TOOLS`, the same data could not serve both, and the pinning below would be asserting a path
    rather than a policy.
    """
    for name, cmd in fast_lane.build_steps(["sign"], include_docs=True):
        assert not cmd[0].endswith("python"), f"{name!r} hardcodes an interpreter: {cmd}"
        assert not Path(cmd[0]).is_absolute(), f"{name!r} hardcodes an absolute interpreter: {cmd}"


def test_the_venv_is_named_as_a_directory_and_the_python_is_derived_from_it() -> None:
    """`VENV_DIR` is the one fact; `VENV_PYTHON` is built from it, so a rename is a single edit."""
    assert fast_lane.VENV_DIR == ".venv"
    assert fast_lane.VENV_PYTHON == fast_lane.BUILD_ROOT / fast_lane.VENV_DIR / "bin" / "python"


def test_step_interpreter_prefers_this_checkouts_venv_python(monkeypatch, tmp_path) -> None:
    """When a `.venv/bin/python` exists it is the interpreter every step runs under.

    This is the fix for the invocation bug that made the lane lie: run the lane through an interpreter without mypki
    installed and pytest aborts at conftest with `ModuleNotFoundError`, while scoped ruff and both doc gates pass: they
    are stdlib-only. The half-green run that comes back reads as "the edit broke a test", when in fact no test of the
    edit ran at all.
    """
    fake = tmp_path / fast_lane.VENV_DIR / "bin" / "python"
    fake.parent.mkdir(parents=True)
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(fast_lane, "VENV_PYTHON", fake)

    assert fast_lane.step_interpreter() == str(fake)


def test_step_interpreter_falls_back_to_the_invoking_one_when_there_is_no_venv(monkeypatch, tmp_path) -> None:
    """No `.venv/bin/python` means the invoking interpreter is used unchanged — the CI-container case.

    A container that installs mypki into the system interpreter has no venv to prefer, and refusing to run there would
    make the lane unusable exactly where CI needs it. The fallback is a decision with a stated reason, not an oversight:
    `interpreter_note` below says which side was taken.
    """
    monkeypatch.setattr(fast_lane, "VENV_PYTHON", tmp_path / fast_lane.VENV_DIR / "bin" / "python")

    assert fast_lane.step_interpreter() == sys.executable


def test_step_command_prefixes_the_chosen_interpreter_to_every_step() -> None:
    """The spawn shape is `[interpreter, *step_args]` for every step the lane can produce."""
    steps = fast_lane.build_steps(["csr", "nav"], include_docs=True)
    prefixed = [fast_lane.step_command("/pretend/python", cmd) for _, cmd in steps]

    assert all(entry[0] == "/pretend/python" for entry in prefixed), prefixed
    assert [entry[1:] for entry in prefixed] == [list(cmd) for _, cmd in steps], (
        "prefixing the interpreter changed a step's own arguments"
    )


def test_the_interpreter_choice_is_printed_rather_than_left_inferred() -> None:
    """Whichever side `step_interpreter` took, `interpreter_note` says so — including that it took one.

    A silent switch is its own failure mode: a reader comparing two runs (this checkout versus CI) has to be able to see
    that they ran under different interpreters. The phrasing is needle-asserted for the same reason as the exit-5
    message: rewording must not drop the reason.
    """
    venv_side = fast_lane.interpreter_note("/checkout/.venv/bin/python")
    assert "interpreter:" in venv_side
    assert ".venv" in venv_side
    assert sys.executable in venv_side, "the invoking interpreter is not named when the lane switches away from it"

    fallback = fast_lane.interpreter_note(sys.executable)
    assert "used unchanged" in fallback, f"the fallback is not stated: {fallback}"


def test_pytest_exit_5_is_reported_as_no_tests_rather_than_a_failure() -> None:
    """Exit 5 means the `-k` pattern matched nothing, and `describe` has to say so in words a reader can act on.

    Read as "failed", it hides the only clue available (a typo in the pattern). Read as "ok", it turns every mistyped
    invocation into a green run that collected zero tests — which is worse than not running the lane at all, because it
    looks like evidence. The phrasing is asserted as a needle so rewording it cannot quietly soften the message.
    """
    assert "NO TESTS RAN" in fast_lane.describe(5)
    assert fast_lane.describe(0) == "ok"
    assert fast_lane.describe(1) == "exit 1"
