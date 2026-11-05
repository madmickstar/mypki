"""The src/ prose gate is pinned from the test side, not merely advertised by the tool.

`tools/check_docstrings.py` polices docstrings and full-line comments under `src/`: a released version named in living
code, a note about how one probe run went, or a pointer at a planning document's numbering. All three rules are patterns
over text, and a pattern that matches nothing is indistinguishable from a clean tree — the failure mode
`tools/check_docs.py --self-test` exists to close on the markdown side. This file closes it here, and adds the two facts
a self-test cannot establish on its own: that the real `src/` reports zero findings, and that the phrases other files
quote out of docstrings are still present in the docstrings carrying them.

Why the needle half matters most. A test or a document quoting a sentence out of a docstring has taken on the job of
keeping that sentence alive; reword the prose and the quoter fails, reading as a code defect. Those phrases were
inventoried before this gate existed, and they are exactly what a mechanical rewrite could delete while every rule still
passes — a gate that only reports findings can clean a tree by removing the thing a test quotes. Asserting survival is
what stops "clean" from meaning "emptied".

Why the checker's own imports are asserted: like `tools/check_version.py`, this gate runs in CI against a checkout where
mypki was never installed, and it has to stay runnable there. A checker that grows an import of the package it reads can
only speak after that package was installed, which inverts the ordering the gate exists to enforce. The check reads the
source rather than asserting "it worked in CI once", because that fact is invisible locally.

Why the fast-lane decision is asserted here: this gate was deliberately kept **out** of the fast lane's doc pair and
recorded as a commit-only step instead, since it reads every module under `src/` rather than four lines of a manifest.
That is a decision with two sides — a cheap gate reachable during an edit, versus a lane that stays cheap on an edit to
one template — so it is asserted as data rather than left in a comment, where a convenience edit could reverse it.
"""

from __future__ import annotations

import ast

import check_docstrings
import fast_lane
from check_docstrings import BUILD_ROOT, POLICED_DIRECTORY

#: Phrases that `tests/`, the harness scripts, README and `docs/page-map.md` quote out of `src/` docstrings. Each is
#: docstring text only: no live code or template spells it, so a rewrite that reworded the docstring would break the
#: quoter rather than fail to compile. Asserted as (module, phrase) pairs, module-scoped, because a phrase surviving in
#: some other file proves nothing about the sentence the quoter actually reads.
DOCSTRING_NEEDLES: tuple[tuple[str, str], ...] = (
    ("app.py", "no API surface advertised"),
    ("ca.py", "no logins, so exposure is controlled by binding"),
    ("cli.py", "cannot run"),
    ("crl.py", "for completeness"),
    ("inspect.py", "Ed25519PublicKey is not an accepted key"),
    ("inspect.py", "is this the expired one?"),
    ("inspect.py", "is this the root or the leaf?"),
    ("inspect.py", "revoked?"),
    ("inspect.py", "why does my client reject this?"),
    ("keys.py", "usable key"),
    ("ocsp_responder.py", "the CA did not say"),
    ("signing.py", "we handled EC"),
    ("validators.py", "invalid SAN"),
    ("validators.py", "server..local"),
)

#: One line carrying all three violations at once, used to prove the rules report separately rather than collapsing a
#: dirty line into one complaint, and that the `all` marker excuses it wholesale.
TRIPLE_VIOLATION = "    # MEASURED in (0.1.0), and the plan's answer 2 is why this line exists\n"

#: The same shape with nothing wrong in it: an invariant stated as an invariant, which no rule may flag.
CLEAN_PROSE = "    # A refusal names what was refused, so the operator can fix the field rather than guess at it\n"

#: The banner splitting the checker into its reading half and its mutation half. The mutation half legitimately builds a
#: throwaway tree to show each rule firing — banning writes there would forbid the proof itself — so the ban on writing
#: is scoped at this marker instead of applied to the whole file.
SELF_TEST_MARKER = "# --------------------------------------------------------------------------------------------"


def _source(module: str) -> str:
    return (BUILD_ROOT / "src" / "mypki" / module).read_text(encoding="utf-8")


def _wrapped(line: str) -> str:
    """One prose line inside a module docstring, which is what makes the checker read it at all."""
    return f'"""\n{line}"""\n'


# ------------------------------------------------------------------------------------- the tree this gate reads now
def test_the_package_has_zero_findings() -> None:
    """`tools/check_docstrings.py` reports nothing over the real `src/`.

    This is the assertion that makes the gate a gate. Every rule is proven able to fire, by the tool's own self-test and
    by the triple-violation check below, so a green run here means the prose was written to the rules rather than that
    the rules were edited into silence.
    """
    findings = check_docstrings.check_package(BUILD_ROOT)
    reported = "\n".join(str(finding) for finding in findings)
    assert findings == [], f"src/ carries release-time prose:\n{reported}"


def test_the_policed_directory_is_src_only() -> None:
    """`tests/` and `tools/` may discuss releases, and that exemption is asserted rather than assumed.

    A checker widened to the whole tree would flag a test named for a release it reproduces and a tool's note about a
    pinned dependency — both facts that have to be written down somewhere. An exemption is only safe while it stays
    visible, so it is pinned here rather than trusted from the tool's own docstring.
    """
    assert POLICED_DIRECTORY == "src"

    policed = check_docstrings.policed_files(BUILD_ROOT)
    assert policed, "the gate found nothing to read, which is not the same as finding nothing wrong"

    src_dir = BUILD_ROOT / "src"
    outside = [p.relative_to(BUILD_ROOT).as_posix() for p in policed if not p.is_relative_to(src_dir)]
    assert outside == [], f"files outside src/ were policed: {outside}"

    suffixes = {path.suffix for path in policed}
    assert suffixes == {".py"}, f"the prose gate reached beyond Python sources: {suffixes}"


def test_the_rules_are_named_and_narrow() -> None:
    """The three rule ids are the vocabulary an allow marker names, so they cannot drift by accident.

    Narrowness is asserted alongside the names, because that is where this rule's damage would land: a dotted-quad
    address in prose (`127.0.0.1`, `10.0.0.1`, the wildcard bind) is not a release citation, and an unbounded pattern
    flags it as one — which would push authors toward blanket markers, the route by which an escape hatch becomes the
    normal path. Both halves of that bargain are asserted as data rather than described: a pin whose major version is
    itself `0.` does read as a citation, and the scoping stops at the third component, so a two-part `pre-0.7` is not
    caught even though `pre-0.7.0` is. src/ prose uses the two-part spelling today, which is why the gap is asserted
    rather than left for someone to rediscover as a surprise non-finding.
    """
    ids = [rule for rule, _, _ in check_docstrings.RULES]
    assert ids == ["version-citation", "one-run-probe", "release-plan-tag"], ids

    patterns = {rule: pattern for rule, pattern, _ in check_docstrings.RULES}
    version = patterns["version-citation"]

    for legal in (
        "cryptography 50.0.2",
        "pydantic-settings 2.16.1",
        "RFC 5280 §5.2.1",
        "Serving on 127.0.0.1 rather than 0.0.0.0 is the default",
        "an IP written as `10.0.0.1` becomes an IP general name",
    ):
        assert not version.search(legal), f"the version rule flags legal prose: {legal!r}"

    for citation in (
        "as of 0.4.0 a save publishes",
        "`0.5.0` dropdowns",
        "pre-0.7.0 wording",
        "fastapi 0.115.0",
        "starlette 0.47.2",
    ):
        assert version.search(citation), f"the version rule stopped recognising a citation: {citation!r}"

    # Where the scoping ends, asserted so the boundary cannot move unnoticed: the `pre-` arm is spelled with three
    # components, so the two-part form reads as ordinary prose and src/ relies on that today. A gate that quietly
    # widened to catch it would turn existing sentences into findings.
    assert not version.search("pre-0.7 certificates"), "the two-part boundary moved without this test knowing"


# --------------------------------------------------------------------------------------------- the gate's own proof
def test_the_self_test_exits_zero() -> None:
    """`main(["--self-test"])` returns 0: each rule fires on synthetic text and clean prose survives it.

    Called in-process rather than by spawning the script, for the same reason `tests/test_fast_lane.py` calls `main`
    directly — the decision happens before any subprocess starts, so this costs milliseconds and cannot nest one pytest
    run inside another.
    """
    assert check_docstrings.main(["--self-test"]) == 0


def test_one_dirty_line_produces_three_named_findings() -> None:
    """A line breaking all three rules is reported three times, once per rule id.

    Collapsing them into "this line is wrong" would make the allow marker unusable: the marker names a rule id, and a
    finding with no id cannot be excused by one.
    """
    findings = check_docstrings.check_text("synthetic.py", _wrapped(TRIPLE_VIOLATION))
    rules = sorted(finding.rule for finding in findings)
    assert rules == ["one-run-probe", "release-plan-tag", "version-citation"], [str(f) for f in findings]

    clean = check_docstrings.check_text("synthetic.py", _wrapped(CLEAN_PROSE))
    assert clean == [], f"clean prose was flagged: {[str(c) for c in clean]}"


def test_the_allow_marker_excuses_a_line_and_only_that_line() -> None:
    """A marker excuses rules on the line it sits on, and never reaches the next one.

    Both directions are asserted on the triple-violation line itself, because that is the only fixture where the two
    claims are separable: excusing one rule there must leave the other two still reporting that same line — a marker
    that silenced the whole line under a single named rule would make the escape hatch far wider than its name says —
    and an identical unmarked copy directly below has to be reported in full, since an excuse that bled downward would
    exempt a paragraph while looking like one line was excused.
    """
    excused = check_docstrings.check_text(
        "synthetic.py",
        '"""\n    # MEASURED defect found by driving the app  # allow-docstring-rule: all\n"""\n',
    )
    assert excused == [], [str(f) for f in excused]

    named = check_docstrings.check_text(
        "synthetic.py",
        _wrapped(TRIPLE_VIOLATION.rstrip("\n") + "  # allow-docstring-rule: one-run-probe"),
    )
    still_reported = sorted(finding.rule for finding in named)
    assert still_reported == ["release-plan-tag", "version-citation"], [str(f) for f in named]
    assert {finding.line for finding in named} == {2}, [str(f) for f in named]

    excused_source = (
        '"""\n' + TRIPLE_VIOLATION.rstrip("\n") + "  # allow-docstring-rule: all\n" + TRIPLE_VIOLATION + '"""'
    )
    leak = check_docstrings.check_text("synthetic.py", excused_source)
    assert sorted({finding.line for finding in leak}) == [3], [str(f) for f in leak]
    assert sorted(finding.rule for finding in leak) == ["one-run-probe", "release-plan-tag", "version-citation"]


def test_the_findings_and_clean_paths_exit_differently(tmp_path) -> None:
    """Exit 1 means there is prose to fix and exit 0 means the tree was read and found clean.

    Asserted end-to-end through `main` on a throwaway tree rather than only through the in-process helpers, because the
    exit code is what CI and the pre-commit hooks actually consume: a wrapper that flattens the two reports success for
    a gate that found work.
    """
    root = tmp_path / "tree"
    target_dir = root / POLICED_DIRECTORY / "mypki"
    target_dir.mkdir(parents=True)
    target = target_dir / "mod.py"

    target.write_text(_wrapped(TRIPLE_VIOLATION), encoding="utf-8")
    assert check_docstrings.main(["--root", str(root)]) == 1

    target.write_text(_wrapped(CLEAN_PROSE), encoding="utf-8")
    assert check_docstrings.main(["--root", str(root)]) == 0

    assert check_docstrings.main(["--print-rules"]) == 0


# --------------------------------------------------------------------------------- the checker stays runnable bare
def test_the_checker_imports_nothing_from_mypki() -> None:
    """`tools/check_docstrings.py` must run where mypki is not installed.

    Asserted by reading its imports rather than by asserting "it worked in CI once": the docs job installs nothing,
    and a prose gate that grew an import of the package it reads could only speak after that package had been
    built, which is exactly the ordering this gate exists to invert. `mypki` must never appear, and anything outside
    the standard library has to be a deliberate edit here rather than a silent one inside the tool.
    """
    source = (BUILD_ROOT / "tools/check_docstrings.py").read_text(encoding="utf-8")

    imported = {
        line.split()[1].split(".")[0] for line in source.splitlines() if line.strip().startswith(("import ", "from "))
    }
    assert "mypki" not in imported, sorted(imported)

    stdlib_only = {"__future__", "argparse", "ast", "collections", "dataclasses", "pathlib", "re", "sys", "tempfile"}
    assert imported <= stdlib_only, f"non-stdlib imports: {sorted(imported - stdlib_only)}"


def test_the_reading_half_writes_nothing() -> None:
    """A prose gate that "fixed" a docstring would rewrite history rather than report it.

    Asserted two ways, following `tests/test_version.py`'s pattern: no write calls in the half of the checker that does
    the reading, and every policed file byte-identical after a real run against this tree. The grep is scoped at the
    mutation-self-test marker because showing a rule firing means building a throwaway tree, and forbidding that would
    forbid the proof. The byte-identical half is what catches a write reaching in through a helper rather than at the
    top level, where the grep would have seen it.
    """
    source = (BUILD_ROOT / "tools/check_docstrings.py").read_text(encoding="utf-8")
    reading_half, mutation_half = source.split(SELF_TEST_MARKER, 1)
    assert mutation_half.strip(), "the checker's mutation half is missing, so the split above proves nothing"

    for forbidden in (".write_text(", ".write_bytes(", ".unlink(", "mkdir"):
        assert forbidden not in reading_half, f"the reading half of the checker calls {forbidden!r}"

    before = {path: path.read_bytes() for path in check_docstrings.policed_files(BUILD_ROOT)}
    assert before, "no src/ files were read, so this proves nothing"

    check_docstrings.check_package(BUILD_ROOT)

    after = {path: path.read_bytes() for path in check_docstrings.policed_files(BUILD_ROOT)}
    assert after == before


# ------------------------------------------------------------------------------------- what the rewrite must not have
def test_every_quoted_phrase_survives_in_its_own_module() -> None:
    """Each phrase quoted by a test, a harness script or a living document is still present in its module.

    The gate can clean a tree by rewording the sentence a quoter reads while every rule still passes. This assertion is
    what makes "zero findings" mean the prose was rewritten rather than removed: the phrase has to exist, in the module
    the quoter names.
    """
    for module, phrase in DOCSTRING_NEEDLES:
        source = _source(module)
        assert phrase in source, f"{module} no longer carries {phrase!r}, quoted by that spelling elsewhere"


def test_each_surviving_phrase_is_still_docstring_text() -> None:
    """The surviving phrases sit inside a docstring, not in a literal that happens to repeat them.

    A phrase relocated into live code would satisfy the assertion above while changing what the quoter is quoting: a
    docstring sentence and a runtime value are different promises, and this inventory was built from docstrings. The
    spans come from the same AST walk the gate uses, so "docstring" means here exactly what it means in the checker.
    """
    for module, phrase in DOCSTRING_NEEDLES:
        source = _source(module)
        hits = [number for number, line in enumerate(source.splitlines(), start=1) if phrase in line]
        assert hits, f"{module} lost {phrase!r}"

        spans = check_docstrings.docstring_spans(ast.parse(source))
        inside = [number for number in hits if any(start <= number <= end for start, end in spans)]
        assert inside, f"{phrase!r} survives in {module} outside a docstring; the quoter reads a docstring"


def test_the_needle_inventory_is_module_scoped_and_not_empty() -> None:
    """The inventory covers several modules, so one module cannot satisfy it by accident.

    Counted per module rather than in total: needles concentrated in two files would leave the rest of `src/` free to
    reword whatever its own quoters read.
    """
    assert len(DOCSTRING_NEEDLES) == 14
    modules = {module for module, _ in DOCSTRING_NEEDLES}
    assert len(modules) >= 8, f"the needle inventory is too concentrated to protect the package: {sorted(modules)}"

    assert len(set(DOCSTRING_NEEDLES)) == len(DOCSTRING_NEEDLES), "a duplicated needle would hide a missing one"


# --------------------------------------------------------------------------------- where this gate is allowed to run
def test_the_prose_gate_is_a_commit_step_not_a_fast_lane_step() -> None:
    """The fast-lane decision is recorded as data rather than left to prose.

    This gate reads every module under `src/`, so it belongs with mypy and coverage measurement in the list of things a
    commit owes, not in the pair of living-doc tools an edit pays for on every keystroke. A decision that exists only in
    a comment reverses itself the first time someone adds a gate to the lane for convenience, which is why both halves
    are asserted here: present in the commit-only list, absent from the doc pair and from anything `build_steps` emits.
    """
    assert "tools/check_docstrings.py" in fast_lane.COMMIT_ONLY_STEPS, fast_lane.COMMIT_ONLY_STEPS
    assert not any("check_docstrings" in tool for tool in fast_lane.DOC_TOOLS), (
        "the fast lane's doc pair gained a whole-src/ prose read; the lane is no longer the cheap half"
    )

    rendered = [f"{name} {' '.join(cmd)}" for name, cmd in fast_lane.build_steps(["sign"], include_docs=True)]
    assert not any("check_docstrings" in entry for entry in rendered), rendered


def test_the_fast_lane_still_names_its_two_doc_tools() -> None:
    """Adding a gate to the commit list must not have moved the fast lane's doc pair.

    Asserted from this side as well, because `tests/test_fast_lane.py` pins the pair and this file is the one that added
    a third prose tool to the tree. If the two assertions ever disagree, that disagreement is the signal that someone
    widened the lane rather than that a test is redundant.
    """
    assert fast_lane.DOC_TOOLS == ("tools/check_version.py", "tools/check_docs.py")
