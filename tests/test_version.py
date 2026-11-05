"""The version chain: one number, four places that must agree, and three exit codes that mean different things.

`tools/check_version.py` is the only place in this project allowed to answer "is this release consistent?", so this file
has to prove the answers it gives are the right ones — including the awkward one. Exit **2** ("cannot check") must
never be
readable as a pass, and the build tree here is not yet a git repository, which means the no-git path is not a
hypothetical
case: it is what `python3 tools/check_version.py --require-tag` actually does on this checkout today.

Three things make these tests worth having in this shape:

* **The version is never written down here.** It is read out of `src/mypki/__init__.py`, the same line hatchling reads.
  A test that asserted `"0.1.0"` would fail on the next release for a reason unrelated to correctness, which is
  how people
  start deleting tests (STYLE §1).
* **Each negative case mutates one thing** in a copy of the tree under `tmp_path` (STYLE §8). Mutating the real
tree would
  be writing to the source this tool is supposed to protect, and a mutation suite that changes two things at once cannot
  say which check fired.
* **Tag behaviour is asserted against a repository built for the purpose.** git is available in this environment, so a
  temporary repo can prove the passing path (annotated tag matching the module), the lightweight-tag rejection, the
  tag-name-versus-code mismatch, and "repo with no tags at all" — which is **drift**, not "cannot check". That
  distinction
  is the difference between a release that forgot its tag and a directory that has no refs to consult.

The tree copies are built by hand rather than copied wholesale: only the four files the chain reads matter
(`src/mypki/__init__.py`, `pyproject.toml`, `CHANGELOG.md`, and git refs), so a copy is three writes and a
mutation, and a
failure names the one file that was changed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# `check_version` lives in tools/, which is on pytest's pythonpath (pyproject: pythonpath = ["tools"]) rather than
# inside
# the package. That placement is deliberate — the CI version job runs this tool **without installing mypki**, so a
# checker
# that could only be imported through the package could only run after the thing it checks had already been built.
import check_version
import pytest

BUILD_ROOT = Path(__file__).resolve().parent.parent
INIT_FILE = "src/mypki/__init__.py"

#: Read from the same line hatchling reads, so no expectation in this file can age out. `check_version`'s own pattern is
#: reused rather than re-typed here: two copies of the "what does a version line look like" regex is how a test starts
#: disagreeing with the tool it tests.
VERSION = check_version.MODULE_LINE_RE.fullmatch(
    next(
        line
        for line in (BUILD_ROOT / INIT_FILE).read_text(encoding="utf-8").splitlines()
        if check_version.MODULE_LINE_RE.fullmatch(line)
    )
).group("version")


# ----------------------------------------------------------------------------------- tree construction


def _init_source(version: str) -> str:
    """The one file the chain starts from, in exactly the spelling hatchling's pattern matches."""
    return f'"""Throwaway package docstring for the version chain tests."""\n\n__version__ = "{version}"\n'


def _tree(tmp_path: Path, *, version: str = VERSION, changelog: str | None = None) -> Path:
    """A minimal project tree whose version chain is consistent, for mutating one thing at a time.

    `pyproject.toml` here is a *reduction* of the real one rather than a copy: it keeps the two tables the tool inspects
    (`[project]`'s `dynamic`, `[tool.hatch.version]`'s path and pattern) and drops everything the chain does not read. A
    test that mutated a full copy would have to diff the copy against the real file to know what it changed, which
    is noise
    in a failure report.
    """
    root = tmp_path / "tree"
    (root / "src/mypki").mkdir(parents=True)
    (root / INIT_FILE).write_text(_init_source(version), encoding="utf-8")
    (root / "pyproject.toml").write_text(
        "[build-system]\n"
        'requires = ["hatchling>=1.24"]\n'
        'build-backend = "hatchling.build"\n\n'
        "[project]\n"
        'name = "mypki"\n'
        'dynamic = ["version"]\n'
        'requires-python = ">=3.10"\n\n'
        "[tool.hatch.version]\n"
        f'path = "{INIT_FILE}"\n'
        'pattern = \'^__version__ = "(?P<version>[^"]+)"$\'\n',
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(
        changelog if changelog is not None else _changelog_for(version),
        encoding="utf-8",
    )
    return root


def _next_minor(version: str) -> str:
    """The version one minor bump ahead of `version`, computed rather than written down.

    Uses `check_version.PEP440_RE`'s own release group instead of a private parser: two implementations of "split a
    version into numbers" is how a fixture starts disagreeing with the tool it feeds, and the tool's regex is already
    the definition of what this project considers a version. `X.Y.Z` -> `X.(Y+1).0`; a one- or four-component value
    raises rather than guessing, because a fixture built from a misread version would assert nothing.
    """
    match = check_version.PEP440_RE.match(version)
    if match is None:
        raise AssertionError(f"VERSION {version!r} is not a plain release version this helper can bump")
    parts = match.group("release").split(".")
    if len(parts) != 3:
        raise AssertionError(f"VERSION {version!r} is not X.Y.Z; refusing to invent a fixture version")
    major, minor = int(parts[0]), int(parts[1])
    return f"{major}.{minor + 1}.0"


def _changelog_for(*versions: str) -> str:
    """A Keep a Changelog body with one `## [X]` heading per version given."""
    sections = "\n".join(f"## [{entry}] - 2026-01-01\n\n- A fact about this release.\n" for entry in versions)
    return f"# Changelog\n\nAll notable changes to mypki are documented here.\n\n{sections}"


def _edit(root: Path, relative: str, replacement: str) -> Path:
    """Replace one file's whole content — the single mutation each test is allowed."""
    target = root / relative
    target.write_text(replacement, encoding="utf-8")
    return target


def _exit_code(root: Path, *, require_tag: bool = False) -> int:
    """Run the check and hand back its exit code.

    Called through `main()` rather than `check()` so the tests exercise the same argument parsing and reporting path CI
    uses; a bug in how the exit code is chosen from the report is exactly as dangerous as a bug in the checks
    themselves.
    """
    arguments = ["--root", str(root)]
    if require_tag:
        arguments.append("--require-tag")
    return check_version.main(arguments)


def _codes() -> tuple[int, int, int]:
    """(consistent, drift, cannot-check), read from the tool rather than hard-coded.

    Asserted against the module's own constants so a change to the contract fails loudly here instead of silently
    turning
    every expectation in this file into a wrong number.
    """
    return check_version.EXIT_OK, check_version.EXIT_DRIFT, check_version.EXIT_CANNOT_CHECK


# --------------------------------------------------------------------------------------- the real tree


def test_the_build_tree_itself_is_consistent() -> None:
    """The definition-of-done assertion for this file: the tree under test passes its own checker.

    Run against the real build root rather than a copy, because every other test here proves the tool can detect
    something
    and this one proves it does not detect it *here*. A green suite with a red version chain is the failure mode
    this whole
    tool exists to prevent, and it is invisible without exactly this test.
    """
    ok, _drift, cannot = _codes()

    assert _exit_code(BUILD_ROOT) == ok != cannot


def _consistent_tree(root: Path, version: str = "9.9.9") -> None:
    """A minimal tree whose first four links are consistent, so the only thing a test can vary is the fifth.

    Without this, a fixture that omits `[tool.hatch.version]` reports *cannot check* for the wrong reason and the
    assertion below would pass against a tool that had never looked at git at all.
    """
    (root / "src" / "mypki").mkdir(parents=True, exist_ok=True)
    (root / "src" / "mypki" / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\ndynamic = ["version"]\n\n'
        "[tool.hatch.version]\n"
        'path = "src/mypki/__init__.py"\n'
        """pattern = \'^__version__ = "(?P<version>[^"]+)"$\'\n""",
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(f"## [{version}] - 2026-01-01\n", encoding="utf-8")


def test_require_tag_on_a_plain_directory_is_cannot_check_rather_than_drift(tmp_path: Path) -> None:
    """A directory with no `.git` has no refs to consult, which is **cannot check** (2), never drift (1).

    Built in a temporary directory rather than asserted against `BUILD_ROOT`, because the answer depends on whether this
    checkout is a repository today — a fact that changes the moment someone runs `git init`, and which no test should be
    pinned to. Asserting the real tree's state here would make the suite flip from pass to fail for a reason that has
    nothing to do with the code under test.

    The distinction is operational, not cosmetic: "no such tag" means a release happened untagged and somebody must go
    tag it, while "this is not a repository" means there are no refs at all. Reporting the first when the truth is the
    second sends someone hunting for a tag that was never supposed to exist.
    """
    ok, drift, cannot = _codes()
    _consistent_tree(tmp_path)

    code = _exit_code(tmp_path, require_tag=True)

    assert code == cannot
    assert code != ok
    assert code != drift


def test_require_tag_in_a_repository_without_the_release_tag_is_drift(tmp_path: Path) -> None:
    """In a real repository, a missing `vX.Y.Z` tag is **drift** (1): git answered, and its answer was "no such tag".

    This is the case that appears once a checkout *is* a repository, and it is the opposite instruction to the test
    above — here somebody genuinely must go tag the release. Asserted in a throwaway repository for the same reason:
    `BUILD_ROOT`'s tag state is a moving target while releases are being cut.
    """
    ok, drift, cannot = _codes()
    _consistent_tree(tmp_path)

    init = subprocess.run(["git", "init", "-q"], cwd=tmp_path, capture_output=True, text=True, check=False)
    if init.returncode != 0:
        pytest.skip("git is not available in this environment")

    code = _exit_code(tmp_path, require_tag=True)

    assert code == drift
    assert code != ok
    assert code != cannot


def test_the_tool_can_be_run_as_a_script_from_the_command_line() -> None:
    """The CI contract, exercised as a process rather than as an import.

    `.github/workflows/ci.yml` runs `python3 tools/check_version.py` with no package installed and no virtualenv, so the
    exit code has to survive `sys.exit(main())` and a bare interpreter. A test that only imported `main()` would
    pass even
    if the `__main__` guard were deleted — which is how a CI step ends up always seeing 0.
    """
    completed = subprocess.run(
        [sys.executable, str(BUILD_ROOT / "tools/check_version.py"), "--root", str(BUILD_ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == check_version.EXIT_OK, completed.stdout + completed.stderr
    assert "version chain consistent" in completed.stdout


# --------------------------------------------------------------------------------- link 1: the module line


def test_a_static_version_in_project_is_drift(tmp_path: Path) -> None:
    """Someone adds `version = "0.1.0"` to `[project]` "to make the IDE happy", and the chain now has two copies.

    The quietest way this breaks: it builds, installs, and produces a wheel whose metadata no longer has to agree
    with the
    module. Detected as drift rather than accepted because `dynamic = ["version"]` is what makes agreement structural.
    """
    ok, drift, _cannot = _codes()
    root = _tree(tmp_path)

    original = (root / "pyproject.toml").read_text(encoding="utf-8")
    _edit(root, "pyproject.toml", original.replace('dynamic = ["version"]', f'version = "{VERSION}"'))

    assert _exit_code(root) == drift != ok


def test_a_missing_dynamic_declaration_is_drift(tmp_path: Path) -> None:
    """The same failure from the other side: no static version either, so hatchling has nothing to read.

    Split from the previous test because they are different mistakes with different fixes — one is "delete this
    line", the
    other is "add that list back" — and a single test covering both would report whichever check fired first.
    """
    ok, drift, _cannot = _codes()
    root = _tree(tmp_path)

    original = (root / "pyproject.toml").read_text(encoding="utf-8")
    _edit(root, "pyproject.toml", original.replace('dynamic = ["version"]', 'dynamic = ["dependencies"]'))

    assert _exit_code(root) == drift != ok


def test_a_changed_hatch_pattern_is_drift(tmp_path: Path) -> None:
    """The pattern no longer matches the line hatchling needs to find.

    MEASURED behaviour worth stating: this is reported as **drift** rather than "cannot check", because both files exist
    and were read — a failed comparison is a disagreement, not an inability to look. The distinction keeps exit 2
    reserved
    for "nothing was learned about this tree".
    """
    ok, drift, cannot = _codes()
    root = _tree(tmp_path)

    original = (root / "pyproject.toml").read_text(encoding="utf-8")
    _edit(
        root,
        "pyproject.toml",
        original.replace(
            'pattern = \'^__version__ = "(?P<version>[^"]+)"$\'', "pattern = '^VERSION = (?P<version>.*)$'"
        ),
    )

    code = _exit_code(root)
    assert code == drift != ok != cannot


def test_a_pattern_that_would_extract_a_different_number_is_drift(tmp_path: Path) -> None:
    """The pattern matches, captures something, and the captured value is not the module's.

    The subtle one. `path` and `pattern` both look plausible, so a reviewer sees nothing wrong; what hatchling
    would put in
    the wheel metadata differs from what `import mypki; mypki.__version__` reports. Asserted as drift with both
    numbers in
    the message, because "the pattern is wrong" is not actionable and "would publish 0.1.0 while the module declares
    9.9.9" is.
    """
    ok, drift, _cannot = _codes()
    root = _tree(tmp_path)

    original = (root / "pyproject.toml").read_text(encoding="utf-8")
    # `[^"]+` -> `[^"]{1,3}`: still matches `0.1.0`, captures only `0.1`. A real drift, invisible to a glance.
    _edit(
        root,
        "pyproject.toml",
        original.replace(
            'pattern = \'^__version__ = "(?P<version>[^"]+)"$\'',
            'pattern = \'^__version__ = "(?P<version>[^"]{1,3})"$\'',
        ),
    )

    assert _exit_code(root) == drift != ok


def test_two_version_lines_in_one_file_is_drift(tmp_path: Path) -> None:
    """Two assignments mean the value depends on execution order while hatchling reads text statically.

    The exact failure `dynamic = ["version"]` was chosen to avoid, reintroduced by someone who "just moved the line down
    for readability". Asserted here because no single line is wrong and every per-line check passes — only the
    count fails.
    """
    ok, drift, _cannot = _codes()
    root = _tree(tmp_path)

    original = (root / INIT_FILE).read_text(encoding="utf-8")
    _edit(root, INIT_FILE, original + f'\n__version__ = "{VERSION}.post1"\n')

    assert _exit_code(root) == drift != ok


@pytest.mark.parametrize(
    "value",
    ["v0.1.0", "release-1", "0.1.0 ", "01.2", "1.01", "1.0.0.01", "not-a-version", ""],
)
def test_a_version_that_is_not_valid_pep_440_is_drift(tmp_path: Path, value: str) -> None:
    r"""Eight malformed values, one shared reason: hatchling would publish them and pip would reject or mangle them.

    `""` is included because it is the shape a botched edit actually produces (the digits deleted, the quotes left), and
    a checker that only rejected obviously non-numeric strings would call it a version. `"01.2"` is PEP 440's
    leading-zero rejection — legal-looking, invalid, and accepted by a naive digit-dot-digit scan. MEASURED against
    packaging 26.3: `Version("01.2")` does not raise, it silently normalises to `1.2`, so this value had to be refused
    by the tool's own pattern rather than left for pip to tidy up.

    `"1.01"` and `"1.0.0.01"` are the same rule on a **non-leading** component, and they used to pass this test while
    being accepted: the release group was lazy, so it captured only `1` / `1.0` and handed `.01` to the
    `(?:\.(?P<post>\d+))` branch — a *post-release* number — which made both values legal. MEASURED against
    packaging 26.3 again:
    `Version("1.01")` normalises to `1.1` and `Version("1.0.0.01")` to `1.0.0.1`, i.e. pip quietly rewrites them into
    numbers nobody wrote down anywhere in this chain. The tool refuses them instead, which is the whole point of not
    importing `packaging` here: a wheel named `mypki-1.01-py3-none-any.whl` would have to be matched against a tag
    `v1.01`, a CHANGELOG heading `[1.01]` and a normalised `1.1` in `pip show`, and the disagreement surfaces as a bug
    report rather than as a build failure.

    Parametrised rather than looped because each value should fail for its own reason in the report, and a loop that
    stops at the first failure hides which of them the regex actually caught.
    """
    ok, drift, _cannot = _codes()
    root = _tree(tmp_path, version=value)

    assert _exit_code(root) == drift != ok


def test_a_missing_module_file_is_cannot_check(tmp_path: Path) -> None:
    """No `__init__.py` means there is no version to compare anything against.

    **Cannot check** (2), not drift: nothing was learned about a version, so nothing can be concluded about
    agreement. The
    chain starts here and every later link depends on it — which is why the tool stops rather than reporting four
    failures
    that are all really one.
    """
    ok, drift, cannot = _codes()
    root = _tree(tmp_path)

    (root / INIT_FILE).unlink()

    code = _exit_code(root)
    assert code == cannot != ok != drift


# ---------------------------------------------------------------------------- link 4: the CHANGELOG section


def test_a_missing_changelog_section_is_drift(tmp_path: Path) -> None:
    """A version bumped with nothing released, or a release shipped with no record of what changed.

    Keep a Changelog headings (`## [X.Y.Z] - YYYY-MM-DD`) are the machine-readable claim; prose about versions is not
    policed, because "supersedes 0.0.9" in a sentence is not a promise that a release exists.
    """
    ok, drift, _cannot = _codes()
    root = _tree(tmp_path, changelog="# Changelog\n\nNothing notable yet.\n")

    assert _exit_code(root) == drift != ok


def test_a_changelog_heading_for_a_future_release_is_drift(tmp_path: Path) -> None:
    """`## [9.9.9]` written before 9.9.9 exists, while every other link still says the current version.

    This is how an abandoned bump survives into a published artifact, where it reads as a promise about a release
    that does
    not exist. Sections *older* than the current version are history and are allowed — flagging those would make
    the tool
    useless for any project past its first release, so the comparison is "ahead of", not "different from".
    """
    ok, drift, _cannot = _codes()
    root = _tree(tmp_path, changelog=_changelog_for("9.9.9", VERSION))

    assert _exit_code(root) == drift != ok


def test_a_changelog_heading_for_the_next_minor_release_is_drift(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    r"""A heading for the *next* minor release while every other link says the current one.

    **MEASURED, and this is the reason `PEP440_RE`'s release group was changed.** With the previous spelling
    (`(?P<release>0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))*?`) the trailing `*?` left the group open, so it stopped at the first
    component: `release="0"` for `0.1.0`, `release="0"` for `0.2.0`, `release="9"` for `9.9.9`. `_release_parts()` then
    compared one-number tuples, and this exact fixture — a changelog promising the next minor release — returned "not
    ahead". Only a differing *major* number tripped the rule, which is why
    `test_a_changelog_heading_for_a_future_release_is_drift` was green while the promise in `check_changelog`'s own
    docstring ("a section **ahead** of the current version … is how an abandoned bump survives") was false for every
    realistic bump: 0.1.0 → 0.2.0 is the bump this project actually makes.

    Kept as a separate test rather than folded into the 9.9.9 one, because 9.9.9 was never the interesting case. The
    assertion is on the message too: it must name both the offending heading and the current version, or an operator
    cannot tell which line of CHANGELOG.md to delete.

    **MEASURED a second time, in the other direction:** this file used to spell the fixture `next_minor = "0.2.0"`, a
    literal one below the version the project was heading to. The day 0.2.0 was actually cut, the test failed on its own
    `assert next_minor != VERSION` — a fixture that had baked in "which release is next" stopped being a future release
    the moment it arrived. That is the same STYLE §1 mistake this file's opening warns about, committed inside a test
    whose subject is drift, so the bump is now computed from `VERSION` via the tool's own regex rather than written
    down.
    """
    ok, drift, _cannot = _codes()
    next_minor = _next_minor(VERSION)
    assert next_minor != VERSION

    root = _tree(tmp_path, changelog=_changelog_for(next_minor, VERSION))

    code = _exit_code(root)
    assert code == drift != ok

    reported = capsys.readouterr().out.splitlines()
    promises = [line for line in reported if "promises release" in line]
    assert len(promises) == 1, reported
    assert next_minor in promises[0]
    assert VERSION in promises[0]


def test_changelog_sections_for_earlier_releases_are_allowed(tmp_path: Path) -> None:
    """The half that must not be over-tightened: history is not drift.

    A checker that flagged every section not equal to the current version would fail on any real changelog, and
    the first
    person to notice would be the release engineer at 23:00 who then disables it. `Unreleased` — Keep a Changelog's own
    heading for work not yet shipped — is exempt for the same reason.
    """
    ok, _drift, _cannot = _codes()
    root = _tree(
        tmp_path,
        changelog=_changelog_for(VERSION, "0.0.9", "0.0.8") + "\n## [Unreleased] - unreleased\n\n- Work in progress.\n",
    )

    assert _exit_code(root) == ok


# ------------------------------------------------------------------------------------------------ git tags
# Built in throwaway repositories under tmp_path. `git` is available in this environment (2.47.x); where it is not, the
# tests skip rather than fail — a missing binary is an environment fact, not a defect in the chain.


def _git_available() -> bool:
    completed = subprocess.run(["git", "--version"], capture_output=True, text=True, check=False)
    return completed.returncode == 0


requires_git = pytest.mark.skipif(not _git_available(), reason="no git binary in this environment")

# Identity for every write these fixtures perform, passed with `-c` rather than written to a config file so the
# commits and
# annotated tags work on a machine with no git identity configured — which CI runners routinely are, and which this
# container is. MEASURED: without it, `git tag -a` dies with "Committer identity unknown" (exit 128). An annotated
# tag needs
# a tagger exactly as a commit needs a committer, so the identity belongs on the shared helper rather than at one
# call site.
GIT_IDENTITY = ["-c", "user.name=mypki tests", "-c", "user.email=tests@example.test"]


def _repo(tmp_path: Path, *, version: str = VERSION) -> Path:
    """A throwaway repository whose only content is a consistent version chain.

    `user.name`/`user.email` are passed with `-c` rather than written to a config file so the commit works on a
    machine with
    no git identity configured — which CI runners routinely are. Every command here is read-only plumbing except
    the ones
    that build the fixture itself.
    """
    root = _tree(tmp_path, version=version)
    commands = [
        ["init", "-q"],
        ["add", "."],
        [*GIT_IDENTITY, "commit", "-q", "-m", f"mypki {version}"],
    ]
    for arguments in commands:
        completed = subprocess.run(["git", *arguments], cwd=str(root), capture_output=True, text=True, check=False)
        assert completed.returncode == 0, completed.stdout + completed.stderr
    return root


def _git_run(root: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """One git command in a throwaway repository, asserted rather than assumed to have worked.

    Every argument here is a literal or a value this file produced itself; `cwd` is the fixture directory. A
    fixture whose
    setup silently failed would produce a test that asserts nothing, so the return code is checked here once
    instead of in
    each caller. `GIT_IDENTITY` is prepended to every command rather than only to the two that need it: read-only
    plumbing
    ignores `-c`, and one rule for all calls is what stops a future write fixture from being added without it.
    """
    completed = subprocess.run(
        ["git", *GIT_IDENTITY, *arguments], cwd=str(root), capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, f"git {' '.join(arguments)}: {completed.stdout}{completed.stderr}"
    return completed


def _tag(root: Path, name: str, *, annotated: bool) -> None:
    arguments = ["tag"]
    if annotated:
        arguments += ["-a", "-m", f"release {name}"]
    arguments.append(name)
    _git_run(root, arguments)


def _tag_at(root: Path, name: str, revision: str) -> None:
    """An annotated tag on a specific commit rather than on HEAD."""
    _git_run(root, ["tag", "-a", "-m", f"release {name}", name, revision])


def _rev_parse(root: Path, revision: str) -> str:
    return _git_run(root, ["rev-parse", revision]).stdout.strip()


@requires_git
def test_a_matching_annotated_tag_completes_the_chain(tmp_path: Path) -> None:
    """The full five-link pass: module, manifest, CHANGELOG and an annotated tag all naming one number.

    Read through `git show <tag>:<path>` rather than the working tree (check_version.py), which is what makes this
    assertion
    about the *released* source: a checkout can be dirty and a release cannot. Proving the passing path exists
    matters as
    much as proving each failure, because a checker that always reports drift is just as useless as one that never does.
    """
    ok, _drift, cannot = _codes()
    root = _repo(tmp_path)
    _tag(root, f"v{VERSION}", annotated=True)

    code = _exit_code(root, require_tag=True)
    assert code == ok != cannot


@requires_git
def test_a_repository_with_no_release_tag_at_all_is_drift(tmp_path: Path) -> None:
    """A release happened and nobody tagged it: git answered, and its answer is "no such tag".

    **Drift** (1), not "cannot check" (2) — the two are opposite diagnoses and only one of them describes this
    state. The
    repository exists, refs were consulted successfully, and what is missing is the tag a release must carry. A CI
    job that
    conflated the two would report "no git here" for a tree that has plenty of git and no discipline.
    """
    ok, drift, cannot = _codes()
    root = _repo(tmp_path)

    code = _exit_code(root, require_tag=True)
    assert code == drift != ok != cannot


@requires_git
def test_a_lightweight_tag_is_refused(tmp_path: Path) -> None:
    """`git tag v0.1.0` without `-a` is not a release marker.

    Annotated tags carry a tagger and a message, and their object type is what lets the tool read *the tagged
    tree* rather
    than whatever HEAD says. A lightweight tag is a pointer someone can move or delete without leaving evidence,
    which is
    precisely the property a release ref must not have.
    """
    ok, drift, _cannot = _codes()
    root = _repo(tmp_path)
    _tag(root, f"v{VERSION}", annotated=False)

    assert _exit_code(root, require_tag=True) == drift != ok


@requires_git
def test_a_tag_whose_name_disagrees_with_the_code_it_tags_is_drift(tmp_path: Path) -> None:
    """A correctly named annotated tag pointing at a commit that declares a **different** number.

    The classic botched bump, and the reason the tool reads `git show <tag>:<path>` rather than trusting the tag
    name. The
    fixture is the passing fixture plus exactly one difference: the tag is placed on the *earlier* commit, so the tagged
    tree still declares 0.0.1 while the working tree, the manifest and the CHANGELOG all agree on the current version.
    Everything a reviewer glances at looks right; only the release ref is stale.

    Asserted against the tagged tree rather than the checkout — which is the whole point: a dirty working copy
    must not be
    able to make an outdated release ref look correct.
    """
    ok, drift, _cannot = _codes()
    # MEASURED: this fixture used to start at `VERSION` and then edit the module *down* to 0.0.1 while leaving a
    # `## [0.1.0]` heading in its CHANGELOG. That is not "the passing fixture plus one difference" — it is a second,
    # unrelated defect (a changelog promising a release newer than the version everything else declares), and it stayed
    # invisible only because `_release_parts` compared major numbers alone. See
    # `test_a_changelog_heading_for_the_next_minor_release_is_drift`. The fixture now reads the way its docstring
    # always claimed: start at 0.0.1, bump forward to the current version, and put the tag on the earlier commit.
    root = _repo(tmp_path, version="0.0.1")
    first_commit = _rev_parse(root, "HEAD")

    # A real bump commit: module and CHANGELOG move together, so nothing else in the chain is broken.
    _edit(root, INIT_FILE, _init_source(VERSION))
    _edit(root, "CHANGELOG.md", _changelog_for(VERSION, "0.0.1"))
    _git_run(root, ["commit", "-q", "-am", f"release {VERSION}"])

    _tag_at(root, f"v{VERSION}", first_commit)

    assert _exit_code(root) == ok  # the working tree is consistent; only the ref is stale
    assert _exit_code(root, require_tag=True) == drift != ok


@requires_git
def test_require_tag_on_an_unrelated_directory_is_cannot_check(tmp_path: Path) -> None:
    """A directory git refuses to answer for is "cannot check", not "the tag is missing".

    Built by hand rather than by `_repo` so there is genuinely no `.git`: `git rev-parse --is-inside-work-tree`
    fails, and
    the tool reports that nothing could be learned. Compared with
    `test_a_repository_with_no_release_tag_at_all_is_drift`,
    which has a repository and refs and simply lacks the tag — same command, opposite exit code, opposite fix.
    """
    ok, drift, cannot = _codes()
    root = _tree(tmp_path)

    code = _exit_code(root, require_tag=True)
    assert code == cannot != ok != drift


# ------------------------------------------------------------------------------------- the tool's own shape


def test_the_checker_imports_nothing_from_mypki() -> None:
    """`tools/check_version.py` must be runnable where mypki is not installed.

    Asserted by reading its imports rather than by asserting "it worked in CI once": the CI version job installs
    nothing,
    and a version checker that grows an import of the package it checks can only run after the artifact with the wrong
    version has already been built. That regression is invisible to every other test in this file.

    `subprocess` is allowed (git plumbing) and is the only non-stdlib import permitted; what must never appear is
    a mypki
    import, which would also make the checker depend on the very code whose version it is verifying.
    """
    source = (BUILD_ROOT / "tools/check_version.py").read_text(encoding="utf-8")

    imported = {
        line.split()[1].split(".")[0] for line in source.splitlines() if line.strip().startswith(("import ", "from "))
    }
    assert "mypki" not in imported, sorted(imported)

    stdlib_only = {"argparse", "re", "subprocess", "sys", "dataclasses", "pathlib", "__future__"}
    assert imported <= stdlib_only, f"non-stdlib imports: {sorted(imported - stdlib_only)}"


def test_the_checker_writes_nothing(tmp_path: Path) -> None:
    """A checker that "fixed" a version would create the confusion it exists to prevent.

    Asserted two ways: the source contains no write calls, and running it against a tree leaves every file
    byte-identical.
    The second half is what catches a future refactor that reaches for `pathlib.write_text` in a helper rather
    than at the
    top level, where this grep would have seen it.
    """
    source = (BUILD_ROOT / "tools/check_version.py").read_text(encoding="utf-8")
    assert ".write_text(" not in source
    assert ".unlink(" not in source
    assert "mkdir" not in source

    root = _tree(tmp_path)
    before = {path: path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}

    _exit_code(root, require_tag=True)

    after = {path: path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}
    assert after == before
