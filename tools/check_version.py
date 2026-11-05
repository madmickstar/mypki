# !/usr/bin/env python3
"""Prove that every place mypki's version is written down says the same number.

Why this exists as a script rather than a test
----------------------------------------------
A version drift is invisible until it hurts someone. `pyproject.toml` here declares `dynamic = ["version"]` and
hatchling
reads `src/mypki/__init__.py::__version__` by static analysis, so the built wheel's manifest and the importable
attribute
cannot disagree *by construction* — but nothing stops the other two links in the chain from drifting: a CHANGELOG
section
for a version that was never released, a release tagged `v0.2.0` while the module still says `0.1.0`, or someone
adding a
static `version = "..."` to `[project]` "just to make the IDE happy". Each of those produces an artifact that
advertises a
version the code disagrees with, and the first person to notice is usually the one filing the bug report.

So the chain checked here is four links long:

  1. `src/mypki/__init__.py` declares `__version__` on **exactly one** line, in the spelling hatchling's pattern
  matches,
     with a value that is valid PEP 440;
  2. `pyproject.toml`'s `[project]` declares `dynamic = ["version"]` and carries **no** static `version = ...`
  (two copies
     of one fact drift the first time someone bumps only one of them);
  3. `[tool.hatch.version]` points at that file with a pattern whose captured group equals the value from link 1 —
  so what
     hatchling would extract is what the module states, not something similar;
  4. `CHANGELOG.md` has a section for exactly this version and no section for a version this chain does not name.

`--require-tag` adds the fifth link, and it is only meaningful on a release ref: an **annotated** tag `vX.Y.Z`
whose tagged
commit declares `__version__ = "X.Y.Z"`. Annotated rather than lightweight because annotated tags carry a tagger and a
message, which is what makes `git show <tag>:src/mypki/__init__.py` read the *released* source rather than whatever HEAD
happens to say.

Why it imports nothing from mypki
---------------------------------
Deliberately stdlib-only and import-free. The CI job that runs this does **not** install the package (see
`.github/workflows/ci.yml`: no `pip install` step in the version job), because a version check that needs the
package to be
importable can only run after a successful build — i.e. after the artifact that a wrong version would have already
shipped.
Reading files is also the honest way to check what hatchling would read: hatchling parses this file statically and never
imports it either.

Why it is read-only
-------------------
Every operation here is `read_text()` or `git show`. A checker that "fixes" a version silently creates the exact
class of
confusion it exists to prevent — a CHANGELOG section written to match a module line nobody reviewed. It reports; a human
decides which of the four files was meant to be right.

Exit codes (and why 2 is never a pass)
--------------------------------------
    0  consistent: every link checked agrees.
    1  drift found: a real disagreement between two places that must agree.
    2  cannot check: a file is missing, or git cannot be consulted at all.

`2` exists so that "I could not look" is never mistaken for "it was fine". A CI step that treated non-zero as
failure and
zero as success would still be wrong if it special-cased 2; the version job therefore asserts `== 0` explicitly,
and this
script prints `cannot-check:` lines so a human reading the log sees *why* nothing was concluded.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# : The one spelling of the version line this project uses. `re.fullmatch` semantics are baked into the anchors
# rather than
#: left to the caller: `^__version__ = "…"$` must match the whole line, or a trailing comment would silently change what
#: hatchling's static parse sees.
MODULE_LINE_RE = re.compile(r'^__version__ = "(?P<version>[^"]+)"$')

# : PEP 440 as much of it as this project ever uses. Deliberately not `packaging.version.Version`: importing
# packaging would
# : make this script depend on something pip installs transitively, and a version checker that fails because a
# dependency is
#: missing reports "cannot check" for the wrong reason. Anchored, so `1.0.0rc1-evil` is not accepted as PEP 440-ish.
#
# Leading zeros are rejected everywhere a number appears (`0|[1-9]\d*`), where a naive `\d+` would accept them. MEASURED
# against packaging 26.3: `Version("01.2")` does not raise — it silently normalises to `1.2`, and `Version("1.01")` to
# `1.1`. So a permissive pattern here would let a typo survive into a wheel whose metadata names a number nobody wrote
# down, and the tag/CHANGELOG links would then disagree with a version that only pip's normalisation ever produced.
#
# The release group is GREEDY and closed (`(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))*`), which is what makes both halves of
# that promise hold. MEASURED against the previous spelling, `…\d*)(?:\.(?:…))*?`, whose laziness left the group open:
# it captured only the first component — `release="1"` for `1.01`, `release="0"` for `0.1.0` — and then absorbed the
# remainder as a *post-release* number, so `1.01` was accepted through `(?P<post>\d+)` matching `.01`. Two failures at
# once: a leading-zero typo passed, and `_release_parts()` compared only major numbers, so a CHANGELOG heading for
# `0.2.0` while the module said `0.1.0` was never reported as drift (only a differing major number, e.g. `9.9.9`,
# tripped it). Greedy plus the tightened suffixes reject `1.01`, `1.0.0.01`, `1.2.3rc01`, `2.0.dev01` and `1.0.0post01`
# while continuing to accept every spelling this project releases (`0.1.0`, `1.2.3rc1`, `2.0.dev1`, `1.0.0-r1`).
PEP440_RE = re.compile(
    r"""
    ^
    (?P<release>(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))*)
    (?:(?P<pre>a|b|rc)(?P<pre_n>0|[1-9]\d*))?
    (?:\.(?P<post>0|[1-9]\d*)|(?P<post_alt>post|rev|-r)(?P<post_n>0|[1-9]\d*))?
    (?:\.dev(?P<dev>0|[1-9]\d*))?
    $
    """,
    re.VERBOSE,
)

# : A release tag: `v` plus a version that must equal the module's. The literal prefix is part of the project's
# convention
#: and CI's `on: tags: ["v*.*.*"]` trigger depends on it.
TAG_RE = re.compile(r"^v(?P<version>[0-9][0-9A-Za-z.]*|.+)$")

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_CANNOT_CHECK = 2


@dataclass(frozen=True)
class GitResult:
    """What a read-only git call produced, with "no git" kept separate from "git refused".

    See `_git` for why the distinction is load-bearing for the exit code: only "nothing was learned" may produce 2.
    """

    ran: bool
    accepted: bool
    stdout: str


@dataclass
class Report:
    """What was checked and what was found, kept separate so the exit code is a decision, not a side effect.

    `fatal` means "cannot check" (a file is missing, git is unusable) and `drift` means "checked and disagreed". Keeping
    them in two lists is what makes exit 2 impossible to reach by accident: only `fatal` can produce it, and a drift is
    never downgraded to a note.
    """

    ok: list[str] = field(default_factory=list)
    drift: list[str] = field(default_factory=list)
    fatal: list[str] = field(default_factory=list)

    def exit_code(self) -> int:
        if self.fatal:
            return EXIT_CANNOT_CHECK
        if self.drift:
            return EXIT_DRIFT
        return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_version.py",
        description="Check that mypki's version agrees across module, manifest, CHANGELOG and (optionally) a git tag.",
        epilog="exit 0 = consistent, 1 = drift found, 2 = cannot check (missing file or no git). 2 is not a pass.",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Project root to check. Defaults to the current directory; CI and tests point it at an extracted tree.",
    )
    parser.add_argument(
        "--require-tag",
        action="store_true",
        help='Also require an annotated tag vX.Y.Z whose tagged commit declares __version__ = "X.Y.Z".',
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    report = check(root, require_tag=args.require_tag)

    for line in report.ok:
        print(f"ok: {line}")
    for line in report.drift:
        print(f"drift: {line}")
    for line in report.fatal:
        print(f"cannot-check: {line}")

    code = report.exit_code()
    if code == EXIT_OK:
        print("version chain consistent")
    elif code == EXIT_DRIFT:
        print(f"VERSION DRIFT: {len(report.drift)} disagreement(s) found")
    else:
        print("CANNOT CHECK — nothing was concluded; this is not a pass")
    return code


# --------------------------------------------------------------------------------------------- the checks


def check(root: Path, *, require_tag: bool) -> Report:
    """Run every link of the chain and collect findings rather than raising on the first one.

    Reporting all findings at once matters: a version bump usually touches two or three files, and an operator who
    learns
    about them one per run spends the evening discovering what they already should have been told. `fatal` findings stop
    the checks that depend on them (no module line means no version to compare against) but never hide the ones
    that were
    already established.
    """
    report = Report(ok=[], drift=[], fatal=[])

    if not root.is_dir():
        report.fatal.append(f"{root} is not a directory")
        return report

    version = check_module(root / "src/mypki/__init__.py", report)
    check_pyproject(root / "pyproject.toml", version, report)

    if version is None:
        # Nothing to compare the remaining links against. This is a fatal finding, not a pass: the chain starts here.
        return report

    check_changelog(root / "CHANGELOG.md", version, report)

    if require_tag:
        check_tag(root, version, report)

    return report


def check_module(module_file: Path, report: Report) -> str | None:
    """Link 1: exactly one `__version__` line, in hatchling's spelling, valid PEP 440. Returns the version or None.

    "Exactly one" is checked rather than "the first one found": two assignments in one file mean the value depends on
    execution order while hatchling reads text statically, so the built wheel and the imported module can disagree
    without
    any single line being wrong. That is the precise failure `dynamic = ["version"]` was chosen to avoid, reintroduced.
    """
    if not module_file.is_file():
        report.fatal.append(f"{relative(module_file)} is missing")
        return None

    try:
        lines = module_file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        report.fatal.append(f"{relative(module_file)} cannot be read: {exc}")
        return None
    except UnicodeDecodeError as exc:
        # A file that is not UTF-8 cannot be parsed by hatchling either, so this is a genuine blocker rather than
        # a style
        # complaint about someone's editor.
        report.fatal.append(f"{relative(module_file)} is not valid UTF-8: {exc}")
        return None

    matches = [line for line in lines if MODULE_LINE_RE.fullmatch(line)]
    if not matches:
        # Named as drift rather than fatal on purpose: the file exists and was read, so this *is* a check that failed —
        # the version line is missing or spelled differently (single quotes, a trailing comment, a space before `=`).
        report.drift.append(f"{relative(module_file)} has no line matching {MODULE_LINE_RE.pattern!r}")
        return None
    if len(matches) > 1:
        report.drift.append(
            f"{relative(module_file)} declares __version__ {len(matches)} times; exactly one is allowed "
            f"(found: {', '.join(sorted(set(matches)))})"
        )
        return None

    version = MODULE_LINE_RE.fullmatch(matches[0])
    assert version is not None  # fullmatch already succeeded above
    value = version.group("version")

    if not PEP440_RE.match(value):
        report.drift.append(
            f"{relative(module_file)} declares {value!r}, which is not a valid PEP 440 release version "
            "(expected e.g. 0.1.0, 1.2.3rc1 or 2.0.dev1)"
        )
        return None

    report.ok.append(f"{relative(module_file)} declares __version__ = {value!r}")
    return value


def check_pyproject(pyproject: Path, version: str | None, report: Report) -> None:
    """Links 2 and 3: `[project]` is dynamic with no static version, and hatchling's pattern yields the same number.

    TOML is parsed by hand rather than with `tomllib`: Python 3.10 (the floor this project supports) has no TOML
    parser in
    the standard library, and adding a dependency to a read-only checker is a poor trade for avoiding thirty lines of
    section scanning. The scanning is deliberately narrow — only the two tables that matter are looked at, and
    nothing here
    pretends to validate TOML generally.
    """
    if not pyproject.is_file():
        report.fatal.append(f"{relative(pyproject)} is missing")
        return

    try:
        text = pyproject.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        report.fatal.append(f"{relative(pyproject)} cannot be read: {exc}")
        return set()

    project = _section(text, "project")
    hatch = _section(text, "tool.hatch.version")
    mentioned: set[str] = set()

    if project is None:
        report.fatal.append(f"{relative(pyproject)} has no [project] table")
    else:
        static = re.search(r"^\s*version\s*=", project, re.MULTILINE)
        if static is not None:
            # The single most common way this chain breaks, and the quietest: it looks tidy, builds fine, and produces a
            # wheel whose metadata no longer has to agree with the module.
            report.drift.append(
                f"{relative(pyproject)} [project] declares a static version; the project must stay "
                'dynamic = ["version"] so the manifest and __version__ cannot disagree'
            )
        dynamic = re.search(r"^\s*dynamic\s*=\s*\[([^\]]*)\]", project, re.MULTILINE)
        if dynamic is None or "version" not in dynamic.group(1):
            report.drift.append(f'{relative(pyproject)} [project] does not declare dynamic = ["version"]')
        else:
            report.ok.append(f"{relative(pyproject)} [project] declares version dynamically")

    if hatch is None:
        report.fatal.append(f"{relative(pyproject)} has no [tool.hatch.version] table")
        return

    path_value = re.search(r'^\s*path\s*=\s*"([^"]+)"', hatch, re.MULTILINE)
    pattern_value = re.search(r"^\s*pattern\s*=\s*'([^']+)'", hatch, re.MULTILINE)
    if path_value is None or pattern_value is None:
        report.drift.append(f"{relative(pyproject)} [tool.hatch.version] needs both path = \"...\" and pattern = '...'")
        return

    target, pattern = path_value.group(1), pattern_value.group(1)

    if version is None:
        # Nothing to compare against yet; the module check already reported why.
        return mentioned

    resolved = Path(target)
    if not resolved.is_absolute():
        resolved = pyproject.parent / target
    if not resolved.is_file():
        report.drift.append(f"{relative(pyproject)} [tool.hatch.version] path {target!r} does not exist")
        return

    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        # An invalid pattern is a build-time failure waiting to happen, and hatchling would fail with a message
        # that reads
        # like a packaging bug rather than like the typo it is.
        report.drift.append(f"{relative(pyproject)} [tool.hatch.version] pattern is not a valid regex: {exc}")
        return

    try:
        target_lines = resolved.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        report.fatal.append(f"{resolved} cannot be read: {exc}")
        return

    extracted = [match.groupdict() for match in (compiled.match(line) for line in target_lines) if match]
    if not extracted:
        report.drift.append(
            f"{relative(pyproject)} [tool.hatch.version] pattern does not match any line in {target}; hatchling would "
            "fail to find a version at build time"
        )
        return
    if len(extracted) > 1:
        report.drift.append(
            f"{relative(pyproject)} [tool.hatch.version] pattern matches {len(extracted)} lines in {target}; it must "
            "match exactly one"
        )
        return

    captured = extracted[0].get("version")
    if captured is None:
        report.drift.append(
            f"{relative(pyproject)} [tool.hatch.version] pattern has no (?P<version>...) group; hatchling cannot name "
            "the version it extracted"
        )
        return

    if captured != version:
        report.drift.append(
            f"{relative(pyproject)} [tool.hatch.version] would publish {captured!r} while the module declares "
            f"{version!r}"
        )
        return

    report.ok.append(f"{relative(pyproject)} hatchling would read {captured!r} from {target}")


def check_changelog(changelog: Path, version: str, report: Report) -> None:
    """Link 4: a section for this exact version, and no section for a release that has not happened yet.

    Both halves matter and they catch opposite mistakes. A missing section means a number was bumped without
    anything being
    released. A section **ahead** of the current version — `## [0.2.0]` while every other link says 0.1.0 — is how an
    abandoned bump survives into a published artifact, where it reads as a promise about a release that does not exist.

    Sections *behind* the current version are expected and allowed: they are the history, and flagging them would
    make this
    tool useless for any project older than its first release. "Behind" is decided by comparing the numeric release part
    only — `0.1.0rc1` and `0.1.0` are treated as the same release magnitude, because this project's releases are plain
    `X.Y.Z` and a full PEP 440 ordering of prerelease suffixes would be complexity this chain never uses.

    Only exact `## [X]` headings are considered. A changelog that quotes versions in prose ("supersedes 0.0.9") is not
    policed for its prose; the heading is the machine-readable claim. `Unreleased` is exempt because it is Keep a
    Changelog's
    own heading for work that has not been released, and policing it would fight the format rather than protect
    the chain.
    """
    if not changelog.is_file():
        report.fatal.append(f"{relative(changelog)} is missing")
        return

    try:
        text = changelog.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        report.fatal.append(f"{relative(changelog)} cannot be read: {exc}")
        return

    sections = re.findall(r"^## \[(?P<version>[^\]]+)\]", text, re.MULTILINE)
    if not sections:
        report.drift.append(
            f"{relative(changelog)} has no '## [X.Y.Z]' release section for {version!r} (Keep a Changelog form)"
        )
        return

    if version not in sections:
        report.drift.append(f"{relative(changelog)} has no section for the current version {version!r}")
    else:
        report.ok.append(f"{relative(changelog)} documents {version!r}")

    ahead = _versions_ahead_of(sections, version)
    if ahead:
        report.drift.append(
            f"{relative(changelog)} promises release(s) newer than the current version {version!r}: "
            f"{', '.join(ahead)} — a section is written when its release happens, not before"
        )


def check_tag(root: Path, version: str, report: Report) -> None:
    """Link 5 (opt-in): an annotated tag `v<version>` whose tagged commit declares that same version.

    Read through `git tag` / `git for-each-ref` / `git show`, all read-only plumbing. The tagged commit's file is
    read via
    `git show <tag>:<path>` rather than the working tree, because a checkout can be dirty and a release cannot: what was
    tagged is what shipped.

    A missing tag is **drift** (1), not "cannot check" (2): git was consulted successfully and the answer it gave is "no
    such tag". Only an unusable git — not a repository, or no git binary at all — is fatal, because then nothing was
    learned about the ref being claimed.
    """
    probe = _git(root, ["rev-parse", "--is-inside-work-tree"])
    if not probe.ran:
        report.fatal.append("--require-tag needs git, and no git binary is available")
        return
    if not probe.accepted or probe.stdout.strip() != "true":
        # Deliberately separate from "no git binary", because the two send an operator in opposite directions. A plain
        # directory (this build tree, until someone runs `git init`) has no refs to consult at all: that is "cannot
        # check", not a release with a missing tag.
        report.fatal.append(f"--require-tag needs a git repository; {root} is not one")
        return

    tags = _git(root, ["tag", "--list", f"v{version}"])
    if not tags.ran or not tags.accepted:
        report.fatal.append("git tag --list failed; the tag chain could not be read")
        return

    listed = [entry for entry in tags.stdout.splitlines() if TAG_RE.fullmatch(entry)]
    if f"v{version}" not in listed:
        annotated = _annotated_tags(root)
        if annotated is None:
            report.fatal.append("git for-each-ref failed; annotated tags could not be identified")
            return
        report.drift.append(
            f"no annotated tag v{version} exists (tagged versions found: {', '.join(annotated) or 'none'}) — a release "
            "must be tagged with the version it publishes"
        )
        return

    if not _is_annotated(root, f"v{version}"):
        report.drift.append(
            f"tag v{version} is a lightweight tag; releases must use annotated tags (`git tag -a`) so the "
            "tagged commit can be read unambiguously"
        )
        return

    shown = _git(root, ["show", f"v{version}:src/mypki/__init__.py"])
    if not shown.ran:
        report.fatal.append("git show failed; the tagged tree could not be read")
        return
    if not shown.accepted:
        report.drift.append(f"tag v{version} does not contain src/mypki/__init__.py at the expected path")
        return

    tagged = [line for line in shown.stdout.splitlines() if MODULE_LINE_RE.fullmatch(line)]
    if len(tagged) != 1:
        report.drift.append(
            f"tag v{version} declares __version__ {len(tagged)} times in src/mypki/__init__.py; exactly one is expected"
        )
        return

    match = MODULE_LINE_RE.fullmatch(tagged[0])
    assert match is not None
    if match.group("version") != version:
        report.drift.append(
            f"tag v{version} points at a commit declaring __version__ = {match.group('version')!r}; the tag name "
            "and the code it tags must agree"
        )
        return

    report.ok.append(f"annotated tag v{version} matches src/mypki/__init__.py at that commit")


# ------------------------------------------------------------------------------------ small helpers


def _release_parts(version: str) -> tuple[int, ...]:
    """The numeric release part of a version, for magnitude comparison only.

    `0.1.0rc1` and `0.1.0` compare equal here on purpose (see `check_changelog`): ranking prerelease suffixes would be
    machinery this project's plain `X.Y.Z` releases never exercise, and unexercised ordering code is where a
    checker starts
    disagreeing with itself.
    """
    match = PEP440_RE.match(version)
    if match is None:
        # Not a version this tool recognises. Returning an empty tuple makes it sort *before* every real release, so an
        # unrecognised heading can never be mistaken for a promised future one — the conservative direction.
        return ()
    return tuple(int(part) for part in match.group("release").split("."))


def _versions_ahead_of(sections: list[str], version: str) -> list[str]:
    """CHANGELOG headings whose release is newer than the version everything else declares.

    `Unreleased` is excluded first because it is not a version at all and `_release_parts` would score it as nothing,
    which a careless comparison would then report as "not ahead" — accidentally correct, for the wrong reason.
    """
    current = _release_parts(version)
    return [entry for entry in sections if entry != "Unreleased" and _release_parts(entry) > current]


def _git(root: Path, arguments: list[str]) -> GitResult:
    """Run one read-only git command, keeping the two failure modes apart.

    `ran` False means **no git binary** — nothing about this tree was learned, which is "cannot check". `ran` True with
    `accepted` False means git ran and refused (not a repository, unknown revision): that is an answer *about this
    tree*,
    and the caller decides whether it means "no such tag" (drift) or "there are no refs here" (cannot check). Collapsing
    the two is what makes a version checker report a missing tool for a plain directory, which is exactly how a release
    engineer loses an afternoon.

    No shell and no interpolation: `subprocess.run` with an argument list where every element is a literal or comes from
    git's own earlier output. This is the only subprocess use in this tool; `--root` is used solely as `cwd` and
    never as
    part of a command line.
    """
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):  # no git on PATH, or an unusable working directory
        return GitResult(ran=False, accepted=False, stdout="")
    return GitResult(ran=True, accepted=completed.returncode == 0, stdout=completed.stdout)


def _annotated_tags(root: Path) -> list[str] | None:
    """Every annotated tag in this repository, or None if git could not answer at all.

    `%(objecttype)` is what distinguishes them: an annotated tag's object is a `tag`, a lightweight tag points
    straight at
    a commit. That difference is what makes `git show <tag>:<path>` read the released tree rather than HEAD's
    working copy.
    """
    listed = _git(root, ["for-each-ref", "--format=%(refname:lstrip=2) %(objecttype)", "refs/tags"])
    if not listed.ran or not listed.accepted:
        return None
    return [
        parts[0]
        for parts in (line.split() for line in listed.stdout.splitlines())
        if len(parts) == 2 and parts[1] == "tag" and TAG_RE.fullmatch(parts[0])
    ]


def _is_annotated(root: Path, tag: str) -> bool:
    """Whether one specific tag is annotated."""
    listed = _git(root, ["for-each-ref", "--format=%(objecttype)", f"refs/tags/{tag}"])
    return listed.ran and listed.accepted and listed.stdout.strip() == "tag"


def _section(text: str, name: str) -> str | None:
    """The body of one TOML table, as raw text, or None when the table is absent.

    A table ends at the next `[...]` header line. Comments inside a table are left in place rather than stripped —
    they are
    why this project's `[project]` block reads the way it does, and stripping them would make the scan fragile
    against the
    very comments that explain the design.
    """
    header = re.compile(r"^\[\s*" + re.escape(name) + r"\s*\]\s*(?:#.*)?$", re.MULTILINE)
    match = header.search(text)
    if match is None:
        return None
    rest = text[match.end() :]
    following = re.search(r"^\s*\[", rest, re.MULTILINE)
    return rest[: following.start()] if following else rest


def relative(path: Path) -> str:
    """How to name a file in a report.

    Kept as one function rather than inlining `str(path)` because every message in this tool names a file, and a single
    place to change means the reports can later be made root-relative (which is what a CI log wants) without rewriting
    twenty f-strings — and without one message quietly keeping an absolute path while the others do not.
    """
    return str(path)


if __name__ == "__main__":  # pragma: no cover - exercised as a script, not as an import
    sys.exit(main())
