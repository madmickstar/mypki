"""The shipped tree as one fact: README's structure tree and its path count, checked against git.

WHY THIS EXISTS
  README.md "Where the files live" ends with a sentence claiming how many paths this repository ships ("taken from
  `git ls-files --cached --exclude-standard --others` at this commit (N paths)") and a fenced block holding them. Both
  were typed by hand, and a hand-typed copy is a second source of truth: it drifts the first time a file is added or
  removed, and nothing in the suite could see it.

  The block is rendered as an indented tree rather than as a flat sorted list, because that is the shape a reader can
  use to find a file. It changes what this tool has to do: `tree_lines` builds directories out of the same paths, and
  `parse_tree_lines` has to read them back — recovering depth from where a connector sits, and each path's parents from
  a stack — before anything can be compared against git.

  MEASURED on commit a4dc4f3: README claimed 75 paths while CHANGELOG.md's own entry for the same commit said 74, plain
  `git ls-files` answered 75, and `make gate` was green on all three (823 passed, TOTAL 3022 stmts / 103 missed).
  A wrong number in a release's own changelog is exactly the kind of failure this file exists to make loud.

  It also makes the drift self-inflicted: adding any tracked file (AGENTS.md included) changes the count and therefore
  makes README's claim stale in the same commit that added it. `make ready` regenerates the block from git before a tree
  is declared final, and tests/test_packaging.py asserts the claim matches afterwards.

THE DENOMINATOR, AND WHY IT IS NOT PLAIN `git ls-files`
  The list is "what a commit would contain": what git already tracks or has staged, plus new files that are not ignored.
  MEASURED mid-change on this checkout: plain `git ls-files` reported 75 paths while `git ls-files --cached
  --exclude-standard --others` reported 78, because three new files were still untracked. Generating README from
  the first number would write a count that becomes false the moment those files are committed — the same class of error
  as the
  74-vs-75 disagreement above. `make zip` deliberately keeps plain `git ls-files`: a release artifact is built from what
  is committed, not from what is merely present.

THE STAMP, AND THE SELF-REJECTION TRAP IT HAD TO BE BUILT AROUND
  `make ready` writes `gate tree: <HEAD^{tree}> <worktree digest> <path count>` to .gate-ready; `make gate`
  refuses (exit 2) unless that line still names the tree it is about to measure. Two traps had to be measured out before
  either half could work:

  * The stamp file must be gitignored. MEASURED: with every file on disk untouched, putting .gate-ready back in the list
    `LS_FLAGS` answers grows the path count 78 -> 79 and changes the digest half too, because the stamp joins both.
    A gate that stamps a tree would then invalidate its own stamp, and README's regenerated count would grow by one on
    every run. No digest hex is quoted here: prose carrying one goes stale the moment any other file in the digest
    changes.
  * The worktree half cannot be `git status --porcelain`. MEASURED: appending a line to a file git already listed as
    modified left `git status --porcelain` byte-identical while the content digest changed. Porcelain names which paths
    differ, never how. See worktree_digest.

THE EXIT CODES A WRAPPER MUST NOT FLATTEN
  0  consistent (or regenerated successfully)
  1  drift: README's count or its enumerated paths disagree with git
  2  cannot check: no git binary, or this checkout is not a git repository
  Same contract as tools/check_version.py, for the same reason: a checker that answers "clean" because it could not read
  anything is worse than no checker.

WHAT IT DOES NOT DO
  It compares paths, counts and tree shape. It cannot tell you whether a sentence about behaviour is true: the
  prose-policing
  gates (tools/check_docs.py, tests/test_docstrings.py) were removed in bc0031b and are not reinstated here.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

BUILD_ROOT = Path(__file__).resolve().parent.parent
README = BUILD_ROOT / "README.md"

#: The sentence README carries above the fenced tree, split so the count is the only part that varies. Defining it once
#: means `render` and the matcher cannot disagree about the wording they are both built from.
#:
#: The command is spelled out in full inside the claim rather than shortened to `git ls-files`, because the
#: shortened form was itself a small lie: this block is generated with three flags, and a reader who typed the
#: sentence by hand would have used the bare command — which answers 75 paths on a tree where 78 are true. Naming the
#: flags in the sentence is what makes the number reproducible by whoever reads it.
CLAIM_PREFIX = (
    "The tree this repository actually ships, taken from "
    "`git ls-files --cached --exclude-standard --others` at this commit ("
)
CLAIM_SUFFIX = " paths):"
CLAIM = re.compile(r"^" + re.escape(CLAIM_PREFIX) + r"(\d+)" + re.escape(CLAIM_SUFFIX) + r"$")

#: The label README's tree opens with. git lists files, never the repository itself, so this line is not a path:
#: `tree_lines` emits it outside the walk and `parse_tree_lines` skips it without resetting nothing else.
ROOT_LABEL = "mypki/"

#: The two connectors this tool renders with, both exactly four columns wide. A reader needs both to recover depth: at
#: depth d a connector starts at column 4 * (d - 1), every earlier four-column group being either `│   ` or `    `.
TREE_CONNECTORS = ("├── ", "└── ")
TREE_CONTINUATIONS = ("│   ", "    ")

#: The tree a commit would contain: tracked and staged paths, plus new files that are not ignored. See the module
#: docstring for why plain `git ls-files` is the wrong denominator while an edit is in flight.
LS_FLAGS = ["ls-files", "--cached", "--exclude-standard", "--others"]

#: Written by `make ready`; read by `make gate`. Gitignored: one machine's statement about one working tree.
STAMP_FILE = BUILD_ROOT / ".gate-ready"


def _git(root: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *arguments], cwd=str(root), capture_output=True, text=True, check=False)


def git_available(root: Path = BUILD_ROOT) -> bool:
    return _git(root, ["--version"]).returncode == 0


def tracked_paths(root: Path = BUILD_ROOT) -> list[str]:
    """Every path a commit from this tree would contain, sorted by path.

    A git query rather than a directory walk for the reason the Makefile's zip target gives: a walk picks up runtime
    state that happens to be sitting in the tree (build/src/logs/mypki.log did exactly that once), and a walk that
    respects .gitignore answers "what is present" rather than "what ships".

    Sorted here rather than passed through, because git does not do it for us. MEASURED on this checkout: the command
    answered `AGENTS.md`, the two new tools, and only then `.env.example` — the untracked half first, each half sorted
    internally (`LC_ALL=C sort -c` reports disorder at line 4). A generated README block that opens with three new files
    is noise in a diff, and an order assertion means nothing unless it names an order this tool defines.
    """
    completed = _git(root, LS_FLAGS)
    if completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(LS_FLAGS)} failed: {completed.stderr.strip()}")
    return sorted(line for line in completed.stdout.splitlines() if line)


def worktree_digest(paths: list[str], root: Path = BUILD_ROOT) -> str:
    """A digest of the *contents* of every path a commit from this tree would contain.

    Why not `git status --porcelain`, which this function used to use: MEASURED twice on this checkout. Appending a line
    to docs/REFERENCE.md — already listed as modified — left `git status --porcelain` byte-identical (same lines, same
    order, that file named as modified in both) while this digest changed, because porcelain reports *which* paths
    differ and never *how*. A guard built on it waves through an edit that landed after `make ready` as long as its file
    was dirty: the mid-run write this stamp exists to catch (a 0.7.2 pass gated a tree whose README was written 15:30:59
    inside a gate running 15:28:15 to 15:33:01). No fingerprint hex is quoted here either, because a hex in prose is
    false as soon as any file inside the digest changes.

    Hashing the listed paths closes that hole: re-measured warm on this tree, best of five, the digest over its 78 paths
    takes 12 ms and the whole fingerprint call 17.4 ms with the git queries included — and a path git lists that is
    unreadable on disk changes the digest instead of passing silently.
    """
    hasher = hashlib.sha256()
    for relative in paths:
        candidate = root / relative
        try:
            content = candidate.read_bytes()
        except OSError:
            hasher.update(f"{relative}\tunreadable\n".encode())
            continue
        hasher.update(f"{relative}\t{hashlib.sha256(content).hexdigest()}\n".encode())
    return hasher.hexdigest()[:16]


def tree_fingerprint(root: Path = BUILD_ROOT) -> str:
    """One line naming the exact tree: committed tree hash, worktree content digest, path count.

    `HEAD^{tree}` alone is not enough. Most of an edit's life is spent uncommitted, and a fingerprint that ignores the
    working tree cannot tell "nothing changed since make ready" from "the tree moved under the gate". The committed half
    is kept as well: it is what makes the stamp name a *release candidate* rather than an arbitrary pile of files.
    """
    tree = _git(root, ["rev-parse", "HEAD^{tree}"])
    if tree.returncode != 0:
        raise RuntimeError(f"git rev-parse HEAD^{{tree}} failed: {tree.stderr.strip()}")
    paths = tracked_paths(root)
    return f"{tree.stdout.strip()} {worktree_digest(paths, root)} {len(paths)}"


def claim_sentence(count: int) -> str:
    """The exact sentence README carries for a tree of `count` paths."""
    return f"{CLAIM_PREFIX}{count}{CLAIM_SUFFIX}"


class _Level:
    """One directory of the rendered tree: the files directly inside it, and its subdirectories."""

    __slots__ = ("dirs", "files")

    def __init__(self) -> None:
        self.dirs: dict[str, _Level] = {}
        self.files: list[str] = []


def tree_lines(tracked: list[str]) -> list[str]:
    """The fenced block README carries: the tracked paths as an indented tree, sorted within every level.

    Directories are not tracked by git — `git ls-files` lists files — so they are built here from the path components
    and rendered with a trailing `/`. Sorting is per level rather than over the flat list: a flat sort puts
    `src/mypki/static/app.js` before `src/mypki/store.py`, which reads as disorder once the same paths are nested.
    """
    root = _Level()
    for path in tracked:
        parts = path.split("/")
        level = root
        for part in parts[:-1]:
            level = level.dirs.setdefault(part, _Level())
        level.files.append(parts[-1])

    lines = [ROOT_LABEL]

    def walk(level: _Level, prefix: str) -> None:
        entries = [(name, True) for name in sorted(level.dirs)] + [(name, False) for name in sorted(level.files)]
        for position, (name, is_dir) in enumerate(entries):
            last = position == len(entries) - 1
            lines.append(f"{prefix}{'└── ' if last else '├── '}{name}{'/' if is_dir else ''}")
            if is_dir:
                walk(level.dirs[name], prefix + ("    " if last else "│   "))

    walk(root, "")
    return lines


def parse_tree_lines(body: list[str]) -> tuple[list[str], list[str]]:
    """Read README's fenced tree back into paths, and name every line that could not be read.

    Returns (sorted paths, unreadable lines). Two things have to be recovered from the drawing:

    * **Depth**, from where a connector sits: column 4 * (depth - 1), every earlier four-column group being either
      `│   ` or `    `. A prefix that is neither is reported rather than guessed at.
    * **The parents**, from a stack carried across the block: `app.py` drawn under `├── mypki/` resolves to
      `src/mypki/app.py`, never to a bare `app.py`. A directory line (trailing `/`) pushes its name; a file line joins
      the stack with it.

    Unreadable lines are returned, not skipped in silence: a block that has drifted into prose, or into a shape this
    tool cannot parse, must fail the check instead of quietly comparing fewer paths than git reports.
    """
    paths: list[str] = []
    unreadable: list[str] = []
    stack: list[str] = []

    for raw in body:
        line = raw.rstrip()
        if not line:
            continue
        positions = [line.index(connector) for connector in TREE_CONNECTORS if connector in line]
        if not positions:
            # No connector at all: the repository label (not a path), or a line that belongs to prose.
            if line == ROOT_LABEL:
                stack = []
                continue
            unreadable.append(raw)
            continue

        cut = min(positions)
        prefix = line[:cut]
        name = line[cut + 4 :]
        if any(prefix[i : i + 4] not in TREE_CONTINUATIONS for i in range(0, cut, 4)) or not name:
            unreadable.append(raw)
            continue

        depth = cut // 4 + 1
        if depth - 1 > len(stack):
            unreadable.append(raw)
            continue

        stack = stack[: depth - 1]
        if name.endswith("/"):
            stack.append(name[:-1])
            continue
        paths.append("/".join([*stack, name]))

    return sorted(paths), unreadable


def parse_readme(text: str) -> tuple[int, int, list[str]]:
    """Locate README's claim and the fenced block below it.

    Returns (claim line number, claimed count, raw block lines). Raises ValueError when either is missing: a checker
    that silently reads nothing always passes.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = CLAIM.match(line)
        if not match:
            continue
        claimed = int(match.group(1))
        body: list[str] = []
        opened = False
        for following in lines[index + 1 :]:
            if following.strip() == "```":
                if opened:
                    return index + 1, claimed, body
                opened = True
                continue
            if opened:
                body.append(following)
        raise ValueError("found the tree claim but no closing fenced block after it")
    raise ValueError(f"README has no line matching {CLAIM.pattern!r}")


def findings(
    claimed: int,
    listed: list[str],
    tracked: list[str],
    *,
    block: list[str] | None = None,
    unreadable: tuple[str, ...] = (),
) -> list[str]:
    """Every way README's tree block disagrees with git. Empty means consistent."""
    out: list[str] = []
    if claimed != len(tracked):
        out.append(f"README claims {claimed} paths, git reports {len(tracked)}")
    if unreadable:
        out.append(f"README's tree has {len(unreadable)} line(s) that cannot be read as a path: {list(unreadable)[:5]}")
    extra = [path for path in listed if path not in tracked]
    missing = [path for path in tracked if path not in listed]
    if extra:
        out.append(f"README lists {len(extra)} path(s) git does not track: {extra[:10]}")
    if missing:
        out.append(f"git tracks {len(missing)} path(s) README does not list: {missing[:10]}")
    # Shape is asserted too, and it is the only comparison that can see a wrong indentation or a swapped sibling: the
    # block is generated, so a hand-edit that reorders or re-nests it is drift rather than taste.
    if block is not None and not extra and not missing and not unreadable and block != tree_lines(tracked):
        out.append(
            "README's tree names every tracked path but is not the shape `make ready` renders "
            "(order within a level, indentation, or the root label)"
        )
    return out


def render(tracked: list[str]) -> str:
    """The claim sentence plus its fenced tree, exactly as README carries them."""
    body = "\n".join(tree_lines(tracked))
    return f"{claim_sentence(len(tracked))}\n\n```\n{body}\n```"


def replace_block(text: str, tracked: list[str]) -> str:
    """Rewrite README's claim and fenced block in place, leaving every other line untouched."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not CLAIM.match(line):
            continue
        end = index + 1
        opened = False
        for offset, following in enumerate(lines[index + 1 :], start=1):
            if following.strip() != "```":
                continue
            if opened:
                end = index + offset
                break
            opened = True
        replaced = lines[:index] + render(tracked).splitlines() + lines[end + 1 :]
        joined = "\n".join(replaced)
        return joined + ("\n" if text.endswith("\n") else "")
    raise ValueError("README has no tree claim to rewrite")


def stamp(path: Path = STAMP_FILE) -> str | None:
    """The fingerprint `make ready` recorded, or None when it never ran."""
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("gate tree: "):
            return line.removeprefix("gate tree: ").strip()
    return ""


def write_stamp(fingerprint: str, path: Path = STAMP_FILE) -> None:
    """Record `gate tree: <fingerprint>` as the only content of the stamp file.

    One line, exactly the form `make gate` compares against and the form AGENTS.md rule 3 asks a gate log to open with.
    Written whole rather than appended: a stale stamp from an earlier tree must not survive next to the current one.
    """
    path.write_text(f"gate tree: {fingerprint}\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check or regenerate README's shipped-tree block against the tree a commit would contain."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="compare README with git (the default)")
    mode.add_argument("--write", action="store_true", help="rewrite README's claim and block from git")
    parser.add_argument("--fingerprint", action="store_true", help="print the one-line tree fingerprint and exit")
    parser.add_argument("--count", action="store_true", help="print only the path count")
    parser.add_argument(
        "--stamp", action="store_true", help="compare the recorded 'make ready' stamp with the current tree"
    )
    parser.add_argument(
        "--write-stamp",
        action="store_true",
        help="write 'gate tree: <fingerprint>' to .gate-ready (what make ready does)",
    )
    arguments = parser.parse_args(argv)

    if not git_available():
        print("cannot check: no git binary in this environment", file=sys.stderr)
        return 2

    try:
        tracked = tracked_paths()
        fingerprint = tree_fingerprint()
    except RuntimeError as error:
        print(f"cannot check: {error}", file=sys.stderr)
        return 2

    if arguments.fingerprint:
        print(fingerprint)
        return 0
    if arguments.write_stamp:
        write_stamp(fingerprint)
        print(f"ok: stamped {STAMP_FILE.name} for this tree ({fingerprint})")
        return 0
    if arguments.count:
        print(len(tracked))
        return 0

    if arguments.stamp:
        recorded = stamp()
        if not recorded:
            print("drift: no 'make ready' stamp; run make ready before make gate", file=sys.stderr)
            return 1
        if recorded != fingerprint:
            print("drift: tree moved since 'make ready'", file=sys.stderr)
            print(f"  stamped: {recorded}", file=sys.stderr)
            print(f"  current: {fingerprint}", file=sys.stderr)
            return 1
        print(f"ok: tree unchanged since 'make ready' ({fingerprint})")
        return 0

    if not README.is_file():
        print(f"cannot check: {README} is not a file", file=sys.stderr)
        return 2
    text = README.read_text(encoding="utf-8")

    try:
        _, claimed, block = parse_readme(text)
    except ValueError as error:
        print(f"drift: {error}", file=sys.stderr)
        return 1

    if arguments.write:
        README.write_text(replace_block(text, tracked), encoding="utf-8")
        print(f"ok: README structure tree regenerated ({len(tracked)} paths)")
        return 0

    listed, unreadable = parse_tree_lines(block)
    problems = findings(claimed, listed, tracked, block=block, unreadable=tuple(unreadable))
    for problem in problems:
        print(f"drift: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"ok: README's shipped-tree block matches git ({len(tracked)} paths)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
