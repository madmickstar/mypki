"""The sdist posture: what a release ships, and — equally important — what it may never reach.

`pyproject.toml`'s `[tool.hatch.build.targets.sdist]` is the only place that answers "what is in the artifact", and an
artifact is judged by both halves of its configuration. `include` decides whether a user who untars a release can
run the
test suite at all; `exclude` decides whether private key material or operator runtime state can ride along with a wheel.
A test that checked only one half would pass on a config that ships `*.pem`, and a config that ships nothing at
all is also
"clean".

Why TOML is scanned by hand rather than parsed: the project supports Python 3.10, and `tomllib` arrives in 3.11
(MEASURED:
importable on this 3.12 venv; absent by design on the floor version). Adding a `tomli` dependency to the dev extras just
to read one file is the same mistake as adding a TOML parser to `tools/check_version.py`, which faces the identical 3.10
floor. So the scan here is deliberately narrow — two array-valued keys in one table — and it fails loudly rather than
guessing, because a packaging test that silently reads nothing is a packaging test that always passes.

Why the "cannot reach" half is measured against the real tree: an exclude list of `["*.pem"]` proves nothing if some
include entry already names a directory full of PEM files. Coverage is computed from what is actually on disk under each
include entry, so the assertion is about this repository, not about a string that looks safe.

Why README's file list lives in this file too: `README.md`'s *Where the files live* block is the same decision written
as prose — it enumerates the paths a release ships and claims how many there are. A hand-typed copy of a file list is a
second source of truth, and MEASURED on commit a4dc4f3 README claimed 75 paths while CHANGELOG.md's entry for the same
commit said 74 with the whole suite green. `tools/tree_manifest.py` regenerates the block from git; the assertions below
check it against git **again, independently** — this file re-asks git with its own flags and its own comparison rather
than calling the tool whose output it audits: a test that grades a tool against itself cannot see the tool change its
definition.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from mypki import __version__
from mypki.app import ERROR_SURFACE_RULE

BUILD_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = BUILD_ROOT / "pyproject.toml"
README = BUILD_ROOT / "README.md"

#: What a release must carry. Named here rather than inlined in each assertion so that adding an entry to `include` is a
#: deliberate edit in two places (the config and this list) instead of a silent one-sided change.
REQUIRED_INCLUDES = [
    "src",
    "tests",
    "tools",
    "assets",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "docs/page-map.md",
    "docs/REFERENCE.md",
    "docs/linux_install.md",
    "deploy/mypki.service",
]

#: What may never appear in an artifact, matched against the *relative* path of every file each include entry covers.
#: `scripts/` and `logs/` are excluded because they are operator-facing runtime state (tracked in git, useless in an
#: install); the key-material extensions are excluded because a shipped private key is not a packaging mistake but a
#: security incident with a changelog entry.
FORBIDDEN_PATTERNS = [
    re.compile(r"^scripts(?:/|$)"),
    re.compile(r"^logs(?:/|$)"),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"\.crt$"),
]

#: The four spellings `exclude` is required to name, asserted as a set rather than "some plausible list". A config that
#: excludes `*.pem` but not `*.key` would still ship the CA key under a different extension, and the difference between
#: those two configs is invisible to a test that only checks "the exclude list is non-empty".
REQUIRED_EXCLUDES = {"scripts", "logs", "*.pem", "*.key", "*.crt"}

#: The documents this repository keeps for whoever works on it rather than for whoever installs it. They are tracked,
#: linted and cited by code, and they are not in `include` — a decision asserted below so it reads as a decision and not
#: as an omission someone could "fix" by adding one line to one of the two lists.
WORKING_RULES_DOCUMENTS = ["AGENTS.md", "SMOKE_TESTING.md"]

#: The flags that answer "which paths would a commit from this tree contain", spelled out here rather than imported from
#: tools/tree_manifest.py. Restating it is deliberate: the README assertions below are meant as an independent second
#: measurement, and if they borrowed the tool's own constant they could only prove the tool agrees with itself.
LS_FLAGS = ["ls-files", "--cached", "--exclude-standard", "--others"]

#: README's claim sentence, matched loosely on purpose. tools/tree_manifest.py pins the wording exactly because it
#: writes that line; this file only has to find it, and a copy of the exact sentence here would be a third place the
#: wording lives. The `\(\d+\)` group is the half being audited.
README_CLAIM = re.compile(r"^The tree this repository .* \((\d+) paths\):$")


# --------------------------------------------------------------------------------- narrow TOML scanning


def _array_entries(table_text: str, key: str) -> list[str]:
    """The string entries of one array-valued key inside a table body.

    A regex over the bracketed array rather than a real parser (see the module docstring for why). It is anchored to the
    key name and refuses to span a second `[` line, so a `key = [...]` in a *different* table cannot be mistaken
    for this
    one — which is how a packaging test starts reading the wheel config while claiming to read the sdist config.
    """
    match = re.search(
        rf"^{re.escape(key)}\s*=\s*\[(?P<items>[^\]]*)\]",
        table_text,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        return []
    return [item for item in re.findall(r'"([^"]*)"|\'([^\']*)\'', match.group("items")) for item in item if item]


def _table_body(text: str, name: str) -> str:
    """The raw text of one TOML table, or raise — a missing table here is the finding, not an empty result.

    Raises rather than returning `""` because every caller would then report "the include list is empty", which is a
    different defect from the one that actually exists (nobody wrote the table at all). Naming the absent table is what
    makes the failure actionable.
    """
    header = re.search(r"^\[\s*" + re.escape(name) + r"\s*\]\s*$", text, re.MULTILINE)
    if header is None:
        raise AssertionError(f"{PYPROJECT} has no [{name}] table")
    rest = text[header.end() :]
    following = re.search(r"^\s*\[", rest, re.MULTILINE)
    return rest[: following.start()] if following else rest


@pytest.fixture(scope="module")
def sdist_config() -> dict[str, list[str]]:
    """`include` and `exclude` from `[tool.hatch.build.targets.sdist]`, read once for the whole module.

    Read from the real file rather than mirrored from the config in test literals: a copy of the config inside the
    test is
    a second source of truth, and it drifts on the first packaging change while staying green (STYLE §1).
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    body = _table_body(text, "tool.hatch.build.targets.sdist")
    return {"include": _array_entries(body, "include"), "exclude": _array_entries(body, "exclude")}


# ---------------------------------------------------------------------------- what an include entry covers


def covered_paths(entry: str) -> list[str]:
    """Every file in this checkout that `entry` would put in the sdist, as POSIX-relative paths.

    Hatchling's `include` entries are repo-relative paths (a directory ships its subtree), so coverage is computed
    the same
    way: a file entry contributes itself, a directory entry contributes its walk. Relative paths are what the forbidden
    patterns match against — an absolute path would let `/home/.../logs/x.log` slip past a pattern anchored on `^logs/`.
    """
    target = BUILD_ROOT / entry
    if target.is_dir():
        return [path.relative_to(BUILD_ROOT).as_posix() for path in sorted(target.rglob("*")) if path.is_file()]
    if target.is_file():
        return [entry]
    # An entry naming nothing is a finding, not an empty coverage set: hatchling would build a "successful" sdist that
    # silently omitted the file everyone assumed was in it.
    raise AssertionError(f"sdist include entry {entry!r} matches no file or directory in {BUILD_ROOT}")


def forbidden_in(paths: list[str]) -> list[str]:
    """Which of `paths` hit a forbidden pattern — empty means clean, and 'clean' here is a measured claim."""
    return [path for path in paths if any(pattern.search(path) for pattern in FORBIDDEN_PATTERNS)]


# ------------------------------------------------------------------------------------------------- include half


def test_include_names_everything_a_release_needs(sdist_config: dict[str, list[str]]) -> None:
    """Every entry is present, as a set — not merely "the include list is long enough".

    `tests` and `tools` are the two that people try to drop because they look like development clutter. Dropping `tools`
    alone would still build a wheel; dropping `tests` while keeping `test_version.py`'s import of `check_version`
    produces
    an sdist whose own test suite aborts at collection with ModuleNotFoundError, which a user reads as "this release is
    broken" rather than "this artifact omitted a file".

    Asserted as a set in both directions, so an entry added to the config without being named here fails too: the config
    and this list are two spellings of one decision, and a one-sided edit ships an artifact missing something its own
    documentation promises.
    """
    assert set(sdist_config["include"]) == set(REQUIRED_INCLUDES), sorted(sdist_config["include"])


@pytest.mark.parametrize("entry", REQUIRED_INCLUDES)
def test_every_include_entry_exists_on_disk(entry: str) -> None:
    """An include entry that names nothing is a silent omission, so each one is checked against the tree.

    `docs/page-map.md` is the sharpest case: it is mypki's citable spec, cited from code as `page-map §N`, and a config
    typo (`docs/` vs `docs/page-map.md`) changes which of the two hatchling honours without any build failing.
    `covered_paths` raising on an entry that matches nothing is what makes that typo fail loudly instead of building a
    "successful" artifact with a hole in it.
    """
    assert covered_paths(entry), f"{entry} covers nothing"


def test_include_covers_the_package_templates_and_static_assets() -> None:
    """The `src` entry must carry every page template, the stylesheet, the script and both SVG assets.

    Seven of mypki's eight surfaces *are* templates; a wheel built from `mypki/*.py` alone installs cleanly and then
    raises at first request with a Jinja `TemplateNotFound`. Asserted as membership in `covered_paths("src")` so the
    finding names the missing asset rather than a count.

    0.2.0 added `about.html`, `settings.html`, `logo.svg` and `favicon.svg`, and removed `home.html` (its prose moved to
    `about.html`, which `/version` now renders). 0.3.0 adds `static/app.js` — the one same-origin enhancement script
    base.html loads. It is optional at runtime (every page works without it) but not optional in the artifact: a wheel
    that shipped the stylesheet and not the script would render pages whose copy buttons do nothing, silently. Keeping
    this list explicit is the packaging equivalent of "which assets does this release have": a stale entry fails against
    a correct tree, which is the finding rather than a nuisance.

    `inspect.html` joins the list with the consent work, and its absence here was an omission rather than a decision:
    `/inspect` shipped in 0.5.0 rendering it, and this test — which exists precisely to catch a template missing from
    the artifact — passed anyway, because `covered_paths("src")` carries the whole package directory and this assertion
    only checks the names written down here. That is the failure mode of an explicit list: it can only complain about
    what it names. The route sweep below (`/inspect`) is the counterpart that would have caught it by rendering it.
    """
    shipped = set(covered_paths("src"))

    for asset in (
        "src/mypki/templates/base.html",
        "src/mypki/templates/about.html",
        "src/mypki/templates/settings.html",
        "src/mypki/templates/csr_generate.html",
        "src/mypki/templates/csr_sign.html",
        "src/mypki/templates/ca_download.html",
        "src/mypki/templates/issued.html",
        "src/mypki/templates/inspect.html",
        "src/mypki/templates/crl.html",
        "src/mypki/templates/error.html",
        "src/mypki/static/style.css",
        "src/mypki/static/app.js",
        "src/mypki/static/logo.svg",
        "src/mypki/static/favicon.svg",
    ):
        assert asset in shipped, f"{asset} is not carried by the sdist's `src` entry"


def test_the_shipped_script_says_copied_and_nothing_else() -> None:
    """0.4.0 changed the copy button's success line, and the change has to survive into the artifact.

    The user's field report asked for one short green line — `Copied to clipboard` — where 0.3.0 printed a sentence
    ("Copied. Nothing was sent anywhere: this is your clipboard."). Both strings live only in `static/app.js`, which
    no route renders and no other test reads, so without an assertion here a re-landing of the old sentence would ship
    green. Asserted against the file the sdist actually carries (the same `covered_paths('src')` view the test above
    uses) rather than against a browser: this box has no browser installed, so what can be proven is what is in the
    artifact — the behaviour in a real browser remains unverified and SMOKE_TESTING.md says so.

    The failure branch is asserted too, because it is the half that must stay verbose: an honest sentence about *what
    went wrong* is the one a reader may not skim past.
    """
    script = (BUILD_ROOT / "src" / "mypki" / "static" / "app.js").read_text(encoding="utf-8")

    assert 'note(button, "Copied to clipboard", false);' in script
    assert "Nothing was sent anywhere" not in script
    assert "could not be copied by this browser" in script

    # The counter text SMOKE_TESTING §10 compares against the server-rendered '0 selected': app.js must build the same
    # shape at zero rather than a different sentence.
    assert '+ " selected";' in script


def test_every_page_route_renders_from_the_shipped_tree(session_client) -> None:
    """The gap a file-list assertion leaves: an asset can be listed here and still not be what a route renders.

    Every page route `create_app` registers is fetched against the real template directory, so a template renamed in
    `app.py` without renaming the file (or the reverse) fails as a 500 here rather than staying invisible behind a green
    packaging check. `/version` is included because in 0.2.0 it renders `about.html` — the one route whose template is
    not guessable from its own path.

    `/inspect` joins the sweep for the same reason it joins the asset list: it was the one page route this file never
    fetched, so a wheel missing `inspect.html` would have shown up as nothing in packaging at all, and as a 500 only if
    some other test happened to GET it. The POST half is exercised in `tests/test_inspect.py`; this sweep is the
    GET-only "the shipped tree can actually render it" check.

    `/crl` joins it in 0.7.0 for the same reason, and its absence here would have been the same class of bug: the nav
    stays seven links (page-map §12), so no other test ever fetches the new page. Only `crl.html` being named above
    **and** fetched here proves the shipped tree can render it.
    """
    for path in (
        "/",
        "/csr/generate",
        "/csr/sign",
        "/ca",
        "/issued",
        "/crl",
        "/about",
        "/settings",
        "/inspect",
        "/version",
    ):
        response = session_client.get(path)
        assert response.status_code == 200, f"{path}: {response.text[:300]}"
        assert "<!DOCTYPE html>" in response.text, path


def test_the_wheel_ships_only_the_package() -> None:
    """The wheel half of the same posture: `[tool.hatch.build.targets.wheel] packages = ["src/mypki"]`.

    Checked in this file rather than a separate one because the two targets are one decision. An sdist that
    carries `tests`
    and `tools` and a wheel that also carried them would install a test suite into site-packages — which is how a
    project
    ends up with `import tests` shadowing somebody else's package.
    """
    body = _table_body(PYPROJECT.read_text(encoding="utf-8"), "tool.hatch.build.targets.wheel")

    assert _array_entries(body, "packages") == ["src/mypki"]


# ------------------------------------------------------------------------------------------------ exclude half


def test_exclude_names_every_forbidden_kind(sdist_config: dict[str, list[str]]) -> None:
    """All five spellings are present. `issued.db` is deliberately *not* here — see the note below.

    `*.crt`, `*.pem`, `*.key` and `*.csr` are key material or certificate requests; `scripts` and `logs` are
    runtime state.
    A generated database is not excluded by pattern because it lives under `<data>/`, which is outside the source
    tree this
    configuration ever looks at — excluding it by glob would imply the config believes it could be in the tree,
    which is a
    claim this file does not want to make.
    """
    assert set(sdist_config["exclude"]) == REQUIRED_EXCLUDES, sorted(sdist_config["exclude"])


@pytest.mark.parametrize("entry", REQUIRED_INCLUDES)
def test_no_include_entry_can_reach_anything_forbidden(entry: str, sdist_config: dict[str, list[str]]) -> None:
    """The half that a `exclude` list alone cannot prove: coverage of every include entry contains nothing forbidden.

    Parametrised per entry so a future `include = [..., "scripts"]` names the offending entry in the failure rather than
    dumping a merged file list. This is the assertion that survives someone adding a top-level `keys/` directory
    tomorrow:
    the *pattern* check catches it even though nothing in today's config mentions it.
    """
    hits = forbidden_in(covered_paths(entry))

    assert not hits, f"sdist include entry {entry!r} would ship forbidden paths: {hits[:10]}"


def test_the_coverage_check_is_not_vacuous() -> None:
    """The mutation check for the test above: `scripts` *would* be caught if it were ever included.

    Without this, an assertion that reads "no include entry reaches scripts/" passes identically when the coverage
    helper
    breaks and returns nothing. Feeding the helper a poisoned entry is the only way to tell a passing posture
    apart from a
    blind one (STYLE §8: mutate one thing, prove the check sees it).
    """
    # The walker half: `covered_paths` has to return real, repo-relative POSIX paths for an entry that exists, because
    # every "no include entry reaches a forbidden thing" assertion below is only as good as this walk. `tools` is the
    # entry to walk now: it is a shipped directory named file by file, and the harness is one of those files.
    walked = covered_paths("tools")
    assert walked, "the coverage helper walks nothing even for an entry that exists"
    assert all(path.startswith("tools/") for path in walked), f"paths were not repo-relative: {walked[:5]}"
    assert "tools/e2e_harness.py" in walked, f"the harness is not where the Makefile gate runs it from: {walked}"

    # The pattern half: a poisoned *path* list must be caught in full. `scripts/` no longer holds anything in this tree,
    # so the old recipe (feed the walker the literal entry `scripts` and demand that everything it found was forbidden)
    # now proves nothing about the patterns — it would read "empty is fully forbidden". Naming the four shapes directly
    # keeps the mutation visible: drop any one pattern from FORBIDDEN_PATTERNS and this assertion goes red.
    poisoned = ["scripts/smoke_test.sh", "logs/mypki.log", "src/mypki/ca_key.pem", "keys/ca.key", "leaf.crt"]
    assert forbidden_in(poisoned) == poisoned, f"a forbidden shape slipped through: {forbidden_in(poisoned)}"


# --------------------------------------------------------------------------------- README's shipped-tree claim


def _git_paths(flags: list[str]) -> list[str]:
    """Ask git one question and return its answer as a sorted path list, or raise.

    Raises rather than returning `[]`: every assertion in this section compares README against git, so a git call that
    failed would otherwise read as "git tracks nothing" — which is a different defect from the one being looked for, and
    it would be reported as a README problem. The failure names the git command instead.
    """
    completed = subprocess.run(
        ["git", *flags],
        cwd=str(BUILD_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"git {' '.join(flags)} failed ({completed.returncode}): {completed.stderr.strip()}")
    return sorted(line for line in completed.stdout.splitlines() if line)


def _readme_claim_and_block(text: str) -> tuple[int, list[str]]:
    """README's claimed path count and the paths its fenced block actually lists.

    Raises when either is missing, which is the same contract `covered_paths` uses for an include entry that names
    nothing: a reader that finds no claim must not report "the claim matches".
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = README_CLAIM.match(line)
        if match is None:
            continue
        body: list[str] = []
        opened = False
        for following in lines[index + 1 :]:
            if following.strip() == "```":
                if opened:
                    return int(match.group(1)), body
                opened = True
                continue
            if opened:
                body.append(following)
        raise AssertionError("found README's tree claim but no closing fenced block after it")
    raise AssertionError(f"README has no line matching {README_CLAIM.pattern!r}")


def _readme_drift(claimed: int, listed: list[str], tracked: list[str]) -> list[str]:
    """Every way README's block disagrees with `tracked`. Empty means consistent — the finding, not a count."""
    out: list[str] = []
    if claimed != len(tracked):
        out.append(f"README claims {claimed} paths, git reports {len(tracked)}")
    extra = [path for path in listed if path not in tracked]
    missing = [path for path in tracked if path not in listed]
    if extra:
        out.append(f"README lists {len(extra)} path(s) git does not track: {extra[:10]}")
    if missing:
        out.append(f"git tracks {len(missing)} path(s) README does not list: {missing[:10]}")
    if not extra and not missing and listed != sorted(tracked):
        out.append("README lists every tracked path but in an order git's own listing does not produce")
    return out


def test_readmes_shipped_tree_claim_and_block_match_git() -> None:
    """README's count **and its enumerated paths** must equal the tree a commit would contain, exactly.

    Two denominators are at work in this file and they are not the same set. `include` answers what the *artifact*
    contains; README's block answers what *the repository* ships — it names `.github/workflows/ci.yml`, `Makefile`,
    `SMOKE_TESTING.md` and `AGENTS.md`, none of which a wheel or sdist carries. Asserting one against the other would be
    a category error; each is asserted against its own source of truth, and README's is git.

    The denominator is `--cached --exclude-standard --others`, not plain `git ls-files`: mid-change, plain answers only
    what is already committed (MEASURED here: 75 against 78 while three new files were still untracked), so a README
    generated from it would be false in the very commit that added those files. That is the same disagreement this
    pairing had at commit a4dc4f3 — 75 in README, 74 in CHANGELOG, both green.

    Asserted as a set **and** as an order: the block is generated by `make ready`, so a hand-edit that reorders it is
    drift too, and a count-only assertion would pass on a list that swapped two entries out.
    """
    claimed, listed = _readme_claim_and_block(README.read_text(encoding="utf-8"))
    tracked = _git_paths(LS_FLAGS)

    assert tracked, "git reported no paths at all, so nothing below could have failed"
    assert README.name in tracked and "pyproject.toml" in tracked, (
        f"git's listing is not this repository: {tracked[:5]}"
    )

    problems = _readme_drift(claimed, listed, tracked)
    assert not problems, "; ".join(problems)
    assert len(listed) == claimed == len(tracked), (claimed, len(listed), len(tracked))


#: The four ways a generated file list goes stale, named as data so a reader can see that every failure mode is covered
#: and not only "the number is wrong": the count drifts on its own, a tracked path disappears from the block, an
#: invented path appears in it, or the order changes. Each becomes one parametrised case below.
README_MUTATIONS = ("count", "missing-path", "invented-path", "reordered")


@pytest.mark.parametrize("mutation", README_MUTATIONS)
def test_the_readme_tree_claim_check_is_not_vacuous(mutation: str) -> None:
    """The mutation check for the README assertion above: a poisoned block must be reported, or it is theatre.

    Same shape as `test_the_coverage_check_is_not_vacuous`. A comparison of README against git passes identically when
    either half stops reading anything — an empty list against an empty list is equality — so the only way to tell a
    passing claim apart from a blind one is to feed the comparison deliberately wrong inputs and demand that each one is
    named (STYLE §8: mutate one thing, prove the check sees it).

    The poisoned inputs are built from git's real listing rather than from literals, so each mutation differs from a
    correct tree in exactly one way and the failure names that one way.
    """
    tracked = _git_paths(LS_FLAGS)
    assert len(tracked) > 1, "git answered with fewer than two paths, so no mutation here could be caught"

    if mutation == "count":
        # Right list, wrong number: exactly the 74-vs-75 disagreement of commit a4dc4f3.
        problems = _readme_drift(len(tracked) + 1, tracked, tracked)
        assert problems, "a claim one path out passed clean"
        assert any("claims" in problem for problem in problems), problems
        return

    if mutation == "missing-path":
        # One tracked path absent from the block, count left correct so only the set comparison can see it.
        dropped = tracked[0]
        problems = _readme_drift(len(tracked) - 1, tracked[1:], tracked)
        assert problems, f"a block missing {dropped!r} passed clean"
        assert any(dropped in problem for problem in problems), problems
        return

    if mutation == "invented-path":
        invented = "docs/a-file-git-does-not-track.md"
        problems = _readme_drift(len(tracked) + 1, [*tracked, invented], tracked)
        assert problems, f"a block naming {invented!r} passed clean"
        assert any(invented in problem for problem in problems), problems
        return

    # Reordered: every path present, the order wrong. A count-only assertion cannot see this one at all.
    reordered = list(tracked)
    reordered[0], reordered[-1] = reordered[-1], reordered[0]
    assert reordered != tracked, "swapping the ends of a one-element list is not a mutation"
    problems = _readme_drift(len(tracked), reordered, tracked)
    assert problems, "a reordered block passed clean"
    assert any("order" in problem for problem in problems), problems


def _throwaway_repo(tmp_path: Path) -> Path:
    """A real git repository built for the purpose, with one committed file and one untracked file.

    Built in a temporary directory rather than by touching this checkout: an assertion about what `--others` does must
    not add a file to the tree it runs in, because that file would move the very fingerprint `make ready` stamped and
    `make gate` compares (the same hermeticity rule tests/test_version.py follows when it needs git refs).
    """
    repository = tmp_path / "repo"
    repository.mkdir()
    environment = dict(os.environ)
    # A container and a CI runner routinely have no git identity configured; `git commit` dies with "Committer identity
    # unknown" (exit 128) unless one is supplied for these calls.
    environment["GIT_AUTHOR_NAME"] = environment["GIT_COMMITTER_NAME"] = "mypki packaging test"
    environment["GIT_AUTHOR_EMAIL"] = environment["GIT_COMMITTER_EMAIL"] = "test@example.invalid"

    def git(*arguments: str) -> None:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=str(repository),
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, f"git {' '.join(arguments)}: {completed.stdout}{completed.stderr}"

    git("init", "-q")
    (repository / "tracked.txt").write_text("committed\n", encoding="utf-8")
    git("add", "tracked.txt")
    git("commit", "-q", "-m", "one tracked file")
    (repository / "untracked.txt").write_text("added, not yet committed\n", encoding="utf-8")
    return repository


def test_the_readme_denominator_sees_a_file_plain_ls_files_does_not(tmp_path: Path) -> None:
    """Why README's claim is generated from `--cached --exclude-standard --others` and not from plain `git ls-files`.

    In a throwaway repository with one committed file and one untracked file, the two commands answer different
    questions: plain `git ls-files` reports what is committed, and this file's flags report what a commit *would*
    contain. A README generated from the first would be born stale in the commit that adds the file — MEASURED on this
    checkout at 75 paths against 78 while AGENTS.md and the two new tools were still untracked, the same shape as the
    74-vs-75 disagreement of commit a4dc4f3.

    Asserted against a repository built for the purpose rather than against this tree's transient state: mid-change the
    difference here is three files, and after this change is committed it is zero. An assertion that only holds while
    somebody is editing is an assertion that quietly stops testing anything.
    """
    repository = _throwaway_repo(tmp_path)

    def repo_paths(flags: list[str]) -> list[str]:
        completed = subprocess.run(["git", *flags], cwd=str(repository), capture_output=True, text=True, check=False)
        assert completed.returncode == 0, f"git {' '.join(flags)}: {completed.stderr.strip()}"
        return sorted(line for line in completed.stdout.splitlines() if line)

    committed = repo_paths(["ls-files"])
    as_if_committed = repo_paths(LS_FLAGS)

    assert committed == ["tracked.txt"], committed
    assert as_if_committed == ["tracked.txt", "untracked.txt"], as_if_committed
    assert set(committed) < set(as_if_committed), "the two denominators answered the same question"

    # The same relation must hold on this repository, which is what ties the throwaway repo back to the assertion
    # above: whatever is committed here is a subset of what README's block is generated from.
    real_committed = _git_paths(["ls-files"])
    real_denominator = _git_paths(LS_FLAGS)
    assert set(real_committed) <= set(real_denominator), (
        f"README's denominator dropped {len(set(real_committed) - set(real_denominator))} committed path(s)"
    )
    for path in sorted(set(real_denominator) - set(real_committed)):
        assert (BUILD_ROOT / path).is_file(), f"{path} is listed by git but absent from disk"
        assert not any(pattern.search(path) for pattern in FORBIDDEN_PATTERNS), f"{path} would be forbidden if shipped"


def test_working_rule_documents_are_deliberately_not_in_the_artifact() -> None:
    """`AGENTS.md` and `SMOKE_TESTING.md` are tracked, gated and cited — and not shipped. That is a decision on purpose.

    The user-facing question this file answers is what a person who untars a release can do with it. Both of these
    documents answer "how do I work **on** this repository": measured costs of one 2-CPU box, shell constraints of this
    container, how to run the harness. Neither helps an installed package run, and `include` is asserted equal to
    `REQUIRED_INCLUDES` in both directions, so shipping them would mean editing two lists in lockstep for no gain to the
    user — while omitting them silently is exactly the one-sided edit that pairing exists to catch. Naming them here is
    what turns the omission into a recorded decision.
    """
    sdist_body = _table_body(PYPROJECT.read_text(encoding="utf-8"), "tool.hatch.build.targets.sdist")
    include = set(_array_entries(sdist_body, "include"))

    for document in WORKING_RULES_DOCUMENTS:
        assert (BUILD_ROOT / document).is_file(), f"{document} is asserted absent from the artifact but is not tracked"
        assert document not in include, f"{document} joined the sdist without this file being told about it"
        assert document not in REQUIRED_INCLUDES, f"{document} is in one of the two lists but not the other"

    # The asymmetry that makes the decision worth recording: docs/REFERENCE.md *is* shipped and links to
    # ../SMOKE_TESTING.md, so an artifact reader can follow a link out of the artifact. Recorded here rather than
    # papered over, so whoever ships SMOKE_TESTING.md one day edits both lists in the same commit.
    assert "docs/REFERENCE.md" in include
    reference = (BUILD_ROOT / "docs" / "REFERENCE.md").read_text(encoding="utf-8")
    if "../SMOKE_TESTING.md" in reference:
        assert "SMOKE_TESTING.md" not in include, "SMOKE_TESTING.md is both linked from a shipped doc and shipped"


def test_no_key_material_exists_anywhere_the_include_entries_walk() -> None:
    """A belt-and-braces sweep of the covered tree, independent of what `exclude` claims.

    The two tests above reason about configuration. This one reasons about the checkout: if a `.pem` from an accidental
    manual run is sitting inside `src/` or `tests/`, hatchling's `exclude` patterns would save it — and this test would
    still report the file, because a key material sitting in the source tree is a problem whether or not it ships.
    """
    covered: set[str] = set()
    for entry in REQUIRED_INCLUDES:
        covered.update(covered_paths(entry))

    offenders = sorted(path for path in covered if path.endswith((".pem", ".key", ".crt", ".csr", ".p12")))

    assert not offenders, f"key material inside the shipped tree: {offenders}"


def test_the_sdist_keeps_the_harness_out_of_an_installed_ca() -> None:
    """`scripts/` is excluded on purpose, and the reason has to survive whoever reads this file next.

    The harness moved out of `scripts/` into `tools/e2e_harness.py`, so two facts are now asserted where one used to be:
      * `scripts/` is still an exclude entry **and nothing is in it any more**: the entry outlived its directory, and
        that is deliberate — a bare `scripts` exclusion is what stops a future operator-facing shell helper (the kind
        someone will write again for curl-by-hand reproduction) from riding into site-packages, where running it against
        a production CA is one tab-completion away.
      * the harness itself lives under `tools/`, which **is** shipped — because `tools/` is already in `include` for
        `test_version.py`'s import, and an end-to-end harness that only needs the project's own dev dependencies is
        something a downstream packager can actually run to prove the release works on their box.
    Asserted as "excluded + empty + the harness exists where the Makefile says it does", so the pair reads as a decision
    rather than an omission.
    """
    scripts = BUILD_ROOT / "scripts"
    assert not scripts.exists() or not any(p.is_file() for p in scripts.rglob("*")), (
        "scripts/ is excluded from the sdist and is meant to stay empty: a tracked harness belongs in tools/, "
        "where the Makefile gate can reach it, not in a directory an installed package never sees"
    )
    assert (BUILD_ROOT / "tools" / "e2e_harness.py").is_file()
    assert "scripts" in REQUIRED_EXCLUDES
    assert "tools" in REQUIRED_INCLUDES


def _spawn_cli(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run a CLI route in a **child process** with its environment pinned inside `cwd`.

    Why a subprocess here when `tests/test_cli.py` deliberately never spawns one: the two files answer different
    questions. `test_cli.py` tests an argv grammar and the exit codes it promises, which needs in-process control over
    streams and fixtures. This file asks what a *release* ships — and whether `pip install mypki` produced something an
    operator can actually type. An entry point is a property of the installed artifact (the wheel's script metadata and
    the presence of `mypki/__main__.py`), so no in-process call to `cli.main()` can prove it: every test in this suite
    could stay green while both routes were broken, exactly as `init-ca --key-type ec` stayed broken through 0.1.0.

    Hermeticity (STYLE §8) needs its own handling because a child process cannot see this session's fixtures: the
    autouse `data_dir` fixture redirects `MYPKI_DATA_DIR` **in this process only**. So both `MYPKI_DATA_DIR` and
    `MYPKI_LOG_FILE` are pinned inside `cwd` here, and the ambient `MYPKI_PORT` / `MYPKI_HOST` /
    `MYPKI_CA_PASSPHRASE` are dropped rather than inherited. `--version` exits inside argparse before any Settings is
    built, so this is belt-and-braces — but a child process that inherits an operator's real data directory is the one
    failure mode this file must never introduce.
    """
    environment = dict(os.environ)
    environment["MYPKI_DATA_DIR"] = str(cwd / "data")
    environment["MYPKI_LOG_FILE"] = str(cwd / "logs" / "mypki.log")
    for inherited in ("MYPKI_PORT", "MYPKI_HOST", "MYPKI_CA_PASSPHRASE"):
        environment.pop(inherited, None)

    return subprocess.run(
        command,
        cwd=str(cwd),
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_python_dash_m_is_a_working_route_to_the_cli(tmp_path: Path) -> None:
    """`python -m mypki --version` starts the CLI, prints `mypki.__version__`, and writes nothing to disk.

    The route matters because it is the one that works without a script entry on PATH: inside a virtualenv created from
    a source checkout, or against a wheel someone built and has not installed yet. MEASURED on this box: 939 ms per
    invocation (the import of `mypki.cli` pulls in fastapi/uvicorn), which is why there is one such test rather than a
    parametrised sweep.

    The empty-directory assertion is not decoration. argparse's `version` action exits during parsing, before
    `main()` configures logging or resolves a data directory, so this flag must not create `<data>/` or `logs/`. A
    future refactor that moves settings resolution above argument parsing would start creating directories here — and
    the assertion catches it as a side effect rather than as a surprise on an operator's machine.
    """
    completed = _spawn_cli([sys.executable, "-m", "mypki", "--version"], tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"mypki {__version__}"
    assert not completed.stderr, completed.stderr
    assert list(tmp_path.iterdir()) == [], f"--version created files: {list(tmp_path.iterdir())}"


def test_the_console_script_route_reports_the_same_version(tmp_path: Path) -> None:
    """`docs/linux_install.md`'s quick start (`mypki init-ca`, `mypki serve`) resolves to the same CLI as
    `python -m mypki`.

    `[project.scripts] mypki = "mypki.cli:main"` is a claim about the built artifact, and this is the only test that
    checks it by running the thing. The script is looked up next to `sys.executable` because that is where pip puts it
    for the interpreter running this suite — and on Windows the same entry becomes `mypki.exe`, so the name is chosen
    by `os.name` rather than assumed (STYLE §12). Asserting `is_file()` before running it is deliberate: a missing
    script should fail as "the install produced no console script", not as an OSError from `subprocess.run`.

    Both routes are asserted against the imported `__version__` rather than a literal, so a release bump cannot leave a
    stale expectation here (the same rule `tools/e2e_harness.py` and `tools/check_version.py` follow).
    """
    script_name = "mypki.exe" if os.name == "nt" else "mypki"
    script = Path(sys.executable).parent / script_name
    assert script.is_file(), f"the editable install produced no console script at {script}"

    completed = _spawn_cli([str(script), "--version"], tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"mypki {__version__}"


def test_a_named_rule_is_cited_by_name_and_not_quoted_again() -> None:
    """`ERROR_SURFACE_RULE` is the only spelling living code may use for the rule it names.

    The phrase this constant carries used to be retyped into five test docstrings, three template comments and two
    documents, so rewording `app.py`'s own sentence was a multi-file sweep — and a rename nobody reported, because
    nothing compared the copies. It is now one name with exactly two spellings in the whole source tree: the
    module-docstring heading it names, and this constant's own value. Both are pinned here, so they cannot drift.

    Read against `app.py` as data rather than against a rendered page, for the same reason the clipboard assertion above
    reads `static/app.js`: these are promises about source text that no route renders.
    """
    phrase = ERROR_SURFACE_RULE

    app_source = (BUILD_ROOT / "src" / "mypki" / "app.py").read_text(encoding="utf-8")
    assert app_source.count("ERROR_SURFACE_RULE = ") == 1, "the rule's name is spelled more than once in its own module"
    # Exact case on purpose: the two legal spellings are the docstring heading and this constant's value, and both are
    # the value itself. A third copy — a retyped quotation anywhere else in app.py — is what this counts away.
    assert app_source.count(phrase) == 2, (
        f"{phrase!r} may appear in app.py only as the module-docstring heading and as ERROR_SURFACE_RULE's value; "
        "a third copy is a quotation that will drift"
    )

    quoted = []
    for entry in ("src", "tests"):
        for path in sorted((BUILD_ROOT / entry).rglob("*")):
            if not path.is_file() or path.suffix not in {".py", ".html"}:
                continue
            if path.relative_to(BUILD_ROOT).as_posix() == "src/mypki/app.py":
                continue
            # Case-insensitive for the scan: a paraphrase in prose or a comment would be as stale as the exact heading.
            if phrase.lower() in path.read_text(encoding="utf-8").lower():
                quoted.append(path.relative_to(BUILD_ROOT).as_posix())
    assert quoted == [], f"living code quotes the phrase instead of naming {ERROR_SURFACE_RULE}: {quoted}"
