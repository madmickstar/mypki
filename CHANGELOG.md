# Changelog

All notable changes to mypki are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). For this project the three numbers mean something concrete,
because "breaking" has to be decidable by somebody reading a diff rather than argued in a release meeting:

- **MAJOR** — a change an operator has to re-learn or re-install for: a route's form fields, a certificate profile
  (`§7` of `docs/page-map.md`), the shape of a row in `issued.db`, or anything that makes an already-installed root CA
  untrustworthy.
- **MINOR** — backwards-compatible capability: a new page, a new `MYPKI_*` knob, a new CLI flag, a new profile field.
- **PATCH** — a fix that changes nothing an operator has to re-learn: a validation message, a header, a path bug, a
  dependency floor.

## Version numbers are release-time facts, not working-commit facts

Ordinary commits do not bump `__version__`. What advances per commit is git history; what advances per **release** is the
number, because a version that changes on every commit answers no question — it cannot be cited in a bug report, pinned in
a requirements file, or matched against a changelog section.

The number lives on exactly one line, `src/mypki/__init__.py::__version__`, and everything else is derived from it:
`pyproject.toml` declares `dynamic = ["version"]` (never a static version), hatchling reads that one line by static
analysis, the `## [X.Y.Z]` heading below records that the release happened, and the annotated tag `vX.Y.Z` is what makes
it reproducible. `tools/check_version.py` proves the chain agrees — exit 0 consistent, exit 1 drift, exit 2 *could not
check*, which is never a pass. A section below is written **when its release is cut**, not before: a heading for a version
that has not shipped is exactly what `check_version.py` reports as drift, because it reads to a user as a promise about a
release that does not exist.

## [0.7.4] - 2026-11-10

### Changed

- **The published CRL is `revoke.crl`, in every place a name appears.** `GET /crl.pem` became `GET /revoke.crl`,
  `<data>/crl/mypki.crl.pem` became `<data>/crl/revoke.crl` (`paths.crl_path`), the URL baked into new leaves'
  `CRLDistributionPoints` is `{crl_base_url}/revoke.crl` (`signing.leaf_extensions`), the download button on `/crl` and the
  `Content-Disposition` filename are both `revoke.crl` (`app.CRL_FILENAME`), and the curl/openssl recipe printed on `/crl`
  reads `-o revoke.crl`. The media type did not move: still `application/pkix-crl`, still `no-store`, still one fixed name
  nobody can configure — the point of the rename is that the file, the route, the advertised URL and the attachment are now
  **one spelling** instead of three (`mypki.crl.pem` on disk, `/crl.pem` in the certificate, `revoke` in the operator's head).
  Touched across `paths.py`, `app.py`, `signing.py`, `crl.py`, `config.py`, `inspect.py`, `templates/crl.html`,
  `docs/page-map.md` §14, `docs/REFERENCE.md`, README and `.env.example`, with the matching needles in
  `tests/test_crl.py`, `test_signing.py`, `test_consent.py`, `test_ocsp.py`, `test_no_key_leakage.py`,
  `test_csr_validate.py` and `tools/e2e_harness.py`.
- **A leaf issued in 0.7.0–0.7.3 advertises a URL this build does not serve.** Its CDP still reads
  `<crl_base_url>/crl.pem`, and this app no longer registers that route: a client that follows the pointer gets whatever
  answers that path on the host, which is nothing mypki produces. **There is no migration, no re-issue and no compatibility
  route**, deliberately — `signing.py` bakes extensions at signing time and mypki cannot edit a certificate that already left
  the building. This is the same posture `/crl` has always stated for certificates issued before 0.7.0 (they carry no pointer
  at all): the artifact is unchanged and still verifies, so those leaves can be checked by handing it to a client explicitly
  (`openssl crl -in revoke.crl -noout -CAfile mypki-root-ca.crt`, `openssl verify -crl_check -CRLfile revoke.crl`). What is
  new in 0.7.4 is that the gap has one more entry: **leaves issued in 0.7.0–0.7.3 now belong to the class of certificates whose
  stated pointer does not resolve against this build**. Stated here rather than on `/crl`: that page's four-item caveat list still
  names only the pre-0.7.0 gap, and rewriting it was outside this pass (its wording is asserted needle-for-needle in
  `tests/test_crl.py` and the harness's §11, so a change there is a three-file change). `/crl`'s lede — "certificates issued from
  0.7.4 onward carry that exact URL" — was corrected with the rename and is true of what this build signs. Certificates issued from
  0.7.4 onward carry `/revoke.crl` and resolve.
- **Country Code (C) on Generate-CSR is a dropdown** (`<select id="country" name="country">`) built by
  `validators.country_options()` from a new `validators.COUNTRY_NAMES` — ISO 3166-1 alpha-2, code order, `AU — Australia` on
  screen and `AU` in the value posted — handed to the page through `generate_context`. The constant lives beside
  `validate_country`, which already owns the rule, so the menu cannot offer what the validator would refuse; picking an option
  is not a shortcut past validation. A blank `— not set —` row comes first (an empty country is legal), and a prefilled value
  no listed code matches arrives as its own row rather than rendering as "Aland Islands". The `<select>` carries `name=`
  itself, unlike `/settings`' Issuing-limits dropdowns, because there is no text box behind it (page-map §2).
- **Three UI changes** (an operator brief; page-map §3, §5, §13):
  - `/csr/sign`'s `Paste a CSR (PEM)` label now carries `.paste-label`, defined in `static/style.css` as
    `color: var(--blue)`. It is a **class**, not an inline `style=` attribute: the app's CSP is `default-src 'self'` with no
    `'unsafe-inline'`, so a style written in markup would keep its weight and silently lose its colour.
  - `/issued` lost its lede. The sentence it carried (no detail page, no search, no delete; a record kept as evidence) is
    still true and is stated where an operator meets it — the column list in page-map §5, the hint under the table, and
    `docs/REFERENCE.md` "Known gaps".
  - `/issued`'s Status cell states its decision once: the stamp span now holds only `YYYY-MM-DD HH:MM:SSZ`, because the pill
    beside it already reads `revoked` on exactly those rows. The harness needle moved with it — `class="hint">YYYY-MM-DD`
    instead of `class="hint">revoked YYYY-MM-DD` — in `tools/e2e_harness.py`, `tests/test_bulk_revoke.py`,
    `tests/test_views.py`, page-map §5 and SMOKE_TESTING §10/§11.
  - `/inspect`'s "what this page cannot tell you" card moved **below** the paste box and took `/settings`' shape: a blue
    `<h2 class="section-heading">Paste PEM</h2>` outside a `<section class="card settings-section">`. The four sentences are
    unchanged word for word, so §15's one-per-sentence counts still hold; only their position moved.
- **Byte-exact needles that the label change broke were repaired rather than loosened**: `tests/test_views.py`'s refusal-order
  assertion and `tools/e2e_harness.py`'s offset comparison both now search for the label *with its class*, so the order
  assertion still proves "the refusal sits above the box it is about" against a page whose label markup changed.

### Fixed

Two findings from the first push to GitHub, both reproduced here before being fixed rather than inferred from a CI log.

- **`pip install -e ".[dev]"` could not resolve on Python 3.10, so four of the eight matrix legs died before running a
  test.** The cause is a floor that asks for a wheel no 3.10 interpreter can install: `httpx2` dropped 3.10 in its own
  2.15.0 release (`requires_python: >=3.11` on 2.15.0, 2.16.0 and everything since), and `dev` demanded `httpx2>=2.16`.
  Reproduced on CPython 3.10.22 — `error: No solution found when resolving dependencies: because the current Python
  version (3.10.22) does not satisfy Python>=3.11 and httpx2==2.16.0 depends on Python>=3.11`. Fixed by splitting the one
  requirement across the boundary (`>=2.16` on 3.11+, `>=2.14,<2.15` below it) instead of raising `requires-python`,
  because the project's stated floor is 3.10 and nothing in `src/` uses a 3.11-only feature. Every other dev dependency
  needed no such help: the resolver backs off on its own when a package declares support (it chose pre-commit 4.6.2 and
  coverage 7.16.2 on the same 3.10 venv while 4.7.0 and 7.17.3 were available) — only a *direct* floor above the supported
  range defeats that, and `httpx2` was the only direct requirement with one. Verified green end to end on 3.10.22:
  **831 passed**, 96.6% coverage, with starlette backing off to 1.7.0 as declared.
- **Two assertions were POSIX-only in disguise, and the first `windows-latest` run found both.** Neither is a defect in
  the product: 821 tests passed on Windows while exactly these two failed, and each failure was a test asking a question
  in one platform's spelling.
  *The console-script lookup.* `tests/test_packaging.py` built the script path as `Path(sys.executable).parent / "mypki.exe"`
  and asserted it existed. pip writes console scripts to `<prefix>\Scripts\`, while `sys.executable`'s parent is
  `<prefix>` — the directory holding `python.exe`. On Linux those two are the same directory (`<prefix>/bin`), which is why
  the assumption survived eight releases made before a Windows runner existed. The lookup now asks
  `sysconfig.get_path("scripts")` — the question actually meant, correct on both platforms and inside a venv — and keeps
  the old guess as a second candidate. The assembly is split into a pure `_console_script_paths()`, so
  `test_the_console_script_lookup_covers_the_windows_layout` reproduces a `C:/hostedtoolcache/windows/Python/3.13.17/x64`
  prefix on any host instead of leaving the claim to a runner.
  *The merged-log encoding.* `tools/fast_lane.py` prints an em dash, and a child whose stdout is redirected on Windows
  writes bytes in the host ANSI codepage, where `—` is `0x97`; the test then read the log back as UTF-8 and died with
  `UnicodeDecodeError: 'utf-8' codec can't decode byte 0x97 in position 70`. The assertion is about the ORDER lines arrive
  in, so the capture's encoding is now pinned (`PYTHONIOENCODING=utf-8` for that child) rather than inherited from whatever
  codepage the runner has. Pinned in the test and deliberately not in `fast_lane.py`: forcing UTF-8 on the product would
  make redirected logs machine-readable while garbling them on an interactive legacy-codepage console. Reproduced here
  without a Windows host by running the child under `cp1252` — the committed version fails at byte `0x97`, the patched one
  passes — and then the whole suite was run again with the ambient codepage forced to `cp1252`: **832 passed**, so no
  sibling of this bug is left hiding in the tests.
- **Every job printed a Node.js 20 deprecation warning.** `actions/checkout@v4` and `actions/setup-python@v5` declare
  `using: node20`, and GitHub now forces them onto Node 24 while saying so on each run. Not a failure — the legs still ran
  and still reported real results — which is precisely why it was worth clearing: a log whose known noise is skimmed past is
  a log where the next warning is also skimmed past. Bumped to `checkout@v5` and `setup-python@v6`, chosen as the first
  majors that stop asking for an overridden runtime rather than the newest ones: read from each tag's own `action.yml`,
  checkout v5/v6/v7 and setup-python v6/v7 all declare `node24`, and every input used here (`fetch-depth`,
  `python-version`, `cache`, `cache-dependency-path`) exists in v5/v6. The newer majors were left alone on purpose —
  checkout v7 refuses fork-PR checkouts under `pull_request_target`/`workflow_run` and setup-python v7 drops the
  `pip-install` input, neither of which this workflow uses, so adopting them would import changes with no demand behind
  them. Both require runner v2.327.1+, which GitHub-hosted runners already exceed; noted in the workflow for whoever adds
  a self-hosted runner later. Verified by parsing the file before and after: jobs, matrix, triggers, permissions,
  concurrency, conditionals and every `run:` line are identical, and only the eight `uses:` refs moved.
- **The Version chain job now names the refs it is about to judge.** A `drift: tag v0.7.4 is a lightweight tag` verdict has
  two causes that send an operator to opposite places — the repository really holds a plain ref (GitHub's Release form makes
  one when you type a new tag name), or the runner never received the tag object. The log offered no way to tell them apart.
  Settled by measurement rather than argument: a full fetch of `+refs/tags/*:refs/tags/*`, which is what this job's own
  `fetch-depth: 0` performs, preserves the object type — in a simulated runner tree `for-each-ref` answered `tag` and
  `--require-tag` exited 0. So a printed `commit` can only mean the remote is lightweight. The new step runs only on tag refs
  and prints `%(objecttype)` plus `%(*objectname)`, the peeled commit, which is the same distinction read from the other
  side. Verified by parsing the workflow before and after: every job, step count elsewhere, matrix, triggers, permissions
  and all existing `run:` lines identical; one step added to `version`.
- **`AGENTS.md` and `SMOKE_TESTING.md` shipped inside the release zip.** Omitting them from the sdist's `include` had been
  the recorded decision, and it was half of one: `make zip` stages its artifact from `git ls-files`, so any tracked path
  rides into the zip whatever `include` says. Both documents answer "how do I work **on** this repository", not "how do I
  run what I installed", so they moved to `docs/working/` and `.gitignore` now names that directory. Three places have to
  agree about the decision and `tests/test_packaging.py` asserts all three — absent from `include`, absent from
  `git ls-files`, matched by an ignore rule — because any two hold while the third does not. Nothing reads either file at
  runtime (checked by grep across `src/`, `tests/` and `tools/`: the surviving references are prose citations), so a fresh
  clone without `docs/working/` runs the suite unchanged; `tools/doc_citations.py`'s aliases follow the new path, and
  `docs/REFERENCE.md`'s three links to `../SMOKE_TESTING.md` became plain text, since a link that resolves on one machine
  404s on GitHub. README's generated tree block re-rendered at **76 paths** (from 78) by `make ready`.

### Testing

- **Counts re-measured on this tree, not inherited.** `pytest --collect-only` answers **831 tests**, and the same command run in a
  detached worktree checked out at `79012a1` also answers 831 — this pass moved needles and prose; it added no test and removed none.
  The suite without coverage answers **831 passed** (243.02 s on this tree before stamping; the closing gate re-measures it with coverage, and
  its numbers belong to that commit's message). The harness was run standalone (`make e2e`, exit 0, **4,847 ms** wall):
  **328 pass / 0 fail / 0 warn** over its 17 sections, and before any number was quoted the log was checked for exactly one
  `tools/e2e_harness.py` invocation and 17 section lines (AGENTS.md rule 3). The scoped fast lanes answer **247 passed** over
  `csr_generate or csr_sign or views or inspect or bulk_revoke or packaging`, **147 passed** over `crl or ocsp or consent or signing or
  leakage`, and `make docs` answers **71 passed** — the same 71 its two files answer at `79012a1`, re-measured in a detached worktree so
  the number quoted here is not an inherited one.
- **The gate that closes this release is quoted in the commit message, not here**, following the rule 0.7.3 recorded: an entry
  that quoted the tree it was written into would move the tree it names. What this section records is what was measured before
  the tree was declared final.
- **What remains unmeasured** is the rendering of all four UI changes — no browser exists on the host these edits were made on,
  so `.paste-label`, the moved `/inspect` card and the dropdown are asserted as markup (a class present in the served asset, a
  `<select>` posting its own value) and never as a page that looks right. SMOKE_TESTING §2 now records this build's stylesheet
  size (**33,002 bytes**, sha256 `f5397c04…`) next to the sizes earlier commits served.

## [0.7.3] - 2026-11-09

### Changed

- **README is an operator's page again, and the rest of it became `docs/REFERENCE.md`.** README now carries, in this
  order: the title with `assets/banner.png`, the CI and Ruff badges, one paragraph saying plainly that this is a small
  browser-based self-hosted PKI app for personal and lab use, not a security product, never for production; then Table of
  Contents, Features (one-liners, app capability only), Quick Start (a link to `docs/linux_install.md`), Configuration
  (carried over verbatim), *Where the files live* — promoted from an H3 under Configuration to its own H2, with the
  `<data>/` map plus a tree of every path the tracked-tree command reports at this commit (78 paths today; see "Added"
  below for the tool that generates it and the flags it uses) — License, and AI. The nine sections
  that were doing the explaining (`What it does`, `Two gotchas that will bite you`, `Serving and exposure`, `Logging`,
  `Divergences we state out loud`, `Known gaps`, `Development`, `Versions and releases`, `Naming`) moved to
  `docs/REFERENCE.md` essentially verbatim: the two gotchas, gotcha 2's four numbered caveats, the 0/1/2/3 exit-code
  table, the CRL's `nextUpdate = thisUpdate + 24 h` promise and OCSP's +4 h, the four restart-only knobs, and both
  measured dependency divergences (`itsdangerous>=2.2`, `httpx2>=2.16`) are all still stated there.
- **`docs/linux_install.md` and `deploy/mypki.service` are new.** The install guide records `mypki serve`'s flags as
  measured from `serve --help` (`--host/--port/--ssl-cert/--ssl-key/--data-dir/--passphrase-env/--log-level/--log-file/
  --no-console-log`), the data-dir precedence (`--data-dir` > `MYPKI_DATA_DIR` > OS default, XDG on Linux), the dotenv
  layering (`.env`, then `<config>/mypki.env`, with a real environment variable beating both), and the two logging facts
  a supervisor has to get right: `MYPKI_LOG_FILE` is relative to the working directory, and `log_to_console` defaults to
  true, so journald sees duplicated lines unless `--no-console-log` is passed. **This container reports
  `systemctl is-system-running` = `offline`, so the unit was written from those measured facts and never started.**
  `systemd-analyze verify deploy/mypki.service` was run: exit 1, one finding — `Command /srv/mypki/.venv/bin/mypki is
  not executable: No such file or directory`, which is the placeholder `ExecStart` path rather than a defect in the unit.
- **41 citations moved to the documents that now hold the claim.** Across `src/` (12), `tests/` (18),
  `docs/page-map.md` (3), `SMOKE_TESTING.md` (2) and `Makefile` (2), a citation is routed by what it supports: gotchas,
  exit codes, the 24 h promise, the restart knobs and the divergences now cite `docs/REFERENCE.md`; the CLI spelling an
  operator types cites `docs/linux_install.md`; two that support text which stayed in README (`cp .env.example .env`, and
  the Windows key-protection paragraph) cite README "Configuration" and README "Where the files live". CHANGELOG.md's own
  nine historical mentions of the README are left as written — they describe states of the tree at the time, and rewriting
  them would make the history wrong.
- **The banner generator is in the tree** as `tools/banner/make_banner.py`, so a banner is reproducible rather than an
  artifact with no recipe. MEASURED: running it with its shipped arguments (font 316, tracking 320, threshold 0.32, TILE 34)
  writes a file whose sha256 equals the banner this tree shipped up to and including commit `d205240` — 2890x578, 9860 B,
  `f9df99a4…4836cc` — byte for byte. It needed one edit to survive `make lint` — an unpacked `grid` became `_grid` (ruff
  RUF059), since `tools/` is linted. Note that Pillow is not in `.venv`: regeneration needs an interpreter that has it.
  As of the swap below this tool reproduces the **previous** banner, not the shipped one; see the next bullet.
- **`assets/banner.png` is now the brand variant.** The file README embeds was replaced byte-for-byte by
  `Style/banners/banner-brand.png` — the near-white-over-blue wordmark with the seal mark and the `SELF HOSTED ROOT CA`
  tagline, chosen from the `make_banner_pro.py` set as the one that reads as copy first and neon second. MEASURED: both
  files are 2890x578 (the same canvas README renders at), so nothing about the link or its layout changed; only the bytes
  did, 9860 B → 25568 B, sha256 `f9df99a4…4836cc` → `b94b12d3…3a0e0`. The superseded banner is kept out of the tree at
  `tmp/banner-legacy-cyan-f9df99a4.png` so the byte-identity claim above stays checkable. `tools/banner/make_banner.py`
  still writes the legacy design; `Style/banners/make_banner_pro.py --install brand` is what regenerates the shipped file.
  No test reads the banner's bytes — `tests/test_packaging.py` asserts only that `assets/banner.png` is in the sdist and
  exists on disk — so this is a visual change with no packaging change behind it.
- **README's Quick Start spells the install out.** It was one sentence pointing at `docs/linux_install.md`, which is the
  right page for a systemd unit and the wrong page for "I have a checkout and a Python". It now gives the venv commands
  (`python3 -m venv .venv`, activate, `pip install ".[dev]"` / `pip install .`), the three commands that follow
  (`init-ca`, `serve`, `info`), the fact that `init-ca` must run first because serving with no CA exits **3**, and
  `python -m mypki …` as the route that works where no console script was installed — then links to
  `docs/linux_install.md` for the Linux service install. Both routes it names are already asserted by
  `tests/test_packaging.py` (`test_python_dash_m_is_a_working_route_to_the_cli`,
  `test_the_console_script_route_reports_the_same_version`).
- **The key-protection paragraph moved to `docs/REFERENCE.md`, where it can be exact.** README's *Where the files live*
  carried "Key protection, honestly" — POSIX `0700`/`0600` plus a re-`stat`, and what `os.chmod` does **not** do on
  Windows. That is a promise whose wording has to be precise, and README is the one page written for a skimmer. The new
  section [Key protection and the data directory](docs/REFERENCE.md#key-protection-and-the-data-directory) holds it in
  full; README keeps the runtime file map and links to that section. `src/mypki/ca.py::_is_posix`'s docstring citation —
  one of the 41 re-routed in the 0.7.2 pass above, which had pointed at README "Where the files live" for exactly this
  paragraph — now points at REFERENCE's new heading instead.
- **`Makefile` says what each target does and nothing else.** Its comment blocks had accumulated a running record of past
  passes — measured durations, commit hashes, counts of commands spent — which is history belonging to this file, not to
  a build file. Every target, recipe and exit-code contract is unchanged; the prose around them is now one or two
  sentences naming the rule rather than the argument that produced it (`tests/test_fast_lane.py` still reads the pytest
  lines in this file and still fails if one restates `-q`).
- **`make zip` writes to `../dist/`.** The artifact landed next to the source tree, where a build directory holding its own
  releases can be mistaken for a release. `RELEASE_DIR := ../dist` names the destination once; `dist/` is where every
  zip and bundle this project has produced now lives.
- **`make clean` removes runtime scratch as well as caches**: `.gate-ready`, `nohup.out` and `.coverage`. Runtime litter
  that only a human remembering to delete is litter that reappears in the next tree.

### Packaging

- **`assets`, `docs/REFERENCE.md`, `docs/linux_install.md` and `deploy/mypki.service` joined the sdist `include`** —
  `pyproject.toml` and `tests/test_packaging.py`'s `REQUIRED_INCLUDES` in the same commit, because those two lists are
  asserted equal in both directions and a one-sided edit ships an artifact missing something its own documentation links
  to. The sharp case is the README itself: it embeds `![banner](assets/banner.png)`, so shipping the README without the
  image ships a broken link; `docs/linux_install.md` links to `../deploy/mypki.service` for the same reason. Two
  parametrised cases per new entry (`test_every_include_entry_exists_on_disk`,
  `test_no_include_entry_can_reach_anything_forbidden`) ride along automatically. `FORBIDDEN_PATTERNS` and
  `REQUIRED_EXCLUDES` are unchanged: a PNG, a `.service` unit and two `.md` files hit no forbidden pattern, and adding an
  entry to the exclude half without a reason would be the kind of change that quietly stops shipping something useful.
- **No packaging change in this release.** `include` and `exclude` are untouched: the swapped banner is the same path, the
  new README sections live in files already shipped, and nothing joined or left the artifact. That is stated rather than
  left to be inferred from an absence, because `tests/test_packaging.py` asserts `include == REQUIRED_INCLUDES` in both
  directions and a reader cannot tell an intentional no-change from an oversight.

### Added

- **`tools/tree_manifest.py` owns README's file list and its count.** One tool answers "which paths would a commit from
  this tree contain": `git ls-files --cached --exclude-standard --others`, **sorted by path**, because git does not sort
  them for us — MEASURED on this checkout, the command answered `AGENTS.md` and the two new tools first and only then
  `.env.example`, untracked half before tracked half, each half sorted internally (`LC_ALL=C sort -c` reports disorder at
  line 4). `--check` compares README's claim sentence and its fenced block with git — count, set **and order** — and exits
  0 consistent / 1 drift / 2 cannot check (no git binary, or this is not a repository), the same three-code contract as
  `tools/check_version.py`, for the same reason: a checker that answers "clean" because it read nothing is worse than no
  checker. `--write` regenerates the block from git; `--count`, `--fingerprint` and `--stamp` answer the smaller questions.
  The fingerprint is `<HEAD^{tree}> <content digest> <path count>`. HEAD's tree alone cannot see an edit that is not yet
  committed, and the worktree half is a sha256 over the **contents** of every listed path rather than
  `git status --porcelain`, because MEASURED here: appending a line to `docs/REFERENCE.md` — already listed as modified —
  left `git status --porcelain` byte-identical, same lines in the same order with that file named as modified in both,
  while this digest changed, since porcelain names *which* paths differ and never *how*. Re-measured warm on this tree:
  the digest over its 78 paths takes **12.0 ms** best of five, `tree_fingerprint()` plus one stamp write takes **17.8 ms**
  best of five, `--fingerprint` as a command line takes **104-106 ms** (five runs) and `--check` **105-129 ms** (four
  runs) — most of which is interpreter start-up, which is why the in-process figures are quoted separately.
- **`tools/doc_citations.py` enumerates every citation from code prose into a document**, so an edit that moves a heading
  can be planned from one file instead of from repeated grepping. MEASURED on this tree, three denominators, one scan:
  **429 references across 48 Python files** — the commit-shaped denominator; **425 across 46** for plain `git ls-files`,
  which cannot see what is not yet committed (measured in a detached worktree at HEAD, where nothing is untracked); and
  **420 references carried by 39 files**, inside the 42 `.py` files that exist under `src/` and `tests/` — three of those
  42 carry none. The last figure is what older notes quote as "420 across 42 files", which conflates files scanned with
  files found, and is corrected here rather than inherited. The spread is the denominator, not the pattern: one scan,
  three questions. Exit 0 enumerated / 2 cannot enumerate; unresolved references are findings and do not change the exit
  code. Re-measured warm: the enumeration runs in **2,921-3,000 ms**.
- **`make inventory`** writes both answers into `reports/inventory.txt` — tracked paths, the tree fingerprint, and every
  citation grouped by target document — because re-deriving those two facts one `grep` at a time cost **113 read-only
  commands out of a 203-command, 161.6-minute pass**. `reports/` is gitignored: committing an inventory would freeze a path
  count that is false in the next commit.
- **`make gate` now refuses before it measures**, and the refusal is exit 2 — the same shape `make test` uses when `K=` is
  empty: "you asked for something this tree cannot answer", not a failure of the tree. Without `.gate-ready` it prints one
  line and stops; with a stamp that no longer matches it prints `gate refused: the tree moved since 'make ready'` plus
  both lines, and stops. MEASURED on this tree, re-measured rather than inherited: unstamped `make gate` exits **2** after
  two lines of output and never starts `_gate-steps`; stamping with `tools/tree_manifest.py --write-stamp` and then
  appending one line to `docs/REFERENCE.md` — a file git already reported as modified — produced exit **2** reading
  `gate tree:` followed by `gate refused: the tree moved`, with no lint, mypy or pytest output anywhere after it (the whole
  log is five lines). The digest half changed while **the path count stayed at 78**, which is the case a count-only or
  status-only guard waves through: one line inside an already-dirty file is invisible to both. Removing the probe line
  restored the stamped fingerprint byte for byte. Timed again today, three runs each: the moved-stamp refusal exits 2 in
  **117-129 ms** against **16-17 ms** for the missing-stamp refusal (40 ms on the first, cold run). Both refuse before
  `_gate-steps` is requested, so neither pays for lint, mypy or pytest.
- **`.gate-ready` is gitignored, and that is load-bearing rather than tidy** — re-measured on 2026-11-08 with every file
  on disk untouched, by adding a `!/.gate-ready` negation to `.gitignore`, asking the tool, and deleting the line again:
  the listed count goes **78 -> 79** and the digest half changes (over 79 paths, then back over 78), because the stamp
  joins both halves. A gate that stamps its own tree
  would then invalidate its own stamp, and README's regenerated count would grow by one on every run: a guard that rejects
  itself. No fingerprint hex is quoted in `.gitignore`, `Makefile`, `AGENTS.md` or `tools/tree_manifest.py`, because a hex
  written in prose is false as soon as any other file inside the digest changes — the same staleness the generated README
  block exists to remove.
- **`make ready` is the boundary between editing and gating**: `tree_manifest --write` first, then `--write-stamp`, in that
  order, because a stamp taken before the regeneration names a tree that no longer exists by the time the gate reads it.
  The guard lives in `gate`'s recipe rather than in its prerequisite list because GNU make runs prerequisites before the
  recipe — MEASURED on this box, GNU Make 4.4.1: `all3: a | z` prints A, then Z-orderonly, then RECIPE-all3 — so the five
  steps moved to `_gate-steps` and `gate` calls them by one recursive make whose exit code propagates.
- **The guard was then exercised against two full gates, with a refusal forced between them, and it did what it claims.**
  Every number below is read out of the gate logs, not retyped. **Gate 1**: `make gate` exits **0** in **274,179 ms** wall
  (started 06:10:27, ended 06:15:01); its first line is `gate tree: <HEAD^{tree}> <worktree digest> 78`, then lint,
  types, the version chain, `830 passed in 264.70s (0:04:24)` at `TOTAL 3022 103 97%` / **96.59%**, and the harness at
  **328 pass / 0 fail / 0 warn** over its 17 sections. Then the tree moved — this section, `docs/REFERENCE.md` and the
  Makefile comment were edited — and `make gate` refused: exit **2**, five lines total (`gate tree:`, the refusal, both
  stamped/current lines), **zero** `_gate-steps` lines anywhere in the log, which is the whole point — nothing was
  measured. The two printed fingerprints differ in the digest half and agree in the count, **78 in both**, because every
  edit landed inside files git already listed as modified: a count-only guard would have waved this through.
  **Gate 2**, after `make ready` re-stamped: exit **0** in **268,673 ms** wall, first line naming a *different* digest
  over the same tree hash and the same 78 paths, `830 passed in 259.27s (0:04:19)`, `TOTAL 3022 103 97%` / **96.59%**,
  harness **328 pass / 0 fail / 0 warn** over 17 sections. In both green runs the post-run `tools/tree_manifest.py
  --fingerprint`, written to its own file and compared with `sed -n '1p'` of that run's log by plain `cmp`, matched byte
  for byte (exit 0 twice). So the guard **never fired on a gated tree** — it fired only on the one tree deliberately
  moved after stamping. **Gate 3** is the one this entry was written under: `make docs` (exit 0, 6,138 ms wall,
  70 passed in 4.27s), then `make ready` (exit 0, 220 ms), then `make gate` exit **0** in **302,546 ms** wall
  (10:18:25 -> 10:23:27) with the same `TOTAL 3022 103 97%` / 96.59%, `830 passed in 293.03s (0:04:53)` and harness
  **328 pass / 0 fail / 0 warn** over 17 sections, its first line again matching the post-run `--fingerprint` byte for
  byte. Five green gates ran on trees differing only in prose — **268,673 / 274,179 / 274,217 / 281,637 / 302,546 ms**, a
  12.6% spread with every one of them reporting 830 passed and 328 harness assertions — which is why gate duration is
  quoted here as a range and never as a ratio of two runs. The refusal between gate 1 and gate 2 cost 117 ms and bought the
  certainty that a gate measured the tree its first line names.
  The green gate that closed this change ran on the finished tree, after every word above was written; its exit code,
  wall, test count and fingerprint match are recorded in this commit's message rather than here, because an entry that
  quoted the tree it was written into would move the tree it names — the same self-rejection `.gate-ready` is gitignored
  to avoid.
- **`make docs` gained `$(TREE_MANIFEST) --check`**, so a change that touches only `.md` now proves three facts instead of
  two: the version chain, that README's shipped-tree claim and its fenced block equal the tree a commit would contain, and
  the two doc-aware test files. Re-measured rather than inherited: exit 0, **70 passed** in 3.49 s / 3.56 s / 3.61 s /
  3.63 s / 4.27 s across five runs (5,373 / 5,413 / 5,483 / 5,511 / 6,138 ms wall for the whole target). Five are quoted
  because the fifth exceeded the other four by 11-24%, which is this box's spread rather than a regression: quoting only
  the fast runs would be quoting a number the next run can beat.
  The "55 passed" this section and the Makefile comment used to claim was re-measured from git rather than inherited, and
  it holds: counted by AST over `git show v0.7.2:tests/test_packaging.py` and `v0.7.2:tests/test_version.py`, counting
  test functions times their `parametrize` argument lengths, and confirmed a second way with `pytest --collect-only` in a
  detached worktree checked out at the tag, those two files answer 26 + 29 = **55** at 0.7.2, **63** at HEAD d3d2c8b, and
  **70** with this change's working edits — fifteen cases out of date: eight from the sdist `include` additions
  (`REQUIRED_INCLUDES` grew 7 -> 11 entries, and two parametrised tests ride on every entry) and seven from the README
  assertions added here. That is exactly how a quoted count goes stale while the suite stays green, and why this entry,
  `docs/REFERENCE.md` and the Makefile comment read their numbers out of a log file rather than retyping them.

### Testing

- **README's shipped-tree claim is now asserted by `tests/test_packaging.py` against git, independently.** The new section
  re-asks git with its own copy of the flags and its own comparison instead of calling `tools/tree_manifest.py`: a test
  that grades a tool against itself cannot see the tool change its definition.
  `test_readmes_shipped_tree_claim_and_block_match_git` asserts count, set and order together;
  `test_the_readme_tree_claim_check_is_not_vacuous` carries **four mutation cases** — `count` (right list, wrong number:
  the 74-vs-75 disagreement of commit `a4dc4f3`), `missing-path` (one tracked path absent, count left correct, so only the
  set comparison can see it), `invented-path` (a path git does not track appears in the block) and `reordered` (every path
  present, order wrong — invisible to a count-only assertion).
  `test_the_readme_denominator_sees_a_file_plain_ls_files_does_not` builds a throwaway repository with one committed and
  one untracked file and proves the two denominators answer different questions there rather than relying on this tree's
  transient mid-change state. The claim sentence itself now names the three flags in full, because the shortened
  "`git ls-files`" was a small lie: it answers 75 paths on a tree where 78 are true.
- **`AGENTS.md` stays out of the sdist `include` and out of `REQUIRED_INCLUDES`, by decision, and that decision is
  asserted.** `test_working_rule_documents_are_deliberately_not_in_the_artifact` names it alongside `SMOKE_TESTING.md`:
  both are tracked, linted, gated and cited by code, and neither is shipped, because both answer "how do I work **on**
  this repository" — measured costs of one 2-CPU box, this container's shell constraints, how to run the harness — and
  `include` is asserted equal to `REQUIRED_INCLUDES` in both directions. Naming them turns the omission into a recorded
  decision instead of a one-sided edit waiting to be "fixed" by adding one line to one list. The asymmetry is recorded
  too: `docs/REFERENCE.md` *is* shipped and links to `../SMOKE_TESTING.md`, so an artifact reader can follow a link out of
  the artifact.
- **README's block is now a tree, and both halves learned to read it.** `tools/tree_manifest.py` gained `tree_lines()`
  (directories built from path components — git tracks files only — sorted per level, since a flat sort puts
  `src/mypki/static/app.js` before `src/mypki/store.py`) and `parse_tree_lines()`, which recovers depth from where a
  connector sits and each path's parents from a stack, returning lines it could not read instead of skipping them. The
  comparison is now against the **drawn shape**, so a swapped sibling or a file nested one level wrong is drift rather
  than taste. `tests/test_packaging.py` carries its own renderer and parser for the same reason as before: grading the
  tool against itself proves only that it agrees with itself.
- **The README mutation cases went four -> five.** `reordered` now swaps two sibling file lines (same set, wrong shape —
  invisible to a set comparison) and the new `prose-line` case drops a sentence into the fenced block, which must be
  reported as "cannot be read as a path" rather than guessed at or silently dropped. Counted by reading the parametrised
  tuple in this tree; the suite's own number is read out of the gate log below rather than retyped here.

## [0.7.2] - 2026-11-06

### Changed

- **A targeted pytest run now says what it ran.** `pyproject.toml`'s `addopts = "-q --strict-markers"` already asks for
  quiet, and both `make test` and `tools/fast_lane.py` asked again: two `-q` flags stack to `-qq`, which suppresses pytest's
  summary line entirely. MEASURED before the change, `make test K=csr_generate` printed dots and `[100%]` and nothing else;
  after it the same command answers `28 passed, 787 deselected in 19.60s`, and the fast lane prints
  `28 passed, 787 deselected in 18.98s`. The flag is now declared in exactly one place. This matters for the same reason the
  lane's exit-5 message exists: a run that cannot report a pass count makes "the pattern matched nothing" indistinguishable
  from "the tests passed", which is the failure mode `make fast` most needs to be able to name.
- **`make fast K=...` accepts both spellings, and rejects neither silently.** Bare keywords are ORed (`K="csr_generate ca_page"`
  → `-k "csr_generate or ca_page"`) because pytest accepts no space-separated list of names — MEASURED,
  `-k "csr_generate ca_page"` exits **4**. A written expression is now passed through as written
  (`K="csr_sign and not csr_generate"` reaches pytest unchanged), because make expands `$(K)` unquoted and the shell had been
  splitting its operators into ordinary words for `' or '` to join: `K="a or b"` became `-k "a or or or b"`, which pytest
  refuses with exit **4** *after* the lane has already paid for scoped ruff and the version chain. `tools/fast_lane.py`
  validates the expression itself instead — a leading binary operator, an operator at the end, or two binary operators side by
  side now exit **2** in 73ms with no step run at all (`bad -k expression: 'or' and 'or' are adjacent operators - pytest has
  nothing between them`). Exit 4 is also translated rather than flattened, alongside the existing exit 5: live probe
  `fast_lane.py csr_sign and not csr_generate` exits 1 reading `[NO TESTS RAN - the -k pattern matched nothing, so this proves
  nothing]`, which is the true report for a valid expression selecting nothing.
- **The lane stopped printing a false claim about its own checkout, and its report now reads in order.** Run *through* the
  venv — which is what `make fast` does, since `PY` resolves to `.venv/bin/python` — and `interpreter_note` printed
  `interpreter: …/.venv/bin/python — no .venv/bin/python in this checkout, so the invoking interpreter is used unchanged`
  while naming that very path as the interpreter. It branched on `interpreter == sys.executable`, which is exactly true when
  the venv python *is* the invoker; it now asks the same question `step_interpreter` asks (does this checkout's venv python
  exist) and prints `… — this checkout's .venv; invoked through … (the same interpreter)`. Separately, Python block-buffers
  stdout whenever it is not a terminal, so `fast_lane.py … > log 2>&1` put `FAILED ruff check` and the skipped-steps line
  *before* `[exit 1] ruff check (0.06s)` — a merged log read the conclusion before the step that caused it. Every printed line
  is flushed now, so a redirected run reads in the order things happened.
- **`make docs`: a cheap target for a change that touches only `.md`.** Until now the Makefile offered `make fast K=<expr>`
  or `make gate`, and `make fast` refuses to run without a `-k` pattern (exit 2, "no -k pattern given") — which a prose edit
  has nothing to put in. The only documented option left for a documentation change was therefore the full suite with coverage
  (`make gate`, four minutes plus on this 2-CPU box, where its duration moves run to run) for an edit that owes about five
  seconds. `make docs` runs the version chain plus `tests/test_packaging.py tests/test_version.py` with coverage off —
  MEASURED on this tree: exit 0, 55 passed, self-reported **3.29s and 3.97s across two runs** (4,971 ms and 5,694 ms wall). Both
  runs are quoted because one duration on this box is not reproducible enough to quote as a single number.
  Those two files are the whole of it because no test reads doc **content**: an AST scan of `tests/*.py` for `read_text`,
  `read_bytes` and `open` calls touching a `.md` path returns **zero** files, the stronger form of the `grep -rn "read_text()"`
  check that only matched one spelling. What survives is two references to doc *paths* — `test_packaging.py`'s
  `REQUIRED_INCLUDES` asserts `README.md`, `CHANGELOG.md` and `docs/page-map.md` are in the sdist and exist on disk, and
  `test_version.py` asserts the CHANGELOG carries this version. Prose itself has been unpolicied here since `bc0031b` deleted
  `tools/check_docs.py`, `tools/check_docstrings.py` and `tests/test_docstrings.py`.
  Coverage is off because it cannot be on: `.venv/bin/python -m pytest --cov=mypki tests/test_packaging.py tests/test_version.py`
  prints `55 passed` and then exits **1** on `TOTAL 3022 1736 43%`, because `fail_under = 85` applies to any `--cov` run
  whatever subset executed. A docs-only commit still owes `make gate` once; `make docs` proves those two facts, not that the
  suite is green. Verified by breaking the tree rather than by reasoning about it: with `README.md` moved out of the checkout,
  the full suite fails **3** tests and this subset fails the same 3 in 4.10s instead of 247s —
  `test_every_include_entry_exists_on_disk[README.md]`, `test_no_include_entry_can_reach_anything_forbidden[README.md]` and
  `test_no_key_material_exists_anywhere_the_include_entries_walk`, all from `covered_paths()` raising at
  `tests/test_packaging.py:136` rather than returning an empty list.
- **`tools/fast_lane.py` now stops at the first failing step.** It did not before, and that is how a 0.06s lint failure came to
  be followed by a 24.84s test run: with an over-long comment injected into `src/mypki/app.py`, the lane reported
  `[exit 1] ruff check (0.06s)` and then ran `pytest -k csr_generate or ca_page` anyway, finishing at **25.06s** to report a
  failure that had been known in 60 ms. The same probe after the fix exits 1 with `fast lane total: 0.06s` (**133 ms wall**),
  and pytest is never attempted. `make gate` has always short-circuited (lint -> types -> version -> cov -> e2e; the same
  injected break ends it in 85 ms with pytest never started), so this was one lane of one gate set disagreeing with the other.
  The steps a stopped run did not reach are now printed as skipped — `stopped at the first failing step: 3 later step(s) never
  ran (ruff format --check, version chain, pytest -k csr_generate or ca_page) - unproven, not passed` — because "the lint
  broke" and "no test of this edit ever ran" are different facts, and a report that omits the second leaves a reader to notice
  its absence. Exit codes are unchanged: 0 all steps passed, 1 a step failed, 2 usage error.
  Pinned by **6** new tests in `tests/test_fast_lane.py`, which previously pinned no short-circuit behaviour at all. They
  monkeypatch `fast_lane.run` into a recorder so the assertion is over *which commands were attempted* rather than over timing,
  and nothing nests pytest inside pytest. That pinning was checked against the code it replaces: new tests against HEAD's
  `fast_lane.py` fail **3** (`test_a_failing_lint_step_stops_the_lane_before_pytest_is_attempted`,
  `test_the_steps_that_never_ran_are_named_as_unproven_rather_than_left_out`,
  `test_a_failing_version_chain_stops_pytest_from_running`) and pass against the fixed one, 22 passed in 0.14s.
  `.github/workflows/ci.yml` is deliberately untouched in this commit: its matrix (2 OS × 4 Python = 8 legs, each
  `python -m pytest --cov=mypki --cov-report=xml`) still runs on docs-only pushes. Path-filtering it was considered and held
  back — a naive `paths-ignore` would skip exactly the `REQUIRED_INCLUDES` assertions above, and no runner here can measure what
  a filtered matrix would actually cost or prove.

- **GUI pass on `/csr/generate` and `/ca`, to the operator's brief.** `/csr/generate` is retitled *Generate CSR and Private
  Key* with "Key is only shown once, it is not stored." under it; its Subject and Key sections are now a blue
  `.section-heading` outside a `.card.settings-section` — `/settings`' styling, the `<fieldset>`/`<legend>` pair it had carried
  since 0.1.0 removed — and its fields carry the X.501 names an operator sees in a certificate viewer (`Common Name (CN)`,
  `Subject Alternative Names (SAN)`, `Organisation (O)`, `Organisation Unit (OU)`, `Country Code (C)`, `State (S)`,
  `Location (L)`, `Email (E)`) with the hint lines the brief dictated. The internal field names, and therefore every validation
  reason, are unchanged: a refusal still reads `country must be exactly two letters`, beside a box labelled `Country Code (C)`.
  On a successful submit three capsule controls sit at the top of the page — `Download CSR and Private Key`,
  `Copy CSR to clipboard`, `Copy Private Key to clipboard` — styled like `/issued`'s green status chips. The two PEM blocks stay
  on the page: they are what `test_csr_generate.py` and the harness read to prove the downloads serve the bytes that were shown,
  and a `<pre>` is the flow that works when a browser refuses clipboard access.
- **A third one-shot artifact: request + key in one file.** `POST /csr/generate` now also holds
  `<stem>-csr-and-key.pem` in process memory (request block first, then key), which is what the new top-of-page download serves.
  **MEASURED with openssl on this box before shipping it:** such a file is read by `openssl req -in` and by `openssl pkey -in`,
  while `openssl x509 -in` refuses it — so the order is pinned by a test rather than assumed, alongside "exactly two blocks" and
  "this generation's key matches this generation's request". Nothing is written to disk: it is a third `store.put` of two strings
  already in memory, and the data-dir tree hash still comes out unchanged.
- **`/ca` renders no certificate bytes.** The page is titled *Root CA Certificate* with no lede under it; its facts card is
  titled with this root's own Common Name in blue, outside the card, and Install instructions moved outside its card the same way.
  `download root-CA cert` and `copy to clipboard` sit at the top of the page, and `The certificate (PEM)` block was deleted — with
  the controls at the top, one page was offering the same root three times. `app.ca_page` passes no extra context any more.
  The copy button fetches `/ca/certificate` (`app.js`'s new `wireCopyUrl`) rather than copying text off the page, and says so when
  a browser refuses, because there is nothing on screen to select.
- **The Key hint is now one derived number, and one context value is gone.** The brief replaced this page's passphrase paragraph with
  "Minimum 8 characters"; that sentence is rendered as `Minimum {{ passphrase_min }} characters`, so the shipped text is byte-identical to
  the brief while the floor still comes from `csr.PASSPHRASE_MIN_LENGTH` — a literal `8` in the template would be a second copy of that constant.
  `generate_context` therefore keeps `passphrase_min` and **drops `passphrase_recommended`**: no part of this page states a recommendation any
  more, and the 12-or-more advice is still said where it always was — by `csr.passphrase_advisory`, on the re-render after an 8–11 passphrase,
  pinned by `test_csr_generate.py::test_a_passphrase_at_the_floor_is_accepted_and_advised`. A context value no template reads is one a refactor
  can put back on the page without anyone deciding to.
- **Harness counts moved 310 → 328** (`.venv/bin/python tools/e2e_harness.py`, `reports/harness-ledger.json`): §2 20 → 27,
  §5 11 → 19, §9 20 → 23. §9's parity assertion inverted — it used to hash the DER inside `id="pem-ca"` against the download's DER;
  it now reads the served certificate's serial and colon-grouped SHA-256 fingerprint out of its own DER and requires both on the
  page, which asks a parser instead of comparing two copies of one string. `GET /static/style.css` re-measured on this build:
  **31,766 B**, sha256 `8b4d507fb6660b…`, served byte-identical to the file.

- **The measurement-history layer was deleted, together with the two gates that policed it.** Removed:
  `docs/measurement-history.md`, `docs/history/` (nine files), `docs/CHANGE_POLICY.md`, `tools/check_docs.py`,
  `tools/check_docstrings.py`, `tests/test_docstrings.py`, and the *Release evidence* subsection of `[0.7.1]` — about
  3,050 lines in total. Those documents existed only to record past measurements and to stop anyone editing them; they
  were also what made a documentation change cost tens of minutes, because every number had to be re-derived and every
  gate re-run to prove a sentence was still true. The history entries above are kept as written; links that pointed at
  deleted files are now plain text rather than dead links.
- **`Makefile` is the single source of truth for commands**, and CI calls it (`make lint`, `make types`, `make version`).
  Previously the commands lived only as prose in README, so each pass re-derived them from memory and
  `--cov-fail-under=85` was retyped by hand on every invocation. The floor now lives once in `[tool.coverage.report]`.
- **The repository is a git repository.** A baseline commit precedes every deletion in this entry, so all of it is
  recoverable; `nohup.out` is now ignored rather than tracked. One test in `tests/test_version.py` had hard-coded "this
  directory has no `.git`" and began reporting drift the moment it did — it now builds its own throwaway tree and, for
  the tag case, its own throwaway repository, so it asserts the behaviour rather than the accident of this checkout.
- **`tools/fast_lane.py` no longer runs a docs gate that does not exist.** `DOC_TOOLS` is now the version chain alone,
  and `tests/test_fast_lane.py` pins it by name while asserting every named tool is actually present on disk.
- **One harness instead of two, and `make gate` runs it.** Deleted: `scripts/smoke_test.sh`, `scripts/smoke_test.ps1`,
  `tools/harness_parity.py` (compared the two logs heading for heading) and `tools/harness_ledger.py` (re-parsed a log to
  recover counts the harness had already printed, and wrote `reports/harness-ledger.md`). `tools/e2e_harness.py` is now the
  only end-to-end harness: it mints its own throwaway CA, spawns `mypki serve` on an ephemeral port, walks SMOKE_TESTING §1–§16
  over one socket, and writes its own counts to `reports/harness-ledger.json` — no log-parsing step in between. `gate` gained
  `e2e` as its last step and lost the echo that used to announce the harness was *not* wired in; `tools/fast_lane.py`
  `COMMIT_ONLY_STEPS` names `tools/e2e_harness.py` where it used to name the two scripts. Nothing under `reports/` is tracked,
  so a run's totals cannot be mistaken for a property of the release.
- **Four harness assertions were measuring the wrong thing, and all four now measure what they claimed to.** Each was
  green against a correct app while asserting something else — the class of defect this project keeps measuring:
  §6 counted `href="` characters instead of following the two download links and reading their labels and
  `Content-Disposition`, so misnamed or swapped downloads passed; §7 posted the DER case in the shape `_form_fields()`
  stringifies an uploaded part, which answered a reason the app never gave for that input; §12 pinned a client-profile
  sentence ending in a period that `signing.py` does not render, reading 0 against a correct page; and §11 searched for
  three serials that were never published on the page it read, replacing hex needles with per-serial listings taken from
  the parsed CRL. Five further raw-byte probes were retired because a DER parser answers the same question more strongly,
  which is also what removed the offset-scoping hack (`8000`/`8200` appearing inside an RSA signature 11 times in 300 signed
  REVOKED answers, 0 times once the search was cut at the signature's AlgorithmIdentifier). §11 STEP F now runs `openssl`
  — six assertions, WARNing when the binary is absent — including `verify -crl_check` with no `different CRL scope`, which
  re-derives `crl.py`'s decision to omit an IssuingDistributionPoint instead of quoting a measurement for it.
- **A fifth stale measurement, found in prose rather than in an assertion.** SMOKE_TESTING §2 claimed `GET /static/style.css`
  serves **28,152 B** on this build and is byte-identical to the shipped 0.7.0 asset. Measured here it answers 200 with
  **28,827 bytes** (sha256 `3d7a609…`, and the same 28,827 at every commit in this tree), while the extracted 0.7.0 zip holds
  28,152 B (`d4b7468…`): the "re-measured on this build" line had itself been carried over from 0.7.0. No assertion reads a
  stylesheet size, so nothing was catching it — the corrected text states both numbers and names which release each belongs to.
- **The scratch litter SMOKE_TESTING measured is gone, and its bullet now says when it was true.** The two deleted shell harnesses left **43** trees
  in `/tmp` on this box — **5** `/tmp/mypki-smoke*` (**1.3M**, 3 holding a private-key block) and **38** `/tmp/pkismoke*` (**33M**, all 38 holding
  a `ca_key.pem`) — **34M** together, holding **207** key-material files tallied as they were removed, **38** of them real CA private keys (one per
  `/tmp/pkismoke*` tree): the harm that sentence existed to warn about. The 207 is a deletion-time tally and cannot be re-derived now the trees are
  gone, so only the directory, size and `ca_key.pem` figures remain checkable. The bullet said this litter "is still sitting here"; it does not, so
  those counts are labelled as a 2026-11-05 measurement and today's state is stated instead. **63** `ca_key.pem` files survive elsewhere in `/tmp`
  (62 mode `0600`, 1 mode `0644`) inside probe trees that predate this pass — `/tmp/h060`, `/tmp/v060`, `/tmp/pkid-071`, `/tmp/doccheck*`,
  `/tmp/sprobe` — plus **87** `/tmp/tmp????????` directories left by `tempfile.mkdtemp` callers that never removed their tree. Those were
  deliberately not touched: SMOKE_TESTING cites three of them, and a measurement you can still re-run is worth more than a clean `/tmp`. Two claims
  drafted for this edit failed when measured rather than assumed, and both are recorded here so they do not come back. "79 key-shaped files under
  `/tmp/pytest-of-user`" was an artefact of `-maxdepth 4`: pytest nests `<basetemp>/<test>/data/ca/ca_key.pem`, below that cut, and the same find
  at full depth returns over 1,700 — a figure that moves with every run, because `make gate` rotates pytest's basetemps. SMOKE_TESTING therefore
  records the mode (`0700`) and the mechanism rather than a count, which is also why no citable number belongs here. And the mode-`000` files are
  not "pytest's unreadable-key cases" in general but one test's fixtures: `test_serve_rejects_a_tls_file_that_exists_but_is_not_readable` in
  `tests/test_cli.py` writes a fake TLS key and `chmod`s it to `000`, because no other portable route makes a file unreadable to its own owner.
  Nothing in `tests/` or `tools/e2e_harness.py` reads SMOKE_TESTING.md at runtime (the harness's only `read_text` calls are its own work-dir
  fixtures, `__init__.py` and the two server logs), so no assertion could have caught any of this — which is the same reason the style.css number
  above went unnoticed.

## [0.7.1] - 2026-11-05

Entries land under `## [Unreleased]` while work is in flight and move under a version heading when that release is cut; this
section was written when 0.7.1 was cut, and what it records is one change on the sign page: **a refused paste is now answered where the operator is standing**. A step-A paste this CA will not
sign used to render `templates/error.html` — a page with no form on it — and the operator had to click back and re-paste. It
now re-renders `/csr/sign` itself, the reason named in red directly above "Paste a CSR (PEM)" with the paste still in the
textarea, while the status stays 400 (malformed) or 403 (privilege claim). **A PATCH by this file's own definition** — "a fix that changes nothing an operator has to re-learn": no route changed its
address or form fields, no `MYPKI_*` knob was added, no certificate profile in `docs/page-map.md` §7 moved, and no row of
`issued.db` changed shape. The MINOR test ("a new page, a new `MYPKI_*` knob, a new CLI flag, a new profile field") is met by
none of its four terms, which is why the number moves in the last place rather than the middle one. `__version__` is now 0.7.1,
and this heading is what makes that legal: the rule is that the number and the section are written **in the same pass**, so
`tools/check_version.py` reads a release rather than drift. Its measured evidence landed in one further pass, at the cut: a
*Release evidence* subsection closed this section, recording the gates, the suite and the packaging checks this release was made
against, with the two harness runs held in _docs/measurement-history.md_ under *0.7.1 release evidence* and their counts in
`reports/harness-ledger.md`. **All three were removed by the pass recorded under [Unreleased].** Nothing here asks you to open a
file that no longer exists: read the subsection with `git show bc0031b^:CHANGELOG.md`, the dated records with
`git show bc0031b^:docs/measurement-history.md`, and note that `reports/harness-ledger.md` was never tracked in git at all — the
harness writes `reports/harness-ledger.json` itself now, which is why its counts are not lost, only its prose.

### Added

- **`app.py::_paste_refused`, the handler that keeps a refusal on its own page.** `csr_sign_submit` now catches its step-A
  rejections (`CsrValidationError`, `KeyPolicyError`, `CaPrivilegeRequestedError`) and calls `_paste_refused`, which re-renders
  `templates/csr_sign.html` with `<section class="form-errors refused">` **above**
  `<label for="csr_pem">Paste a CSR (PEM)</label>`. Asserted as an ORDER in both harnesses and in
  `tests/test_views.py::test_a_refused_paste_is_named_on_the_sign_page_above_the_box_it_belongs_to`: "the reason appears
  somewhere in the body" is also true of a page that mentions it only in a nav link, so the block's line/offset has to precede
  the label's. The handler names its own status mapping rather than inheriting one — **400** for `CsrValidationError`, **400**
  for `KeyPolicyError`, **403** for `CaPrivilegeRequestedError` — identical to what `_register_error_handlers` chose, so a curl
  or PowerShell script still reads "bad input" and "refused" as two different answers. Status is decided by *what was wrong*;
  the surface by *where the fix can be typed*. The `log.info` lines are unchanged (`rejected input at …`,
  `refused CA privilege at …`) — they are what the harnesses and an operator's log reader already depend on — and the reason
  keeps its `<p class="reason">` class, so "read mypki's stated reason" remains one selector whichever surface rendered it.
- **Four `sign_context` keys carry it** (`refused_reason`, `refused_hint`, `paste_value`, `paste_redacted`). All four are inert
  on every ordinary render of the sign page (`None`, `None`, `""`, `0`) and are filled only by `_paste_refused`. They live in
  `sign_context` rather than being spelled in the template for the same reason `consent_field` does (page-map §3 rule 6): a
  name invented in a template is a name the handler that reads it cannot see.
- **The paste survives, and the filtering of it is said out loud.** `csr_pem` returns through
  `inspect.redact_private_key_bodies` — armour lines kept, a private key's base64 replaced with the marker — and
  `paste_redacted` renders as a count when anything was filtered: *N private-key block(s) in your paste were **not** echoed
  back*. Filtering what somebody pasted with nothing on screen saying so is the quiet edit this project refuses elsewhere (see
  `settingsfile.preserve_unmanaged`), so the count is rendered rather than left implicit.
- **`.form-errors.refused` in `--rose`** (`static/style.css`, three rules — the block, its `<h2>` and its `.reason`): the box
  shape of the existing amber `.form-errors`, recoloured, because *nothing was written — fix this and submit again* and *this
  request was refused* are different answers that happen to need the same layout. `--rose` is the colour this app already uses
  for a refusal on `/inspect`; no new variable was introduced.
- **Five link labels now read *Sign a certificate***, matching the sign page's own `<h1>`: `templates/error.html`,
  `templates/about.html` (its `<dt>` and its `<dd>`), `templates/issued.html`, `templates/csr_generate.html` and
  `templates/inspect.html`. The sidebar item in `templates/base.html` deliberately stays **Sign CSR** — it is the short nav
  label, not the page title — and `tests/test_nav.py` is deliberately unchanged because that file asserts the sidebar wording.
- **`tools/check_docstrings.py`, the gate that keeps release-time prose out of `src/`.** Three rules, each with an id a line
  can name in a `# allow-docstring-rule: <id>` marker: `version-citation` (a `0.x.y` token or `pre-0.x.y` phrasing),
  `one-run-probe` (`MEASURED`, or a scratch probe path under `/tmp/`) and `release-plan-tag` (`answer N`, or a parenthesised
  version). It reads docstring lines and full-line comments only — decided from the AST, so a version inside a string literal
  is behaviour rather than prose and stays unpoliced — and it covers `src/` alone, because a test named for a release it
  reproduces and a checker's note about a pinned dependency are both facts that have to be written down somewhere. Stdlib-only
  like `tools/check_version.py`, so the CI docs job can run it against a checkout with nothing installed. Exit codes: **0**
  clean, **1** findings or a failed self-test, **2** usage error.

### Changed

- **What still reaches `error.html`, stated where it can be misread.** An oversized body (`SizeGuardMiddleware` refuses it
  before any route runs, so there is no form to put a reason on), a missing or bad CSRF token, `/inspect` (which describes
  rather than signs) and a bad address all keep mypki's error page at 400/403/413. The exception handlers for
  `CsrValidationError` and `CaPrivilegeRequestedError` stay registered — they are the net for those errors raised on a route
  with no form of their own to re-render, same status and same sentence.
- **README's route table and page-map §0/§3 were rewritten in the same pass as the behaviour**, not after it: §0 gained a rule
  row for the refused paste (reason on the sign page, status unmoved, only a refusal with *no form to put it on* renders
  `error.html`), §0's error-page paragraph now says where this build reaches that page, §3's rule-6 bullet names the body that
  carries a 403 as "the sign page with its own form still on it", and §3's panel sentence states that refused extensions are
  answered at 403 **on this same page**.
- **Release-time prose was moved out of `src/` docstrings rather than deleted**, and the move is recorded verbatim in
  _docs/history/narrative.md_ (since deleted; read it with `git show bc0031b^:docs/history/narrative.md`): the version citations
  and one-run probe notes that were *not* already carried by a frozen history entry are copied there byte for byte, each with the
  docstring it belonged to, before the living sentence was rewritten to state the invariant instead. The rewrite touched only
  docstrings and full-line comments — no
  behaviour, no status code and no user-visible string moved, so this is the *Wording* class and neither harness script changed.
  `app.py`'s module-docstring heading keeps its name and drops the version tag beside it, which is what lets
  `ERROR_SURFACE_RULE` keep citing that heading while `tests/test_packaging.py` still counts exactly two spellings of it in the
  module. The quoted phrase appears in no other Python or HTML file under `src/` or `tests/`, as that test already asserted.
- **The new prose gate is wired into every place a gate lives, and `tools/harness_parity.py` deliberately is not.**
  `docs/CHANGE_POLICY.md`'s gate list, README's *Development* block, the CI docs job and two new local hooks in
  `.pre-commit-config.yaml` all run `tools/check_docstrings.py` and its `--self-test`. `tools/harness_parity.py` is documented in
  both places as a **release-time comparison rather than a commit hook**, because it needs exactly one harness log from each
  implementation and exits **2** — never a pass in this project — when fewer than two usable logs are given: a commit supplies
  neither, and making a commit produce them would put two full harness runs in front of every commit to answer a question that
  only has an answer once both harnesses have been driven against the same build. `ci.yml` carries that reasoning as a comment
  instead of a job, since a job that cannot supply its own inputs can only assert that it refused to run.
- **`tools/fast_lane.py` gained the prose gate in its commit-only list and *not* in its doc pair.** The lane stays scoped ruff,
  `tools/check_version.py`, `tools/check_docs.py` and a targeted `pytest -k`; `tools/check_docstrings.py` joins `mypy src` and
  coverage measurement as what a commit owes. That is an explicit decision, recorded both ways: the alternative — adding it to
  `DOC_TOOLS` — would have made every edit pay for a read of every module under `src/`, including an edit confined to one
  template, and it would have required editing `tests/test_fast_lane.py`, which pins that pair in three separate assertions.
  `tests/test_docstrings.py` now asserts the decision as data: present in `COMMIT_ONLY_STEPS`, absent from `DOC_TOOLS`, and
  absent from anything `build_steps` can emit.

### Testing

- **Four new tests.** `tests/test_views.py` gained the order assertion above
  (`test_a_refused_paste_is_named_on_the_sign_page_above_the_box_it_belongs_to`), plus
  `test_a_ca_privileged_paste_is_refused_on_the_sign_page_at_403` (the privilege claim keeps its 403 *and* its form) and
  `test_an_inline_refusal_is_still_the_sign_page_with_its_nav_and_headers` (a refusal that re-renders the sign page must still
  carry the nav and the four security headers — a bespoke error body would pass the first two tests and fail this one).
  `tests/test_no_key_leakage.py` gained `test_a_refused_paste_that_is_echoed_back_carries_no_key_body`: the echoed paste keeps
  its armour lines, carries none of the key's base64 in PEM or decoded form, and names the filtered count.
- **Collection moved 782 → 786 tests** with zero skips (`test_views.py` 84 → 87, `test_no_key_leakage.py` 17 → 18), and then
  **786 → 790** when the frozen record landed: `docs/history` and `docs/measurement-history.md` were added to the sdist's
  `include` list and to `REQUIRED_INCLUDES` in the same commit, and `tests/test_packaging.py` parametrizes two assertions over
  that list (`test_every_include_entry_exists_on_disk`, `test_no_include_entry_can_reach_anything_forbidden`), so each new entry
  contributes exactly one test to each. **The +4 is intended growth, not drift** — it is the mechanism doing its job: an include
  entry earns its own on-disk existence check and its own "cannot reach a forbidden path" check. The list is also asserted as a
  set in both directions, so the growth is what makes a one-sided edit (config changed, test list not) fail rather than pass.
  `tests/test_packaging.py` went 25 → 29 on that change and is the only file affected; every other module's collected count is
  unchanged from the 786 run.
  Coverage TOTAL moved 3008 → **3025 statements / 103 missed = 96.60%** (the 0.7.0 release was cut against 3008 / 97 = 96.78%).
  The +17 statements and the +6 missed lines are **all in `app.py` (834/49 → 851/55)** — every other module's row is unchanged,
  MEASURED by re-running the frozen 0.7.0 tree under this venv (`/tmp/extract-070/mypki-0.7.0`: TOTAL 3008 / 97) and diffing the
  two `Missing` lists line by line rather than inferring them. The six new uncovered lines are: `on_csr_validation`'s body (its
  `log.info` and its `return _render_error`) and `on_ca_privilege`'s body, both now **bypassed** for a sign-page paste because
  `csr_sign_submit` catches those two errors itself — the handlers stay registered and still answer them on any route without a form
  of its own; and `_paste_refused`'s `else:` arm, the `KeyPolicyError` branch. **That last gap is deliberate and it is not new**:
  0.7.0's `Missing` column already listed `on_key_policy`'s body. No test pastes a weak key because generating a sub-2048-bit
  RSA key costs real entropy in a suite that is otherwise fixture-driven; both harnesses cover the same route live. The gap is
  recorded here rather than left for the next reader to find it in the `Missing` column.
- **The harness total moved against 0.7.0's ledger, MEASURED rather than predicted** (an earlier draft of this bullet named a
  number and was wrong by one: §1 gained an assertion too). Both harnesses exited 0 on 2026-11-03, each against its own freshly
  minted data dir (`/tmp/pkismoke-071sh` for the `.sh`, `/tmp/pkismoke-071ps1` for the `.ps1` under `/tmp/pwsh/pwsh` 7.6.9), and
  their ledgers agree section by section; the totals, per-section counts and heading positions lived in
  `reports/harness-ledger.md` (since deleted), which is what `tools/check_docs.py` sent a reader to rather than a
  copy of it here — no count from either harness is quoted in this file. What the new assertions check: the
  `.form-errors.refused` block being present, its refusal paragraph preceding *Paste a CSR (PEM)* in document order (the same
  ORDER fact the `.sh` checks by line and the `.ps1` by string offset), the rejected paste being echoed back into its own
  textarea, and no confirmation panel having been rendered (`This is what the request says` appearing zero times — the half that
  proves nothing was staged); plus the sign page's *"CSR requesting CA powers will be refused."* sentence, where a
  renamed-heading assertion replaced a needle rather than adding one. A **control run** of the extracted shipped zip reproduced
  0.7.0's own ledger the same day, so the movement is a measured delta between two trees and not an arithmetic expectation. The
  dated records of those runs, and of the pair this release was actually cut against on 2026-11-05, were held in
  _docs/measurement-history.md_ under *0.7.1 release evidence* (since deleted; `git show bc0031b^:docs/measurement-history.md`).
- **`tests/test_docstrings.py` (new) pins the prose gate from the test side.** It asserts zero findings over the real `src/`, a
  passing `--self-test`, that a line breaking all three rules is reported three times rather than collapsed, that the allow
  marker excuses its own line and only that line, that exit **1** and exit **0** stay distinguishable end-to-end through `main`,
  that the checker imports nothing from `mypki` and stays within the standard library (the same shape as
  `tests/test_version.py`'s stdlib-only check), and that the reading half of the checker writes nothing — verified both by
  grepping that half and by running the gate against this tree and comparing every file byte for byte. Its needle assertions
  hold fourteen phrases that tests, documents or both harness scripts quote out of `src/` docstrings: each has to still exist,
  in its own module, and still be *docstring* text rather than a literal that happens to repeat it. That half is what stops a
  gate from cleaning a tree by deleting the sentence a test quotes.
- **Coverage denominators are reconciled rather than guessed.** Read straight from `coverage.parser` with no exclusion pattern
  at all, `src/` holds more statements than the report's TOTAL column; the difference is entirely `# pragma: no cover`, and the
  count of those markers in `src/` is small enough to list by hand. One occurrence is prose explaining why the marker is honest
  in `__main__.py` rather than a dodge — that file only runs when it *is* the process, and coverage traces the parent instead.
  The numbers for this build are read from the gate output rather than copied into this file.

### Changed (wording, resolved in this pass)

- **`app.py`'s module-docstring heading was made true without renaming it.** It read *Two error surfaces instead of one*,
  which the second bullet contradicted: the docstring now lists three (typed field → 200 on the same form; refused paste →
  400/403 on the sign page; a refusal with no form to answer → `error.html`). The phrase itself is **kept** — five test
  docstrings (`tests/test_consent.py`'s *two error surfaces* sentence, three of `tests/test_csr_generate.py`'s docstrings, and
  `tests/test_views.py`'s refusal-order test), page-map §3 and SMOKE_TESTING.md's
  §16 row quote it, and a heading reworded underneath tests that name it is a rename those tests would never report. The heading
  now reads *"Two error surfaces instead of one" (0.2.0) — the name is kept, the count is not: there are three now*, so the
  quotation stays valid and the sentence stops lying. `templates/csr_sign.html`'s comment says the same thing in the template's
  own voice, naming where the phrase is quoted from; page-map §3's heading gained the matching clause.

- **That quoting is now gone: the rule is cited by name** (`docs/CHANGE_POLICY.md`, *Wording* class). `app.py` defines
  `ERROR_SURFACE_RULE`, whose value is that module-docstring heading, and every living citation of the rule — three template
  comments, five test docstrings across `test_consent.py`, `test_csr_generate.py` and `test_views.py`, page-map §3's own
  heading (now *Error surfaces*), and SMOKE_TESTING.md's §16 row — names the constant instead of retyping the sentence.
  Rewording the docstring is then a one-file edit rather than the multi-file sweep the bullet above exists to reconcile.
  The phrase itself now survives in three kinds of place, and only these: `app.py`'s heading plus the constant's own value
  (the two spellings that must agree), `docs/history/0.2.0.md` (since deleted; `git show bc0031b^:docs/history/0.2.0.md`) where it
  records what 0.2.0 said and was not editable, and
  this file's changelog entries — including the one above — which are records of past passes rather than live citations.
  `tests/test_packaging.py` guards both ends mechanically: the constant is assigned exactly once in `app.py`, its value is
  quoted there exactly twice (heading and assignment), and no other Python file under `src/` or `tests/` contains the phrase
  at all. A silent rename, or a quotation creeping back into living code, fails a gate instead of drifting. Neither harness
  script ever quoted the phrase, so both scripts are byte-identical to their recorded hashes and no harness assertion moved.
- **The cost of that pass is now a command, not a discipline** (`docs/CHANGE_POLICY.md`, *Wording* class again: no behaviour, no
  status code and no user-visible string moved). `tools/fast_lane.py` runs the cheap subset named in this file's own gate list —
  scoped `ruff check`, scoped `ruff format --check`, `tools/check_version.py`, `tools/check_docs.py` and a targeted
  `pytest -k … --no-cov` — and **omits `mypy src`, coverage measurement, `scripts/smoke_test.sh` and `scripts/smoke_test.ps1`**,
  printing those four as what a commit still owes. The omission is pinned by `tests/test_fast_lane.py`, which asserts over
  `LINT_STEPS`, `DOC_TOOLS`, `COMMIT_ONLY_STEPS` and every step `build_steps` can produce that no type gate, no `-cov` flag and
  no harness run enters the lane; it also pins the two exit codes a wrapper would otherwise flatten — `main([])` returning **2**
  rather than calling an argument-free invocation a pass, and pytest's exit **5** reported as *NO TESTS RAN* rather than as either
  a failure or a success. The tests this lane drops are the ones named in `COMMIT_ONLY_STEPS`: `mypy src`, the full-suite
  `pytest --cov` run, and both harness scripts. Two further omissions were dropped from the suite itself rather than from the lane:
  `tests/test_ocsp.py`'s `test_the_page_map_carries_sections_14_and_15_with_the_promised_words` and
  `test_the_page_map_no_longer_claims_that_nothing_is_published`, both page-map transcription tests whose needles are asserted in
  `tools/check_docs.py`'s rules and the docs gate itself, so a spec-quote test re-checking spec text was asserting one fact in two
  places. `tools/harness_parity.py` is the additive comparison half: it reads two harness logs with `tools/harness_ledger.py`'s
  parsing patterns, prints one row per section with each side's PASS count, and exits **1** on a missing section, a renamed
  heading or a count that differs by one, printing `parity: NO` for the pair it just compared. Neither tool's output is copied
  into this file: **NO counts** from either harness are quoted here, because per-section totals are measurements of one run and
  `reports/harness-ledger.md` is what carried them (never tracked in git; the harness writes `reports/harness-ledger.json` now).

## [0.7.0] - 2026-11-02

A **MINOR** release by this file's own definition: revocation became an artifact instead of only a row, and everything new
is additive — this file's MINOR test ("a new page, a new `MYPKI_*` knob, a new CLI flag, a new profile field") is met by its
first term twice (`/crl`, `/crl.pem`) and its second term exactly once (`MYPKI_CRL_BASE_URL`); there is no new CLI flag, and the
only certificate-profile change is two extensions *added* to newly-issued leaves. What an operator has to re-learn is one sentence long: **this host now publishes a CRL and answers OCSP, and only clients that
consult them act on it.** Nothing else moved. No existing route changed address or form fields; no certificate profile in
`docs/page-map.md` §7 was re-labelled (two extensions were *added* to newly-issued leaves, which is what the "new profile
field" term covers); no row of `issued.db` changed shape and no migration runs; **an existing data directory opens with no
manual step** — startup simply writes `<data>/crl/mypki.crl.pem`, and a host that has never revoked anything publishes a
valid zero-entry artifact rather than an error. The root CA on disk is untouched: `ca.py` already sets `crl_sign=True`
(MEASURED), so signing CRLs and OCSP responses needs no re-issue and no second key. A `<config>/mypki.env` written by 0.5.0,
0.5.1, 0.5.2 or 0.6.0 reads back unchanged — the one new knob is absent from it and takes its documented default. And
**certificates issued before 0.7.0 carry no `CRLDistributionPoints` and no `AuthorityInfoAccess`**: there is no migration and
no re-issue (that was an explicit product decision, not an omission), which is also why the CRL deliberately carries no
`IssuingDistributionPoint` — measured against openssl 3.5.6, an IDP-scoped CRL makes `openssl verify -crl_check` answer
`error 44 at 0 depth lookup: different CRL scope` for every such certificate, i.e. this CA's own history. What did **not**
change is the client side of revocation at all: no fetching, no enforcement, no delete, and a revoked certificate stays
trusted by clients that never consult an artifact until it expires. The gate this release was cut against, and the two harness runs that
re-measured it on the released tree (2026-11-02, each against its own freshly minted tree and data dir), were recorded in full — totals,
coverage, per-section ledger and log layout — in _docs/measurement-history.md_ under *0.7.0 release evidence* (since deleted;
`git show bc0031b^:docs/measurement-history.md`).
Against 0.6.0's measured total the release is **+37**: +36 in §11, all of it the new STEP F block (CRL + OCSP, asserted after the
revocations that create its subject), and +1 in §12 (`/about`'s rewritten revocation caveat now asserts two sentences where the dead one
asserted one). `openssl` was still never invoked by either harness. The 0.6.0 run it is compared against was kept as history in
_docs/history/0.6.0.md_ (since deleted; `git show bc0031b^:docs/history/0.6.0.md`) rather than overwritten here.

### Added

- **`src/mypki/crl.py`, `<data>/crl/mypki.crl.pem`, and three routes.** `GET /crl` renders the human page (facts card read
  back **from the file on disk**, the copyable PEM block, the advertised URL, the Rebuild control, and four measured caveats);
  `GET /crl.pem` serves the artifact as `application/pkix-crl` with `no-store`, `nosniff` and a literal
  `Content-Disposition: attachment; filename="mypki.crl.pem"`; `POST /crl/rebuild` is CSRF-checked as its first statement and
  re-signs the same data — it revokes nothing, and the page says so beside the button. A keyless host answers the existing
  `CaNotFoundError` **503** rather than a new error class.
- **The entry rule (answer 8), stated where it can be misread.** Entries are rows with `revoked_at_utc IS NOT NULL` **and**
  `not_after_utc > now`: revocations stamped in 0.2.0–0.6.0 are included, and a revoked certificate whose own validity has
  lapsed is **dropped**. "Removed from the CRL" reads as "un-revoked" to a human, so `/crl`, README gotcha 3 and page-map §14
  each say plainly that the row stays in `issued.db` forever and there is no un-revoke. `CRLNumber` comes from
  `store.count_revoked()` rather than `len(entries)` because entries can shrink while RFC 5280 §5.2.1 wants the number to grow.
- **`IssuedStore.revoked_records()`** (read-only, ordered by stamp then serial, **no 500-row cap** — `list_records` caps
  because it renders a page, and a capped CRL would leave the 501st revoked certificate trusted). The introspection guard in
  `tests/test_store.py` ("exactly one UPDATE, no delete") passes untouched: this adds a read, not a mutation.
- **`MYPKI_CRL_BASE_URL`** (`http://mypki.my.lab` by default), the release's only new knob. It is a *base*, not a full URL —
  `app.py` spells `/crl.pem` and `/ocsp`, so a certificate can never advertise a path this app does not serve. Plain `str`, so
  clearing the box on `/settings` is refused naming the knob rather than silently reverting; a `field_validator(mode="before")`
  refuses anything not starting with `http://` or `https://` **at startup**, because the value is copied into every certificate
  issued afterwards, and trailing slashes are stripped rather than rejected. Live (not in `STARTUP_ONLY_KNOBS`) but not
  retroactive: it reaches only certificates issued after the change.
- **`CRLDistributionPoints` and `AuthorityInfoAccess` on newly-issued leaves** (`…/crl.pem`, `…/ocsp`), both non-critical, both
  added by `signing.leaf_extensions()` from that one base. "Extensions are never copied from the CSR" still holds and is now
  load-bearing rather than incidental: a request carrying its own distribution point is still classified ignorable, still
  dropped, still named — asserted against a request asking for `http://crl.internal/crl.der`, which produces
  `urls == ["http://mypki.my.lab/crl.pem"]` and nothing else.
- **`src/mypki/ocsp_responder.py` + `POST /ocsp`.** Every status is built with `add_response_by_hash`, echoing both CertID
  hashes and the request's own hash-algorithm instance verbatim (mypki stores no certificate PEM, and `issuer_key_hash` cannot
  be recomputed for a SHA-256 request — measured). GOOD / REVOKED / UNKNOWN come from this host's store; a revoked-and-expired
  serial answers **UNKNOWN**, the one status that does not contradict the CRL next door. `ReasonFlags.unspecified` always, because
  the stored reason is operator prose and inventing a code from prose would be a claim this CA cannot support. `thisUpdate` +
  **4 h**; the request's nonce echoed when present; responder = the root certificate itself (`responder_id(NAME, ca.cert)`,
  `certificates([ca.cert])`), signed SHA-256. Protocol refusals are bodies at HTTP 200: `30 03 0a 01 01` (MALFORMED_REQUEST) and
  `30 03 0a 01 02` (INTERNAL_ERROR), each exactly five bytes. Two size limits, both measured end-to-end: the handler answers
  MALFORMED_REQUEST above **8 KiB** without signing anything, while a body over `max_csr_chars + 8192` (**40,192**) is answered by
  mypki's HTML **413** from the unmodified `SizeGuardMiddleware`, declared-length and chunked alike. No cache.
- **Two fixed lifetimes as module constants, not knobs**: `crl.CRL_LIFETIME` (24 h) and `ocsp_responder.OCSP_LIFETIME` (4 h), plus
  `OCSP_MAX_REQUEST_BYTES` (8192). Page-map §11 states why none of the three gets a `MYPKI_*` row, a preset or an empty-value rule.

### Changed

- **The sentences that became false were rewritten in the same commit as the behaviour**, not after it: `/issued`'s confirmation
  and footer, `/about`'s "what this CA does not do", `/ca`'s "What installation does not do", `/inspect`'s four self-describing
  sentences, `/csr/sign`'s validity hint and issued note, `signing.leaf_extensions()`'s docstring ("no CRLDistributionPoints, no
  AuthorityInfoAccess appear here at all" — true through 0.6.0, false from 0.7.0), `config.py`'s ceiling comment and
  `validity_default_days` description (both rendered verbatim on `/settings`), `store.py`'s reason-length comment, `inspect.py`,
  `csr.py`, four `app.py` docstrings, README's intro and gotcha 2 (now four numbered caveats), and page-map §0/§3/§5/§7/§8/§11/§12/§13.
  `tests/test_signing.py`'s exact ordered extension list grew from six entries to eight and its name/prose were rewritten from what
  the function actually returns rather than from the old sentence. Released CHANGELOG history is left as written: a 0.6.0 section
  saying "no CRL" is a record of what was true then.
- **`MYPKI_VALIDITY_MAX_DAYS` stays at 1461**, with its prose rewritten. 0.2.0's reasoning ("the honest fix is the CRL release")
  has now happened, and the ceiling's remaining justification is the measured one: a CRL entry or an OCSP answer counts only for a
  client that consults one, so validity remains the bound that needs no cooperation from anyone else.
- **`MYPKI_PUBLIC_BASE_URL`'s description says what does feed a certificate**: `crl_base_url`, because the two facts have different
  lifetimes — one describes how you reach this host today, the other is frozen into certificates that outlive the change.

### Testing

- **`tests/test_crl.py` (41 collected from 38 test functions, three parametrized)** and **`tests/test_ocsp.py` (31 tests)**, both openssl-free (the CI job's "NO OpenSSL binary is
  required anywhere" is a contract, not a preference). What they assert as data: `CRLNumber` non-decreasing across a rebuild that
  *removed* an entry; the >500-row case; 159-bit serial round-trips (MEASURED: 101 of 200 real mypki serials carry the top bit);
  no `IssuingDistributionPoint` and no `DeltaCRLIndicator`; atomic write leaving no temp file and a world-readable artifact; page and
  artifact byte-identical because both read the file; the four caveats present on `/crl` as written words; a rebuild refused without a
  token costing **no** signature (asserted by comparing the file byte-for-byte); the OCSP decision table including the
  revoked-and-expired/never-revoked-and-expired pair; the hash echo under SHA-1 **and** SHA-256; the 4 h interval on the artifact; a
  hand-verified signature (`public_key().verify(parsed.signature, parsed.tbs_response_bytes, PKCS1v15(), SHA256())`) plus the
  `sha256WithRSAEncryption` OID; nonce echo and no-extension-when-absent; determinism at a pinned instant; both handler caps and the
  middleware 413; keyless and no-CA hosts answering DER and creating no `<data>/crl/`; `GET /ocsp` → 405.
- **`tests/test_no_key_leakage.py`** gained `/crl` and `/crl.pem` to its page sweep (the first non-HTML entries it has ever searched,
  matched via `.decode("latin-1")`) plus three new tests: the CRL is armour-free with `AuthorityKeyIdentifier ==
  from_issuer_public_key(...)` and two GETs byte-identical; an OCSP body carries no bytes of the CA key in DER, PEM or base64 form and
  verifies against the public key; and both refusals carry **no** bytes of any kind.
- **`tests/test_packaging.py`**: `/crl` joins the every-page GET sweep (the nav stays seven links, so nothing else ever fetched it) and
  `src/mypki/templates/crl.html` joins the asset list. `/ocsp` deliberately does **not** join the GET sweep — it answers 405 JSON, and a
  sweep that asserts 200 + `<!DOCTYPE html>` would be asserting the wrong contract. No `.crl.pem` fixture is committed under `src/` or
  `tests/`, so the key-material walk stays green; the generated artifact lives outside the tree, like `issued.db`.
- **Collection moved 704 → 782 tests** (`test_crl.py` 41 + `test_ocsp.py` 31 new; coverage TOTAL 2730 → 3008 statements, 97
  missed, 96.78%), with zero skips.
- **The shipped artifact was tested as shipped.** `mypki-0.7.0.zip` (749,618 B, sha256 `74a9523916870e787e0cdf9456a930cab93c0162c97a8b398b8d10cec7d489cd`,
  79 entries = 68 files + 11 dir entries under `mypki-0.7.0/`) was built from an explicit 68-path list — the 0.6.0 list plus exactly five additions
  (`src/mypki/crl.py`, `src/mypki/ocsp_responder.py`, `src/mypki/templates/crl.html`, `tests/test_crl.py`, `tests/test_ocsp.py`) and zero deletions —
  staged with `tar cf -T` and zipped with `zip -q -r -X`; the manifest leak scan (`pyc|__pycache__|.env$|logs/|.pem$|.key$|.crt$|venv|coverage|.git/|cache|nohup`)
  returns **RC=1** (clean), and the per-file sha256 aggregate matches **three ways**: build tree == staging tree == extracted tree
  (`16435edb3a82741355a93ce6c5c7bb09c87232b89fcb07fab3449a4a65e5c260` over 68 files). Unzipped to `/tmp/extract-070`, with `PYTHONPATH` pinned to the
  extracted `src` (this venv's editable install of `build/` would otherwise answer the import), the gate re-ran green inside the archive: **782 tests /
  0 skips, TOTAL 3008 / 97 missed = 96.78%**, `mypy` clean over 19 source files, `ruff check` clean, `tools/check_version.py` exit 0 naming the extracted
  paths. **Both harnesses were then run from the extracted tree against their own freshly minted data dirs** (2026-11-03, `/tmp/s11b/run_harness_x070.sh`
  retargeted at `<extract>`): `.sh` on `http://127.0.0.1:8621`, `.ps1` on `:8623` under `/tmp/pwsh/pwsh` 7.6.9, plain `init-ca` (CN=mypki Root CA,
  RSA 3072), `HOME` + the four `XDG_*` redirected, `MYPKI_CONFIG_DIR`/`APPDATA` unset, no `--base` / `-Base`, server cwd `<extract>/src`. Both exited 0, and
  their full ledgers — totals, per-section counts and heading positions — were held in
  _docs/measurement-history.md_ under *Both harnesses run from the extracted shipped zip* (since deleted;
  `git show bc0031b^:docs/measurement-history.md`). The extracted ledger was identical to the `build/` ledger recorded there,
  which is what makes the zip a copy of the tested tree rather than a rebuild of it.
- **One file in the frozen archive is not the file in the build tree: `CHANGELOG.md` itself.** The copy inside
  `mypki-0.7.0.zip` (1,146 lines / 117,061 B) lacks the `## [0.6.0] - 2026-11-01` heading this QA pass
  restored above — the archive was cut before it was re-attached — so in that copy the 0.6.0 narrative and
  its `### Added` / `### Changed` / `### Fixed (harness defects found by running §16 against a correct app)`
  sub-headings sit under no release heading. The zip was **not** rebuilt to carry this line. Re-checked 2026-11-03
  against an extracted copy: **66 of the 68 shipped paths hash equal** between `/home/user/mypki/build` and
  `mypki-0.7.0.zip`, and the two that differ are this file and `SMOKE_TESTING.md` — both edited after the
  archive was frozen, each difference recorded in its own file rather than hidden by re-zipping.

### Known gaps in 0.7.0 (deliberate, not pending work)

Still absent after this release, all of it stated on `/crl` and in README gotcha 2: no CRL or OCSP **fetching** by mypki itself
(`openssl verify` does not fetch a baked CDP either — measured, `error 3 … unable to get certificate CRL`, with the CRL served live on
a port and no GET in the server log); no delta CRLs and no IDP scoping; no un-revoke and no delete; no delegated OCSP responder, so the
responder is a root carrying no `id-kp-OCSPSigning` (accepted by openssl 3.5, **unmeasured** against a browser or Go client); no CRL
coverage of certificates issued before 0.7.0; and no way to make a client that never consults an artifact honour a revocation.

## Release index

Everything below 0.7.0 was frozen history held one file per release under `docs/history/`, moved out of this file so a change
to the current build never had to be reconciled against a previous release's measurements. **That directory was deleted by the
pass recorded under [Unreleased], so no path in the list below opens today.** The bold labels link to each release's tag; the
prose is still recoverable, one command per release, from the commit that preceded the deletion:

```bash
git show bc0031b^:docs/history/0.6.0.md   # substitute the version for any row below
```

Frozen files were append-only and were not policed by `tools/check_docs.py`; that checker was deleted in the same pass, which is
why nothing here is enforced any more. The 0.7.1 and 0.7.0 sections above are this file's own text and remain readable in place —
only the per-release *files* are gone.

- **[0.6.0]** - 2026-11-01 - `bc0031b^:docs/history/0.6.0.md`
- **[0.5.2]** - 2026-10-31 - `bc0031b^:docs/history/0.5.2.md`
- **[0.5.1]** - 2026-10-31 - `bc0031b^:docs/history/0.5.1.md`
- **[0.5.0]** - 2026-10-30 - `bc0031b^:docs/history/0.5.0.md`
- **[0.4.0]** - 2026-10-29 - `bc0031b^:docs/history/0.4.0.md`
- **[0.3.0]** - 2026-10-29 - `bc0031b^:docs/history/0.3.0.md`
- **[0.2.0]** - 2026-10-28 - `bc0031b^:docs/history/0.2.0.md`
- **[0.1.0]** - 2026-10-26 - `bc0031b^:docs/history/0.1.0.md`

[Unreleased]: https://github.com/madmickstar/mypki/compare/v0.7.4...HEAD
[0.7.4]: https://github.com/madmickstar/mypki/releases/tag/v0.7.4
[0.7.3]: https://github.com/madmickstar/mypki/releases/tag/v0.7.3
[0.7.2]: https://github.com/madmickstar/mypki/releases/tag/v0.7.2
[0.7.1]: https://github.com/madmickstar/mypki/releases/tag/v0.7.1
[0.7.0]: https://github.com/madmickstar/mypki/releases/tag/v0.7.0
[0.6.0]: https://github.com/madmickstar/mypki/releases/tag/v0.6.0
[0.5.2]: https://github.com/madmickstar/mypki/releases/tag/v0.5.2
[0.5.1]: https://github.com/madmickstar/mypki/releases/tag/v0.5.1
[0.5.0]: https://github.com/madmickstar/mypki/releases/tag/v0.5.0
[0.4.0]: https://github.com/madmickstar/mypki/releases/tag/v0.4.0
[0.3.0]: https://github.com/madmickstar/mypki/releases/tag/v0.3.0
[0.2.0]: https://github.com/madmickstar/mypki/releases/tag/v0.2.0
[0.1.0]: https://github.com/madmickstar/mypki/releases/tag/v0.1.0
