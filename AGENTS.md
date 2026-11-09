# Working rules for this repository

Read this before editing anything here. These rules exist because of measured cost, not preference: one documentation
pass on this box took **161.6 minutes** (203 shell commands) to write four documents, and the largest single block of it
— **67.5 minutes, 70 commands, zero writes into the repo** — was spent re-deriving facts by hand while a full test suite
was running in the background. Every rule below targets one measured failure.

Numbers quoted here were measured on a 2-CPU container and are durations of *that* box, not properties of the release.

---

## 1. Inventory first, then edit. Do not re-derive facts with repeated grepping.

**Before changing anything, produce the inventory once, into a file, and work from that file.**

```sh
make inventory                                            # one file: tracked paths + every code-to-doc citation
.venv/bin/python tools/tree_manifest.py --check           # does README's shipped-tree claim match git? (105-129 ms)
.venv/bin/python tools/tree_manifest.py --fingerprint     # one line identifying the exact tree (104-106 ms)
```

If a change touches documentation, enumerate what cites it before editing any of it. On this tree that enumeration is
**429 document references across 48 Python files** — **420 of them carried by 39 files**, inside the 42 `.py` files under
`src/` and `tests/` (three of those 42 carry none), the narrower figure older notes quote as "420 across 42 files" — and it
runs in **2,921-3,000 ms** across timed runs on this tree. Always
attach the denominator: `tools/doc_citations.py`
scans `.py` prose, so its count moves when its own docstring does, and `git ls-files` alone answers 46 files / 425
references because it cannot see what is not yet committed. Doing the same discovery one `grep` at a time is what produced
113 read-only commands (56% of that session).

Ask for, or write, the inventory as a file — a file survives a session ending; a memory of what was read does not.

**Do not re-grep the tree to answer a question you have already answered.** If the answer is not in the inventory, add it
to the inventory once, then continue.

## 2. Do not run a full suite until the tree is final. `make gate` now refuses if you do.

The tiers exist and are cheap-to-expensive in this order:

| Tier | Command | Measured cost on this box | Proves |
|---|---|---|---|
| scoped | `make fast K=<expr>` | seconds | lint + version chain + a targeted `pytest -k` |
| documentation | `make docs` | **70 passed**, five runs: 3.49 / 3.56 / 3.61 / 3.63 / 4.27 s (5,373 / 5,413 / 5,483 / 5,511 / 6,138 ms wall) | version chain, README's shipped-tree claim vs `git ls-files --cached --exclude-standard --others`, and the two doc-aware test files |
| declared final | `make ready` | 220-226 ms wall warm (twelve runs; 247-248 ms cold) | stops editing; regenerates generated blocks; records the tree fingerprint |
| full | `make gate` | refuses in 16-17 ms with no stamp and in 117-129 ms with a stale one; otherwise **268.7-302.5 s** wall — five clean green runs measured when this file was written: 268,673 / 274,179 / 274,217 / 281,637 / 302,546 ms, every one reporting 830 tests and harness 328 pass / 0 fail / 0 warn — and it prints `gate tree: …` as its first line | lint, types, version chain, full suite with coverage, end-to-end harness |

`make gate` **exits 2** unless `make ready` has been run *and the tree has not moved since*. That refusal is the point:
a documentation change does not need a four-minute suite at every iteration, and a four-minute suite run twice — once as
a baseline before any edit existed, once invalidated by an edit landing mid-run — is eight minutes bought for nothing.

Run the full gate **once**, after the last write. If you edit after `make ready`, run `make ready` again; `gate` will tell
you the tree moved rather than silently measuring something stale.

## 3. Every gate log must say which tree it gated.

A green suite is only evidence about the tree it measured. `make gate` now prints a fingerprint as its first line:

```
gate tree: <HEAD^{tree}> <sha256 of uncommitted state, first 16 hex> <tracked path count>
```

and `make ready` writes that same line to `.gate-ready`. Redirect the log (`make gate > /tmp/gate.txt 2>&1`) and the stamp
is inside it. Compare the log's first `gate tree:` line with `tools/tree_manifest.py --fingerprint` run after the gate to
know whether a re-run is owed, instead of guessing.

The digest is over file **contents**, not `git status` output: MEASURED twice on this tree, appending a line to
`docs/REFERENCE.md` — a file git already reported as modified — left `git status --porcelain` byte-identical while the
digest changed, so a status-based guard would have waved through exactly the mid-run write it exists to catch. `.gate-ready`
is gitignored for a measured reason too: with every file on disk untouched, putting the stamp back in the tracked list grows
the path count **78 → 79** and changes the digest half as well, i.e. a gate that stamps its tree invalidates its own stamp.
No digest hex is quoted anywhere in this file on purpose — a hex written in prose is false the moment any other file inside
the digest changes.

This rule exists because three full-suite logs in one release pass recorded **no tree at all** — no commit, no tree hash —
so "re-gate the exact tree" could only be honoured by re-running and hoping. One of those gates was invalidated by a write
that landed mid-run (`README.md` written 15:30:59 inside a gate that ran 15:28:15 → 15:33:01), costing a full re-run plus
about nine minutes of `sleep` polling. Stamping costs **17.8 ms** (fingerprint plus one write, warm, best of five) out of
`make ready`'s measured **220-226 ms** wall.

**Polling rule:** do not launch a long run and then poll it with repeated `sleep`. One backgrounded run needs one wait.
Seven `sleep 45/120/180/200` commands in that pass totalled **13.6 minutes**, and 20 of the polls asked about a log that
had already stopped growing.

**One run at a time, into one file.** A gate log is only evidence if exactly one process wrote it. MEASURED the hard way:
relaunching a closing `make gate` while the previous one was still running put **two runs in the same file** — two harness
summaries instead of one, 34 section lines instead of 17, and pytest reporting 287-289 s instead of 259-272 s because two
suites were sharing two CPUs. Nothing failed, no exit code was wrong, and every number in that log was false. Before
quoting a gate log, count its harness invocations (`grep -c 'tools/e2e_harness.py'`) and section lines: one and seventeen,
or the log is not quotable.

---

## Facts about this repository that change how you work here

- **Documentation is load-bearing in code.** Docstrings and test docstrings cite documents by section (`docs/REFERENCE.md`
  gotcha 1, `page-map §7`, README "Configuration"). Moving or renaming a section makes those citations point at things
  that no longer exist. Enumerate them before moving text: `make inventory` writes them all to one file.
- **A documentation change is also a packaging change.** `tests/test_packaging.py` asserts
  `set(sdist_config["include"]) == set(REQUIRED_INCLUDES)` **in both directions**, so adding a shipped file means editing
  `pyproject.toml` *and* `REQUIRED_INCLUDES` in the same commit. A one-sided edit is a red test, not a style issue.
- **Generated prose must be generated, not typed.** README's "Where the files live" structure tree and its path count come
  from `git ls-files --cached --exclude-standard --others`, rendered as an indented tree. `make ready` rewrites them;
  `make docs` checks them; `tests/test_packaging.py` re-asks git independently, draws the tree with its own renderer and
  carries five mutation cases (wrong count, missing path, invented path, two siblings swapped, a non-path line in the
  block) so the assertion cannot be vacuous. On commit `a4dc4f3` README claimed 75 paths (and its fenced
  block held exactly 75 lines) while CHANGELOG.md's own entry for the same commit said 74 — both re-read from git today.
  The full-suite logs from that pass were green at 823 passed, but they recorded no tree, so which commit they measured is
  not recoverable: that is rule 3's problem as much as this one. Nothing in the suite could see the disagreement;
  `tools/tree_manifest.py` now can.
- **Adding any tracked file changes the count.** That is why `make ready` regenerates README rather than leaving you to
  notice later. It also means a new file must be *tracked* before `ready` will list it: an ignored file ships nothing and
  claims nothing.
- **Nothing runs automatically at commit time.** `.git/hooks` contains only `.sample` files, so pre-commit must be invoked
  explicitly (`.venv/bin/python -m pre_commit run --files <every changed file>`, or `--all-files`, measured at **1.08 s**
  with a warm cache) and CI never runs `make gate` — it runs `make lint`, `ruff format --check`, `make types`,
  `pytest --cov`, `make version`.
- **A green suite does not prove prose is correct.** The prose-policing gates (`tools/check_docs.py`,
  `tools/check_docstrings.py`, `tests/test_docstrings.py`) were removed in `bc0031b`. `tools/tree_manifest.py` checks only
  mechanical facts (paths, counts, order). No tool here can tell you whether a sentence about behaviour is true.

## Shell constraints on this box (each one cost time when ignored)

- `/bin/sh` has **no process substitution** (`<(...)`) and **no `mapfile`**. Use `xargs -a file cmd` instead.
- Piping to `tail`/`head` **masks the exit code**. Redirect to a file first, then read the file.
- `git` opens a pager unless `export GIT_PAGER=cat` and `git --no-pager`.
- `/bin/sh` has no `time` builtin; time with `date +%s%N` around the command.

## Naming things that cannot be measured from this box

Report these as unmeasurable rather than as verified: GitHub Actions runner costs and wall time (this checkout has **0
remotes**; nothing is pushed), browser rendering of README or any page, clipboard behaviour in a browser, starting
`deploy/mypki.service` on a real host (`systemctl is-system-running` answers `offline`), the byte-identity of a regenerated
banner (Pillow is not installed in `.venv`), and your own or an agent's edit/thinking time between commands.
