# What a change has to update

mypki's gates are cheap (ruff 0.03 s, mypy 0.5 s, the version chain 0.1 s, pytest ~4 min). Until now the documentation
around them was not: a five-line CSS rule invalidated sentences in two documents because those sentences contained
**hand-copied measurements and line-number citations**, and every edit shifted them. This file states what a change is
allowed to touch, so the cost lands on the code that changed rather than on prose that did not.

## Two rules that make small changes cheap

**1. Measurements are generated, never retyped.** A harness run's totals, per-section counts, log length and heading
positions live in `reports/harness-ledger.md`, produced by `tools/harness_ledger.py` from the log itself:

```bash
scripts/smoke_test.sh --report /tmp/report.md > /tmp/run.log 2>&1
python3 tools/harness_ledger.py /tmp/run.log --label "build .sh" --write   # -> reports/harness-ledger.{md,json}
```

Documents **link** to that file. A document that quotes a number from it has taken on the job of keeping that number
true, so `tools/check_docs.py` refuses the quote. The same applies to coverage and test counts: read them from the gate
output at the moment you need them.

**2. Cite a name, never a position.** Write "`_paste_refused`", "`test_a_refused_paste_is_named_on_the_sign_page_above_the_box_it_belongs_to`",
"the `.form-errors.refused` block", "§7's *Rejections name their reason*" — all of which survive an edit anywhere in the
file. A citation written as a filename glued to a line number, a colon-and-digits anchor with no name attached, "the line
before the label", or a slash-separated list of heading positions — all four die on the first unrelated edit above them, and a
document full of them has to be re-verified after every change. `tools/check_docs.py` enforces this on the living documents;
frozen history is exempt because a past measurement is exactly what history is for.

## Change classes

| Class | Code | Tests | Harnesses | Living docs | Frozen history |
|---|---|---|---|---|---|
| **Cosmetic** — colour, spacing, a CSS rule that changes no visible string | edit | none | none | none | none |
| **Wording** — a label, a sentence, a heading | edit | the assertions whose needle is that string (`.sh` **and** `.ps1`, plus any test needle) | needle only | only the page-map row if the spec quotes the string | none |
| **Behaviour** — a new route response, status code or error surface | edit | 1–3 tests | 1 assertion per script | one paragraph under `[Unreleased]` in `CHANGELOG.md`, no measurements | none |
| **Contract** — form fields, certificate profile, `issued.db` row shape, CA trust | edit | full sweep | full sweep | page-map section + changelog entry | the release is cut: history entry written once |

A change that needs more documentation than its class allows is either misclassified or the documents are wrong; treat
that as a defect in the documents and fix the documents, not the change.

## When measurements get written down

Once, when a release is cut. `CHANGELOG.md`'s own preamble already says version numbers are release-time facts rather
than working-commit facts; the same applies to evidence. During development an entry says what changed and which test or
assertion proves it. At release time the entry gains its measured evidence (totals, coverage, per-section ledger) in one
pass, against the logs of that release — not re-derived for every intermediate commit, and never reconciled against a
previous release's numbers.

Historical measurements are **append-only and never re-derived**: `docs/history/` (per-release changelog sections) and
`docs/measurement-history.md` (dated harness/coverage/label-comparison records). Old entries are not restated, because a
measurement is a record of one run and rewriting one to match a new build invents a run nobody performed.

**What append-only actually forbids is editing or moving an existing entry. It does not fix which end a new one joins, and
this file states no ordering rule it cannot prove.** `docs/measurement-history.md` holds two halves:

- **Dated `##` sections**, each a block moved verbatim out of a living document. A new block is **appended after the last
  section**. Both append steps whose scripts still survive on disk write exactly that way — read the file, strip trailing
  newlines with `rstrip("\n")`, concatenate the new block onto the end — and this pass added its own section by the same method.
  Which step wrote which section is now established from what survives: the two surviving bottom-appenders are, in run order,
  the script that wrote the first `##` section and the one that wrote the second, and their document order matches their run
  order. The file itself was built whole in a single write by the one-shot split step that created it, which refuses to run
  again once the file exists. No ordering rule is claimed for the sections beyond "appended, not inserted".
- **A bullet list of per-build records.** **No chronological ordering rule can honestly be stated for it, and none is stated
  here.** Measured on 2026-11-04, the date each bullet names is neither ascending nor descending down the document; the list's order
  records *where each paragraph came from* when it was moved out of the living documents — a provenance order rather than a
  chronological one. The measurement and the exact shape of the sequence are in
  [docs/measurement-history.md](docs/measurement-history.md), under *Ordering of this file's own bullet list*, because quoting them
  here would be the retyped measurement this file forbids.

Two claims about this ordering were made and dropped during that pass, and both are recorded rather than smoothed over. The first
said new entries land at the **top** of `docs/measurement-history.md`; the append steps that built the file wrote at the bottom. The
replacement sentence then claimed the bullet list "reads oldest-first", and measuring the list disproved *that* too. A policy document
that asserts a false ordering is worse than one that states none: the next contributor follows the false rule, moves or re-dates a
frozen entry to make the dates line up, and editing a frozen measurement is the single thing "append-only" exists to forbid.

`docs/history/` needs no ordering rule at all: each release is its own file, so a new release adds a file instead of editing one.

## Gate list

```bash
ruff check src tests tools            # lint
ruff format --check src tests tools   # format
mypy src                              # types
python3 tools/check_version.py        # version chain: module -> manifest -> CHANGELOG section
python3 tools/check_docs.py           # living docs free of copied measurements and line citations
python3 tools/check_docs.py --self-test   # proves each docs rule can fire
python3 tools/check_docstrings.py     # src/ docstrings and comments carry no release-time prose
python3 tools/check_docstrings.py --self-test   # proves each src/ prose rule can fire
python3 -m pytest --cov=mypki --cov-report=term-missing --cov-fail-under=85
```

`tools/fast_lane.py` is the cheap subset of this list rather than another gate: scoped ruff, the two living-doc tools and a
targeted `pytest -k`, omitting mypy, coverage measurement, the src/ prose gate and both harness scripts because those answer
questions an unchanged signature or an unmoved status code did not raise, and a partial run measures a partial denominator no
commit gate can be compared to. The src/ prose gate stays out for the same reason as mypy rather than because it is slow: it
reads every module under `src/`, which an edit confined to one template did not make a live question.
`tests/test_fast_lane.py` asserts the omission instead of trusting the tool's intentions; the list above stays what a commit owes.

**The gates are scoped on purpose, and the scope is what makes their file counts mean anything.** CI runs
`ruff check src tests tools` and `ruff format --check src tests tools`: every file either command names is a file this project
owns, so its count is stable across releases and comparable between them. A bare `.` is not that gate. Ruff's `.` walk visits
Markdown for *format* but not for *lint*, and it applies `.gitignore` only inside a git repository — so in a checkout without
`.git` it also walks generated artifacts under `reports/`. The two commands are therefore asymmetric about documentation:
`ruff check README.md` answers "No Python files found" and exits 0, which means a clean `ruff check .` says nothing whatsoever
about the documents. `tools/check_docs.py` is the only gate that reads them.

This file deliberately quotes no file counts for either command, because a count that moves when a document is added or removed
is exactly the kind of measurement this policy refuses to retype. The counts measured on 2026-11-04, and the decomposition that
explains why `.` and the scoped form differ, are recorded in [docs/measurement-history.md](docs/measurement-history.md).

`tools/check_docs.py --self-test` matters as much as the gate itself: a pattern that matches nothing passes forever, so
the mutation check shows each rule firing on synthetic text and clean prose surviving it. The same holds for
`tools/check_docstrings.py --self-test`, which is that proof for the src/ prose rules.

**Two of these gates read one artifact each, and a third needs two.** `tools/check_docstrings.py` reads only `src/`: a
docstring that names a release, records how one probe run went, or points at a planning document's numbering is history
sitting inside living code, and `docs/history/` is where that sentence belongs. It exits 1 on findings, so a prose edit to
a docstring is caught by the same mechanism as a code edit — and its rules are pinned from the test side too, in
`tests/test_docstrings.py`, which asserts zero findings over the real tree, a passing self-test, that the checker stays
stdlib-only, and that the phrases tests and documents quote out of docstrings are still present.

`tools/harness_parity.py` is deliberately **not** a commit hook. It answers a comparative question — do the `.sh` and
`.ps1` logs describe the same run shape, heading for heading and per-section PASS count for per-section PASS count — so it
requires exactly two harness logs, one from each harness, and exits **2** when fewer than two usable logs are given. A
commit hook cannot supply those: a commit does not run either harness, and running both to feed a hook would put minutes of
two harness runs in front of every commit for a question that only has an answer at release time, when both logs exist from
the release's own runs. It therefore sits in the release pass next to `tools/harness_ledger.py` rather than in this list or
in the pre-commit hooks, and it exits **1** on a divergence it finds rather than excusing one: a harness legitimately
gaining an assertion on one side before the other catches up is a real state of this project that the tool reports instead
of approving.

## What this costs a small change

| Step | Typical time |
|---|---|
| edit + targeted tests (`pytest -k …`) | 5–20 min |
| full gates | ~4 min, mostly pytest |
| harness assertion (Behaviour class only) | 10–15 min, both scripts |
| living-doc paragraph (Behaviour class and above) | ≤10 min |
| ledger regeneration | seconds |

Documentation time is capped by the change classes above. If a cosmetic edit needs a documentation edit at all, that is
the rule being violated rather than work that has to be done.
