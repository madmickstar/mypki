# mypki — every command this project runs, in one place.
#
# WHY THIS FILE EXISTS
#   Until now the commands lived as prose in README.md (their home is now docs/REFERENCE.md "Development") and in
#   docs/CHANGE_POLICY.md — a file this checkout no longer has: `git cat-file -e HEAD:docs/CHANGE_POLICY.md` answers
#   exit 128, because bc0031b deleted it. Each pass re-derived the commands from
#   memory. That is where release time went: reconstructing which exact invocation produced a number, and retyping
#   `--cov-fail-under=85` by hand every run (the floor was never declared in pyproject.toml). A target name is cheaper
#   to remember than a command line, and a command written once cannot disagree with itself.
#
# START HERE
#   make inventory        one file answering "what is tracked, and what cites the docs" — write it once, edit from it
#   make fast K=sign      while editing: scoped lint + version chain + targeted pytest -k, no coverage
#   make docs             a change that touches only .md: version chain + shipped-tree claim + two doc-aware test files
#   make ready            stop editing: regenerate generated blocks, then stamp the tree this gate will measure
#   make gate             refuses unless 'make ready' ran and nothing moved since; prints the tree it measured
#   make zip              release artifact from the git file list (run last; a zip is a copy of what was gated)
#
# COVERAGE FLOOR
#   `fail_under = 85` lives in [tool.coverage.report] in pyproject.toml. It is not repeated on any command line here,
#   so there is one place to change it and no chance of a run that silently had no floor at all.

SHELL := /bin/bash

# This checkout's venv when it exists, otherwise the invoking interpreter — the same rule tools/fast_lane.py uses,
# stated once more because make cannot import that decision. A half-created .venv must fall back rather than fail.
PY := $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)

VERSION := $(shell sed -n 's/^__version__ = "\([^"]*\)"$$/\1/p' src/mypki/__init__.py)
DIST_NAME := mypki-$(VERSION)
STAGE := /tmp/$(DIST_NAME)-stage

# K= is the pytest -k expression for `make fast` and `make test`. Empty is a mistake, not a full run: an empty pattern
# would silently select nothing and read as green.
K ?=

# The two test files that know documents exist at all, named once so `docs` below and the comment above it cannot
# disagree about which files a docs-only change owes. See the `docs` target for why these two and not more.
DOC_TESTS := tests/test_packaging.py tests/test_version.py

#: The tool that owns "which paths does this repository track", and therefore owns README's file list and its count.
TREE_MANIFEST := tools/tree_manifest.py

#: Written by `ready`, read by `gate`. Deliberately gitignored: it is one machine's statement about one working tree,
#: not a fact about the release. Ignoring it is load-bearing, not tidiness — MEASURED on this checkout, putting
#: `.gate-ready` back into the list `git ls-files --cached --exclude-standard --others` answers grows the path count 78 ->
#: 79 and changes the digest half too, because the stamp joins both. No digest hex is quoted here: a hex written in prose
#: is false as soon as any other file inside the digest changes, which is the staleness `ready` regenerates README to avoid.
#: A gate that stamps its own tree would invalidate its own stamp, and README's regenerated count would grow by one on
#: every run: a guard that rejects itself.
GATE_STAMP := .gate-ready

#: `inventory`'s output. reports/ is gitignored for the same reason as the harness ledger (see .gitignore).
INVENTORY := reports/inventory.txt

#: The doc-citation enumerator `inventory` runs. Named separately from `TREE_MANIFEST` because they answer two different
#: questions — which paths exist, and which of them point at a document section.
CITATIONS := tools/doc_citations.py

.DEFAULT_GOAL := help

.PHONY: help lint types cov test fast docs version ready inventory gate _gate-steps e2e zip clean

help:
	@echo "mypki $(VERSION) — targets:"
	@echo "  make fast K=<expr>   scoped ruff + version chain + pytest -k <expr> (no coverage)"
	@echo "  make inventory       tracked paths + tree fingerprint + every doc citation in code -> $(INVENTORY)"
	@echo "  make docs            .md-only change: version chain + shipped-tree claim + $(DOC_TESTS) (no coverage)"
	@echo "  make lint            ruff check + format --check, scoped to src tests tools"
	@echo "  make types           mypy src"
	@echo "  make cov             full suite with coverage; floor 85 from pyproject.toml"
	@echo "  make test K=<expr>   targeted pytest only, coverage disabled"
	@echo "  make version         tools/check_version.py: 0 consistent, 1 drift, 2 cannot check"
	@echo "  make e2e             the end-to-end harness: real server, real HTTP, real openssl"
	@echo "  make ready           declare the tree final: regenerate generated blocks, then stamp $(GATE_STAMP)"
	@echo "  make gate            refuse without a matching stamp, print 'gate tree', then lint types version cov e2e"
	@echo "  make zip             build $(DIST_NAME).zip from git ls-files, leak-scan it, prove digests"
	@echo "  make clean           remove caches, .coverage and staging dirs"

lint:
	$(PY) -m ruff check src tests tools
	$(PY) -m ruff format --check src tests tools

types:
	$(PY) -m mypy src

cov:
	$(PY) -m pytest --cov=mypki --cov-report=term-missing

# No `-q` here. `pyproject.toml`'s addopts already declares `-q --strict-markers`, and a second `-q` stacks to `-qq`,
# which suppresses pytest's summary line entirely: MEASURED, `make test K=csr_generate` printed dots and [100%] and no pass
# count and no duration, while the same file without the extra flag answered '28 passed in 17.74s'. A targeted run that
# cannot say how many tests it ran has thrown away the one number that distinguishes "the pattern matched" from "the pattern
# matched nothing" - which is the same evidence fast_lane.py's exit-5 and exit-4 messages exist to protect.
#
# K= is passed through to pytest unchanged, so this target accepts a real -k expression (`K="csr_sign and not csr_generate"`)
# as well as one keyword. `make fast` instead reads bare keywords as ORed, because it joins them itself; see
# tools/fast_lane.py's HOW THE PATTERN IS READ.
test:
	@test -n "$(K)" || (echo "make test needs K=<pytest -k expression>" && exit 2)
	$(PY) -m pytest -p no:cacheprovider --no-cov -k "$(K)"

fast:
	$(PY) tools/fast_lane.py $(K)

# A documentation edit had no cheap target: `make fast` refuses to run without a -k pattern (exit 2, "no -k pattern
# given"), and a .md-only change has no code keyword to put in K=, so the only documented option left was the full
# gate. What a docs change actually owes is much less than that. MEASURED on this tree, re-measured rather than inherited:
# `make docs` exits 0 with **70 passed**, four runs: 3.49s / 3.56s / 3.61s / 3.63s (5,373 / 5,413 / 5,483 / 5,511 ms wall
# for the whole target), and `tools/check_version.py` alone measures 100-101 ms warm, 125 ms on a cold run. Four runs are
# quoted because one duration on this box is not reproducible enough to quote as a single number. The comment this replaced
# claimed "55 passed", and that claim was re-measured rather than inherited: counted by AST (test functions times their
# parametrize argument lengths) over `git show v0.7.2:tests/test_packaging.py` and `v0.7.2:tests/test_version.py`, and
# confirmed with `pytest --collect-only` in a detached worktree checked out at the tag, those two files answer 26 + 29 =
# 55 at v0.7.2, 34 + 29 = 63 at HEAD d3d2c8b, and 41 + 29 = 70 in this working tree — fifteen cases more than the
# sentence quoted: eight from the sdist `include` additions earlier in this pass (`REQUIRED_INCLUDES` grew 7 -> 11 entries,
# two parametrised tests per entry) and seven from this change's README assertions. That is exactly how a quoted count goes stale while the suite stays green, and the
# reason `make cov`'s own number is read out of a log file rather than retyped here.
# No gate duration is quoted against it: `make cov` has measured between 232s and 278s on this 2-CPU box across runs of one
# tree, so the comparison that survives is 'seconds versus minutes', not a ratio of two numbers.
#
# These two files are the whole of it because no test reads doc CONTENT: an AST scan of tests/*.py for read_text,
# read_bytes and open calls touching a .md path returns zero files (the prose-policing gates `tools/check_docs.py`,
# `tools/check_docstrings.py` and `tests/test_docstrings.py` were deleted in bc0031b). What survives is two
# references to doc *paths*: test_packaging.py's REQUIRED_INCLUDES asserts README.md, CHANGELOG.md,
# docs/page-map.md, docs/REFERENCE.md, docs/linux_install.md and assets/banner.png are in the sdist and exist on disk,
# and test_version.py asserts CHANGELOG carries this version. AGENTS.md is deliberately not one of them — it is tracked
# and gated but not shipped, the same posture SMOKE_TESTING.md has; both lists are asserted equal in both directions, so
# that decision is enforced by tests/test_packaging.py rather than left as an omission.
# Since this target grew `$(TREE_MANIFEST) --check`, a third fact is proven: README's shipped-tree claim and its fenced
# path block agree with the tree a commit would contain, count and set and order included. That is the coupling that
# `make ready` regenerates and `make gate` refuses to measure an unstamped tree for.
# That is also why a docs-only commit still owes `make gate` once: this target proves those three facts, not that the
# suite is green.
#
# Coverage is off for the same reason it is off in the fast lane. MEASURED again on this tree:
# `pytest --cov=mypki tests/test_packaging.py tests/test_version.py` prints 70 passed and TOTAL 3022 1736 43% (42.55%),
# then exits 1, because fail_under = 85 applies to any --cov run whatever subset was executed. A partial run does not
# measure a partial denominator; it measures nothing.
docs:
	$(PY) tools/check_version.py
	$(PY) $(TREE_MANIFEST) --check
	$(PY) -m pytest -p no:cacheprovider --no-cov $(DOC_TESTS)

version:
	$(PY) tools/check_version.py

# `inventory` writes one file answering the two questions a documentation edit has to ask before it starts: which paths
# does this repository track, and which of them cite a document section. It exists because answering them by grepping cost
# 113 read-only commands out of a 203-command pass (tools/doc_citations.py's header records the arithmetic). The file lands
# under reports/, which is gitignored: an inventory is one machine's answer about one tree, and committing it would freeze
# a path count into the repository that is false in the next commit.
inventory:
	@mkdir -p $(dir $(INVENTORY))
	$(PY) $(CITATIONS) > $(INVENTORY)
	@echo "inventory written: $(INVENTORY)"

# `ready` is the boundary between editing and gating. It regenerates everything that is generated (today, README's
# shipped-tree claim and its fenced block) and then stamps the tree, so `gate` has something to compare against. The two
# halves are one target because they have to be in that order: a stamp taken before the regeneration would name a tree
# that no longer exists by the time the gate reads it.
ready:
	$(PY) $(TREE_MANIFEST) --write
	$(PY) $(TREE_MANIFEST) --write-stamp

# `e2e` is the end-to-end harness: it mints its own throwaway CA, spawns a real server on an ephemeral port, drives
# SMOKE_TESTING.md §1-§16 over one socket, and cleans its scratch tree up after itself (exit 0 pass / 1 FAIL / 2 nothing
# checked — the same contract both shell harnesses had). It runs LAST in `gate` because it is the only gate that can say
# "the bytes a browser would have received are right": lint, mypy and pytest all answer questions about source, and a
# green suite with a broken download header is exactly the failure this project keeps measuring.
e2e:
	$(PY) tools/e2e_harness.py

# `gate` is two things in a fixed order: refuse, then measure. The guard lives in the recipe rather than in the
# prerequisite list because GNU make runs prerequisites before the recipe (MEASURED on this box, GNU Make 4.4.1:
# `all3: a | z` prints A, then Z-orderonly, then RECIPE-all3) — a guard written as a recipe would run last and gate
# anyway. So the recipe refuses first and only then asks for the steps, via one recursive make whose exit code propagates.
#
# The refusal is exit 2, the same shape `test:` uses when K= is empty: "you asked for something this tree cannot answer"
# rather than a failure of the tree. And the stamp is printed as the first line of every green run too, so a gate log
# names the tree it measured without anyone having to remember to ask (AGENTS.md rule 3).
#
# MEASURED on this tree, three timed runs each: with no stamp at all the refusal exits 2 in 16-17 ms (40 ms cold) and
# prints two lines; with a stamp that no longer matches it exits 2 in 117-129 ms, because that half pays for
# `$(TREE_MANIFEST) --fingerprint` (104-106 ms as a command line, of which 12.0 ms is the digest over 78 paths and 17.8 ms
# is fingerprint plus stamp write, both best of five in-process — the rest is interpreter start-up). Both refuse before
# `_gate-steps` is ever requested.
gate:
	@test -f $(GATE_STAMP) || (echo "gate refused: no $(GATE_STAMP) — run 'make ready' first" && exit 2)
	@stamped=$$(cat $(GATE_STAMP)); \
	current=$$($(PY) $(TREE_MANIFEST) --fingerprint); \
	echo "gate tree: $$current"; \
	if [ "$$stamped" != "gate tree: $$current" ]; then \
		echo "gate refused: the tree moved since 'make ready'"; \
		echo "  stamped: $$stamped"; \
		echo "  current: gate tree: $$current"; \
		exit 2; \
	fi
	$(MAKE) --no-print-directory _gate-steps

# The five steps a commit owes, split out so `gate`'s recipe can speak before them. Order is cheapest-first: a lint error
# found in 0.06s should not be followed by a four-minute suite against a tree that already failed.
_gate-steps: lint types version cov e2e

# The manifest comes from git, not from a hand-typed list and not from a directory walk. A directory walk would pick up
# runtime state that happens to be sitting in the tree (build/src/logs/mypki.log did exactly that once); a hand-typed
# list drifts the first time a file is added. `git ls-files` is the tree as committed — which is what was gated.
zip: gate
	@rm -rf $(STAGE) && mkdir -p $(STAGE)/$(DIST_NAME)
	git ls-files > $(STAGE)/manifest.txt
	tar cf - -T $(STAGE)/manifest.txt | tar xf - -C $(STAGE)/$(DIST_NAME)
	cd $(STAGE) && zip -q -r -X $(DIST_NAME).zip $(DIST_NAME) -x '*/manifest.txt'
	@echo "== leak scan (expect no matches; key material and runtime state must not ride along) =="
	@if unzip -l $(STAGE)/$(DIST_NAME).zip | awk '{print $$4}' \
	    | grep -E '^logs/|^src/logs/|\.pem$$|\.key$$|\.crt$$|\.csr$$|nohup\.out|\.coverage$$|__pycache__|^reports/|^\.venv/'; \
	then echo "LEAK FOUND — refusing to publish"; rm -f $(STAGE)/$(DIST_NAME).zip; exit 1; else echo "clean"; fi
	mv -f $(STAGE)/$(DIST_NAME).zip ../$(DIST_NAME).zip
	@rm -rf $(STAGE)
	@sha256sum ../$(DIST_NAME).zip

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache __pycache__ src/mypki/__pycache__ tests/__pycache__ tools/__pycache__
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -f .coverage
