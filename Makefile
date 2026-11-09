# mypki — every command this project runs, in one place.
#
# CI calls these same targets (see .github/workflows/ci.yml), so a command that exists only in CI and nowhere else
# cannot drift into being the one that actually matters. Commands are written once here rather than repeated as prose.
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

# This checkout's venv when it exists, otherwise the invoking interpreter — the same rule tools/fast_lane.py uses.
# A half-created .venv must fall back rather than fail.
PY := $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)

VERSION := $(shell sed -n 's/^__version__ = "\([^"]*\)"$$/\1/p' src/mypki/__init__.py)
DIST_NAME := mypki-$(VERSION)
STAGE := /tmp/$(DIST_NAME)-stage

# Release artifacts land outside the source tree, one directory up: dist/ holds every zip and bundle this project has
# produced, and a build tree that carries its own artifacts is a build tree that can be mistaken for a release.
RELEASE_DIR := ../dist

# K= is the pytest -k expression for `make fast` and `make test`. Empty is a mistake, not a full run: an empty pattern
# would silently select nothing and read as green.
K ?=

# The two test files that know documents exist at all (see the `docs` target for why these two and not more).
DOC_TESTS := tests/test_packaging.py tests/test_version.py

#: The tool that owns "which paths does this repository track", and therefore owns README's structure tree and its count.
TREE_MANIFEST := tools/tree_manifest.py

#: Written by `ready`, read by `gate`. Gitignored on purpose: it is one machine's statement about one working tree, not
#: a fact about the release. If it were tracked it would join both halves of the fingerprint, so a gate that stamps its
#: own tree would invalidate its own stamp and README's regenerated count would grow by one on every run.
GATE_STAMP := .gate-ready

#: `inventory`'s output. reports/ is gitignored for the same reason as the harness ledger (see .gitignore).
INVENTORY := reports/inventory.txt

#: The doc-citation enumerator `inventory` runs. Named separately from `TREE_MANIFEST`: they answer two different
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
	@echo "  make zip             build $(DIST_NAME).zip from git ls-files into $(RELEASE_DIR), leak-scan it, print sha256"
	@echo "  make clean           remove caches, .coverage, staging dirs and runtime scratch"

lint:
	$(PY) -m ruff check src tests tools
	$(PY) -m ruff format --check src tests tools

types:
	$(PY) -m mypy src

cov:
	$(PY) -m pytest --cov=mypki --cov-report=term-missing

# No `-q` on any pytest line in this file: pyproject.toml's addopts already declares `-q --strict-markers`, and a second
# `-q` stacks to `-qq`, which suppresses the summary line — the pass count and duration that distinguish "the pattern
# matched" from "the pattern matched nothing". tests/test_fast_lane.py asserts this rule against the lines below.
#
# K= is passed to pytest unchanged, so a real -k expression works (`K="csr_sign and not csr_generate"`) as well as one
# keyword. `make fast` instead reads bare keywords as ORed, because it joins them itself; see tools/fast_lane.py.
test:
	@test -n "$(K)" || (echo "make test needs K=<pytest -k expression>" && exit 2)
	$(PY) -m pytest -p no:cacheprovider --no-cov -k "$(K)"

fast:
	$(PY) tools/fast_lane.py $(K)

# The cheap target for a change that touches only .md files: `make fast` refuses without a -k pattern and a prose edit
# has no code keyword to put in K=, so without this target the only documented option for a docs change was the full
# gate. It proves three facts — the version chain agrees, README's structure tree matches git, and the two doc-aware
# test files pass — and nothing else: it is not evidence that the suite is green, which a docs-only commit still owes
# once via `make gate`. Coverage is off because a partial --cov run measures a partial denominator and exits 1 on the
# floor whatever subset was executed.
docs:
	$(PY) tools/check_version.py
	$(PY) $(TREE_MANIFEST) --check
	$(PY) -m pytest -p no:cacheprovider --no-cov $(DOC_TESTS)

version:
	$(PY) tools/check_version.py

# Writes one file answering the two questions a documentation edit has to ask before it starts: which paths this
# repository tracks, and which of them cite a document section. Answering them one grep at a time is what a measured
# pass spent 113 read-only commands on (tools/doc_citations.py's header records the arithmetic). reports/ is gitignored:
# an inventory is one machine's answer about one tree, and committing it would freeze a path count that is false in the
# next commit.
inventory:
	@mkdir -p $(dir $(INVENTORY))
	$(PY) $(CITATIONS) > $(INVENTORY)
	@echo "inventory written: $(INVENTORY)"

# The boundary between editing and gating. Regenerate everything that is generated (today, README's structure tree and
# its path count), then stamp the tree so `gate` has something to compare against. One target, in that order: a stamp
# taken before the regeneration would name a tree that no longer exists by the time the gate reads it.
ready:
	$(PY) $(TREE_MANIFEST) --write
	$(PY) $(TREE_MANIFEST) --write-stamp

# The end-to-end harness: mints its own throwaway CA, spawns a real server on an ephemeral port, drives SMOKE_TESTING.md
# §1-§16 over one socket, and cleans its scratch tree up after itself (exit 0 pass / 1 FAIL / 2 nothing checked). It runs
# LAST in `gate` because it is the only step that can say "the bytes a browser would have received are right" — lint,
# mypy and pytest all answer questions about source.
e2e:
	$(PY) tools/e2e_harness.py

# Two things in a fixed order: refuse, then measure. The guard lives in the recipe rather than in the prerequisite list
# because GNU make runs prerequisites before the recipe — a guard written as a prerequisite would run last and gate
# anyway. Refusal is exit 2 (the same shape `test:` uses when K= is empty): "you asked for something this tree cannot
# answer", not a failure of the tree. The stamp is printed as the first line of every green run too, so a gate log names
# the tree it measured without anyone having to remember to ask (AGENTS.md rule 3).
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

# The five steps a commit owes, split out so `gate`'s recipe can speak before them. Order is cheapest-first: a lint
# error found in 0.06s should not be followed by a four-minute suite against a tree that already failed.
_gate-steps: lint types version cov e2e

# The manifest comes from git, not from a hand-typed list and not from a directory walk: a walk picks up runtime state
# that happens to be sitting in the tree (build/src/logs/mypki.log did exactly that once), and a hand-typed list drifts
# the first time a file is added. Plain `git ls-files` — not the three-flag form README's tree uses — because a release
# artifact is built from what is committed, not from what is merely present.
zip: gate
	@mkdir -p $(RELEASE_DIR)
	@rm -rf $(STAGE) && mkdir -p $(STAGE)/$(DIST_NAME)
	git ls-files > $(STAGE)/manifest.txt
	tar cf - -T $(STAGE)/manifest.txt | tar xf - -C $(STAGE)/$(DIST_NAME)
	cd $(STAGE) && zip -q -r -X $(DIST_NAME).zip $(DIST_NAME) -x '*/manifest.txt'
	@echo "== leak scan (expect no matches; key material and runtime state must not ride along) =="
	@if unzip -l $(STAGE)/$(DIST_NAME).zip | awk '{print $$4}' \
	    | grep -E '^logs/|^src/logs/|\.pem$$|\.key$$|\.crt$$|\.csr$$|nohup\.out|\.coverage$$|__pycache__|^reports/|^\.venv/'; \
	then echo "LEAK FOUND — refusing to publish"; rm -f $(STAGE)/$(DIST_NAME).zip; exit 1; else echo "clean"; fi
	mv -f $(STAGE)/$(DIST_NAME).zip $(RELEASE_DIR)/$(DIST_NAME).zip
	@rm -rf $(STAGE)
	@sha256sum $(RELEASE_DIR)/$(DIST_NAME).zip

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache __pycache__ src/mypki/__pycache__ tests/__pycache__ tools/__pycache__
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -f .coverage $(GATE_STAMP) nohup.out
	@echo "clean: caches, .coverage, $(GATE_STAMP) and runtime scratch removed"
