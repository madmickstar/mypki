# mypki — every command this project runs, in one place.
#
# WHY THIS FILE EXISTS
#   Until now the commands lived as prose in README.md and docs/CHANGE_POLICY.md, and each pass re-derived them from
#   memory. That is where release time went: reconstructing which exact invocation produced a number, and retyping
#   `--cov-fail-under=85` by hand every run (the floor was never declared in pyproject.toml). A target name is cheaper
#   to remember than a command line, and a command written once cannot disagree with itself.
#
# START HERE
#   make fast K=sign      while editing: scoped lint + version chain + targeted pytest -k, no coverage
#   make docs             a change that touches only .md: version chain + the two doc-aware test files, no coverage
#   make gate             before committing: lint, types, version chain, full suite with coverage, then the harness
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

.DEFAULT_GOAL := help

.PHONY: help lint types cov test fast docs version gate e2e zip clean

help:
	@echo "mypki $(VERSION) — targets:"
	@echo "  make fast K=<expr>   scoped ruff + version chain + pytest -k <expr> (no coverage)"
	@echo "  make docs            .md-only change: version chain + $(DOC_TESTS) (no coverage)"
	@echo "  make lint            ruff check + format --check, scoped to src tests tools"
	@echo "  make types           mypy src"
	@echo "  make cov             full suite with coverage; floor 85 from pyproject.toml"
	@echo "  make test K=<expr>   targeted pytest only, coverage disabled"
	@echo "  make version         tools/check_version.py: 0 consistent, 1 drift, 2 cannot check"
	@echo "  make e2e             the end-to-end harness: real server, real HTTP, real openssl"
	@echo "  make gate            everything a commit owes (lint types version cov e2e)"
	@echo "  make zip             build $(DIST_NAME).zip from git ls-files, leak-scan it, prove digests"
	@echo "  make clean           remove caches, .coverage and staging dirs"

lint:
	$(PY) -m ruff check src tests tools
	$(PY) -m ruff format --check src tests tools

types:
	$(PY) -m mypy src

cov:
	$(PY) -m pytest --cov=mypki --cov-report=term-missing

test:
	@test -n "$(K)" || (echo "make test needs K=<pytest -k expression>" && exit 2)
	$(PY) -m pytest -q -p no:cacheprovider --no-cov -k "$(K)"

fast:
	$(PY) tools/fast_lane.py $(K)

# A documentation edit had no cheap target: `make fast` refuses to run without a -k pattern (exit 2, "no -k pattern
# given"), and a .md-only change has no code keyword to put in K=, so the only documented option left was the full
# gate. What a docs change actually owes is much less than that, MEASURED as `make docs` on this tree: exit 0, 55 passed,
# self-reported 3.29s and 3.97s across two runs (4,971ms and 5,694ms wall). tools/check_version.py alone measures 100ms.
# No gate duration is quoted against it: `make cov` has measured between 232s and 278s on this 2-CPU box across runs of one
# tree, so the comparison that survives is 'seconds versus minutes', not a ratio of two numbers.
#
# These two files are the whole of it because no test reads doc CONTENT: an AST scan of tests/*.py for read_text,
# read_bytes and open calls touching a .md path returns zero files (the prose-policing gates `tools/check_docs.py`,
# `tools/check_docstrings.py` and `tests/test_docstrings.py` were deleted in bc0031b). What survives is two
# references to doc *paths*: test_packaging.py's REQUIRED_INCLUDES asserts README.md, CHANGELOG.md and
# docs/page-map.md are in the sdist and exist on disk, and test_version.py asserts CHANGELOG carries this version.
# That is also why a docs-only commit still owes `make gate` once: this target proves those two facts, not that the
# suite is green.
#
# Coverage is off for the same reason it is off in the fast lane. Measured here:
# `pytest --cov=mypki tests/test_packaging.py tests/test_version.py` prints 55 passed and TOTAL 3022 1736 43% and
# then exits 1, because fail_under = 85 applies to any --cov run whatever subset was executed. A partial run does not
# measure a partial denominator; it measures nothing.
docs:
	$(PY) tools/check_version.py
	$(PY) -m pytest -p no:cacheprovider --no-cov $(DOC_TESTS)

version:
	$(PY) tools/check_version.py

# `e2e` is the end-to-end harness: it mints its own throwaway CA, spawns a real server on an ephemeral port, drives
# SMOKE_TESTING.md §1-§16 over one socket, and cleans its scratch tree up after itself (exit 0 pass / 1 FAIL / 2 nothing
# checked — the same contract both shell harnesses had). It runs LAST in `gate` because it is the only gate that can say
# "the bytes a browser would have received are right": lint, mypy and pytest all answer questions about source, and a
# green suite with a broken download header is exactly the failure this project keeps measuring.
e2e:
	$(PY) tools/e2e_harness.py

gate: lint types version cov e2e

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
