"""`python -m mypki` → the same entry point as the `mypki` console script.

Why this exists: after `pip install mypki` the console script is available, but an operator working inside a virtualenv
from a source checkout, or one debugging a wheel they just built without installing it, needs a route in that does not
depend on a script entry being on PATH. Two ways to start the same CLI means one of them can fail without hiding the
other (`docs/linux_install.md`, which the README's Quick Start links to, spells the CLI as `mypki …`; the module
route is what works from a source checkout).

Before this suite grew its subprocess tests, neither route was exercised anywhere in the
suite: `docs/linux_install.md` spells the CLI as `mypki …`, `.github/workflows/ci.yml` never invokes it at all, and
`tools/e2e_harness.py` spawns its own server but reaches it over HTTP rather than through `python -m`. That is the same
blind spot that let `init-ca --key-type ec` ship broken and unexercised (see CHANGELOG *Fixed*).

`main()` returns an int rather than calling `sys.exit` itself, so tests can assert exit codes 0/1/2/3 directly; the
`SystemExit` conversion happens here, at the boundary where a process actually exists.
"""

from __future__ import annotations

import sys

from .cli import main

# The pragma is honest here rather than a coverage dodge: this guard only runs when the module IS the process
# entry point, which cannot happen inside pytest's own process. A subprocess test proves the route works but
# cannot move this number, because coverage traces the parent process only (`python -m mypki --version` leaves
# __main__.py at 0% while an in-process `import mypki.__main__` reports 100%). What actually covers the route is
# test_python_dash_m_is_a_working_route_to_the_cli in tests/test_packaging.py.
if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
