"""mypki -- a self-hosted mini certificate authority with a browser front end.

Why this package exists: running an internal CA usually means either a heavyweight appliance or a shell full of
`openssl` invocations. mypki collapses that to one root key on disk, seven pages in one sidebar nav and three CLI
commands, so one operator can issue properly-profiled X.509 certificates on Linux or Windows without leaving Python's
`cryptography` library. What it deliberately is *not*: an ACME/SCEP/EST service, a multi-tenant CA, or a REST API (see
docs/REFERENCE.md "Known gaps").

`__version__` here is the single source of truth for the whole release chain -- pyproject.toml declares
`dynamic = ["version"]`, hatchling reads exactly this line by static analysis, CHANGELOG.md must carry a section
for it, and `tools/check_version.py` proves all four agree. Bump this line, nothing else.
"""

from __future__ import annotations

__version__ = "0.7.3"

from .app import create_app
from .config import Settings, get_settings

__all__ = ["Settings", "__version__", "create_app", "get_settings"]
