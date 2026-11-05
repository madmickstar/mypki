"""Fixtures for mypki's tests, and why every one of them is synthetic.

mypki has no upstream service to stand in for, so "hermetic" here means something specific: **no test may read or write
the operator's real data directory.** The reference project achieves hermeticity by deselecting a `live` marker; mypki
has nothing that needs the network, so the equivalent posture is enforced instead by pointing `MYPKI_DATA_DIR` at a
temporary directory before any `Settings` object is built (STYLE §8). That single fixture is what makes it safe to run
this suite on a machine that has a real CA on it.

Three things the fixtures provide:

1. `data_dir` — an autouse fixture that redirects the data dir into `tmp_path` and clears the `lru_cache` on
   `get_settings()`. Autouse because a test that forgets to request it is the failure mode; the protection has to apply
   by default rather than by remembering.
2. `throwaway_ca` — a real CA (real keys, real X.509) created inside that temporary directory. Real rather than mocked
   because mypki's whole surface is certificate semantics: a stand-in certificate object would let a wrong extension
   profile pass every test that never inspects a signature.
3. `client` — a `TestClient` bound to an app whose CA was loaded from the temporary directory, so the web tests exercise
   the same startup path `mypki serve` uses (key loaded once, handed to the app as state) rather than a special
   test-only
   wiring.

A note on `ScratchClient`: it disables cookie persistence by default. Half of `test_views.py` is about what happens when
a session does *not* carry the right state — a POST with no CSRF token, a download link from an expired artifact — and a
client that silently keeps cookies makes those tests assert nothing at all. Tests that need a session pass
`persist_cookies=True` and say so in their own docstring.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from mypki import paths
from mypki.app import create_app
from mypki.ca import CaBundle, init_ca, load_ca
from mypki.config import Settings
from mypki.keys import KeySpec

# --------------------------------------------------------------------------------- hermeticity (autouse)


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point every data-dir resolution at `tmp_path`, for every test, with no opt-in.

    Runs before `Settings` is constructed anywhere in the test, and clears `get_settings`'s cache on both entry
    and exit:
    a cached `Settings` from a previous test would carry the previous test's temporary directory, and a cached one left
    behind here would carry *this* test's now-deleted directory into the next test. Both produce failures that look like
    path bugs in `paths.py` rather than as fixture leakage.
    """
    root = tmp_path / "data"
    monkeypatch.setenv(paths.DATA_DIR_ENV, str(root))
    monkeypatch.delenv("MYPKI_SECRET_KEY", raising=False)
    monkeypatch.delenv("MYPKI_CA_PASSPHRASE", raising=False)

    from mypki.config import get_settings

    get_settings.cache_clear()
    try:
        yield root
    finally:
        get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _no_real_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep `~/.local/share` and `%LOCALAPPDATA%` out of every resolution.

    The XDG variables are pointed at `tmp_path` so a test that checks the *default* branch proves the default branch's
    rules rather than proving that this developer's home directory exists. Without this, `test_paths.py` would pass on a
    machine with no CA and fail on one with a CA — the definition of a non-hermetic test.
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    # `USERPROFILE` is the Windows spelling of "home": `ntpath.expanduser("~")` -- and therefore `WindowsPath.home()`
    # -- reads it, not `HOME`. Pinning only `HOME` left every Windows-hosted run resolving mypki's fallback branches
    # against the developer's real profile. **MEASURED on a real Windows 10 host:** five tests failed that way, one of
    # them reading `C:\Users\Michael\.local\share\mypki` out of a test that had just set `HOME` to a temp dir. A
    # non-hermetic fixture is exactly what this function exists to prevent, and the leak was invisible on Linux.
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "users" / "me"))


@pytest.fixture(autouse=True)
def _no_stray_env_file(tmp_path: Path) -> Iterator[None]:
    """Run every test from its own empty directory, so a developer's `.env` cannot answer for an assertion.

    `Settings` declares `env_file=".env"` (config.py), and pydantic-settings resolves that relative to the
    **current working directory**. That is correct behaviour for an operator and a hermeticity hole for a test
    suite: a `.env` in the repository root silently re-defines whichever default a test happens to be asserting.
    **MEASURED on a real Windows 10 host:** an operator following this project's own README (`cp .env.example
    .env`, then set `MYPKI_HOST=0.0.0.0`) turned two green tests red, with failures that read like path bugs in
    the product -- `'https://127.0.0.1:8443'` missing from a banner that said `https://0.0.0.0:8443`, and
    `cannot bind 127.0.0.1:8443` missing from an error naming `0.0.0.0`. Reproduced on Linux with a one-line
    `.env` holding `MYPKI_MAX_SANS=7`: `get_settings().max_sans` became 7, so the file reaches every reader in
    the process, including `cli.settings_with_cli_overrides`. The `settings` fixture below already passes
    `_env_file=None`, but that only protects tests that use it; a test driving `cli.main()` cannot pass it.

    Chdir into a fresh empty subdirectory of `tmp_path` for the duration of each test: no `.env` can be found
    there, and it is not the directory any default resolves to, which keeps assertions of the form
    `data dir <cwd>` absent from stderr meaningful rather than trivially true. **MEASURED:** pytest's
    `pythonpath` entries (`src`, `tools`) are absolute before fixtures run, so `import check_version` survives
    the chdir; test_version.py and test_packaging.py both stayed green with this fixture active.
    """
    import os
    import tempfile

    previous = Path.cwd()
    # Deliberately a *sibling* of `tmp_path`, never a child of it: `test_packaging.py` asserts that `tmp_path`
    # itself is empty after a CLI route runs, and a directory created inside it would read as the CLI having
    # written something -- which is exactly what that assertion exists to catch.
    workdir = Path(tempfile.mkdtemp(prefix=f"{tmp_path.name}.cwd-", dir=tmp_path.parent))
    try:
        os.chdir(workdir)
        yield
    finally:
        os.chdir(previous)
        # The directory is left to pytest's basetemp garbage collection rather than removed here. **MEASURED:**
        # `monkeypatch.chdir` records the cwd as it finds it -- which, for a test that runs after this fixture,
        # *is* `workdir` -- and restores it in its own teardown; deleting `workdir` here made that restore raise
        # `FileNotFoundError` at teardown in `test_paths.py`. Deleting nothing is the only ordering-safe choice,
        # and it is also the Windows-safe one: a directory a process is standing in cannot be removed.


# --------------------------------------------------------------------------------------------- settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings pinned to the temporary data dir, with no `.env` influence.

    Constructed directly rather than via `get_settings()` so a developer's real `.env` in the repository root cannot
    change what a test asserts. `_env_file=None` is the documented pydantic-settings way to say that (MEASURED: without
    it, a stray `.env` in cwd is read and a knob in it silently re-defines a default the test is checking).
    """
    return Settings(  # type: ignore[call-arg]
        data_dir=tmp_path / "data",
        log_file=tmp_path / "logs" / "mypki.log",
        secret_key="test-session-secret-not-a-real-one",
        _env_file=None,
    )


@pytest.fixture
def data_root(settings: Settings) -> Path:
    return settings.data_dir or (Path.cwd() / "data")


# ------------------------------------------------------------------------------------------------- CA


@pytest.fixture
def throwaway_ca(data_root: Path) -> CaBundle:
    """A real RSA-3072 root CA created inside the isolated data dir.

    Real keys, real certificate, real file permissions — because mypki's correctness claims are about X.509 semantics
    (which extensions a leaf carries, whether a chain verifies) and a fabricated certificate object would let a wrong
    profile pass every test that does not verify a signature. Cost: RSA-3072 key generation takes about a third of a
    second per test that asks for it, which is the price of asserting something true.
    """
    init_ca(
        data_root,
        common_name="mypki Test CA",
        organization="mypki tests",
        country="XX",
        spec=KeySpec.from_string("rsa-3072"),
        days=3650,
    )
    return load_ca(data_root)


@pytest.fixture
def ca_bundle(throwaway_ca: CaBundle) -> CaBundle:
    """Alias so tests can name what they actually want."""
    return throwaway_ca


@pytest.fixture
def leaf_keypair() -> rsa.RSAPrivateKey:
    """A throwaway leaf key for signing tests that do not need a CA."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# ----------------------------------------------------------------------------------------------- clients


class ScratchClient(TestClient):
    """A `TestClient` that does not persist cookies unless asked to.

    See the module docstring: half of the CSRF and one-shot-download tests are about a request arriving with the *wrong*
    session state, and automatic cookie persistence turns each of those into an accidental happy path.
    """

    def __init__(self, app: object, *, persist_cookies: bool = False) -> None:
        super().__init__(app, base_url="http://testserver")  # type: ignore[arg-type]
        if not persist_cookies:
            self.cookies.clear()


@pytest.fixture
def client(settings: Settings, ca_bundle: CaBundle) -> Iterator[ScratchClient]:
    """A client for an app whose CA was loaded once at startup, from the isolated data dir.

    `ca_bundle` is passed in rather than discovered, mirroring what `mypki serve` does (page-map §6): the CLI loads and
    decrypts the key once and hands it to the factory. A test that let `create_app` discover the CA would be testing a
    path no operator ever runs.
    """
    app = create_app(settings, ca_bundle=ca_bundle, session_secret="test-session-secret-not-a-real-one")
    with ScratchClient(app, persist_cookies=False) as client:
        yield client


@pytest.fixture
def session_client(settings: Settings, ca_bundle: CaBundle) -> Iterator[ScratchClient]:
    """A client that *does* keep cookies — the two-step signing flow needs one.

    Named separately from `client` so the difference is visible at the call site: a test using this one is asserting a
    stateful flow, and a test using `client` is asserting a single request's behaviour.
    """
    app = create_app(settings, ca_bundle=ca_bundle, session_secret="test-session-secret-not-a-real-one")
    with ScratchClient(app, persist_cookies=True) as client:
        yield client


@pytest.fixture
def client_without_ca(settings: Settings) -> Iterator[ScratchClient]:
    """An app on a host with no CA at all — the state page-map §1 says every page must handle.

    No `ca_bundle` argument, so `create_app` runs its discovery path and finds nothing. That is deliberate: the "run
    `mypki init-ca`" notice is behaviour that has to be proven for the app as actually constructed, not for a
    stubbed one.
    """
    app = create_app(settings)
    with ScratchClient(app, persist_cookies=False) as client:
        yield client


# ------------------------------------------------------------------------------- CSR helpers (shared shapes)


@pytest.fixture
def sample_csr_pem() -> str:
    """A valid PEM CSR with DNS + IP SANs, generated fresh per test.

    Generated rather than checked in as a fixture file: a committed CSR is a fixed key that eventually expires or gets
    distrusted by some toolchain update, and every test using it then fails for a reason unrelated to the code under
    test. The cost is one 2048-bit keypair per test (~100 ms), which buys a CSR that is always genuinely valid.
    """
    from mypki.csr import CsrFields, build_csr
    from mypki.validators import SanSet

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fields = CsrFields(
        common_name="server.internal",
        sans=SanSet(dns=("server.internal", "*.lab.internal"), ips=("10.0.0.7",)),
        organization="mypki tests",
        country="XX",
        email="ops@example.test",
    )
    return build_csr(fields, key)


@pytest.fixture
def sample_details(sample_csr_pem: str):
    """The validated view of `sample_csr_pem`, for signing tests that want details rather than PEM."""
    from mypki.csr import parse_and_validate_csr

    return parse_and_validate_csr(sample_csr_pem, 32000)


# ------------------------------------------------------------------------------------ misc helpers


@pytest.fixture
def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------- shared assertion helpers


def csrf_token(client: TestClient, path: str) -> str:
    """Read the CSRF token a page renders, from the client's own live session.

    Needs a cookie-persisting client (`session_client`): with `ScratchClient`'s default the GET that produced the token
    and the POST that submits it would be two different sessions, and every such test would silently be testing
    "no token in this session" rather than the form. Fails loudly rather than returning `None`, because a missing token
    means the template stopped rendering the field -- which is the bug, not a detail of this helper.
    """
    response = client.get(path)
    if response.status_code != 200:
        raise AssertionError(f"{path} returned {response.status_code}; cannot read a CSRF token from it")
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    if match is None:
        raise AssertionError(f"no csrf_token field found in {path}")
    return match.group(1)


def snapshot_tree(root: Path) -> dict[str, tuple[int, str]]:
    """Every file under `root` as `{relative path: (size in bytes, sha256 of content)}`.

    The byte-for-byte assertion `test_csr_generate.py` needs is a *tree* comparison, not a "did the DB file appear"
    check: a generation that appended one row to `issued.db`, or touched a CA file's mtime-and-content, changes a hash
    here. Directories are included as zero-length entries so an empty new directory is caught too.
    """
    if not root.exists():
        return {}
    entries: dict[str, tuple[int, str]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            entries[relative] = (0, "dir")
        else:
            entries[relative] = (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
    return entries


def pem_block_count(text: str, marker: str) -> int:
    """Count PEM armour occurrences, not lines.

    Shared because the same assertion appears in several files and `text.count(marker)` is the honest form of it; a test
    that counts lines (`sum(1 for line in text.splitlines() if marker in line)`) answers 1 for two blocks on one
    line and
    cannot tell a chain from a single certificate.
    """
    return text.count(marker)


__all__ = ["ScratchClient", "csrf_token", "pem_block_count", "snapshot_tree"]
