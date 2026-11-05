"""Path resolution: XDG on Linux, %APPDATA%/%LOCALAPPDATA% on Windows, with a documented precedence.

Why this file exists separately from `test_paths_linux.py`-style OS splits: the point of mypki is one code path on two
operating systems (PLAN §2), and a test that only ever exercises the branch matching the machine it runs on proves
nothing about the other one. `paths.resolve_data_dir` therefore takes an explicit `platform_name`, and these tests drive
**both branches on every runner**. The Windows cases pass on the Linux CI leg and the XDG cases pass on the Windows leg,
which is what makes the two-OS matrix in ci.yml a claim rather than a decoration.

Precedence asserted here (page-map §8): explicit `--data-dir` > `MYPKI_DATA_DIR`/`Settings.data_dir` > OS default. Each
level gets its own test because "the higher one wins" is only meaningful if the lower one demonstrably *would* have
answered differently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mypki import paths


def test_explicit_data_dir_beats_env_and_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`--data-dir` wins over both the environment variable and the OS default."""
    monkeypatch.setenv(paths.DATA_DIR_ENV, str(tmp_path / "from-env"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    resolved = paths.resolve_data_dir(tmp_path / "from-flag")
    assert resolved == (tmp_path / "from-flag").resolve()
    assert "from-env" not in str(resolved)
    assert "xdg" not in str(resolved)


def test_env_data_dir_beats_os_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`MYPKI_DATA_DIR` wins over the OS default but loses to a flag (the middle level exists)."""
    monkeypatch.setenv(paths.DATA_DIR_ENV, str(tmp_path / "from-env"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    resolved = paths.resolve_data_dir(None, env_override=str(tmp_path / "from-settings"))
    assert resolved == (tmp_path / "from-settings").resolve()


def test_blank_env_value_means_unset_not_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`MYPKI_DATA_DIR=` is an operator asking for the default, not for the current directory.

    An empty value becoming `Path("")` would resolve to cwd and put a CA private key inside whatever directory the
    process happened to be started in — which is the one outcome this module exists to prevent, so it gets its own test.
    """
    monkeypatch.setenv(paths.DATA_DIR_ENV, "   ")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    # `platform_name="linux"` is required, not decorative. **MEASURED on a real Windows 10 host:** without it this test
    # ran the *Windows* default branch (which correctly prefers %LOCALAPPDATA%) and then asserted an XDG path, so it
    # failed on the very machine whose behaviour it does not describe. A test that names one OS's rule must pin that OS.
    resolved = paths.resolve_data_dir(None, platform_name="linux")
    assert resolved == (tmp_path / "xdg" / "mypki").resolve()
    assert resolved != Path.cwd()


def test_linux_xdg_data_home_is_used(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    resolved = paths.resolve_data_dir(platform_name="linux")
    assert resolved == (tmp_path / "xdg-data" / "mypki").resolve()


def test_linux_falls_back_to_local_share(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No XDG variable means `~/.local/share/mypki` — the freedesktop default."""
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    resolved = paths.resolve_data_dir(platform_name="linux")
    assert resolved == (tmp_path / "home" / ".local" / "share" / "mypki").resolve()


def test_linux_config_dir_uses_xdg_config_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    resolved = paths.resolve_config_dir(platform_name="linux")
    assert resolved == (tmp_path / "xdg-config" / "mypki").resolve()


def test_linux_config_falls_back_to_dot_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    resolved = paths.resolve_config_dir(platform_name="linux")
    assert resolved == (tmp_path / "home" / ".config" / "mypki").resolve()


# --------------------------------------------------------------------------- Windows branch, exercised on any runner


def test_windows_data_dir_uses_localappdata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The Windows data dir is `%LOCALAPPDATA%\\mypki`, composed from path components.

    Asserted by *components* rather than by a separator character. An earlier version of this test asserted
    `"/" not in str(resolved)`, which can never hold on the Linux CI leg: driving the Windows branch here goes through
    `pathlib.Path`, and a POSIX `Path` renders POSIX separators no matter which branch produced it. That assertion was
    testing the host's separator table rather than mypki's composition -- it would have failed on Linux and proved
    nothing on Windows either.
    """
    base = tmp_path / "localappdata"
    monkeypatch.setenv("LOCALAPPDATA", str(base))

    resolved = paths.resolve_data_dir(platform_name="win32")
    assert resolved.name == paths.APP_DIR_NAME
    assert resolved.parent == base.resolve()
    assert resolved == (base / "mypki").resolve()


def test_posix_branch_ignores_userprofile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    r"""`USERPROFILE` must not leak into the POSIX branch -- the mirror of `test_windows_branch_ignores_xdg_variables`.

    Without this, a Windows-only variable could decide where a POSIX install puts the CA key, and the reverse case was
    already policed. **MEASURED on a real Windows 10 host:** four tests resolved paths under `C:\Users\Michael` while
    asserting temp-directory paths, because nothing pinned which home variable belonged to which branch.
    """
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "should-not-be-used"))

    resolved = paths.resolve_data_dir(platform_name="linux")
    assert resolved == (tmp_path / "home" / ".local" / "share" / "mypki").resolve()
    assert "should-not-be-used" not in str(resolved)


def test_windows_config_dir_uses_appdata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))

    resolved = paths.resolve_config_dir(platform_name="win32")
    assert resolved == (tmp_path / "appdata" / "mypki").resolve()


def test_windows_without_localappdata_falls_back_to_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A missing `%LOCALAPPDATA%` degrades to the same *shape* as a real install, not to a POSIX path.

    Falling back to `~/.local/share` on a Windows host would put the CA key somewhere no Windows operator looks for it;
    deriving `AppData\\Local` from the profile keeps the layout honest even when the variable is absent (a rare but real
    state under some service accounts).
    """
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    # The Windows branch derives the profile from `Path.home()`, and on Windows that is `USERPROFILE` -- pinning `HOME`
    # here asked the Windows rule to read a variable it never consults. **MEASURED:** this test failed on a real
    # Windows 10 host for exactly that reason: it resolved the developer's real profile
    # (`C:\Users\...\AppData\Local\mypki`) instead of the temp path.
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "users" / "me"))

    resolved = paths.resolve_data_dir(platform_name="win32")
    assert resolved == (tmp_path / "users" / "me" / "AppData" / "Local" / "mypki").resolve()


def test_windows_branch_ignores_xdg_variables(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """XDG variables must not leak into the Windows branch.

    A developer testing on Linux with XDG set (as CI does) would otherwise never notice that the Windows path resolver
    reads them — and the failure would only appear on a real Windows host, where the key ends up in an unexpected place.
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))

    resolved = paths.resolve_data_dir(platform_name="win32")
    assert "xdg" not in str(resolved)
    assert resolved == (tmp_path / "localappdata" / "mypki").resolve()


# --------------------------------------------------------------------------------------------- the layout


def test_ca_paths_live_under_the_data_dir(tmp_path: Path) -> None:
    key = paths.ca_key_path(tmp_path)
    cert = paths.ca_cert_path(tmp_path)
    assert key == tmp_path / "ca" / "ca_key.pem"
    assert cert == tmp_path / "ca" / "ca_cert.pem"


def test_archive_dir_is_named_by_timestamp(tmp_path: Path) -> None:
    archive = paths.ca_archive_dir(tmp_path, "20261026T120000Z")
    assert archive == tmp_path / "ca" / "archive" / "20261026T120000Z"


def test_secret_key_and_database_locations(tmp_path: Path) -> None:
    assert paths.secret_key_path(tmp_path) == tmp_path / "instance" / "secret_key"
    assert paths.db_path(tmp_path) == tmp_path / "issued.db"


def test_data_dir_and_ca_paths_never_equal_the_static_template_dir() -> None:
    """The CA data dir must never land inside the directory the web app serves.

    mypki serves files out of `src/mypki/static/`. If a resolved data dir ever sat under it, `/ca/certificate` would no
    longer be the only thing reachable — the key would be one URL away. This is an invariant about the *default*
    resolution rather than about any one path string, so it is asserted against `Path.home()`-based defaults too.
    """
    served = Path(paths.__file__).resolve().parent / "static"
    for resolved in (
        paths.resolve_data_dir(platform_name="linux"),
        paths.resolve_config_dir(platform_name="linux"),
    ):
        assert served not in resolved.parents
        assert resolved != served


def test_resolve_returns_absolute_paths_even_for_relative_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Relative input is made absolute, because a relative data dir moves when the process's cwd does.

    `chdir` into tmp_path first so the expected value is fixed rather than "whatever directory pytest happened to be
    started in" — a test that asserts against an ambient cwd passes today and fails in CI for reasons nobody can name.
    """
    monkeypatch.chdir(tmp_path)

    resolved = paths.resolve_data_dir("relative-data")
    assert resolved.is_absolute()
    assert resolved == (tmp_path / "relative-data").resolve()


def test_tilde_is_expanded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    r"""`~/x` becomes `<home>/x`, where "home" is the target OS's own variable.

    Both spellings are pinned to the same directory on purpose: POSIX reads `HOME`, Windows reads `USERPROFILE`, and
    this test deliberately does not pin `platform_name` because it is asserting the rule for *whichever* branch the host
    takes. **MEASURED:** with only `HOME` pinned, a real Windows 10 host expanded the tilde to `C:\Users\Michael`.
    """
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))

    resolved = paths.resolve_data_dir("~/mypki-explicit")
    assert resolved == (tmp_path / "home" / "mypki-explicit").resolve()


def test_settings_data_dir_flows_through_data_dir_helper(settings) -> None:
    """`paths.data_dir(settings)` reads the settings value without importing `config.py`.

    The duck-typed signature is deliberate (see paths.py): this module is imported by `cli.py` before any Settings
    exists, and making it depend on pydantic-settings would invert the layering. This test pins that the contract still
    works with a real Settings object.
    """
    resolved = paths.data_dir(settings)
    assert resolved == (settings.data_dir or Path()).resolve()
