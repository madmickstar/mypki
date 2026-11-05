"""Where mypki keeps its files, resolved per OS from `pathlib` only.

Why this module exists: the CA private key must not live under any directory a web server can serve, and it must
land in the *right* place on both Linux and Windows without the operator spelling it out. Getting that wrong is
not cosmetic -- a data dir inside the project tree ends up next to the templates, and one resolved relative to the
cwd moves when a supervisor changes `WorkingDirectory`. So the rules live here, once, and every other module asks
instead of improvising.

Why string-building with `/` is banned here: on Windows that produces `C:\\Users\\me\\AppData\\Local\\mypki/ca/...`,
which works until it doesn't (mixed separators defeat `startswith` checks and make path assertions unreadable).
Everything below composes `Path` objects.

Precedence, for both dirs (page-map §8): explicit `--data-dir` > `MYPKI_DATA_DIR` > OS default.

|              | Config dir                       | Data dir                          |
|--------------|----------------------------------|-----------------------------------|
| Linux/macOS  | `$XDG_CONFIG_HOME/mypki` else    | `$XDG_DATA_HOME/mypki` else       |
|              | `~/.config/mypki`                | `~/.local/share/mypki`            |
| Windows      | `%APPDATA%\\mypki`               | `%LOCALAPPDATA%\\mypki`           |

The `platform_name` parameter on the resolvers is not a hook for production code to abuse -- callers never pass
it. It exists so `tests/test_paths.py` can exercise the Windows branch (`%APPDATA%`/`%LOCALAPPDATA%`) on the Linux
CI runner and the XDG branch on the Windows runner, which is what makes the two-OS matrix meaningful instead of a
matrix that tests its own host twice.

Both defaults deliberately sit **outside** any web-served directory: `%LOCALAPPDATA%` and `~/.local/share` are never
the working directory of an app whose static files come out of `src/mypki/static/`.
"""

from __future__ import annotations

import logging
import ntpath
import os
import posixpath
import sys
from pathlib import Path

log = logging.getLogger("mypki.paths")

APP_DIR_NAME = "mypki"

#: Environment variable that overrides the data dir for every command (page-map §8).
DATA_DIR_ENV = "MYPKI_DATA_DIR"

__all__ = [
    "APP_DIR_NAME",
    "DATA_DIR_ENV",
    "ca_archive_dir",
    "ca_cert_path",
    "ca_dir",
    "ca_key_path",
    "config_dir",
    "crl_dir",
    "crl_path",
    "data_dir",
    "db_path",
    "instance_dir",
    "resolve_config_dir",
    "resolve_data_dir",
    "secret_key_path",
]


def _is_windows(platform_name: str | None) -> bool:
    """Which OS branch to take. Defaults to the one actually running; tests pass an explicit value."""
    return (platform_name or sys.platform) == "win32"


def _home_for(platform_name: str | None) -> Path:
    r"""The home directory of the OS whose branch is being taken, not necessarily this host's.

    `pathlib.Path.home()` follows the running interpreter's flavour: on Windows it resolves through `USERPROFILE` via
    `ntpath`, and `WindowsPath.expanduser()` does the same. That is correct in production -- a Windows operator means
    their Windows profile -- but it makes the `platform_name` parameter a lie, because a test that drives the POSIX
    branch on a Windows runner receives a Windows home. **On a real Windows host:** five tests failed this
    way, one setting `HOME` and getting `C:\Users\<name>` back. Resolving the home with the flavour of the branch being
    taken is what "drive both branches on every runner" (this module's own docstring) has always claimed to mean.

    The two flavours read different variables by design: POSIX uses `HOME`, Windows uses `USERPROFILE`. A test that
    pins one and drives the other branch is asserting a rule that does not apply to it.
    """
    if _is_windows(platform_name):
        return Path(ntpath.expanduser("~"))
    return Path(posixpath.expanduser("~"))


def _expand_user(path: Path, platform_name: str | None) -> Path:
    """Expand a leading `~` with the target OS's home.

    Deliberately not `Path.expanduser()`, for the reason given in `_home_for`. Only a bare `~` or `~/sub` is handled,
    which is all mypki documents (`--data-dir ~/mypki`, `.env.example`); `~user` is not supported on either OS here.
    """
    text = str(path)
    if text != "~" and not text.startswith(("~/", "~\\")):
        return path
    remainder = text[2:].lstrip("/\\")
    home = _home_for(platform_name)
    return home if not remainder else home / remainder


def _first_set_env(*names: str) -> str | None:
    """First non-blank environment value among `names`, or None.

    Blank counts as unset: `MYPKI_DATA_DIR=` in a `.env` is an operator asking for the default, not a request for
    the current directory. Without this rule an empty value becomes `Path("")`, which resolves to cwd and puts the
    CA key inside the project tree -- the exact outcome this module exists to prevent.
    """
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip():
            return value.strip()
    return None


def resolve_data_dir(
    explicit: str | Path | None = None,
    *,
    env_override: str | Path | None = None,
    platform_name: str | None = None,
) -> Path:
    """Resolve the data directory (page-map §8). Always absolute, always `.resolve()`d.

    `env_override` is what `Settings.data_dir` supplies; it sits below an explicit `--data-dir` and above the OS
    default. The three-level precedence is a parameter list rather than each caller reading `os.environ`, so a
    CLI flag, a `.env` value and an XDG default can be tested against each other without editing the process env.
    """
    for candidate in (explicit, env_override):
        if candidate is not None and str(candidate).strip():
            return _expand_user(Path(str(candidate).strip()), platform_name).resolve()

    if _is_windows(platform_name):
        # %LOCALAPPDATA% is per-user, which is the protection story Windows actually offers (page-map §8).
        base = _first_set_env("LOCALAPPDATA")
        if base is None:
            # Not a POSIX fallback: same shape as a real Windows install, just derived from the profile.
            base = str(_home_for(platform_name) / "AppData" / "Local")
            log.warning("LOCALAPPDATA is not set; using %s for the mypki data dir", base)
        return (Path(base) / APP_DIR_NAME).resolve()

    data_home = _first_set_env("XDG_DATA_HOME")
    # A separate name on purpose: `base` above is `str | None` because the Windows branch may not have found
    # %LOCALAPPDATA%, and reassigning a `Path` into that same variable makes every later reader (and mypy) hold two
    # types in one name. The POSIX default gets its own variable instead of a widening assignment.
    base_path = Path(data_home) if data_home else _home_for(platform_name) / ".local" / "share"
    return _expand_user(base_path / APP_DIR_NAME, platform_name).resolve()


def resolve_config_dir(
    explicit: str | Path | None = None,
    *,
    env_override: str | Path | None = None,
    platform_name: str | None = None,
) -> Path:
    """Resolve the config directory. Same precedence as `resolve_data_dir`, different OS defaults.

    mypki's configuration is env-driven (12-factor), so nothing *has* to live here -- this is where a future
    `mypki.toml` or an operator's `.env` copy belongs, and it is resolved now so the two dirs cannot end up as one
    directory that also happens to be web-served.
    """
    for candidate in (explicit, env_override):
        if candidate is not None and str(candidate).strip():
            return _expand_user(Path(str(candidate).strip()), platform_name).resolve()

    if _is_windows(platform_name):
        base = _first_set_env("APPDATA")
        if base is None:
            base = str(_home_for(platform_name) / "AppData" / "Roaming")
            log.warning("APPDATA is not set; using %s for the mypki config dir", base)
        return (Path(base) / APP_DIR_NAME).resolve()

    config_home = _first_set_env("XDG_CONFIG_HOME")
    # Same reason as in `resolve_data_dir`: the Windows branch's `base` is `str | None`.
    base_path = Path(config_home) if config_home else _home_for(platform_name) / ".config"
    return _expand_user(base_path / APP_DIR_NAME, platform_name).resolve()


def data_dir(settings: object | None = None, *, platform_name: str | None = None) -> Path:
    """The data dir for this run, reading `settings.data_dir` duck-typed.

    Typed as `object | None` rather than `Settings` on purpose: importing `config.py` from here would make the
    lowest-level module in the project depend on pydantic-settings, and `paths.py` is imported by `cli.py` before
    any settings exist. It only ever needs one attribute.
    """
    env_override = getattr(settings, "data_dir", None)
    return resolve_data_dir(env_override=str(env_override) if env_override else None, platform_name=platform_name)


def config_dir(settings: object | None = None, *, platform_name: str | None = None) -> Path:
    """The config dir for this run. Same duck-typing rationale as `data_dir`."""
    env_override = getattr(settings, "config_dir", None)
    return resolve_config_dir(env_override=str(env_override) if env_override else None, platform_name=platform_name)


# -------------------------------------------------------------------------------------- the layout (page-map §8)


def ca_dir(root: Path) -> Path:
    return root / "ca"


def ca_key_path(root: Path) -> Path:
    """`<data>/ca/ca_key.pem`. Never served, never logged, never stored in the DB."""
    return ca_dir(root) / "ca_key.pem"


def ca_cert_path(root: Path) -> Path:
    """`<data>/ca/ca_cert.pem` -- the only certificate this app ever serves."""
    return ca_dir(root) / "ca_cert.pem"


def ca_archive_dir(root: Path, timestamp: str) -> Path:
    """`<data>/ca/archive/<UTC-timestamp>/`, where `--force` puts the pair it replaced. Nothing is deleted."""
    return ca_dir(root) / "archive" / timestamp


def instance_dir(root: Path) -> Path:
    return root / "instance"


def secret_key_path(root: Path) -> Path:
    """Session secret for `SessionMiddleware`, 0600 on POSIX (page-map §8)."""
    return instance_dir(root) / "secret_key"


def db_path(root: Path) -> Path:
    """SQLite database of issued-cert records. Metadata only -- no keys, no PEM bodies."""
    return root / "issued.db"


def crl_dir(root: Path) -> Path:
    """`<data>/crl/`, the one directory holding a generated artifact this app serves to anyone (page-map §14).

    Under `<data>` rather than inside the project tree for the reason this module exists at all: nothing web-served may
    hold the files this CA signs with, and the CRL is the first generated artifact that is *meant* to be fetched. It
    sits beside `ca/` and `instance/` so one path (`MYPKI_DATA_DIR`, or the OS default) decides where every file this
    project writes lands, and a backup of `<data>/` is a backup of everything.
    """
    return root / "crl"


def crl_path(root: Path) -> Path:
    """`<data>/crl/mypki.crl.pem` -- the published CRL, rebuilt rather than appended (page-map §14).

    One fixed name on purpose. The URL that certificates carry (`<crl_base_url>/crl.pem`) is spelled by `app.py` from
    `Settings.crl_base_url`, and a filename an operator could configure would be a second spelling of the same location
    -- one that can disagree with the pointer baked into every leaf issued since.

    Unlike `ca_key_path`, this file is world-readable by design (see `crl.write_crl_pem`): it is served to anyone who
    asks and contains no secret. The private key stays where `ca_key_path` puts it, at 0600.
    """
    return crl_dir(root) / "mypki.crl.pem"
