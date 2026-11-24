"""`<config-dir>/mypki.env`: the file `/settings` writes, and how it is read back at startup.

Why a file at all
------------------------------------------------------------------------
Until now a knob could only be changed in a shell environment, in a `.env` next to the working directory, or with a CLI
flag, and `/settings` could only *report* the result. That is honest but passive: an operator who wants the CA to
default to two-year leaves has to know the spelling of the knob, find the right file, and restart the right process.
Writing the knobs back to a file the app itself reads closes that loop without inventing a database, a daemon, or a
second source of truth.

Why *this* location and this format
------------------------------------------------------------------------
`<config-dir>/mypki.env` (`$XDG_CONFIG_HOME/mypki/mypki.env`, `%APPDATA%\\mypki\\mypki.env`) rather than `./.env`: the
working directory is whatever a supervisor happened to start the process from, so a settings file there moves with the
service unit and lands in a web-served tree for anyone who runs `mypki serve` from the project checkout. The config dir
is already resolved per OS by `paths.resolve_config_dir`, is outside every served directory, and is already documented
as "where an operator's `.env` copy belongs" (page-map §8).

The format is plain `KEY=VALUE` lines with the `MYPKI_` prefix, i.e. exactly the spelling `config.py` documents. A value
may also be wrapped in double (or single) quotes, as `.env.example` now writes every value: reading drops the quotes and
decodes escapes the way dotenv does, and a line this page does not manage is written back exactly as found. An
operator can open it in a text editor, and the same line works in a shell or a systemd unit — one spelling for one knob,
which is the rule the whole config layer already follows (page-map §11).

Precedence, checked against the pinned settings layer rather than assumed
------------------------------------------------------------------------
`Settings(env_file=…)` is **silently ignored** by this project: `model_config` sets `extra="ignore"`, so the keyword is
swallowed as an unknown field and every value stays at its default (measured here: two files saying `MYPKI_MAX_SANS=5`
and `MYPKI_MAX_SANS=9` both produced 100). The keyword that works is `_env_file`, and it accepts a **tuple in which the
later entry wins** (`_env_file=(A,B)` → B's value; `(B,A)` → A's value). A real process environment variable beats every
file. So `config.get_settings()` passes `_env_file=(".env", <config>/mypki.env)`: the working-directory `.env` first,
this file last, real env above both.

One consequence that has to stay visible on `/settings`: dotenv-supplied knobs *do* appear in
`Settings.model_fields_set`, so a value read out of this file is indistinguishable from one read out of a shell variable
to `_settings_source`. That is why the page keeps its "these cannot be told apart" paragraph and adds an explicit
"saved for the next start" line rather than claiming to know which layer won.

What this module refuses to do
------------------------------------------------------------------------
* It does not write `MYPKI_SECRET_KEY` or either `ssl_*` path, and it leaves any such line already in the file
  exactly as it found it (see `UNMANAGED_KEYS` and `preserve_unmanaged`). A session-signing secret written by a
  browser form is a way to move a secret from a 0600 file into a request body, a proxy log and a browser history.
* It does not write `MYPKI_CONFIG_DIR`. That knob decides **where this file lives**, so it cannot be set inside the
  file: startup has to know which directory to open before it can read the file.
* It never writes a value it has not validated. A bad save would otherwise surface as a pydantic `ValidationError`
  at the *next* startup — a CA that refuses to start because of something typed into a text box an hour earlier (see
  `validate_candidate`).
"""

from __future__ import annotations

import codecs
import logging
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .config import Settings
from .logsetup import resolve_level

log = logging.getLogger("mypki.settingsfile")

#: Name of the file `/settings` writes, inside the resolved config dir (page-map §8).
CONFIG_FILE_NAME = "mypki.env"

#: Knobs this page will not write, and why each one is on the list.
#:
#: `secret_key` signs the session cookie that carries the CSRF token: sending it through a form means it appears in a
#: POST body, in whatever logs that body, and in the browser that typed it. `ssl_certfile`/`ssl_keyfile` are paths to
#: a *server* private key; `/settings` already refuses to display them (app._settings_rows) and refusing to edit them
#: is the same rule seen from the other side. `config_dir` is where this file lives, so it cannot be carried by it.
UNMANAGED_KEYS: tuple[str, ...] = ("secret_key", "ssl_certfile", "ssl_keyfile", "config_dir")

_UNMANAGED_REASONS: dict[str, str] = {
    "secret_key": "it signs the session cookie; a form would put it in a POST body and a browser history",
    "ssl_certfile": "a path to your TLS certificate; this page neither displays nor edits it",
    "ssl_keyfile": "a path to your TLS private key; this page neither displays nor edits it",
    "config_dir": "it is the directory this file lives in, so the file cannot carry it",
}

#: A dotenv line this module can read and write back unchanged: `KEY=value`, optionally preceded by `export `.
_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")

#: A whole value wrapped in one pair of double (or single) quotes, optionally followed by a trailing `# comment`. The
#: body may hold backslash escapes, which is why it is `(?:[^"\\]|\\.)*` and not `[^"]*`: a value written as
#: `"Lab \"One\""` has to end at the *last* quote, not the first.
_DOUBLE_QUOTED_RE = re.compile(r'^"((?:[^"\\]|\\.)*)"\s*(?:#.*)?$')
_SINGLE_QUOTED_RE = re.compile(r"^'((?:[^'\\]|\\.)*)'\s*(?:#.*)?$")

#: The escapes `python-dotenv` decodes, per quote style (measured against the pinned 1.x parser). Inside double quotes:
#: backslash, both quote marks, and a b f n r t v. Inside single quotes: only backslash and the single quote. Any other
#: character after a backslash is left alone -- which is why a single `\t` inside double quotes is a TAB, and why a
#: Windows path wants forward slashes (or doubled backslashes) when it is quoted.
_DOUBLE_ESCAPES_RE = re.compile(r"\\[\\'\"abfnrtv]")
_SINGLE_ESCAPES_RE = re.compile(r"\\[\\']")

__all__ = [
    "CONFIG_FILE_NAME",
    "UNMANAGED_KEYS",
    "SettingsFileError",
    "config_file_path",
    "editable_field_names",
    "env_file_layers",
    "preserve_unmanaged",
    "read_saved_values",
    "render_file",
    "unmanaged_reason",
    "validate_candidate",
    "write_settings_file",
]

#: Knobs whose empty box is a decision rather than an omission. `config.py` reads an empty `MYPKI_LOG_FILE=` as "no file
#: logging" — its own validator calls that house behaviour — so the form has to be able to say "console only".
_EMPTY_LINE_IS_A_CHOICE: frozenset[str] = frozenset(
    {
        "log_file",
        "default_organization",
        "default_organizational_unit",
        "default_country",
        "default_state",
        "default_locality",
        "default_email",
    }
)

#: Knobs where an empty box is neither a value nor a choice, because `config.py` declares them as plain `str` and has
#: no empty-means-unset validator to honour it. Checked against this project's own settings layer, writing the empty
#: line would survive to startup: `MYPKI_HOST=` reads back as `''` (and `cli._is_loopback('')` is False, so the
#: LAN-exposure warning fires for a bind address nobody typed), and `MYPKI_CA_CN=` reads back as `''`, leaving
#: `mypki init-ca` to sign a CA with no name. `log_level` is here too because startup does reject it -- through
#: `logsetup.resolve_level`, an hour later, which is precisely the failure this page exists to prevent.
_EMPTY_IS_NOT_A_VALUE: frozenset[str] = frozenset({"host", "ca_cn", "log_level"})


class SettingsFileError(ValueError):
    """A save that will not be written: the reason names the knob and what it must be.

    Shaped like `errors.MypkiError`'s `reason` habit rather than as a bare exception type because `/settings`
    renders this into its amber block verbatim, and an operator has to be able to fix the field from the message
    alone.
    """

    def __init__(self, reason: str, *, field: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field


# --------------------------------------------------------------------------------------------- which knobs, where


def editable_field_names() -> tuple[str, ...]:
    """Every `Settings` field `/settings` may write, in `config.py`'s declaration order.

    Derived from `Settings.model_fields` rather than a hand-written list so a knob added to `config.py` appears on
    the page automatically — the same reason `_settings_rows` iterates the model (app.py). The cost is that a new
    knob becomes editable without a decision being taken here; `UNMANAGED_KEYS` is where a decision *is* taken, and
    `test_settings_save.py` asserts the split so it cannot happen silently.
    """
    return tuple(name for name in Settings.model_fields if name not in UNMANAGED_KEYS)


def unmanaged_reason(name: str) -> str:
    """Why one knob is not editable from this page, for the read-only card that says so."""
    return _UNMANAGED_REASONS.get(name, "not editable from this page")


def config_file_path(settings: object | None = None) -> Path:
    """`<resolved config dir>/mypki.env`.

    Resolved through `paths.resolve_config_dir`, i.e. from `MYPKI_CONFIG_DIR`/the OS default — **never** from a
    value read out of this file, which would be circular (see `config_dir_is_not_editable`). `settings` is
    duck-typed for the same reason `paths.data_dir()` is: it only needs `.config_dir`.
    """
    from . import paths

    explicit = getattr(settings, "config_dir", None)
    return paths.resolve_config_dir(env_override=str(explicit) if explicit else None) / CONFIG_FILE_NAME


def env_file_layers(settings: object | None = None) -> tuple[str | Path, ...]:
    """The dotenv layers `Settings` should read, **earliest first** (the later entry wins).

    `".env"` is kept as the literal spelling `model_config` declares, so a project-directory `.env` keeps working
    exactly as before this file existed; `<config>/mypki.env` is appended, so what `/settings` wrote wins over it.
    A real environment variable still beats both (measured: `MYPKI_MAX_SANS=42` won over two files that disagreed).
    """
    return (".env", config_file_path(settings))


# ------------------------------------------------------------------------------------------------- reading a file


def _decode_value(raw: str) -> str:
    """The value `python-dotenv` would hand to pydantic for the text after `KEY=`.

    Three shapes, decided the way dotenv decides them: a double-quoted value (quotes dropped, backslash escapes
    decoded, a trailing `# comment` ignored), a single-quoted one (quotes dropped, only backslash and `'` decoded) and
    an unquoted one (an inline ` # comment` dropped). Without the escape decoding, a quoted path written with doubled
    backslashes would be reported here as having doubled separators while startup runs with single ones -- the page and
    the process disagreeing about what one line says.
    """
    double = _DOUBLE_QUOTED_RE.match(raw)
    if double is not None:
        return _DOUBLE_ESCAPES_RE.sub(lambda m: codecs.decode(m.group(), "unicode-escape"), double.group(1))
    single = _SINGLE_QUOTED_RE.match(raw)
    if single is not None:
        return _SINGLE_ESCAPES_RE.sub(lambda m: codecs.decode(m.group(), "unicode-escape"), single.group(1))
    return re.sub(r"\s+#.*", "", raw).rstrip()


def _read_raw_values(path: Path) -> dict[str, str]:
    """The `KEY=value` lines in the file as **written** (quotes, escapes, trailing comment intact), later line winning.

    The shared first half of `read_saved_values` (which decodes) and `preserve_unmanaged` (which must not: a line this
    page does not manage has to come back out byte-for-byte, or a hand-written `MYPKI_SECRET_KEY="a #b"` would be
    rewritten as `a #b` and read back by dotenv as `a`).
    """
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE_RE.match(line)
        if match is None:
            continue
        values[match.group(1)] = match.group(2)
    return values


def read_saved_values(path: Path) -> dict[str, str]:
    """The `KEY=value` lines already in the file, as the strings dotenv would produce; a later line wins.

    Parsed here rather than through `python-dotenv` on purpose: dotenv is present in this venv only **transitively**
    (via pydantic-settings), and a module that writes a file it cannot guarantee it can read would be the worse
    dependency. This parser handles the shape `render_file` produces plus comments, blank lines, `export ` prefixes and
    quoted values; `Settings` reads the same file through dotenv at startup, and `test_settings_save.py` proves the two
    readings agree on every managed knob.

    Quoted values are decoded the way dotenv decodes them (see `_decode_value`): the surrounding quotes are dropped,
    and inside double quotes a backslash escape is resolved. Writing `"value"` then reading `value` is therefore not a
    silent edit -- it is what startup does too. Whitespace inside the quotes is kept; whitespace outside is not.
    """
    return {name: _decode_value(raw) for name, raw in _read_raw_values(path).items()}


def preserve_unmanaged(path: Path) -> list[tuple[str, str]]:
    """`KEY=value` pairs for keys this module must not overwrite, in the order they appear in the file.

    An operator who hand-wrote `MYPKI_SECRET_KEY=…` into `<config>/mypki.env` must not lose it because they pressed
    Save on a form that never displayed it. Silently dropping a line nobody asked to drop is how a settings page
    becomes dangerous.
    """
    # RAW text, not the decoded value: this is written straight back by `render_file`, and a quoted line (`"a #b"`,
    # `"C:\\\\www"`) must keep its quotes and escapes or dotenv reads something different at the next start.
    saved = _read_raw_values(path)
    # Compared uppercased: `render_file` always writes the canonical spelling, but a hand-edited file might carry
    # `mypki_secret_key=` or `Mypki_Host=`, and pydantic-settings matches env names case-insensitively. A line is
    # preserved unless its uppercase form is one of the knobs this page manages — so an odd-cased secret line
    # survives, and an odd-cased duplicate of a managed knob is the one thing that gets rewritten (leaving both in
    # the file would be two answers to one question, decided by dotenv's read order).
    managed = {f"MYPKI_{name.upper()}" for name in editable_field_names()}
    return [(name, value) for name, value in saved.items() if name.upper() not in managed]


# ------------------------------------------------------------------------------------------------ writing a file


def render_file(values: Mapping[str, str], preserved: list[tuple[str, str]]) -> str:
    """The file body: a header, every managed knob `values` carries, then the untouched unmanaged lines.

    Written as a full rewrite of the managed keys rather than an in-place edit of each line because the form posts every
    editable knob on every save: "what is in the file" and "what the page showed" must be the same set, or a knob that
    vanished from the form would linger invisibly in the file and win at the next startup. The preserved half is
    what keeps that rewrite from being destructive.
    """
    lines = [
        "# mypki settings written by /settings (mypki 0.3.0+).",
        "# Plain KEY=VALUE, same MYPKI_* spelling as a shell variable or a .env in the working directory.",
        "# Read at startup BELOW real environment variables and `mypki serve` flags; it wins over ./.env.",
        "# A line for a knob this page does not manage is left here untouched if you add one by hand.",
        "",
    ]
    for name in sorted(values):
        lines.append(f"{name}={_dotenv_text(values[name])}")
    if preserved:
        lines.append("")
        lines.append("# Kept exactly as they were found; /settings does not edit these.")
        for name, value in preserved:
            lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def _dotenv_text(value: str) -> str:
    """`value` as it must be spelled after `KEY=` for dotenv to read it back unchanged.

    Plain values stay bare, so the file stays the hand-editable `MYPKI_PORT=8543` every other document shows -- and a
    Windows path keeps its single backslashes. Only a value dotenv would otherwise misread is wrapped in double
    quotes (with backslash and `"` escaped): one containing `#` (an unquoted ` #` starts a comment, so `Lab #1 CA`
    would come back as `Lab`), a quote character, or leading/trailing whitespace (dotenv strips it).
    """
    if value == value.strip() and not any(ch in value for ch in "#\"'"):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_settings_file(path: Path, body: str) -> None:
    """Write the body, creating the config dir, and make the file owner-only on POSIX.

    `0o600` because a settings file is allowed to contain a data directory, a log path and — if an operator added it by
    hand — a secret. Same reasoning as `ca.PRIVATE_FILE_MODE`: create with the mode rather than write-then-chmod, so
    there is no window where the file is world-readable. On Windows `os.open` takes the mode argument but ignores
    it, and NT's default ACLs are already owner-scoped; `ca._is_posix()` is why this module does not pretend
    otherwise.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(str(path), flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(body)
    if os.name == "posix":
        os.chmod(str(path), 0o600)


# --------------------------------------------------------------------------------------------- validate before write


def _empty_means_default(name: str, raw: str) -> str | None:
    """What an empty text box means for this knob: write the line, drop it, or refuse.

    Checked one empty submitted value at a time, each result read back
    through `Settings(_env_file=…)` against the file `/settings` actually writes: `MYPKI_DATA_DIR=` yields
    `PosixPath('.')`, not `None` — an operator who cleared the data-dir box would, at the next start, put a root CA's
    private key into whatever directory the service happened to be standing in. `MYPKI_LOG_FILE=` and every
    `MYPKI_DEFAULT_…=` yield `None`, because `config.py` carries a validator that honours empty as unset
    (`_empty_log_file_means_console_only`) or says so in the field description ("Empty leaves the field blank").
    `MYPKI_HOST=` yields `''`, and `cli._is_loopback('')` is False, so mypki would print its LAN-exposure warning for a
    bind address nobody typed; `MYPKI_CA_CN=` yields `''`, i.e. `mypki init-ca` signing a CA with no name;
    `MYPKI_LOG_LEVEL=` survives startup and fails an hour later inside `logsetup.resolve_level`. Those measurements,
    not a guess about what "empty" means, are what the branches below encode.

    Four answers, one per kind of knob:
      * a knob in `_EMPTY_LINE_IS_A_CHOICE` (`log_file`, the six subject defaults) — an empty box is a real choice
        ("console only", "no prefilled organisation"), so the empty line is written and startup reads it back as None;
      * a knob in `_EMPTY_IS_NOT_A_VALUE` (`host`, `ca_cn`, `log_level`) — refused here, naming the knob;
      * a `… | None` knob that is not a choice (`data_dir`, `public_base_url`) — the line is dropped, because writing
        `MYPKI_DATA_DIR=` would land on the cwd, which is not what clearing a data-directory box means;
      * anything else that is neither a choice nor declared `… | None` — also refused naming the knob, rather than
        silently reverting to mypki's default behind the operator's back.
    """
    if raw.strip():
        return raw.strip()
    if name in _EMPTY_LINE_IS_A_CHOICE:
        # `MYPKI_LOG_FILE=` reads back as None through config.py's own `_empty_log_file_means_console_only`,
        # and each `MYPKI_DEFAULT_…=` reads back as None too. So the empty line IS the answer here, and it has to
        # survive `validate_candidate`'s final pass rather than be dropped as a None.
        return ""
    if name in _EMPTY_IS_NOT_A_VALUE or not _annotation_allows_none(name):
        # Not a choice knob, and startup would either keep the empty string (host, ca_cn) or reject it later, an hour
        # from now, inside logsetup.resolve_level (log_level): refuse here instead, naming the knob.
        raise SettingsFileError(
            f"MYPKI_{name.upper()} cannot be empty: mypki would start with an empty {name}, which is not a setting.",
            field=name,
        )
    return None


def _annotation_allows_none(name: str) -> bool:
    """True when `config.py` declares this knob as `… | None`, i.e. startup can hold "unset" for it.

    Used to decide what an empty box may mean: only a knob the model can actually store as None can have its empty
    box mean "mypki's default". For every other knob the empty string would survive into the running process, and the
    numeric ones would reach pydantic as `""` and come back reporting a bound the operator never violated.
    """
    text = str(Settings.model_fields[name].annotation)
    return "None" in text or "Optional" in text


def _bound_text(name: str) -> str | None:
    """`"1 to 65535"` for a `Field(ge=…, le=…)` knob, or None when the field declares no numeric bounds.

    Read out of `model_fields[name].metadata`, i.e. the *same* `Ge`/`Le` objects pydantic enforces, so the message
    the page shows cannot drift from the rule that actually rejects the value. That is the point of this helper: the
    alternative — writing the bounds into the template by hand — is a page that promises one range while `config.py`
    enforces another.
    """
    ge = le = None
    for constraint in Settings.model_fields[name].metadata:
        text = repr(constraint)
        if text.startswith("Ge("):
            ge = constraint.ge  # type: ignore[attr-defined]
        elif text.startswith("Le("):
            le = constraint.le  # type: ignore[attr-defined]
    if ge is None and le is None:
        return None
    if ge is not None and le is not None:
        return f"{ge} to {le}"
    if ge is not None:
        return f"at least {ge}"
    return f"at most {le}"


def _error_reason(name: str, message: str) -> str:
    """A pydantic message rewritten as one an operator can act on.

    `Input should be greater than or equal to 1` is true and useless next to a text box; the useful form names the knob,
    states the bound mypki's own `Field` declares, and quotes what was typed. The bound comes from `_bound_text` rather
    than from parsing pydantic's sentence, so this page's promise and `config.py`'s rule stay one fact.
    """
    field_name = f"MYPKI_{name.upper()}"
    bound = _bound_text(name)
    if bound:
        return f"{field_name} must be {bound}; you entered an invalid value."
    return f"{field_name} is not a valid value: {message}"


def validate_candidate(current: Settings, submitted: Mapping[str, str]) -> dict[str, str]:
    """The `MYPKI_*` lines to write, or a `SettingsFileError` naming the first bad knob.

    Validation runs through **`config.py` itself**: the candidate is built by taking what this process resolved
    (`current.model_dump()`, so unmanaged knobs keep their live values), replacing every editable knob with the
    submitted text, and constructing a fresh `Settings`. That re-runs each `Field(ge=…, le=…)` *and* both model
    validators — the one that refuses `MYPKI_VALIDITY_DEFAULT_DAYS` above `MYPKI_VALIDITY_MAX_DAYS`, and the one
    that runs the six subject defaults through `validate_country`/`validate_email`/`validate_printable_field`.
    Re-implementing those rules here would be a second copy of them, and a second copy is what drifts.

    Why the whole candidate rather than one field at a time: a save can be wrong as a *pair* (default 400 against a
    ceiling of 200), and a page that validated each box in isolation would write a file the next startup refuses to
    read.

    The returned dict holds only keys whose value differs from leaving the knob out — an empty optional box is dropped
    rather than written as `KEY=` (see `_empty_means_default`).
    """
    candidate_values: dict[str, Any] = dict(current.model_dump())
    normalised: dict[str, str] = {}

    for name in editable_field_names():
        if name not in submitted:
            # The form posts every editable knob; a missing key means the request was not this page's form, and guessing
            # would mean writing a partial file. Refuse instead.
            raise SettingsFileError(
                f"MYPKI_{name.upper()} was not submitted; save from the Settings page rather than a custom form.",
                field=name,
            )
        raw = _empty_means_default(name, str(submitted.get(name) or ""))
        if raw is None:
            candidate_values[name] = None
            continue
        if "\n" in raw or "\r" in raw:
            raise SettingsFileError(
                f"MYPKI_{name.upper()} cannot contain a line break; one value per KEY=VALUE line.", field=name
            )
        candidate_values[name] = raw
        normalised[name] = raw

    # `log_level` is the one editable knob `config.py` does not validate itself: its type is plain `str`, so a file
    # saying MYPKI_LOG_LEVEL=banana is a perfectly legal Settings object and only fails at startup, inside
    # logsetup.resolve_level — an hour after the text box, which is exactly the failure this page exists to prevent.
    # Calling resolve_level here means "validated before write" stays true for this knob too, and it is the same
    # function that will run at startup rather than a second copy of its allow-list.
    try:
        resolve_level(str(candidate_values["log_level"]))
    except ValueError as exc:
        raise SettingsFileError(f"Refusing to save: {exc}", field="log_level") from None

    try:
        validated = Settings(**candidate_values)  # type: ignore[call-arg]
    except ValidationError as exc:
        first = exc.errors()[0]
        location = str(first.get("loc", ()))
        bad_field = next((part for part in first.get("loc", ()) if isinstance(part, str)), None)
        if bad_field is None or bad_field not in Settings.model_fields:
            # A model validator raising without naming a field (the validity-pair and subject-default
            # checks raise with the knob named in their own message): keep pydantic's sentence, it already
            # names the knobs.
            raise SettingsFileError(f"Refusing to save: {first.get('msg', location)}", field=None) from None
        raise SettingsFileError(_error_reason(bad_field, str(first.get("msg", ""))), field=bad_field) from None

    # The validated object is the answer, not the submitted text: `MYPKI_DEFAULT_COUNTRY=au` becomes `AU` the same
    # way it would at startup, so what lands in the file is what mypki will actually run with.
    written: dict[str, str] = {}
    for name in editable_field_names():
        value = getattr(validated, name)
        if value is None and name not in _EMPTY_LINE_IS_A_CHOICE:
            continue
        written[f"MYPKI_{name.upper()}"] = _as_file_value(name, value)
    return written


def _as_file_value(name: str, value: Any) -> str:
    """A validated Python value back into dotenv text.

    `bool` first and deliberately: `str(True)` is `"True"`, which pydantic reads back as True, but `"true"` is what an
    operator writes in a shell and what every other mypki document shows, so the file stays hand-editable in the
    spelling people expect. `Path` becomes its string form (a relative path stays relative — that is what
    `config.py` promises for `log_file`, and rewriting it to absolute would make the file unportable between the two
    OSes this project ships on).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        # Only reachable for a knob in `_EMPTY_LINE_IS_A_CHOICE` (every other None is dropped by the caller). It has
        # to render as an empty line and NOT as `KEY=None`: dotenv then hands pydantic the four-character
        # string "None", and `MYPKI_LOG_FILE=None` becomes `PosixPath('None')` -- a log file named None, which is the
        # same class of bug config.py's `_empty_log_file_means_console_only` exists to prevent.
        return ""
    return str(value)
