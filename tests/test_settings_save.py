"""The save half of `/settings`: what may be written, what is refused, and what the next start reads back.

`/settings` became editable in 0.3.0, which moved the risk from "an operator can read a knob" to "an operator can write
one". Three promises carry the old safety intent forward, and every test here is about one of them:

1. **The editable/unmanaged split is exhaustive.** `editable_field_names()` is derived from `Settings.model_fields`, so
   a knob added to `config.py` becomes editable with no decision taken anywhere. That is only safe while the split is
   *asserted*: this file checks that every field is either editable or named in `UNMANAGED_KEYS`, and that nothing
   secret-shaped landed in the editable half.
2. **Nothing reaches the file unvalidated.** A bad value would otherwise surface as a pydantic `ValidationError` at the
   *next* startup — a CA that refuses to boot because of something typed into a text box an hour earlier. So each
   refusal is asserted twice: the message names the knob and the bound, and the file on disk is byte-identical to what
   it was before the save.
3. **What lands in the file is what mypki will run with.** The written line is read back two ways — through this
   project's own parser (`read_saved_values`) and through dotenv at startup (`Settings(_env_file=…)`) — and the two must
   agree on every managed knob, or `/settings` is displaying one value and starting another.

MEASURED on this build (pydantic-settings 2.16.1 / pydantic 2.x), and it is what the empty-box cases assert rather than
what intuition suggests: `MYPKI_DATA_DIR=` reads back as `PosixPath('.')` (the cwd, not "unset"), which is why an empty
data-dir box writes no line at all; `MYPKI_LOG_FILE=` and every `MYPKI_DEFAULT_…=` read back as `None`, so those empty
lines *are* written; `MYPKI_HOST=` reads back as `''` and `cli._is_loopback('')` is False, and `MYPKI_LOG_LEVEL=`
survives startup only to fail inside `logsetup.resolve_level`, so both empties are refused here instead.

Hermeticity comes from `conftest.py`: **both** config homes are pinned inside `tmp_path` — `$XDG_CONFIG_HOME` and
`%APPDATA%` — so `config_file_path()` resolves under whichever one this OS actually reads and no test can touch a real
operator's config file. Assertions that name a home go through `expected_config_home()` below rather than hard-coding
the POSIX spelling: on a Windows runner the resolved file is `<tmp_path>/appdata/mypki/mypki.env`.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import mypki.cli as cli
from conftest import csrf_token
from mypki.app import STARTUP_ONLY_KNOBS, create_app
from mypki.config import Settings, get_settings
from mypki.settingsfile import (
    CONFIG_FILE_NAME,
    UNMANAGED_KEYS,
    SettingsFileError,
    config_file_path,
    editable_field_names,
    env_file_layers,
    preserve_unmanaged,
    read_saved_values,
    render_file,
    unmanaged_reason,
    validate_candidate,
    write_settings_file,
)

POSIX = os.name == "posix"
#: Which branch `paths.resolve_config_dir` takes for the interpreter actually running: it branches on
#: `(platform_name or sys.platform) == "win32"`, and no test here passes `platform_name`.
WINDOWS = sys.platform == "win32"


#: A `Settings` that is deliberately *not* the defaults: a data dir, no log file and a session secret. Half these tests
#: are about what a save does to a value that already exists, and defaults would make "changed" and "unchanged"
#: indistinguishable.
def _current() -> Settings:
    return Settings(  # type: ignore[call-arg]
        data_dir=Path("/tmp/mypki-test-data"),
        log_file=None,
        secret_key="a-session-secret-not-a-real-one",
        _env_file=None,
    )


def as_text(value: Any) -> str:
    """What the browser posts for a knob whose current value is `value`.

    Local on purpose. The form posts `true`/`false` for a checkbox and an empty string for an unset box, and a test that
    posted `True` or `None` would be asserting against a body no template can produce. This mirrors
    `app._knob_input`'s `text_value` without importing a private function into the test suite.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def submitted(**overrides: str) -> dict[str, str]:
    """A complete form body — every editable knob, current values as text — with the named ones replaced.

    Completeness matters: `validate_candidate` refuses a missing knob rather than guess, and every refusal test here
    must therefore mutate one value in a *full* submission, or it would be testing the completeness guard instead of the
    bound it names.
    """
    current = _current()
    body = {name: as_text(getattr(current, name)) for name in editable_field_names()}
    body.update(overrides)
    return body


def expected_config_home() -> Path:
    """The environment home `paths.resolve_config_dir` reads on *this* OS (paths.py §resolve_config_dir).

    Windows takes `%APPDATA%/mypki`; POSIX takes `$XDG_CONFIG_HOME/mypki`. `conftest._no_real_home` pins both inside
    `tmp_path`, so whichever branch the running interpreter takes, its home is already hermetic — and a test that names
    only one of them asserts against a variable the resolved path never consulted. MEASURED on a real Windows 10 host:
    this test failed there while asserting `XDG_CONFIG_HOME`, because `resolve_config_dir` had returned
    `%APPDATA%\\mypki\\mypki.env`.
    """
    if WINDOWS:
        return Path(os.environ["APPDATA"])
    return Path(os.environ["XDG_CONFIG_HOME"])


def bounds(name: str) -> tuple[int, int]:
    """The `(ge, le)` pair `config.py` declares for a numeric knob, read from the same metadata pydantic enforces.

    Assertions below build their expected sentence out of these numbers rather than writing "1 to 65535" by hand: a test
    that hard-codes a bound passes happily on the day someone changes the `Field`, which is the drift this project
    refuses elsewhere (STYLE §8).
    """
    low = high = None
    for constraint in Settings.model_fields[name].metadata:
        text = repr(constraint)
        if text.startswith("Ge("):
            low = constraint.ge  # type: ignore[attr-defined]
        elif text.startswith("Le("):
            high = constraint.le  # type: ignore[attr-defined]
    assert low is not None and high is not None, f"{name} declares no numeric bounds"
    return int(low), int(high)


# --------------------------------------------------------------------------------------- the editable/unmanaged split


def test_the_editable_and_unmanaged_split_covers_every_settings_field() -> None:
    """Nothing may be neither — an unlisted field would silently stop being editable — and nothing secret is editable.

    This is the guard that makes `editable_field_names()` being derived from the model safe rather than lucky.
    """
    editable = editable_field_names()

    assert set(editable) | set(UNMANAGED_KEYS) == set(Settings.model_fields), (
        "a Settings field is in neither list, so /settings would silently stop editing it"
    )
    assert not set(editable) & set(UNMANAGED_KEYS)
    # Order is `config.py`'s declaration order, which is what `SETTINGS_SECTIONS` and the page both rely on.
    assert editable == tuple(name for name in Settings.model_fields if name not in UNMANAGED_KEYS)

    # The secret-shaped knobs stay out. Naming them here rather than only counting the lists means a new field called
    # something like `api_token` fails this test instead of quietly appearing as a text box on /settings.
    assert set(UNMANAGED_KEYS) == {"secret_key", "ssl_certfile", "ssl_keyfile", "config_dir"}


def test_every_unmanaged_knob_comes_with_a_reason() -> None:
    """The read-only card on `/settings` explains each one, so the refusal is visible rather than a missing box."""
    for name in UNMANAGED_KEYS:
        reason = unmanaged_reason(name)
        assert reason and reason != "not editable from this page", f"{name} has no stated reason"


def test_config_dir_is_not_editable_because_it_is_where_the_file_lives() -> None:
    """`MYPKI_CONFIG_DIR` cannot be carried by the file whose location it decides.

    Asserted as a property of the path rather than as a line in a list: `config_file_path` resolves through
    `paths.resolve_config_dir`, and a value read out of the file would make startup depend on having already opened it.
    """
    assert "config_dir" in UNMANAGED_KEYS

    path = config_file_path(_current())
    assert path.name == CONFIG_FILE_NAME
    assert path.parent.name == "mypki"
    # conftest.py pins BOTH config homes inside tmp_path; the resolved file has to sit under the one this OS reads.
    assert path.is_relative_to(expected_config_home() / "mypki")


def test_env_file_layers_puts_the_saved_file_last_of_the_dotenv_layers() -> None:
    """`./.env` first, `<config>/mypki.env` last — pydantic-settings lets the *later* entry win (settingsfile.py)."""
    current = _current()
    layers = env_file_layers(current)

    assert layers[0] == ".env"
    assert layers[-1] == config_file_path(current)
    assert len(layers) == 2


# -------------------------------------------------------------------------------------------------- writing a file


def test_a_save_writes_mypki_env_with_every_managed_knob_and_no_unmanaged_one(tmp_path: Path) -> None:
    """The file is a full rewrite of the managed knobs, in `MYPKI_*` spelling, and never carries a secret."""
    current = _current()
    written = validate_candidate(current, submitted(port="8543", max_sans="25"))
    path = config_file_path(current)
    write_settings_file(path, render_file(written, preserve_unmanaged(path)))

    body = path.read_text(encoding="utf-8")
    lines = dict(line.split("=", 1) for line in body.splitlines() if line and not line.startswith("#"))

    assert lines["MYPKI_PORT"] == "8543"
    assert lines["MYPKI_MAX_SANS"] == "25"
    # Every knob that has a value is present: the managed half is a full rewrite, so a line an earlier save wrote for a
    # knob this form no longer shows cannot linger invisibly and win at the next startup. (`public_base_url` is absent
    # because its box was empty and it is `… | None` -- see test_an_empty_optional_url_box_writes_no_line.)
    present = {f"MYPKI_{name.upper()}" for name in editable_field_names() if getattr(current, name) is not None}
    assert present <= set(lines), f"missing: {sorted(present - set(lines))}"

    for name in UNMANAGED_KEYS:
        assert f"MYPKI_{name.upper()}" not in lines, f"{name} was written by a browser form"

    # The header states the precedence an operator would otherwise have to guess.
    assert "Read at startup BELOW real environment variables" in body


@pytest.mark.skipif(not POSIX, reason="POSIX mode bits; Windows relies on NT's owner-scoped default ACLs")
def test_the_saved_file_is_owner_only(tmp_path: Path) -> None:
    """`0600`, for the same reason `ca.py` uses it for a private key: created with the mode, not chmodded after.

    A settings file is allowed to name a data directory and a log path, and an operator may hand-write a secret into it.
    Group- or world-readable would put the location of a CA's key material in a file every user on the host can open.
    """
    current = _current()
    path = config_file_path(current)
    write_settings_file(path, render_file(validate_candidate(current, submitted()), []))

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & 0o077 == 0, f"{path} is group- or world-readable: {oct(mode)}"


def test_the_config_directory_is_created_when_it_does_not_exist(tmp_path: Path) -> None:
    """A fresh host has no `<config>/mypki` yet; pressing Save must not fail because of that."""
    current = _current()
    path = config_file_path(current)
    assert not path.parent.exists()

    write_settings_file(path, render_file(validate_candidate(current, submitted()), []))

    assert path.is_file()


# --------------------------------------------------------------------------------------------- refusing a bad value


def test_a_port_out_of_range_is_refused_naming_the_bound(tmp_path: Path) -> None:
    """The message names the knob and the range `config.py` actually enforces — not pydantic's generic sentence.

    The bound is read from the same `Ge`/`Le` objects that produced the rejection, so the page's promise and the model's
    rule cannot drift apart (`settingsfile._bound_text`).
    """
    low, high = bounds("port")
    current = _current()

    for bad in ("0", str(high + 1)):
        with pytest.raises(SettingsFileError) as excinfo:
            validate_candidate(current, submitted(port=bad))

        assert excinfo.value.field == "port"
        assert excinfo.value.reason == f"MYPKI_PORT must be {low} to {high}; you entered an invalid value."


def test_a_non_numeric_limit_is_refused_naming_that_limit() -> None:
    """`max_sans=abc` is refused against *its* bound, so the operator fixes the box they broke."""
    low, high = bounds("max_sans")

    with pytest.raises(SettingsFileError) as excinfo:
        validate_candidate(_current(), submitted(max_sans="abc"))

    assert excinfo.value.field == "max_sans"
    assert excinfo.value.reason == f"MYPKI_MAX_SANS must be {low} to {high}; you entered an invalid value."


def test_default_validity_above_the_ceiling_is_refused_as_a_pair() -> None:
    """A save can be wrong as a *pair*, which is why validation runs on the whole candidate at once.

    `MYPKI_VALIDITY_DEFAULT_DAYS=400` and `MYPKI_VALIDITY_MAX_DAYS=200` are each inside their own `Field` bounds; only
    `config.py`'s model validator can see the contradiction. A page that validated each box separately would write both
    and leave the next startup to fail.
    """
    with pytest.raises(SettingsFileError) as excinfo:
        validate_candidate(_current(), submitted(validity_default_days="400", validity_max_days="200"))

    reason = excinfo.value.reason
    assert "MYPKI_VALIDITY_DEFAULT_DAYS=400" in reason
    assert "MYPKI_VALIDITY_MAX_DAYS=200" in reason
    # A model validator names the knobs inside its own message rather than reporting one field, so `field` stays None
    # and pydantic's sentence is kept verbatim instead of rewritten into a bound that was never violated.
    assert excinfo.value.field is None


@pytest.mark.parametrize(
    ("knob", "value", "expected"),
    [
        ("default_country", "XYZ", "country must be exactly two letters"),
        ("default_email", "nope@nowhere@lab", "exactly one @"),
    ],
)
def test_a_subject_default_is_validated_by_the_same_rule_the_form_uses(knob: str, value: str, expected: str) -> None:
    """`MYPKI_DEFAULT_COUNTRY=AUSTRALIA` would be accepted at startup and then rejected on every Generate-CSR submit.

    Asserted here so the mistake is named once, in the box it was typed into, rather than appearing later as a form that
    looks broken against a field nobody touched (config.py `_subject_defaults_are_valid_values`).
    """
    with pytest.raises(SettingsFileError) as excinfo:
        validate_candidate(_current(), submitted(**{knob: value}))

    assert knob in excinfo.value.reason
    assert expected in excinfo.value.reason


def test_an_unknown_log_level_is_refused_before_the_write() -> None:
    """`log_level` is the one editable knob `config.py` does not validate — so this module calls its validator.

    `MYPKI_LOG_LEVEL=banana` is a perfectly legal `Settings` object (the field is plain `str`) and only fails at startup
    inside `logsetup.resolve_level`, i.e. an hour after the text box. Refusing it here keeps "validated before write"
    true for this knob too, through the same function that will run at startup rather than a second copy of its
    allow-list.
    """
    with pytest.raises(SettingsFileError) as excinfo:
        validate_candidate(_current(), submitted(log_level="banana"))

    assert excinfo.value.field == "log_level"
    assert "log_level must be one of" in excinfo.value.reason
    assert "'banana'" in excinfo.value.reason


def test_a_value_with_a_line_break_cannot_be_saved() -> None:
    """One value per `KEY=VALUE` line; a newline would write two lines from one text box.

    This is checked before pydantic runs because the damage here is to the *file format*, not to the value: a CA common
    name containing a newline would be re-read as a different setting entirely.
    """
    with pytest.raises(SettingsFileError) as excinfo:
        validate_candidate(_current(), submitted(ca_cn="two\nlines"))

    assert excinfo.value.field == "ca_cn"
    assert "cannot contain a line break" in excinfo.value.reason


def test_a_form_that_omits_a_knob_is_refused_rather_than_guessed() -> None:
    """The page posts every editable knob on every save, so a missing one means this was not the page's form.

    Writing a partial file would leave a knob that no longer appears on `/settings` still winning at the next startup —
    a setting that is invisible and unremovable from the UI.
    """
    body = submitted(port="8543")
    del body["max_sans"]

    with pytest.raises(SettingsFileError) as excinfo:
        validate_candidate(_current(), body)

    assert excinfo.value.field == "max_sans"
    assert "was not submitted" in excinfo.value.reason


# ------------------------------------------------------------------- what an empty text box means, per knob (measured)


def test_an_empty_data_dir_box_writes_no_line_at_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """MEASURED: `MYPKI_DATA_DIR=` reads back as `PosixPath('.')`, not `None`.

    So the line that looks like "I want mypki's default" actually means "put the root CA's private key in whatever
    directory the service happens to be standing in". Clearing the box therefore drops the knob, and the next start
    resolves the OS default.
    """
    current = _current()
    assert current.data_dir is not None

    written = validate_candidate(current, submitted(data_dir=""))

    assert "MYPKI_DATA_DIR" not in written
    path = config_file_path(current)
    write_settings_file(path, render_file(written, []))
    assert "MYPKI_DATA_DIR=" not in path.read_text(encoding="utf-8")
    # And the next start really does get the OS default rather than the cwd. `MYPKI_DATA_DIR` has to be cleared first:
    # conftest.py sets it for every test, and a real environment variable beats this file (the precedence page-map §12
    # states out loud), so leaving it set would assert the env layer rather than what the file says.
    monkeypatch.delenv("MYPKI_DATA_DIR", raising=False)
    assert Settings(_env_file=str(path)).data_dir is None  # type: ignore[call-arg]


def test_an_empty_log_file_box_writes_an_empty_line_and_means_console_only() -> None:
    """MEASURED: `MYPKI_LOG_FILE=` reads back as `None` via config.py's own `_empty_log_file_means_console_only`.

    "Console only" is a real choice an operator is entitled to make from the page, so this empty box *must* write its
    line — dropping it instead would silently restore `logs/mypki.log`, which is the default rather than the answer.
    """
    current = _current()
    written = validate_candidate(current, submitted(log_file="some/logs/app.log"))
    # Compared as paths, not strings: `settingsfile._as_file_value` keeps a relative path relative (rewriting it to
    # absolute would make the saved file unportable between the two OSes), and `str(WindowsPath('some/logs/app.log'))`
    # is `some\\logs\\app.log`. MEASURED on Windows: the string comparison failed there on separators alone.
    assert Path(written["MYPKI_LOG_FILE"]) == Path("some/logs/app.log")

    cleared = validate_candidate(current, submitted(log_file=""))
    assert cleared["MYPKI_LOG_FILE"] == ""

    path = config_file_path(current)
    write_settings_file(path, render_file(cleared, []))
    assert "MYPKI_LOG_FILE=\n" in path.read_text(encoding="utf-8")
    assert Settings(_env_file=str(path)).log_file is None  # type: ignore[call-arg]


def test_a_choice_knob_never_writes_the_word_none() -> None:
    """`MYPKI_LOG_FILE=None` would read back as `PosixPath('None')` — a log file actually named None.

    MEASURED on pydantic-settings 2.16.1. The empty line is the encoding of "no file logging"; the four-character string
    `None` is not, and it survives dotenv and pydantic both. This is the same class of bug config.py's
    `_empty_log_file_means_console_only` exists to prevent, approached from the writing side.
    """
    for knob in ("log_file", "default_country", "default_email", "default_organization"):
        written = validate_candidate(_current(), submitted(**{knob: ""}))
        assert written[f"MYPKI_{knob.upper()}"] != "None"


@pytest.mark.parametrize("knob", ["host", "ca_cn", "log_level"])
def test_an_empty_box_on_a_required_knob_is_refused_naming_the_knob(knob: str) -> None:
    """These three are plain `str` in `config.py`, so an empty line would survive into the running process.

    MEASURED consequences of writing one anyway: `MYPKI_HOST=` yields `''`, and `cli._is_loopback('')` is False, so
    mypki prints its LAN-exposure warning for a bind address nobody typed; `MYPKI_CA_CN=` yields `''`, i.e. `mypki
    init-ca` signing a CA with no name; `MYPKI_LOG_LEVEL=` passes startup and fails later inside
    `logsetup.resolve_level`.
    """
    with pytest.raises(SettingsFileError) as excinfo:
        validate_candidate(_current(), submitted(**{knob: ""}))

    assert excinfo.value.field == knob
    assert f"MYPKI_{knob.upper()} cannot be empty" in excinfo.value.reason


def test_an_empty_optional_url_box_writes_no_line() -> None:
    """`public_base_url` is `str | None`, so an empty box means "unset" and the line is dropped."""
    written = validate_candidate(_current(), submitted(public_base_url=""))

    assert "MYPKI_PUBLIC_BASE_URL" not in written


def test_an_empty_subject_default_writes_an_empty_line_and_reads_back_as_blank() -> None:
    """`config.py` documents these as "Empty leaves the field blank", so the empty line is what says so.

    Dropping the line instead would restore mypki's own default (`Lab`, `IT`, `AU`) behind an operator who had just
    asked for no prefilled organisation — a silent revert this module promises not to do.
    """
    current = _current()
    body = submitted(
        default_organization="",
        default_organizational_unit="",
        default_country="",
        default_state="",
        default_locality="",
        default_email="",
    )
    written = validate_candidate(current, body)

    for name in (
        "default_organization",
        "default_organizational_unit",
        "default_country",
        "default_state",
        "default_locality",
        "default_email",
    ):
        assert written[f"MYPKI_{name.upper()}"] == "", name

    path = config_file_path(current)
    write_settings_file(path, render_file(written, []))
    from_file = Settings(_env_file=str(path))  # type: ignore[call-arg]
    for name in ("default_organization", "default_country", "default_email"):
        assert getattr(from_file, name) is None, f"{name} came back as {getattr(from_file, name)!r}"


# ------------------------------------------------------------------------------------------------ reading it back


def test_the_own_parser_and_dotenv_agree_on_every_managed_knob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`read_saved_values` and `Settings(_env_file=…)` must describe the same file with the same values.

    The page shows the first and the server starts from the second. If they disagree, `/settings` is honest about a file
    that mypki then runs differently — which is worse than not showing the file at all. Asserted per knob rather than as
    "the two dicts look similar", including the knobs whose line is intentionally empty.
    """
    current = _current()
    written = validate_candidate(
        current,
        submitted(
            host="10.0.0.5",
            port="8543",
            ca_cn="mypki Lab CA",
            validity_default_days="90",
            max_sans="25",
            log_file="",
            default_country="",
            log_to_console="false",
        ),
    )
    path = config_file_path(current)
    write_settings_file(path, render_file(written, []))

    # Cleared for the same reason as above: conftest's MYPKI_DATA_DIR would answer for data_dir instead of the file.
    monkeypatch.delenv("MYPKI_DATA_DIR", raising=False)

    parsed = read_saved_values(path)
    from_file = Settings(_env_file=str(path))  # type: ignore[call-arg]

    assert parsed == written, "the file no longer reads back as the values that were validated"

    for name in editable_field_names():
        knob = f"MYPKI_{name.upper()}"
        live = getattr(from_file, name)
        if knob not in parsed:
            # A dropped line has to mean the default, or a knob would be unset at startup and displayed as its default.
            assert live == Settings.model_fields[name].default, f"{knob} absent but startup says {live!r}"
            continue
        expected = parsed[knob]
        if isinstance(live, bool):
            assert expected in ("true", "false"), f"{knob} is a checkbox written as {expected!r}"
            assert live == (expected == "true")
        elif live is None:
            assert expected == "", f"{knob} reads back as {live!r} from the text {expected!r}"
        else:
            assert str(live) == expected, f"{knob}: file says {expected!r}, startup says {live!r}"


def test_a_hand_written_secret_line_survives_a_save() -> None:
    """An operator who hand-wrote `MYPKI_SECRET_KEY=…` must not lose it because they pressed Save on a form that never
    displayed it. Silently dropping a line nobody asked to drop is how a settings page becomes dangerous."""
    current = _current()
    path = config_file_path(current)
    write_settings_file(path, "MYPKI_SECRET_KEY=hand-written-not-a-real-one\nMYPKI_MAX_SANS=7\n")

    preserved = preserve_unmanaged(path)
    assert ("MYPKI_SECRET_KEY", "hand-written-not-a-real-one") in preserved

    body = render_file(validate_candidate(current, submitted(max_sans="25")), preserved)
    write_settings_file(path, body)

    text = path.read_text(encoding="utf-8")
    assert "MYPKI_SECRET_KEY=hand-written-not-a-real-one" in text
    assert Settings(_env_file=str(path)).secret_key == "hand-written-not-a-real-one"  # type: ignore[call-arg]
    assert read_saved_values(path)["MYPKI_MAX_SANS"] == "25"


def test_an_odd_cased_secret_line_survives_but_an_odd_cased_managed_knob_is_rewritten() -> None:
    """pydantic-settings matches env names case-insensitively, so preservation compares uppercased.

    `mypki_secret_key=` survives (nobody asked to touch it). An odd-cased duplicate of a *managed* knob is the one thing
    that does get rewritten: leaving both in the file would be two answers to one question, decided by dotenv's read
    order rather than by the page.
    """
    current = _current()
    path = config_file_path(current)
    write_settings_file(path, "mypki_secret_key=odd-case-not-a-real-one\nmypki_port=9999\n")

    preserved = preserve_unmanaged(path)
    assert ("mypki_secret_key", "odd-case-not-a-real-one") in preserved
    assert not any(name.upper() == "MYPKI_PORT" for name, _ in preserved)

    write_settings_file(path, render_file(validate_candidate(current, submitted(port="8543")), preserved))
    parsed = read_saved_values(path)

    assert parsed["mypki_secret_key"] == "odd-case-not-a-real-one"
    assert parsed["MYPKI_PORT"] == "8543"
    assert "mypki_port=9999" not in path.read_text(encoding="utf-8")


def test_comments_blank_lines_and_export_prefixes_survive_the_own_parser(tmp_path: Path) -> None:
    """The file is meant to be hand-edited, so the reader has to cope with what an editor writes.

    A parser that silently dropped a commented-out knob would still be correct here — but one that read a comment *as*
    a value, or choked on `export `, would turn an operator's own edit into an unexplained setting.
    """
    path = tmp_path / "mypki.env"
    path.write_text(
        '# a note\n\nexport MYPKI_MAX_SANS=42\n  MYPKI_CA_CN = "Quoted CA Name"  \nnot a line at all\n',
        encoding="utf-8",
    )

    parsed = read_saved_values(path)

    assert parsed["MYPKI_MAX_SANS"] == "42"
    # Quotes are unwrapped because dotenv unwraps them: writing `"value"` then reading `value` must
    # not be a silent edit.
    assert parsed["MYPKI_CA_CN"] == "Quoted CA Name"
    assert len(parsed) == 2


def test_a_later_line_wins_over_an_earlier_one_in_the_same_file() -> None:
    """Both readers do this, and the page must describe the file the way startup sees it."""
    path = expected_config_home() / "mypki" / "dupcheck.env"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("MYPKI_MAX_SANS=1\nMYPKI_MAX_SANS=9\n", encoding="utf-8")

    assert read_saved_values(path)["MYPKI_MAX_SANS"] == "9"


def test_reading_a_file_that_does_not_exist_yields_nothing(tmp_path: Path) -> None:
    """A host that has never pressed Save is not an error."""
    assert read_saved_values(tmp_path / "absent.env") == {}
    assert preserve_unmanaged(tmp_path / "absent.env") == []


# --------------------------------------------------------------------------------- a refused save changes nothing


def test_a_refused_save_leaves_the_existing_file_byte_identical(tmp_path: Path) -> None:
    """The whole point of validating first: a rejected save must not be a partial write.

    Asserted as a tree hash rather than as "the port line still looks right", because the failure mode this catches is
    `render_file` having already replaced some other knob before the bad one was noticed.
    """
    current = _current()
    path = config_file_path(current)
    write_settings_file(path, render_file(validate_candidate(current, submitted(port="8543")), []))
    config_dir = path.parent
    before = dict(_tree(config_dir))

    with pytest.raises(SettingsFileError):
        validate_candidate(current, submitted(port="0"))

    assert _tree(config_dir) == before


def test_a_refused_save_creates_no_file_on_a_host_that_has_never_saved(tmp_path: Path) -> None:
    """The refusal must not create the config dir either — "nothing was written" has to mean nothing."""
    current = _current()
    path = config_file_path(current)

    with pytest.raises(SettingsFileError):
        validate_candidate(current, submitted(max_sans="abc"))

    assert not path.exists()


def _tree(root: Path) -> dict[str, tuple[int, str]]:
    """`conftest.snapshot_tree`, imported lazily so the module-level import list stays about mypki."""
    from conftest import snapshot_tree

    return snapshot_tree(root)


# ------------------------------------------------------------------------------------------- CLI precedence, measured


def test_a_cli_flag_still_beats_the_saved_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`mypki serve --port` wins over `<config>/mypki.env`, which is what the page's own wording promises.

    Driven through `cli.settings_with_cli_overrides` because that is the function `mypki serve` actually calls, and it
    names the dotenv layers explicitly (cli.py): a `Settings(**merged)` construction would otherwise fall back to
    `model_config`'s `env_file=".env"` alone and the saved file would be invisible to the very command about to start
    the server. Both arms are asserted — the flag winning, and no-flag seeing the file — because only the second proves
    the first is a precedence rule rather than an accident of the file never being read.
    """
    current = _current()
    path = config_file_path(current)
    write_settings_file(path, render_file(validate_candidate(current, submitted(port="8543")), []))

    get_settings.cache_clear()
    no_flag = cli.settings_with_cli_overrides(cli.build_parser().parse_args(["serve"]))
    assert no_flag.port == 8543, "the saved file is invisible to `mypki serve`"

    with_flag = cli.settings_with_cli_overrides(cli.build_parser().parse_args(["serve", "--port", "8123"]))
    assert with_flag.port == 8123, "a CLI flag lost to the saved file"

    get_settings.cache_clear()


def test_a_real_environment_variable_beats_the_saved_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """The precedence the page states out loud: real env above `<config>/mypki.env` above `./.env`.

    This is what makes "I saved it and nothing changed" answerable rather than mysterious, and it is why `/settings`
    keeps its resolved-state table below the form.
    """
    current = _current()
    path = config_file_path(current)
    write_settings_file(path, render_file(validate_candidate(current, submitted(max_sans="25")), []))

    monkeypatch.setenv("MYPKI_MAX_SANS", "7")
    get_settings.cache_clear()

    assert Settings().max_sans == 7  # type: ignore[call-arg]
    assert read_saved_values(path)["MYPKI_MAX_SANS"] == "25"

    get_settings.cache_clear()


# --------------------------------------------------------------------------------- the HTTP route, end to end


@pytest.fixture
def settings_client(settings: Settings) -> TestClient:
    """A cookie-persisting client for a host with no CA — which is all `/settings` needs.

    Local rather than conftest's `session_client` because that fixture builds a throwaway RSA-3072 CA, and nothing on
    `/settings` reads one; `client_without_ca` does not persist cookies, and the CSRF token has to survive from the GET
    to the POST. Building it here keeps both facts visible at the call site.
    """
    app = create_app(settings, session_secret="test-session-secret-not-a-real-one")
    from conftest import ScratchClient

    with ScratchClient(app, persist_cookies=True) as client:
        yield client


def _post_settings(client: TestClient, **fields: str):
    """POST the Settings form with the session's own token, plus whatever fields the test names."""
    token = csrf_token(client, "/settings")
    return client.post("/settings", data={"csrf_token": token, **fields})


def _input_value(page, knob: str) -> str | None:
    """The `value=` of one knob's input on `/settings`, read structurally rather than by substring.

    `assert 'value="8543"' in page.text` is true of a page where 8543 appears in somebody else's box, and after
    0.5.0 the same number can legitimately appear twice on this page (the saved value in the input, and the file
    echo in the status panel). Anchoring on `name="MYPKI_PORT"` is what makes the assertion about the knob being
    asserted on. The tag is joined across lines first because settings.html breaks an input over several lines,
    exactly as `test_views._knob_value()` does.
    """
    joined = re.sub(r"\n\s*", " ", page.text)
    match = re.search(rf'<input[^>]*name="{knob}"[^>]*value="([^"]*)"', joined)
    return None if match is None else match.group(1)


def _pending_sentences(page, knob: str | None = None) -> list[str]:
    """The tag-free text of every rose "active only after reboot" sentence beside `knob`'s box.

    Zero, one, or (which would be a bug) more than one. Empty on three cases that must stay empty: a knob that is
    not startup-only, a startup-only knob whose saved line already equals what this process resolved, and any box
    re-rendered from `overrides` after a rejected save — see `app._pending_saved_value` for the four rules this list
    exists to test.
    """
    blocks = re.findall(r'<p class="pending-saved">(.*?)</p>', page.text, re.S)
    out = []
    for block in blocks:
        # Tags are replaced with a SPACE rather than removed: `…as</span> <span…8443…` would otherwise glue into
        # `as8443`, and a test that then looked for "as 8443" would fail against a page that says exactly that.
        text = re.sub(r"<[^>]+>", " ", block)
        if knob is None or knob in text:
            out.append(" ".join(text.split()))
    return out


def _full_form(**overrides: str) -> dict[str, str]:
    """Every editable knob in the form's own spelling (`MYPKI_PORT`), with one or more replaced.

    `overrides` are **field** names (`port="70000"`) because that is how every other test in this file names a knob, and
    they are translated here rather than passed through: a body carrying a bare `port=` is ignored by
    `app._submitted_settings_fields`, which would turn a "this save was refused" test into a "this save wrote the
    defaults" test -- green for the wrong reason.
    """
    body = {f"MYPKI_{name.upper()}": as_text(getattr(_current(), name)) for name in editable_field_names()}
    for name, value in overrides.items():
        assert name in editable_field_names(), f"{name} is not an editable knob"
        body[f"MYPKI_{name.upper()}"] = value
    return body


def test_the_settings_page_offers_a_save_button_and_an_input_per_editable_knob(client_without_ca: TestClient) -> None:
    """The page is a form now, and the assertion is on the shape rather than on a count.

    Every editable knob has to appear as a named control; a knob that renders as text but posts nothing would be a knob
    that silently stops being editable, which is what `validate_candidate`'s missing-knob refusal exists to catch.
    """
    page = client_without_ca.get("/settings")

    assert '<button class="save-settings" type="submit">Save Settings</button>' in page.text
    for name in editable_field_names():
        assert f'name="MYPKI_{name.upper()}"' in page.text, f"{name} is not submittable"


def test_saving_through_the_page_writes_the_file_and_names_what_changed(settings_client: TestClient) -> None:
    """A successful save re-renders from the file's contents and lists what moved.

    "Saved" without a list of what changed is indistinguishable from "nothing needed to change", and this page's whole
    promise is that an operator can tell those apart. 0.4.0 adds the second half of that distinction: each changed knob
    is marked `applied now` or `active only after reboot`, because a save no longer means one thing for every knob.
    """
    path = config_file_path(settings_client.app.state.settings)  # type: ignore[attr-defined]
    response = _post_settings(settings_client, **_full_form(port="8543", max_sans="25"))

    assert response.status_code == 200
    assert '<section class="done">' in response.text
    assert '<span class="pill active">Saved</span> to <code>' in response.text
    assert '<span class="mono">MYPKI_PORT</span>' in response.text
    assert '<span class="mono">MYPKI_MAX_SANS</span>' in response.text
    # The two markers, on the two knobs that actually differ: `max_sans` is read per request, `port` is the listener.
    assert 'class="live-marker">applied now' in response.text
    assert 'class="restart-marker">active only after reboot' in response.text

    parsed = read_saved_values(path)
    assert parsed["MYPKI_PORT"] == "8543"
    assert parsed["MYPKI_MAX_SANS"] == "25"


def test_an_unticked_checkbox_saves_an_explicit_false(settings_client: TestClient) -> None:
    """An unticked checkbox submits *nothing*, and an absent key in a dotenv file means mypki's default, not false.

    Without the explicit `false` written by `app._submitted_settings_fields`, unticking "log to console" would silently
    turn logging back on at the next start — the box would appear to have done nothing.
    """
    body = _full_form()
    del body["MYPKI_LOG_TO_CONSOLE"]

    response = _post_settings(settings_client, **body)
    assert response.status_code == 200

    parsed = read_saved_values(config_file_path(settings_client.app.state.settings))  # type: ignore[attr-defined]
    assert parsed["MYPKI_LOG_TO_CONSOLE"] == "false"
    saved = config_file_path(settings_client.app.state.settings)
    from_file = Settings(_env_file=str(saved))  # type: ignore[call-arg]
    assert from_file.log_to_console is False


def test_a_rejected_save_names_the_knob_fills_in_every_value_and_writes_nothing(settings_client: TestClient) -> None:
    """The amber block, the retained values and the untouched file — all three in one response.

    Asserted together because they are one promise: an operator who typed 70000 into the port box has to be able to fix
    that box without retyping eight others, and must not have written the mistake while doing it.
    """
    path = config_file_path(settings_client.app.state.settings)  # type: ignore[attr-defined]
    write_settings_file(path, render_file(validate_candidate(_current(), submitted(port="8543")), []))
    before = _tree(path.parent)

    response = _post_settings(settings_client, **_full_form(port="70000"))

    assert response.status_code == 200
    assert '<section class="form-errors">' in response.text
    assert "Not saved" in response.text
    assert "MYPKI_PORT must be 1 to 65535" in response.text
    assert "Nothing was written to <code>" in response.text
    # The typed value is what the box shows now, not the file's value.
    assert 'value="70000"' in response.text
    # …and nothing says "active only after reboot" beside it. 70000 never reached `<config>/mypki.env`, so a rose marker
    # here would describe a pending change that does not exist (rule 2 of `app._pending_saved_value`: an override wins,
    # and the amber block above already says in words what happened to this submission).
    assert _pending_sentences(response, "MYPKI_PORT") == []

    assert _tree(path.parent) == before


def test_a_rejected_pair_save_reports_the_contradiction_as_one_problem(settings_client: TestClient) -> None:
    """Two individually-valid boxes that contradict each other, named together.

    The page cannot show this by marking either box red on its own; the sentence has to carry both numbers or the
    operator fixes the wrong one.
    """
    response = _post_settings(settings_client, **_full_form(validity_default_days="400", validity_max_days="200"))

    assert "MYPKI_VALIDITY_DEFAULT_DAYS=400" in response.text
    assert "MYPKI_VALIDITY_MAX_DAYS=200" in response.text
    assert "Not saved" in response.text


def test_a_save_without_the_csrf_token_writes_nothing(settings_client: TestClient) -> None:
    """`/settings` is the one route that writes a file the next startup trusts, so CSRF runs before any parsing.

    Kept in this file rather than only in the CSRF suite because the promise here is about the *file*: a forged POST
    must leave `<config>/mypki.env` exactly as it was.
    """
    path = config_file_path(settings_client.app.state.settings)  # type: ignore[attr-defined]
    before = _tree(path.parent)

    response = settings_client.post("/settings", data=_full_form(port="8543"))

    # 400 rather than 403: `csrf.py` documents a CSRF failure as mypki's own 400 page with nothing performed, which is
    # the same answer every other bad request in this app gives.
    assert response.status_code == 400
    assert "CSRF token" in response.text
    assert not path.exists() or _tree(path.parent) == before


def test_a_config_directory_that_cannot_be_written_is_reported_not_500(settings_client: TestClient) -> None:
    """`<config>/mypki` existing as a *file* is this host's state, not the operator's typo.

    Asserted because the alternative is a 500 on the one page that writes settings: an operator who once ran something
    that made a file where the directory belongs would get a traceback rather than "fix this directory and save again",
    with no way to find out which path to fix.
    """
    settings = settings_client.app.state.settings  # type: ignore[attr-defined]
    path = config_file_path(settings)
    path.parent.parent.mkdir(parents=True, exist_ok=True)
    path.parent.write_text("not a directory", encoding="utf-8")

    response = _post_settings(settings_client, **_full_form(port="8543"))

    assert response.status_code == 200
    assert "Could not write " in response.text
    assert str(path) in response.text
    assert "Fix the directory and save again" in response.text
    # The file that was in the way is still there, unchanged: a failed write created nothing and replaced nothing.
    assert path.parent.read_text(encoding="utf-8") == "not a directory"


def test_a_second_identical_save_reports_that_nothing_changed(settings_client: TestClient) -> None:
    """The "unchanged" branch of the green block, which is what makes the changed-branch meaningful.

    The file is still rewritten (the managed half is always a full rewrite), so the honest sentence is about what
    *changed*, and this test is what stops that sentence from being decorative.
    """
    first = _post_settings(settings_client, **_full_form(port="8543"))
    assert "MYPKI_PORT" in first.text

    second = _post_settings(settings_client, **_full_form(port="8543"))

    assert "Every value was already what this file said" in second.text
    saved = config_file_path(settings_client.app.state.settings)
    assert read_saved_values(saved)["MYPKI_PORT"] == "8543"


def test_a_host_that_has_never_saved_shows_no_pending_sentences(settings_client: TestClient) -> None:
    """Nothing pending on a box that nothing has ever been saved into.

    The other side of the 0.5.0 rule, and the side that decides whether the marker means anything: if `/settings` put a
    rose "active only after reboot" sentence beside all four startup-only boxes on every visit, an operator would learn
    to ignore it. `render_settings` passes `read_saved_values(config_file)`, which is `{}` when the file does not exist,
    and rule 3 of `_pending_saved_value` turns that into no marker — so a fresh host renders these four exactly as they
    rendered in 0.4.0.

    `STARTUP_ONLY_KNOBS` is iterated rather than listed here for the same reason `_settings_sections` refuses a knob it
    does not know: if the set changes, this test follows it instead of asserting an old membership.
    """
    live = settings_client.app.state.settings  # type: ignore[attr-defined]
    page = settings_client.get("/settings")

    assert page.status_code == 200
    assert _pending_sentences(page) == [], "a host with no saved file rendered a pending sentence"
    for name in STARTUP_ONLY_KNOBS:
        knob = f"MYPKI_{name.upper()}"
        assert _input_value(page, knob) == as_text(getattr(live, name)), f"{knob} does not show what this process runs"


def test_a_saved_knob_that_needs_a_restart_says_so(settings_client: TestClient) -> None:
    """`port` is read once at startup; a save that silently did nothing would read as a broken page.

    Asserted on the wording rather than on which knobs are in the list, because the list is `app.STARTUP_ONLY_KNOBS`'s
    business and this file's business is that the operator is told.
    """
    response = _post_settings(settings_client, **_full_form(port="8543"))

    assert "read once at startup: restart mypki before these take effect" in response.text
    assert "MYPKI_PORT" in response.text
    # 0.4.0 marks the same fact on the knob itself, not only in a paragraph below the form — and from 0.5.0 that mark is
    # rendered on the box as well as in the green block, so the sentence survives the visit that happens a week later.
    assert 'class="restart-marker">active only after reboot' in response.text
    assert _pending_sentences(response, "MYPKI_PORT") != []


# --------------------------------------------------------------------------- what a save does to THIS process (0.4.0)


def test_a_saved_issuing_limit_applies_to_the_next_request_without_a_restart(settings_client: TestClient) -> None:
    """The point of 0.4.0's hot-reload, asserted where it is observable: a page that renders the limit.

    `/csr/generate` prints `MYPKI_MAX_SANS` in its hint text, so saving 25 and re-fetching that page answers "did the
    running process adopt what it just wrote?" without reaching into `app.state` — which is how an operator would check
    it, and therefore how this test checks it. Asserting only `app.state.settings.max_sans == 25` would pass on a build
    that stored the new Settings while every handler kept reading the old one.
    """
    response = _post_settings(settings_client, **_full_form(max_sans="25", max_csr_chars="16384"))
    assert response.status_code == 200

    live = settings_client.app.state.settings  # type: ignore[attr-defined]
    assert live.max_sans == 25, "the save reached the file but not the process that wrote it"
    assert live.max_csr_chars == 16384

    # csr_generate.html renders the limit as "Up to {{ max_sans }} entries.", read from `settings_of()` per request.
    page = settings_client.get("/csr/generate")
    assert "Up to 25 entries" in page.text, page.text[:400]


def test_a_saved_startups_only_knob_changes_the_file_but_not_this_process(settings_client: TestClient) -> None:
    """The other half of hot-reload, and the half that must NOT happen.

    `port` is uvicorn's bind and `session_max_age` is baked into the SessionMiddleware built at startup; adopting them
    mid-life would mean a process whose cookie lifetime and whose listener disagree with what `create_app` configured.
    So the file changes and this process does not, and the page says so in red — which is the honest version of what
    0.3.0 said for every knob.
    """
    before = settings_client.app.state.settings  # type: ignore[attr-defined]
    response = _post_settings(settings_client, **_full_form(port="8543", session_max_age="7200"))

    assert response.status_code == 200
    after = settings_client.app.state.settings  # type: ignore[attr-defined]
    assert after.port == before.port, "a startup-only knob was adopted by a process that cannot re-bind"
    assert after.session_max_age == before.session_max_age

    saved = read_saved_values(config_file_path(before))
    assert saved["MYPKI_PORT"] == "8543"
    assert saved["MYPKI_SESSION_MAX_AGE"] == "7200"


def test_a_saved_logging_knob_is_reapplied_to_the_running_process(settings_client: TestClient) -> None:
    """`configure_logging` is idempotent, so the logging knobs join the live group in 0.4.0.

    Asserted on the level actually set on the root logger rather than on `Settings.log_level`, because the whole claim
    is about handlers and levels in this process: a build that published a fresh Settings without re-running
    `logsetup.configure_logging` would pass the field assertion and still log at the old level. `log_file` stays under
    the test's own tmp dir so no save can point a real host's log somewhere else.
    """
    import logging

    settings = settings_client.app.state.settings  # type: ignore[attr-defined]
    response = _post_settings(
        settings_client,
        **_full_form(log_level="DEBUG", log_file=str(settings.log_file), log_to_console="true"),
    )

    assert response.status_code == 200
    assert logging.getLogger().level == logging.DEBUG, "the save did not reach the root logger"
    assert settings_client.app.state.settings.log_level.upper() == "DEBUG"  # type: ignore[attr-defined]


def test_a_plain_get_after_a_save_does_not_claim_that_a_save_just_happened(settings_client: TestClient) -> None:
    """The green block is about an action, not about a file existing — and the boxes are about the file, not the bind.

    Two subjects share this test because they are the same visit: a plain GET on a host that has been saved. 0.3.0
    passed the saved file's contents into the template and let `settings.html` read "the file has values in it" as "a
    save just happened", so every later visit opened with a green confirmation for something nobody had done (MEASURED
    against 0.3.0's template before that was fixed). 0.5.0 changed the other half: those contents now go into the
    **inputs** of the four startup-only knobs, each with a rose sentence naming what this process is still honouring.
    The green block must stay absent; the saved value and the live value must both be present.

    `port` is moved by +100 from whatever this fixture resolved rather than hard-coded to 8543, because the assertion
    that matters is "the box shows the file's value **and not** the live one" — a literal 8443/8543 pair would also
    pass on a build where the fixture happened to resolve a different port.
    """
    live = settings_client.app.state.settings  # type: ignore[attr-defined]
    first = _post_settings(settings_client, **_full_form(port=str(live.port + 100)))
    assert '<span class="pill active">Saved</span>' in first.text

    later = settings_client.get("/settings")
    assert later.status_code == 200
    assert '<span class="pill active">Saved</span>' not in later.text

    # The other half of what 0.5.0 changed, and the half an operator used to trip over. `port` is startup-only and this
    # process never re-bound, so before 0.5.0 the box showed 8443 — what is running — while the file held 8543, and a
    # reload weeks later could not distinguish "the save was refused" from "the save is waiting for a reboot". Now the
    # box states the file's truth and the rose sentence beside it states the process's truth. Both numbers are on
    # screen;
    # neither is inferred from the absence of the other.
    saved = read_saved_values(config_file_path(live))["MYPKI_PORT"]
    assert saved == str(live.port + 100)
    assert _input_value(later, "MYPKI_PORT") == saved, "the box must show what the file says"
    assert _input_value(later, "MYPKI_PORT") != str(live.port), "the box still shows the live bind"

    # The paragraph is found by its CLASS rather than by a phrase inside it: Jinja keeps the template's own line breaks
    # verbatim, so a sentence written across four lines in settings.html is four lines in the response. MEASURED on this
    # build — `re.sub(r"\s+", " ", page)` then searching for one joined sentence reported 0 matches against a page that
    # renders exactly one. The class is the contract between app.py, settings.html and style.css; the wording below is
    # asserted after whitespace normalisation, not before it.
    pending = _pending_sentences(later, "MYPKI_PORT")
    assert len(pending) == 1, f"expected exactly one rose sentence beside MYPKI_PORT: {pending}"
    assert "active only after reboot" in pending[0]
    assert f"still running MYPKI_PORT as {live.port}" in pending[0], pending[0]
    assert "the saved value goes live at the next start" in pending[0]

    # A startup-only knob whose file line already agrees with this process gets NO sentence: `host` was submitted as
    # what it already is. Without this rule every one of the four boxes would carry rose all the time, which trains an
    # operator to ignore the one marker that means something.
    assert _input_value(later, "MYPKI_HOST") == live.host
    assert _pending_sentences(later, "MYPKI_HOST") == []

    # And a live knob keeps showing what this process resolved rather than anything from the file: `max_sans` was saved
    # and adopted, so the box and the running limit are the same number and there is nothing pending to announce.
    assert _input_value(later, "MYPKI_MAX_SANS") == str(live.max_sans)
    assert _pending_sentences(later, "MYPKI_MAX_SANS") == []

    # 0.4.0's permanent sentence at the foot of the form is still there, because a box that now shows a saved value
    # makes it MORE important rather than less: four boxes on this page can legitimately disagree with the running
    # process and the reader has to be told which four those are before they start comparing numbers.
    assert "Restart mypki after changing" in later.text
    assert "read once at startup" in later.text


def test_a_save_the_process_cannot_adopt_says_so_instead_of_claiming_success(
    settings_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The layers disagree with the file this process just wrote.

    How a real host gets here: a systemd unit or a shell exports `MYPKI_MAX_SANS=nonsense` while the server is running.
    The Save itself validates — `validate_candidate` constructs its candidate from this process's own values plus what
    was typed, and an explicit value outranks the environment in pydantic-settings — but the *rebuild* reads every layer
    again, including that broken variable. So "written" and "adopted" genuinely come apart, and 0.4.0 has to name which
    one happened: an operator who believes a limit is in force when it is not is worse served by a green tick than by a
    red sentence.
    """
    settings = settings_client.app.state.settings  # type: ignore[attr-defined]
    path = config_file_path(settings)

    first = _post_settings(settings_client, **_full_form(max_sans="25"))
    assert first.status_code == 200
    assert read_saved_values(path)["MYPKI_MAX_SANS"] == "25"

    # The body is built before the environment is poisoned: `_full_form` reads mypki's own defaults through
    # `Settings()`, and a broken `MYPKI_MAX_SANS` in the environment would break *that* rather than the save.
    body = _full_form(max_sans="30")
    monkeypatch.setenv("MYPKI_MAX_SANS", "not-a-number")

    second = _post_settings(settings_client, **body)

    assert second.status_code == 200
    assert "could not adopt it" in second.text
    assert str(path) in second.text
    assert "The values take effect at the next start." in second.text
    # The file really was written; only the adoption failed. That distinction is the whole point of the message.
    assert read_saved_values(path)["MYPKI_MAX_SANS"] == "30"
    # The boxes show what was typed, because this process is no longer running those values.
    assert 'value="30"' in second.text
    monkeypatch.delenv("MYPKI_MAX_SANS", raising=False)
