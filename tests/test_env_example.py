"""`.env.example` is a contract with the operator who copies it to `.env`, so its shape is asserted, not assumed.

What is pinned here, and why each one earns a test:

* **Every value is double-quoted** -- live lines and commented-out examples alike -- and the app reads the quoted file
  to exactly the same `Settings` as the unquoted one. The second half is the point: quoting is only an improvement if
  startup treats `KEY="value"` and `KEY=value` as the same knob, including the empty value `KEY=""`.
* **The config and data directories are live and relative** (`.config`, `.data`), so an app run from `/opt/mypki` keeps
  its state in `/opt/mypki/.data` and `/opt/mypki/.config`, and both are gitignored: the data dir holds the CA key.
* **Section titles are three-line banners** (rule, title, rule) rather than a title glued to the end of a rule.
* **Inside `CSR subject prefills`, every comment comes before the first variable**, so the variables read as one block.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from dotenv import dotenv_values

from mypki import paths
from mypki.config import Settings

ROOT = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = ROOT / ".env.example"
GITIGNORE = ROOT / ".gitignore"

pytestmark = pytest.mark.skipif(not ENV_EXAMPLE.is_file(), reason=".env.example is not part of this source tree")


@pytest.fixture(autouse=True)
def _no_ambient_mypki_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A real environment variable outranks any dotenv file, so the suite's MYPKI_DATA_DIR would mask the example."""
    for name in [key for key in os.environ if key.startswith("MYPKI_")]:
        monkeypatch.delenv(name)


KNOB_LINE = re.compile(r"^(#?)(MYPKI_[A-Z0-9_]+)=(.*)$")
RULE = "# " + "-" * 78


def _lines() -> list[str]:
    return ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()


def _section(title: str) -> list[str]:
    """The lines between one banner's closing rule and the next banner's opening rule."""
    lines = _lines()
    start = next(i for i, line in enumerate(lines) if line == f"# {title}" and lines[i - 1] == RULE) + 2
    end = next((i for i in range(start, len(lines)) if lines[i] == RULE), len(lines))
    return lines[start:end]


def test_every_knob_line_is_wrapped_in_double_quotes() -> None:
    knob_lines = [match for line in _lines() if (match := KNOB_LINE.match(line))]
    assert len(knob_lines) >= 25, "the example lost most of its knobs"
    for match in knob_lines:
        value = match.group(3)
        assert re.fullmatch(r'"[^"]*"', value), f"{match.group(2)} is not double-quoted: {value!r}"


def test_the_quoted_file_loads_to_the_same_settings_as_the_unquoted_one(tmp_path: Path) -> None:
    quoted = tmp_path / "quoted.env"
    unquoted = tmp_path / "unquoted.env"
    quoted.write_text(ENV_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    unquoted.write_text(
        re.sub(r'^(MYPKI_[A-Z0-9_]+)="(.*)"$', r"\1=\2", quoted.read_text(), flags=re.M), encoding="utf-8"
    )

    from_quoted = Settings(_env_file=str(quoted))  # type: ignore[call-arg]
    from_unquoted = Settings(_env_file=str(unquoted))  # type: ignore[call-arg]

    assert from_quoted.model_dump() == from_unquoted.model_dump()
    assert from_quoted.port == 8443
    assert from_quoted.log_to_console is True
    assert from_quoted.ca_cn == "mypki Root CA"


def test_an_empty_quoted_value_means_what_an_empty_unquoted_one_means(tmp_path: Path) -> None:
    """`MYPKI_LOG_FILE=""` is console-only logging and an empty prefill is a blank field, exactly as without quotes."""
    path = tmp_path / ".env"
    path.write_text('MYPKI_LOG_FILE=""\nMYPKI_DEFAULT_ORGANIZATION=""\nMYPKI_DEFAULT_EMAIL=""\n', encoding="utf-8")

    settings = Settings(_env_file=str(path))  # type: ignore[call-arg]

    assert settings.log_file is None
    assert settings.default_organization is None
    assert settings.default_email is None


def test_the_example_values_are_the_ones_the_code_defaults_to_apart_from_the_two_directories() -> None:
    """The example documents the defaults; the only intended difference is the app-local config and data dirs."""
    from_example = Settings(_env_file=str(ENV_EXAMPLE))  # type: ignore[call-arg]
    defaults = Settings(_env_file=None)  # type: ignore[call-arg]

    differing = {name for name in Settings.model_fields if getattr(from_example, name) != getattr(defaults, name)}
    assert differing == {"data_dir", "config_dir"}


def test_data_and_config_dirs_are_live_relative_paths_in_the_example() -> None:
    values = dotenv_values(ENV_EXAMPLE)
    assert values["MYPKI_DATA_DIR"] == ".data"
    assert values["MYPKI_CONFIG_DIR"] == ".config"
    # Uncommented: a `#` in front of either would make the example's default the OS directory again.
    live = {match.group(2) for line in _lines() if (match := KNOB_LINE.match(line)) and not match.group(1)}
    assert {"MYPKI_DATA_DIR", "MYPKI_CONFIG_DIR"} <= live


def test_the_relative_dirs_resolve_against_the_directory_the_app_runs_in(tmp_path: Path, monkeypatch) -> None:
    """With the app in `/opt/mypki` the defaults land in `/opt/mypki/.data` and `/opt/mypki/.config`."""
    app_dir = tmp_path / "opt" / "mypki"
    app_dir.mkdir(parents=True)
    monkeypatch.chdir(app_dir)

    settings = Settings(_env_file=str(ENV_EXAMPLE))  # type: ignore[call-arg]

    assert paths.data_dir(settings) == (app_dir / ".data").resolve()
    assert paths.config_dir(settings) == (app_dir / ".config").resolve()


def test_gitignore_names_both_directories() -> None:
    entries = {line.strip() for line in GITIGNORE.read_text(encoding="utf-8").splitlines()}
    assert ".data/" in entries
    assert ".config/" in entries


def test_section_titles_are_three_line_banners() -> None:
    lines = _lines()
    titles = [lines[i + 1] for i, line in enumerate(lines) if line == RULE and lines[i + 2] == RULE]
    assert titles == [
        "# serving",
        "# storage",
        "# CA defaults",
        "# issue limits",
        "# CSR subject prefills",
        "# logging",
        "# secrets",
    ]
    # And no rule still carries its title on the same line.
    assert not [line for line in lines if re.match(r"^# -{20,} \S", line)]


def test_csr_prefill_comments_all_come_before_the_variables() -> None:
    section = _section("CSR subject prefills")
    first_variable = next(i for i, line in enumerate(section) if KNOB_LINE.match(line))
    assert any(line.startswith("#") for line in section[:first_variable])
    after = [line for line in section[first_variable:] if line.strip()]
    assert after, "the section lost its variables"
    assert all(KNOB_LINE.match(line) and not line.startswith("#") for line in after), after
    assert {KNOB_LINE.match(line).group(2) for line in after} == {  # type: ignore[union-attr]
        "MYPKI_DEFAULT_ORGANIZATION",
        "MYPKI_DEFAULT_ORGANIZATIONAL_UNIT",
        "MYPKI_DEFAULT_COUNTRY",
        "MYPKI_DEFAULT_STATE",
        "MYPKI_DEFAULT_LOCALITY",
        "MYPKI_DEFAULT_EMAIL",
    }
