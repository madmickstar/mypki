"""Configuration for mypki: every knob environment-driven, so one wheel runs as a home-lab box or an internal service.

Why this module exists (and why not a `mypki.toml`): the CA's behaviour limits -- how long a certificate may live,
how big a paste may be, how many SANs one request may carry -- are the security posture, not cosmetics. They have
to be readable and settable in the same place an operator already sets host and port, and `pydantic-settings` gives
that plus startup validation for free: an out-of-range limit is a `ValidationError` at process start rather than a
surprise mid-signing, which is the difference between "the CA refuses to start" and "the CA issued a 10-year cert".

Naming note: every variable carries the `MYPKI_` prefix with **no** unprefixed aliases. A bare `DATA_DIR`, `HOST` or
`PORT` in the same environment as another service is either silently adopted by mypki or silently ignored by it, and
both readings are wrong; a prefix makes the ownership of each knob explicit (page-map §11).

Every numeric knob uses `Field(ge=…, le=…)` so an impossible value cannot be constructed at all, and every knob
carries a `description=` that says what it costs -- the cost is the part an operator has to reason about before
changing a default.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, PrivateAttr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .errors import CsrValidationError
from .validators import validate_country, validate_email, validate_printable_field

log = logging.getLogger("mypki.config")

#: Hard ceiling on `validity_max_days` (page-map §7 + README gotcha 2).
#:
#: It was 825 days for as long as this project had no revocation at all: with nothing to revoke, the validity date was
#: the *only* bound on a mis-issued certificate, and 825 days also happened to sit inside the window platforms apply to
#: TLS server certificates. Because `/issued` now records revocations (`store.revoke`, page-map §5), so
#: 2-, 3- and 4-year leaves become a defensible operator choice rather than an unbounded bet, and the ceiling moves to
#: 1461 days (4 years).
#:
#: The pinned builder accepts `not_valid_after` at 825, 1000, 1188, 1461 and even 3650
#: days without complaint, so nothing in this library enforces 825 -- the old ceiling was a policy this project chose,
#: not a limit it hit.
#:
#: **Stated as a caveat rather than as a fact:** browser and OS lifetime rules for TLS
#: server certificates (the widely cited 398/825-day windows) are enforced by publicly-trusted-CA / certificate-
#: transparency policy on the platforms I cannot exercise from this Linux box. A leaf issued by a self-hosted root you
#: installed yourself is outside that public-CA policy path, but platform-level lifetime rules may still apply. If a
#: 3- or 4-year server certificate is refused by a client, drop back to `MYPKI_VALIDITY_MAX_DAYS=825` -- the knob exists
#: so this is a configuration change and not a code change.
#:
#: The reason the ceiling is still finite: validity is the one bound on a wrong certificate that needs no cooperation
#: from the client. This host now also publishes a CRL and answers OCSP (page-map §14/§15), but those only
#: reach a client that consults them — a certificate may carry no pointer at all, and openssl never fetches
#: one even when it is baked in (§2/P-CRL-4). The 4-year ceiling stays as the compromise; a CRL is not a licence to
#: issue for longer.
VALIDITY_MAX_DAYS_CEILING = 1461


def _check_printable(field_name: str) -> Callable[[str | None], str | None]:
    """`validate_printable_field` with its field name pre-chosen, for use in a table of checks.

    `validate_printable_field(value, name)` takes the name so its message can name the field; pairing the two in a table
    of (knob, check) pairs needs the one-argument shape. The return type is spelled as a `Callable[[str | None], str |
    None]` rather than `object` so that `_SUBJECT_DEFAULT_CHECKS` says what it holds and the loop that calls these
    checks type-checks instead of being silenced.
    """

    def check(value: str | None) -> str | None:
        return validate_printable_field(value, field_name)

    return check


#: Which validator governs which prefilled subject default. A table rather than six inline calls because the pair --
#: "this knob, checked by this rule" -- is the fact worth reading. `validate_printable_field` needs the field name for
#: its message, hence the small partials below.
_SubjectCheck = Callable[[str | None], str | None]

_SUBJECT_DEFAULT_CHECKS: tuple[tuple[str, _SubjectCheck], ...] = (
    ("default_organization", _check_printable("MYPKI_DEFAULT_ORGANIZATION")),
    ("default_organizational_unit", _check_printable("MYPKI_DEFAULT_ORGANIZATIONAL_UNIT")),
    ("default_country", validate_country),
    ("default_state", _check_printable("MYPKI_DEFAULT_STATE")),
    ("default_locality", _check_printable("MYPKI_DEFAULT_LOCALITY")),
    ("default_email", validate_email),
)

__all__ = ["VALIDITY_MAX_DAYS_CEILING", "Settings", "get_settings"]


class Settings(BaseSettings):
    """Runtime configuration. Read once via `get_settings()`, or construct directly in tests."""

    model_config = SettingsConfigDict(
        # `env_file` is declared here for documentation and for any reader that honours it, but **this project's own
        # instances do not rely on it**: passing `env_file=` to `Settings(...)` is
        # swallowed by `extra="ignore"` below. The layers actually read are passed as `_env_file=(…)` by
        # `config.get_settings()` and `cli.settings_with_cli_overrides`, in the order
        # `settingsfile.env_file_layers()` returns (./.env, then <config-dir>/mypki.env).
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="MYPKI_",
        extra="ignore",
        # Field names stay usable directly, which is what tests and embedders pass; the MYPKI_* spelling is for
        # the environment. Without this, a field value passed straight in would be rejected by its own model.
        populate_by_name=True,
    )

    # ------------------------------------------------------------------------- serve
    host: str = Field(
        default="127.0.0.1",
        description=(
            "Bind address. Default is loopback because there are no logins here: exposure is controlled by binding "
            "and TLS (page-map §0). Any non-loopback value makes `mypki serve` print a LAN-exposure warning."
        ),
    )
    port: int = Field(
        default=8443,
        ge=1,
        le=65535,
        description=(
            "Listen port. 8443 is conventional for an internal HTTPS service; nothing else on this host may "
            "already hold it."
        ),
    )
    ssl_certfile: Path | None = Field(
        default=None,
        description=(
            "TLS certificate for uvicorn (`ssl_certfile`). Costs a leaf cert valid on this host's name -- issued by "
            "this very CA, or by whatever already fronts it. Set both ssl_* knobs to get https_only session cookies."
        ),
    )
    ssl_keyfile: Path | None = Field(
        default=None,
        description=(
            "TLS private key for uvicorn (`ssl_keyfile`). This is a *server* key, not the CA key: it lives wherever "
            "the operator keeps it and mypki never writes or reads `<data>/ca/ca_key.pem` on its behalf."
        ),
    )
    public_base_url: str | None = Field(
        default=None,
        description=(
            "Absolute base URL the app is reached at, for messages that must be copy-pasteable. Costs nothing; "
            "unset means relative links only. Not used for anything a certificate carries — the pointer baked into "
            "newly-issued leaves comes from `crl_base_url` below: the two facts have different lifetimes — one "
            "describes how you reach this host today, the other is frozen into certificates that outlive the change."
        ),
    )
    crl_base_url: str = Field(
        default="http://mypki.my.lab",
        description=(
            "Absolute HTTP(S) base this CA advertises inside the certificates it issues: `CRLDistributionPoints` is "
            "this base plus `/crl.pem`, and `AuthorityInformationAccess` is this base plus `/ocsp`. Plain `str`, not "
            "`… | None`: there is always a value, so clearing the box is refused naming this knob rather than silently "
            "reverting. Changing it changes only certificates issued **after** the change — a leaf already installed "
            "somewhere keeps the pointer it was born with and mypki cannot edit it. The name must resolve where the "
            "clients are: binding 127.0.0.1 while advertising a host name leaves the CRL and OCSP URLs unreachable "
            "without DNS, a hosts entry or a proxy (page-map §14)."
        ),
    )

    # ------------------------------------------------------------------------ storage
    data_dir: Path | None = Field(
        default=None,
        description=(
            "Where ca/, instance/ and issued.db live. Unset means the OS default (`$XDG_DATA_HOME/mypki`, else "
            "`~/.local/share/mypki`; `%LOCALAPPDATA%\\mypki` on Windows). Setting it to something inside a "
            "web-served directory would expose nothing today and everything after a future refactor."
        ),
    )
    config_dir: Path | None = Field(
        default=None,
        description=(
            "Config dir (`$XDG_CONFIG_HOME/mypki`, else `~/.config/mypki`; `%APPDATA%\\mypki` on Windows). Since "
            "0.3.0 this holds `mypki.env`, the file `/settings` writes and startup reads back; it is resolved before "
            "that file is opened, so this knob cannot itself be carried by it (see `settingsfile.UNMANAGED_KEYS`)."
        ),
    )

    # --------------------------------------------------------------------- CA defaults
    ca_cn: str = Field(
        default="mypki Root CA",
        description=(
            "Default `--common-name` for `mypki init-ca`. Changing it later means re-issuing the CA and "
            "re-installing it on every client."
        ),
    )
    ca_default_days: int = Field(
        default=3650,
        ge=1,
        le=3650,
        description=(
            "Default `--days` for the root CA. A root is trusted by explicit installation rather than by policy, so "
            "it may outlive a leaf; 10 years costs an early retirement if the key is ever lost."
        ),
    )

    # ------------------------------------------------------------------- issue limits
    validity_default_days: int = Field(
        default=365,
        ge=1,
        le=VALIDITY_MAX_DAYS_CEILING,
        description=(
            "Default `validity_days` on the sign page. Revocations are recorded, published in a CRL and answered over "
            "OCSP from 0.7.0 -- but only clients that consult them see it, so a mistake is still mostly waited out. "
            "That is why the default stays at one year even though the ceiling is now "
            f"{VALIDITY_MAX_DAYS_CEILING}."
        ),
    )
    validity_max_days: int = Field(
        default=VALIDITY_MAX_DAYS_CEILING,
        ge=1,
        le=VALIDITY_MAX_DAYS_CEILING,
        description=(
            f"Highest `validity_days` the sign page will accept (ceiling {VALIDITY_MAX_DAYS_CEILING} = 4 years). "
            "Over-max is rejected naming this limit, never silently clamped. Raised from 825 in 0.2.0 because "
            "`/issued` now records revocations; set it back to 825 if a client refuses a long-lived leaf, or while "
            "waiting for the CRL release that makes revocation visible to clients."
        ),
    )
    max_sans: int = Field(
        default=100,
        ge=1,
        le=1000,
        description=(
            "Cap on SAN entries per CSR. Each SAN is a name this CA is being asked to vouch for; the cap bounds "
            "one request's blast radius."
        ),
    )
    max_csr_chars: int = Field(
        default=32000,
        ge=1024,
        le=1_000_000,
        description=(
            "Cap on the pasted CSR textarea. A 4096-bit RSA CSR is ~2.5 KB, so 32 000 covers every accepted key "
            "with room for a large SAN list; the limit exists to reject oversized input through mypki's own error "
            "page rather than starlette's bare JSON `Field exceeded maximum size of 1024KB.` (MEASURED, starlette 1.6)."
        ),
    )
    session_max_age: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description=(
            "Session cookie lifetime in seconds. Also bounds how long a pending two-step signing (page-map §3) "
            "can survive an interrupted browser."
        ),
    )

    # --------------------------------------------------------------- CSR subject defaults
    # The Generate-CSR form starts pre-filled with these, so an operator who always signs for the same organisation
    # types a common name and nothing else. They are settings rather than constants because "Lab / IT / AU" is somebody
    # else's organisation: the point of the feature is that each host states its own defaults instead of everybody
    # editing a template.
    #
    # `default_*` deliberately does NOT mean "required": an empty value leaves the field blank on the page, and every
    # one of these goes through the same validators the form applies (`validate_printable_field`, `validate_country`,
    # `validate_email`) -- see `_subject_defaults_are_valid_values`.
    default_organization: str = Field(
        default="Lab",
        description="Prefills `O=` on the Generate-CSR page (page-map §2). Empty leaves the field blank.",
    )
    default_organizational_unit: str = Field(
        default="IT",
        description="Prefills `OU=` on the Generate-CSR page. Empty leaves the field blank.",
    )
    default_country: str = Field(
        default="AU",
        description="Prefills `C=` on the Generate-CSR page. Must be exactly two letters when set (validate_country).",
    )
    default_state: str = Field(
        default="Victoria",
        description="Prefills `ST=` on the Generate-CSR page.",
    )
    default_locality: str = Field(
        default="Melbourne",
        description="Prefills `L=` on the Generate-CSR page.",
    )
    default_email: str = Field(
        default="it@mypki.lab",
        description="Prefills the email subject attribute on the Generate-CSR page (not a SAN -- see csr.py).",
    )

    # ----------------------------------------------------------------------- logging
    log_level: str = Field(
        default="INFO",
        description=(
            "CRITICAL|ERROR|WARNING|INFO|DEBUG. An unknown name is a startup error, not a silent fallback "
            "(`logsetup.resolve_level`)."
        ),
    )
    log_file: Path | None = Field(
        default=Path("logs/mypki.log"),
        description=(
            "Rotating log file. A relative path resolves against the working directory and the resolved absolute "
            "path is logged as the first line, so 'where did it actually land?' is answerable from the process. An "
            "empty value means console-only."
        ),
    )
    log_max_bytes: int = Field(
        default=10 * 1024 * 1024,
        ge=1024,
        le=1024 * 1024 * 1024,
        description="Rotate once the log file passes this many bytes (default 10 MiB).",
    )
    log_backup_count: int = Field(
        default=5,
        ge=0,
        le=100,
        description=(
            "Rotated files kept besides the live one, so disk use stays bounded at log_max_bytes times "
            "(log_backup_count + 1). 0 keeps only the live file."
        ),
    )
    log_to_console: bool = Field(
        default=True,
        description=(
            "Mirror logs to stderr as well as the file. Costs nothing locally; costs a supervisor duplicating "
            "output when it already captures stdout."
        ),
    )

    # ----------------------------------------------------------------------- secrets
    secret_key: str | None = Field(
        default=None,
        description=(
            "Session signing key. Unset means mypki generates one into `<data>/instance/secret_key` (0600) and reuses "
            "it, so sessions survive a restart. Setting it explicitly is how you keep sessions valid across hosts; "
            "a value in `.env` is readable by anyone who can read the file."
        ),
    )

    # ------------------------------------------------------------------ derived state
    #: The **raw text** each TLS knob arrived as, before `Path` coerced it. Empty when the value never was text
    #: (a direct `Settings(ssl_certfile=Path(...))` construction, or a rebuild from `model_dump()`). Filled by
    #: `_keep_raw_ssl_spellings`; read through `raw_path_spelling`. The reason it exists is in that validator.
    _raw_ssl_spellings: dict[str, str] = PrivateAttr(default_factory=dict)

    @model_validator(mode="wrap")
    @classmethod
    def _keep_raw_ssl_spellings(cls, data: Any, handler: Callable[[Any], Any]) -> Any:
        r"""Record how `ssl_certfile`/`ssl_keyfile` were **spelled** before `Path` re-wrote them.

        Why the spelling has to be captured and cannot be re-derived from the field (probed against this venv's
        pinned pydantic and pydantic-settings versions):

        * a `mode="wrap"` model validator sees the merged input mapping **before** field coercion, in every
          construction path mypki uses: dotenv lines (`MYPKI_SSL_CERTFILE=C:\root_apps\...` arrives verbatim,
          doubled backslashes and all), real environment variables, and `Settings(**kwargs)` from
          `cli.settings_with_cli_overrides` / `app._publish_saved_settings`. A `mode="before"`
          `@field_validator` also sees the raw value, but it cannot be an instance method (pydantic raises
          `PydanticUserError: The @field_validator decorator cannot be applied to instance methods`), so it has no
          way to write into a private attribute -- which is why this one is `wrap`.
        * `Path` **destroys** the spelling on Windows. `str(PureWindowsPath("C:\\root_apps\\server.crt"))` comes back
          as `C:\root_apps\server.crt` (doubled separators collapsed), while `PurePosixPath` of the same string keeps
          them doubled. So a doubled-separator mistake is literally invisible to anything that re-reads
          `str(settings.ssl_certfile)` on Windows -- exactly the host where the mistake is made most often.

        A wrap validator is the only place that sees both the raw input and the finished model, so it is the only
        place this can be recorded. It changes nothing about the value: `handler(data)` runs the ordinary
        construction, including every field bound and every other model validator.
        """
        model = handler(data)
        if isinstance(data, Mapping):
            for name in ("ssl_certfile", "ssl_keyfile"):
                value = data.get(name)
                # Only text is worth keeping. A `Path` handed in directly (tests, embedders, a rebuild from
                # `model_dump()`) has already lost the spelling, and `str()` of it is all that is left -- which is
                # what `cli._tls_spelling` falls back to.
                if isinstance(value, str):
                    model._raw_ssl_spellings[name] = value
        return model

    def raw_path_spelling(self, field_name: str) -> str | None:
        """The text `field_name` was configured as, or None when it was never given as text.

        Public because the whole point is that `cli.py` must be able to ask an error message about a spelling that
        `Path` no longer holds. Returns None rather than falling back inside this module so the caller can say which
        of the two spellings it judged.
        """
        return self._raw_ssl_spellings.get(field_name)

    @field_validator("validity_default_days", "validity_max_days", "ca_default_days", mode="before")
    @classmethod
    def _no_string_days(cls, value: object) -> object:
        return value

    @model_validator(mode="after")
    def _default_validity_within_ceiling(self) -> Settings:
        """`validity_default_days` must be inside the ceiling it is a default *of*.

        A model validator rather than `le=` on the field, because the bound is another knob's value: setting
        `MYPKI_VALIDITY_DEFAULT_DAYS=400` against `MYPKI_VALIDITY_MAX_DAYS=200` is a configuration contradiction,
        and it has to fail at startup -- otherwise every signing request fails later with an error that reads like a
        user's mistake rather than the operator's.
        """
        if self.validity_default_days > self.validity_max_days:
            raise ValueError(
                f"MYPKI_VALIDITY_DEFAULT_DAYS={self.validity_default_days} exceeds "
                f"MYPKI_VALIDITY_MAX_DAYS={self.validity_max_days}"
            )
        return self

    @model_validator(mode="after")
    def _subject_defaults_are_valid_values(self) -> Settings:
        """The prefilled subject defaults must satisfy the same validators the form applies to them.

        Without this, `MYPKI_DEFAULT_COUNTRY=AUSTRALIA` is accepted at startup and then rejected on every Generate-CSR
        submit: an operator sees "country must be exactly two letters" against a field they never typed and reasonably
        concludes the page is broken. Failing here names the knob instead -- the mistake is theirs, made once, in
        `.env`, where it can actually be fixed.

        Each default is checked with the validator that governs its field (`validate_country` for `C=`, `validate_email`
        for the address, `validate_printable_field` for the rest), so a blank value stays None and renders as an empty
        input rather than as the string "None".
        """
        for name, check in _SUBJECT_DEFAULT_CHECKS:
            try:
                object.__setattr__(self, name, check(getattr(self, name)))
            except CsrValidationError as exc:
                raise ValueError(f"{name}: {exc.reason}") from None
        return self

    @field_validator("crl_base_url", mode="before")
    @classmethod
    def _crl_base_url_is_a_full_http_url(cls, value: object) -> str:
        """A scheme-qualified URL or a startup failure (plan U1).

        Why this knob is strict when `public_base_url` next door is relaxed: the value is **copied into every
        certificate issued afterwards**. `mypki.my.lab` (no scheme) or `ftp://…` would be encoded faithfully into
        `CRLDistributionPoints` and `AuthorityInformationAccess`, read correctly on `/settings`, and fail at a client
        with an error that never mentions this knob. Startup is the last moment the mistake is cheap to fix.

        `mode="before"` so trimming happens before validation and a blank submit still arrives as text. Because the
        field is a plain `str`, `/settings` refuses an empty value naming this knob (`_empty_means_default`, which
        raises `SettingsFileError` for a knob outside `_EMPTY_LINE_IS_A_CHOICE`) — there is deliberately no "unset means
        no CDP" branch anywhere in the app.

        Trailing slashes are stripped rather than rejected: `http://host//crl.pem` is legal to encode and broken to
        fetch, and a doubled slash is invisible on `/settings`.
        """
        text = "" if value is None else str(value).strip()
        if not text:
            raise ValueError(
                "crl_base_url must be an absolute URL starting with http:// or https:// (for example "
                "http://mypki.my.lab); an empty value would leave newly-issued certificates pointing nowhere."
            )
        stripped = text.rstrip("/")
        if not stripped.startswith(("http://", "https://")):
            raise ValueError(
                f"crl_base_url must start with http:// or https:// (got {text!r}). This value is copied into every "
                "newly-issued certificate's CRLDistributionPoints and AuthorityInfoAccess, so a host name without a "
                "scheme becomes a pointer no client can fetch."
            )
        return stripped

    @field_validator("log_file", mode="before")
    @classmethod
    def _empty_log_file_means_console_only(cls, value: object) -> object:
        """An empty `MYPKI_LOG_FILE=` means "no file logging" (house behaviour).

        pydantic would otherwise coerce `""` to `Path("")`, which resolves to the current directory, and mypki would
        try to rotate a log file named after the directory it is standing in. An explicit opt-out has to actually work.
        """
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @property
    def tls_enabled(self) -> bool:
        """True only when **both** TLS files are given.

        Half-configured TLS is not TLS: a cert without a key (or the reverse) makes uvicorn fail at bind time with an
        error that looks like a file permission problem. Requiring both here means `session_cookie https_only` and the
        startup banner agree about which mode the process is actually in (page-map §0)."""
        return self.ssl_certfile is not None and self.ssl_keyfile is not None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """The process-wide Settings, read once.

    Cached because every request would otherwise re-read `.env` and re-run validation, and because the CLI and the
    app must see the *same* limits -- two `Settings()` instances built at different times are two answers to
    "what is the maximum validity?", which is precisely the drift this project refuses elsewhere. Callers that need
    CLI overrides build a fresh `Settings` instead of mutating this one (see `cli.settings_with_cli_overrides`).

    A second dotenv layer, `<config-dir>/mypki.env`, is what `/settings` writes (page-map §12). The
    keyword that carries it is `_env_file`, **not** `env_file=`:
    `Settings(env_file=…)` is swallowed by this model's `extra="ignore"` and every value stays at its default, while
    `_env_file` accepts a tuple in which the **later entry wins** -- hence the order from
    `settingsfile.env_file_layers`: `./.env` first, `<config>/mypki.env` last, and a real environment variable above
    both.

    The import is inside the function rather than at module level because `settingsfile.py` needs `Settings` to read its
    fields and bounds; a top-level import in either direction would be a cycle between these two modules.
    """
    from .settingsfile import env_file_layers

    # No `type: ignore[call-arg]` on the `Settings()` call itself, although the reference project carries one there.
    # Checked with `mypy --warn-unused-ignores src` under the pinned toolchain: the ignore is reported as
    # unused, because every field has a default and `BaseSettings.__init__` takes `**values: Any`. Carrying an
    # ignore for a code mypy does not emit hides the day a *real* error appears on this line -- the comment would
    # swallow it. `_env_file` is the private pydantic-settings knob, so that one argument does need the ignore.
    return Settings(_env_file=env_file_layers())  # type: ignore[call-arg]
