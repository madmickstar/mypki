"""Command line entry point (`mypki`): `init-ca`, `serve`, `info`.

Subcommands, and why each exists:

  init-ca   create the one root CA. The only code path in this project that writes a private key, and deliberately
            reachable only from a terminal: the GUI has no route that can mint a CA, because "no logins" means every
            browser-reachable write must be an operation whose blast radius is bounded (page-map §6).
  serve     run the web app. Refuses to start without a CA rather than serving an empty UI.
  info      print what CA is loaded and where the data actually lives. Exists for the same reason the reference
            project's `check`/`probe` do: an operator needs to see resolved state from a terminal, on a host whose
            logs they may not have open, without starting a browser.

There is no `sign`, `revoke` or `export-key` subcommand, by design (docs/REFERENCE.md "Naming"): the GUI is the
signing surface so
validation and the extension profile cannot be bypassed, revocation does not exist here, and an export command would be
the one place this project could hand out the thing it exists to protect.

Exit codes are part of the interface, documented in docs/REFERENCE.md "What it does" so a wrapper script never has
to parse stderr:

  0  success
  1  validation/usage failure (bad CN, bad SAN, invalid key spec, unwritable permissions)
  2  refused: the CA already exists and --force was not given
  3  required state missing: no CA found (serve/info), or an encrypted key this process cannot decrypt

"Refused" and "cannot run" are different answers and must not share a code. Ctrl-C is 130, which is the shell's own
convention rather than a mypki decision.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import ssl
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from . import __version__, paths
from .ca import describe_ca, format_fingerprint, init_ca, key_matches_certificate, load_ca, secret_session_key
from .config import Settings, get_settings
from .csr import PASSPHRASE_MIN_LENGTH, PASSPHRASE_RECOMMENDED_LENGTH, passphrase_advisory
from .errors import CaAlreadyExistsError, CaNotFoundError, CaPassphraseError, KeyPolicyError, MypkiError
from .keys import ALLOWED_KEY_SPECS, KeySpec
from .logsetup import configure_logging, resolve_level
from .settingsfile import env_file_layers
from .store import IssuedStore

log = logging.getLogger("mypki.cli")

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_REFUSED = 2
EXIT_MISSING_STATE = 3

__all__ = ["build_parser", "main", "settings_with_cli_overrides"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mypki",
        description="Self-hosted mini certificate authority: create a root CA, sign CSRs from a browser.",
    )
    parser.add_argument("--version", action="version", version=f"mypki {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init-ca", help="create the root CA (the only way to create one)")
    init.add_argument(
        "--data-dir", default=None, help="override the data directory (default MYPKI_DATA_DIR or OS default)"
    )
    init.add_argument("--common-name", default=None, help="CA common name (default MYPKI_CA_CN)")
    init.add_argument("--organization", default=None, help="subject O= attribute")
    init.add_argument("--organizational-unit", default=None, help="subject OU= attribute")
    init.add_argument("--country", default=None, help="subject C= attribute: exactly two letters")
    init.add_argument("--key-type", choices=["rsa", "ec"], default="rsa", help="CA key algorithm (default rsa)")
    init.add_argument(
        "--key-size", type=int, default=3072, help="RSA bits for the CA key (2048/3072/4096; default 3072)"
    )
    init.add_argument("--curve", choices=["P-256", "P-384"], default="P-256", help="EC curve when --key-type ec")
    init.add_argument(
        "--days", type=int, default=None, help="CA validity in days (default MYPKI_CA_DEFAULT_DAYS = 3650)"
    )
    init.add_argument("--encrypt", action="store_true", help="encrypt the CA private key with a passphrase")
    init.add_argument(
        "--passphrase-env",
        default="MYPKI_CA_PASSPHRASE",
        metavar="NAME",
        help="read the passphrase from this environment variable instead of prompting (never from argv)",
    )
    init.add_argument(
        "--force", action="store_true", help="replace an existing CA by archiving it first (never deletes)"
    )
    init.add_argument(
        "--secure-acl", action="store_true", help="Windows only: harden the key with icacls; skipped if absent"
    )
    _add_logging_flags(init)
    init.set_defaults(handler=cmd_init_ca)

    serve = sub.add_parser("serve", help="run the web app")
    serve.add_argument("--host", default=None, help="bind address (default 127.0.0.1; anything else prints a warning)")
    serve.add_argument("--port", type=int, default=None, help="listen port (default MYPKI_PORT = 8443)")
    serve.add_argument("--ssl-cert", default=None, help="TLS certificate file for uvicorn (ssl_certfile)")
    serve.add_argument("--ssl-key", default=None, help="TLS private key file for uvicorn (ssl_keyfile)")
    serve.add_argument("--data-dir", default=None, help="override the data directory")
    serve.add_argument(
        "--passphrase-env", default="MYPKI_CA_PASSPHRASE", metavar="NAME", help="env var holding the CA key passphrase"
    )
    _add_logging_flags(serve)
    serve.set_defaults(handler=cmd_serve)

    info = sub.add_parser("info", help="show the loaded CA, its data dir and the issued-record count")
    info.add_argument("--data-dir", default=None, help="override the data directory")
    _add_logging_flags(info)
    info.set_defaults(handler=cmd_info)

    return parser


def _add_logging_flags(parser: argparse.ArgumentParser) -> None:
    """Logging overrides on every subcommand, not just `serve`.

    Wiring these only to `serve` makes them unreachable exactly when you want to raise the level — a failing
    `init-ca` or
    an unhelpful `info` are the commands you run when something is wrong, and being unable to debug them from the same
    command line is how an operator ends up editing `.env` to find out why `.env` was not the problem.
    """
    parser.add_argument("--log-level", default=None, help="CRITICAL|ERROR|WARNING|INFO|DEBUG (default MYPKI_LOG_LEVEL)")
    parser.add_argument("--log-file", default=None, help="log file path; pass an empty value for console-only logging")
    parser.add_argument("--no-console-log", action="store_true", help="do not mirror logs to stderr")


def _cli_flag_overrides(args: argparse.Namespace) -> dict[str, object]:
    """Which knobs this process was **given on the command line**, in `Settings` field spelling.

    Two callers need the same answer and must not compute it two ways. `settings_with_cli_overrides` splats it into a
    fresh `Settings` so the flags outrank every dotenv layer; `cmd_serve` hands it to `create_app`, which keeps it on
    `app.state.cli_overrides` so that `/settings`' hot-reload can re-apply it after rebuilding from those same
    layers. Without the second use, a Save would silently outrank `mypki serve --port 9000` — the precedence this
    project documents in the opposite order.

    Only flags that were actually given appear. An argparse default of `None` means "the operator said nothing", and
    recording it as an override would make every knob look flag-set on every host, which is the same lie
    `cli.settings_with_cli_overrides`' docstring already calls out for `model_dump()`.
    """
    overrides: dict[str, object] = {}
    if getattr(args, "data_dir", None):
        overrides["data_dir"] = args.data_dir
    if getattr(args, "host", None):
        overrides["host"] = args.host
    if getattr(args, "port", None) is not None:
        overrides["port"] = args.port
    if getattr(args, "ssl_cert", None):
        overrides["ssl_certfile"] = args.ssl_cert
    if getattr(args, "ssl_key", None):
        overrides["ssl_keyfile"] = args.ssl_key
    if getattr(args, "log_level", None):
        overrides["log_level"] = args.log_level
    if getattr(args, "log_file", None) is not None:
        # argparse distinguishes "flag absent" (None) from "flag given empty" (""), and the empty form is how you ask
        # for console-only logging (page-map §11).
        overrides["log_file"] = args.log_file or None
    if getattr(args, "no_console_log", False):
        overrides["log_to_console"] = False
    return overrides


def settings_with_cli_overrides(args: argparse.Namespace) -> Settings:
    """A fresh `Settings` with any CLI overrides folded in.

    Two things this has to get right, both learned the hard way in the reference project:

    1. **Re-validate rather than `model_copy(update=…)`.** `model_copy` skips validation, so a bad `--log-level` or a
       nonsensical `--data-dir` would survive into the app and surface later as a crash inside request handling rather
       than as a usage error at startup.
    2. **Return a new object rather than mutating the cached one.** `get_settings()` is `lru_cache`d; mutating its
    result
       would make every later reader in the process see this command's flags, which turns a CLI override into global
       state with no way to observe it.
    """
    overrides = _cli_flag_overrides(args)

    base = get_settings()
    # A fresh Settings re-reads every dotenv layer (`./.env` then `<config-dir>/mypki.env`, see
    # `settingsfile.env_file_layers`) and re-runs every validator, then the CLI wins over all of it. Constructing
    # from the merged dict rather than mutating keeps validation in the path (see docstring).
    #
    # The layers have to be named here explicitly: `Settings(**merged)` is a direct construction, so it would otherwise
    # fall back to `model_config`'s `env_file=".env"` alone and `/settings`' saved file would be invisible to the very
    # command that is about to start the server — `mypki serve` and the page disagreeing about what is running.
    merged = {**base.model_dump(), **overrides}
    # The two TLS knobs are the fields whose *spelling* matters (config.py `_keep_raw_ssl_spellings`), and
    # `model_dump()` hands back a `Path`, which has already lost it -- on Windows `Path` actively rewrites it,
    # separators, and pathlib folds a doubled spelling into a single one. So for
    # whichever half of the pair the command line did **not** name, carry the text the dotenv layers were configured
    # with rather than the coerced object: pydantic builds the same `Path` from that string, and the wrap validator can
    # record a spelling it would otherwise never see. A flag that *was* given is already raw text out of argparse.
    for field_name in ("ssl_certfile", "ssl_keyfile"):
        if field_name in overrides:
            continue
        spelling = base.raw_path_spelling(field_name)
        if spelling is not None:
            merged[field_name] = spelling

    try:
        # No `type: ignore` here, unlike the one at `config.get_settings`: `merged` is a plain `dict[str, object]`
        # splatted into pydantic-settings' `__init__(self, **values: Any)`, which mypy accepts (checked with
        # --warn-unused-ignores on pydantic-settings 2.16.1: an ignore on this line is reported as unused).
        return Settings(_env_file=env_file_layers(base), **merged)  # type: ignore[call-arg]
    except Exception as exc:  # pydantic ValidationError and friends are all usage errors here
        raise ValueError(str(exc)) from exc


# --------------------------------------------------------------------------------------------- init-ca


def _ec_candidate(curve: str) -> str:
    """`--curve P-256` -> the allow-list spelling `ec-p256`.

    A helper rather than an inline expression because the ternary that calls it is already at the house line length,
    and a name here also says what the string is for: `keys.py` owns the allow-list, this only formats into it.

    The `p` is part of the name, not decoration -- `KeySpec.name` canonicalises an EC spec as `ec-p256`, so anything
    else is a string the allow-list does not contain. **BUG FOUND BY `tests/test_cli.py`:** this function used
    to be `f"ec-{curve.removeprefix('P-').lower()}"`, which produced `ec-256` and made `mypki init-ca --key-type ec`
    fail with exit 1 on every host while every non-CLI test stayed green (nothing else in the suite drove this flag
    pair). Keeping the digits rather than stripping a known prefix mirrors `keys._curve_key`, whose own docstring names
    the same class of bug.
    """
    return f"ec-p{''.join(char for char in curve if char.isdigit())}"


def _ca_key_spec(args: argparse.Namespace) -> KeySpec:
    """Map `--key-type/--key-size/--curve` onto a validated spec.

    The CLI takes them as three separate flags because that is how an operator thinks about it; `KeySpec` takes
    one allow-
    listed name because that is how a policy is enforced. Translating here (rather than letting `keys.py` accept
    arbitrary
    sizes) keeps the allow-list the single gate: `--key-size 1024` fails with the accepted list in the message
    instead of
    generating a key and refusing it afterwards.
    """
    candidate = f"rsa-{args.key_size}" if args.key_type == "rsa" else _ec_candidate(args.curve)
    if candidate not in ALLOWED_KEY_SPECS:
        raise KeyPolicyError(candidate, ", ".join(ALLOWED_KEY_SPECS))
    return KeySpec.from_string(candidate)


def _passphrase_for_init(args: argparse.Namespace) -> bytes | None:
    """Get the CA passphrase from the named env var or a `getpass` prompt (page-map §6).

    Never argv: a passphrase in argv is visible in `ps`, in shell history and in any audit log of process launches. The
    env-var route exists for automation where no terminal is attached; `getpass` is the interactive default
    because it does
    not echo. Both are read here and nowhere else, so there is one place to audit.
    """
    if not args.encrypt:
        return None
    env_name = args.passphrase_env or "MYPKI_CA_PASSPHRASE"
    from_env = os.environ.get(env_name)
    if from_env:
        # Says only that the value came from the environment -- never what it was, and never how long it was. The
        # warning
        # here is a fixed sentence rather than `passphrase_advisory`, because that helper names the exact length: on the
        # prompted path the operator just typed the value in front of themselves, but an env-sourced passphrase's length
        # would otherwise land in stdout, and therefore in whatever captured this command's output.
        print(f"passphrase read from ${env_name}")
        if len(from_env) < PASSPHRASE_RECOMMENDED_LENGTH:
            print(
                f"warning: that passphrase is shorter than {PASSPHRASE_RECOMMENDED_LENGTH} characters; "
                f"{PASSPHRASE_RECOMMENDED_LENGTH} or more is better for an encrypted CA key",
                file=sys.stderr,
            )
        return from_env.encode("utf-8")

    # 8 enforced, 12 recommended -- the same pair `csr._validated_passphrase` applies to the web form, imported rather
    # than
    # restated here so "the minimum passphrase" is one number in this project instead of two a reader must reconcile.
    first = getpass.getpass(
        f"Passphrase for the CA private key (at least {PASSPHRASE_MIN_LENGTH} characters, "
        f"{PASSPHRASE_RECOMMENDED_LENGTH} or more is better): "
    )
    if len(first) < PASSPHRASE_MIN_LENGTH:
        raise ValueError(
            f"a passphrase must be at least {PASSPHRASE_MIN_LENGTH} characters; a shorter one makes an encrypted key "
            f"barely harder to guess than an unencrypted file ({PASSPHRASE_RECOMMENDED_LENGTH} or more is better)"
        )
    second = getpass.getpass("Confirm the passphrase: ")
    if first != second:
        raise ValueError("the two passphrases do not match")
    # On this path naming the length is harmless and useful: it is a number the operator chose seconds ago, and the
    # warning has to be specific enough that they know which of their two rules they just broke.
    advisory = passphrase_advisory(first)
    if advisory:
        print(f"warning: {advisory}", file=sys.stderr)
    return first.encode("utf-8")


def cmd_init_ca(args: argparse.Namespace) -> int:
    settings = get_settings()
    root = paths.resolve_data_dir(args.data_dir, env_override=str(settings.data_dir) if settings.data_dir else None)
    try:
        spec = _ca_key_spec(args)
    except KeyPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    days = args.days if args.days is not None else settings.ca_default_days
    if days < 1:
        print("error: --days must be at least 1", file=sys.stderr)
        return EXIT_USAGE

    try:
        passphrase = _passphrase_for_init(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    common_name = args.common_name or settings.ca_cn
    try:
        from .validators import validate_common_name, validate_country, validate_printable_field

        common_name = validate_common_name(common_name)
        country = validate_country(args.country)
        organization = validate_printable_field(args.organization, "organization")
        organizational_unit = validate_printable_field(args.organizational_unit, "organizational_unit")
    except MypkiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        result = init_ca(
            root,
            common_name=common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            spec=spec,
            days=days,
            passphrase=passphrase,
            force=args.force,
            secure_acl=args.secure_acl,
        )
    except CaAlreadyExistsError as exc:
        # A refusal, not a failure: exit 2 so a wrapper can tell "this CA exists" from "something broke" (page-map §6).
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except KeyPolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, RuntimeError) as exc:
        # Includes the POSIX mode assertion in ca.py: an unwritable or world-readable key path is a usage problem the
        # operator can fix (umask, ownership), so it is exit 1 rather than a traceback.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print("Created root CA.")
    print(f"  subject          {result.subject}")
    print(f"  serial           {result.serial_hex}")
    print(f"  not before (UTC) {result.not_before_utc:%Y-%m-%d %H:%M:%S}Z")
    print(f"  not after  (UTC) {result.not_after_utc:%Y-%m-%d %H:%M:%S}Z")
    print(f"  sha256 fingerprint {format_fingerprint(result.fingerprint_hex)}")
    print(f"  key              {result.key_spec}{' (encrypted with a passphrase)' if result.encrypted_key else ''}")
    print(f"  certificate      {result.cert_path}")
    print(f"  private key      {result.key_path}")
    if result.archived_to is not None:
        print(f"  previous CA archived to {result.archived_to} (nothing was deleted)")
    print()
    print("Back up the private key now. It cannot be recovered, and losing it means re-initialising the CA and")
    print("re-installing it on every client that trusted the old one.")
    if result.encrypted_key:
        print(f"The passphrase is not stored anywhere: supply it at startup with ${args.passphrase_env}.")
    return EXIT_OK


# ------------------------------------------------------------------------------------------------ serve


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        settings = settings_with_cli_overrides(args)
    except ValueError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        # Validated here so a bad --log-level is a usage error rather than a traceback from inside create_app/uvicorn.
        log_level = resolve_level(settings.log_level)
    except ValueError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    tls_problem = _tls_file_problem(settings)
    if tls_problem is not None:
        print(tls_problem, file=sys.stderr)
        return EXIT_USAGE

    configure_logging(settings)
    root = paths.resolve_data_dir(args.data_dir, env_override=str(settings.data_dir) if settings.data_dir else None)
    log.info("data dir %s", root)

    from .app import create_app  # deferred: `init-ca` and `info` must not need FastAPI imported to run

    try:
        bundle = load_ca(root, passphrase=_startup_passphrase(args), passphrase_env=args.passphrase_env)
    except CaNotFoundError as exc:
        print(f"cannot serve: {exc}", file=sys.stderr)
        return EXIT_MISSING_STATE
    except CaPassphraseError as exc:
        print(f"cannot serve: {exc}", file=sys.stderr)
        return EXIT_MISSING_STATE

    if not bundle.key_present:
        print(
            "cannot serve: the CA certificate is present but its private key is not loadable, so nothing could be "
            "signed. Run `mypki init-ca --force` or supply the passphrase.",
            file=sys.stderr,
        )
        return EXIT_MISSING_STATE

    try:
        secret = secret_session_key(root, settings.secret_key)
    except OSError as exc:
        print(f"error: cannot create the session secret in {root}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    import uvicorn

    # `dict[str, Any]` and not `dict[str, object]`: uvicorn ships `py.typed` and `Config.__init__` declares each of
    # its ~40 parameters individually (`host: str`, `port: int`, `log_config: dict | str | PathLike | None`, ...).
    # mypy expands `**kwargs` against every declared parameter, and `dict` is **invariant** in its value type, so a
    # `dict[str, object]` matched none of them -- a wall of arg-type errors, every one naming the same
    # dict rather than any real mistake here. `Any` is the honest type for this bag: everything mypki puts in it was
    # validated upstream (`Settings.host`/`Settings.port` are field-validated; `log_level` comes from `resolve_level`,
    # which raises on anything uvicorn would not accept) and uvicorn's own defaults cover the rest.
    config_kwargs: dict[str, Any] = {
        "host": settings.host,
        "port": settings.port,
        # int, so uvicorn cannot re-map a level name differently from resolve_level's answer.
        "log_level": logging.getLevelName(log_level).lower(),
        # `log_config=None` is load-bearing, not tidiness: uvicorn's own dictConfig gives the `uvicorn` logger
        # propagate=False plus its own handlers, so every server line would skip the rotating file entirely.
        # See logsetup.py measured behaviour 2 -- do not "tidy up" this argument.
        "log_config": None,
    }
    if settings.ssl_certfile and settings.ssl_keyfile:
        config_kwargs["ssl_certfile"] = str(settings.ssl_certfile)
        config_kwargs["ssl_keyfile"] = str(settings.ssl_keyfile)

    # The flags are passed on rather than left folded inside `settings`: `/settings`' hot-reload rebuilds a fresh
    # `Settings` from the dotenv layers after a Save, and without knowing what this process was given on the command
    # line the saved file would silently outrank `mypki serve --port 9000` the moment anybody pressed Save.
    app = create_app(settings, ca_bundle=bundle, session_secret=secret, cli_overrides=_cli_flag_overrides(args))

    scheme = "https" if settings.tls_enabled else "http"
    print(f"mypki {__version__} serving {scheme}://{settings.host}:{settings.port}")
    print(f"  data dir: {root}")
    if not settings.tls_enabled:
        print(
            "  WARNING: plain HTTP. The CA is reachable without TLS, so signing requests travel in the clear\n"
            "           and the session cookie cannot be Secure. Pass --ssl-cert/--ssl-key, or run nginx/Caddy/\n"
            "           IIS in front of this origin and terminate TLS there -- but then Secure cookies have to\n"
            "           come from the proxy, because they need BOTH TLS knobs here.",
        )
    if not _is_loopback(settings.host):
        print(
            f"  WARNING: bound to {settings.host}, which is not loopback. There are no logins here: anyone who\n"
            f"           can reach port {settings.port} can ask this CA to sign certificates. Firewall it to the\n"
            "           subnet that needs it.",
        )

    # The Server object is held rather than built inline: `server.started` afterwards is the only reliable way
    # to tell a startup failure apart from a clean shutdown.
    server = uvicorn.Server(uvicorn.Config(app, **config_kwargs))
    try:
        server.run()
    except ssl.SSLError as exc:
        # `ssl.SSLError` **is** an OSError (every SSL failure mode probed here reports
        # isinstance(OSError)=True), so this arm has to precede the bind arm below or a bad certificate is reported as
        # "cannot bind". `_tls_file_problem` catches these cases before uvicorn is ever reached; staying mapped here
        # anyway is what keeps a file that changed between the pre-flight and the bind from turning into a bind error.
        print(
            f"error: the TLS pair this process was given could not be loaded for {settings.host}:{settings.port}: "
            f"{exc}. Check MYPKI_SSL_CERTFILE ({settings.ssl_certfile}) and MYPKI_SSL_KEYFILE "
            f"({settings.ssl_keyfile}): the certificate must be a PEM certificate, the key its matching unencrypted "
            "PEM private key.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    except OSError as exc:
        print(f"error: cannot bind {settings.host}:{settings.port}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        return 130
    except SystemExit as exc:
        # A failed bind does NOT raise OSError up into
        # this function. uvicorn logs the error through its own `uvicorn.error` logger, shuts the lifespan down,
        # and calls sys.exit(STARTUP_FAILURE) -- SystemExit(3). SystemExit is not an OSError, so the branch above
        # never ran for the most common real failure of this command: the operator got a bare uvicorn line and
        # exit 3, while docs/REFERENCE.md documents 3 as 'required state missing: no CA found'. **On a real
        # Windows
        # 10 host:** `[Errno 10048] ... only one usage of each socket address ...` then shutdown lines and no
        # mypki message at all -- the same shape as the Linux reproduction.
        if server.started:
            raise  # a server that did bind and exited on its own terms is not this function's call to make
        print(
            f"error: cannot start {settings.host}:{settings.port}: the server never bound "
            f"(uvicorn exited with {exc.code}). The reason is in the uvicorn.error line above. "
            f"Another process already holds port {settings.port}, or that address is unavailable.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    return EXIT_OK


#: The two knobs that make a TLS pair, as (`Settings` field name, knob spelling used in messages).
_TLS_KNOBS: tuple[tuple[str, str], ...] = (("ssl_certfile", "MYPKI_SSL_CERTFILE"), ("ssl_keyfile", "MYPKI_SSL_KEYFILE"))


def _tls_file_problem(settings: Settings) -> str | None:
    r"""Pre-flight check on the TLS pair, or None when there is nothing to check.

    Why this exists at all (found on a real Windows host and reproduced on Linux): with both knobs set but a path
    that does not exist, uvicorn raises `FileNotFoundError` while it builds its SSL context, the bind never happens,
    and `cmd_serve`'s `except OSError` reported it as `error: cannot bind <host>:<port>: [Errno 2] No such file or
    directory`. That sentence names neither the knob nor the file, so an operator goes looking for a process holding
    the port instead of fixing the path they typed. Checking here turns it into exit 1 that says which knob and which
    path.

    The second half is **what the files contain**, not only whether they exist. The operator's next report was
    `error: cannot bind <host>:<port>: [SSL] PEM lib` with both knobs pointing at real, readable files.
    Probed on this box against `ssl.SSLContext.load_cert_chain`:

      garbage cert, empty cert, a private key in the cert slot, a certificate in the key slot -> `ssl.SSLError`
        `[SSL] PEM lib`;
      a cert/key pair that does not match -> `ssl.SSLError` `[X509: KEY_VALUES_MISMATCH] key values mismatch`;
      an encrypted server key -> OpenSSL stops and prompts `Enter PEM pass phrase` on stdin, which a
        backgrounded `mypki serve` cannot answer.

    Every one of those is `isinstance(exc, OSError) == True`, so all of them reached the same misleading bind sentence.
    Parsing the pair here names the knob and says what is wrong with it. The loads are `cryptography`'s own PEM readers,
    i.e. exactly the shape OpenSSL wants, and only the **first** certificate in the cert file is parsed -- a leaf plus
    its issuing chain in one file is normal and still passes.

    Only the *complete* pair is checked: `Settings.tls_enabled` requires both (config.py), and a half set is not TLS at
    all -- `cmd_serve` deliberately forwards nothing in that case, so there is no file to open and no failure to name.
    A directory counts as unusable because opening it raises `IsADirectoryError`, an OSError like any other.
    """
    if not settings.tls_enabled:
        return None

    # Two passes, in this order, because the cheaper mistake is the more common one and a message about bytes would
    # send an operator to the wrong file: first "is there something to open at all", then "what is inside it".
    for field_name, knob in _TLS_KNOBS:
        # `ssl_certfile`/`ssl_keyfile` are `Path | None` and `tls_enabled` already proved both are set; the assert is
        # for mypy, which cannot narrow across two separate fields from a property on a third.
        path = getattr(settings, field_name)
        assert path is not None
        spelling = _tls_spelling(settings, field_name, path)
        hint = _separator_hint(spelling, path)
        if not path.exists():
            return f"config error: {knob} points at a file that does not exist: {path}{hint}"
        if not os.access(path, os.R_OK):
            return f"config error: {knob} is not readable by this process: {path}{hint}"
        if path.is_dir():
            return f"config error: {knob} is a directory, not a certificate or key file: {path}"

    certificate: x509.Certificate | None = None
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None = None

    for field_name, knob in _TLS_KNOBS:
        path = getattr(settings, field_name)
        assert path is not None  # as above; the existence pass already proved the pair is complete
        try:
            body = path.read_bytes()
        except OSError as exc:  # pragma: no cover - defensive: the checks above passed, so this is a race with deletion
            return f"config error: {knob} could not be read: {path}: {exc}"

        if field_name == "ssl_certfile":
            problem, certificate = _certificate_slot_problem(body)
        else:
            problem, private_key = _private_key_slot_problem(body)
        if problem is not None:
            return f"config error: {knob} {problem}: {path}"

    # Both files parse and both slots hold the right kind of object; the remaining way this pair fails is the one a
    # copy-paste causes -- a certificate from one key sitting next to another key's `*.key`.
    if certificate is not None and private_key is not None and not key_matches_certificate(private_key, certificate):
        return (
            f"config error: MYPKI_SSL_CERTFILE and MYPKI_SSL_KEYFILE do not match: the public key in "
            f"{settings.ssl_certfile} is not the key in {settings.ssl_keyfile}. OpenSSL reports this as "
            "[X509: KEY_VALUES_MISMATCH]. Issue a new leaf for this key, or point both knobs at one pair."
        )
    return None


def _certificate_slot_problem(body: bytes) -> tuple[str | None, x509.Certificate | None]:
    """`(problem, certificate)` for whatever the cert slot holds.

    The two refusals are spelled differently on purpose: a private key in the certificate slot is the swapped-file
    mistake and says so, while anything else that will not parse gets the general sentence. `ValueError` is what both
    `load_pem_x509_certificate` arms raise here (garbage -> "Unable to load PEM file", a key file -> "Valid
    PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters").
    """
    try:
        return None, x509.load_pem_x509_certificate(body)
    except ValueError:
        pass
    if _is_pem_private_key(body):
        return (
            "points at a private key, not a certificate (the two knobs look interchangeable and are not: the "
            "certificate slot wants BEGIN CERTIFICATE)"
        ), None
    return "does not hold a PEM certificate that could be parsed", None


def _private_key_slot_problem(body: bytes) -> tuple[str | None, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None]:
    r"""`(problem, key)` for whatever the key slot holds, or (None, key) when it is usable.

    `password=None` because uvicorn has no passphrase knob and OpenSSL's fallback is a prompt on stdin (an
    encrypted key made this probe stop at `Enter PEM pass phrase`). An unanswerable prompt is worse than a refusal, so
    an encrypted server key is refused here with the fix named. The two failure arms are different exceptions and mean
    different things (the two refusals say which is which):

      `TypeError: Password was not given but private key is encrypted` -- it *is* a private key, just one uvicorn
        cannot open;
      `ValueError: Valid PEM but no BEGIN/END delimiters for a private key found` -- it is something else entirely,
        and the follow-up certificate load says whether that something is the swapped-file mistake or unparsable bytes.

    The final `isinstance` narrowing is not decoration: `load_pem_private_key` is typed as returning a union covering
    Ed25519/Ed448/DH and the post-quantum key types, none of which OpenSSL will accept for a TLS server certificate and
    none of which mypki issues (`keys.ALLOWED_KEY_SPECS`). Naming the type an operator pasted in beats handing it to
    uvicorn to fail on, and beats widening this function's annotation to a union nothing here can use.
    """
    encrypted_problem = (
        "is an encrypted private key, and uvicorn cannot be given its passphrase: it would stop and prompt on stdin, "
        "which a server process cannot answer. Write this server key unencrypted (this is not the CA key)"
    )
    certificate_problem = (
        "points at a certificate, not a private key (the two knobs look interchangeable and are not: the key slot "
        "wants BEGIN PRIVATE KEY)"
    )

    try:
        loaded = load_pem_private_key(body, password=None)
    except TypeError:
        return encrypted_problem, None
    except ValueError:
        try:
            x509.load_pem_x509_certificate(body)
        except ValueError:
            return "does not hold a PEM private key that could be parsed", None
        return certificate_problem, None

    if not isinstance(loaded, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        return f"is a {type(loaded).__name__} key, which OpenSSL will not use for a TLS server certificate", None
    return None, loaded


def _is_pem_private_key(body: bytes) -> bool:
    """True when this byte string is a readable PEM private key of any kind.

    Used only to name a mistake more precisely, never to accept it: `load_pem_private_key` with no password raises on
    an encrypted key, and an encrypted key in the cert slot should still read as "a private key", so the marker test is
    textual here rather than another load attempt.
    """
    if b"-----BEGIN" in body and b"PRIVATE KEY-----" in body:
        return True
    try:
        load_pem_private_key(body, password=None)
    except (ValueError, TypeError):
        return False
    return True


def _tls_spelling(settings: Settings, field_name: str, path: Path) -> str:
    """The text the operator actually wrote for one TLS knob, falling back to `str(path)`.

    `Settings._raw_ssl_spellings` (config.py) is what makes this possible on Windows; a rebuild that only ever saw a
    `Path` has nothing to report beyond `str(path)`, which remains correct behaviour on POSIX.
    """
    raw = settings.raw_path_spelling(field_name)
    return raw if raw is not None else str(path)


def _separator_hint(text: str, resolved: Path | None = None) -> str:
    r"""A trailing hint for the one spelling mistake that produces this failure most often.

    With the pinned settings layer plus dotenv: a saved line written as `MYPKI_SSL_CERTFILE=C:\\root_apps\\...`
    (doubled backslashes, which is what an editor or a script that escaped for a shell produces) reaches pydantic
    verbatim as a path containing literal doubled separators. On Windows that is not the path the operator means; on
    any OS it is a path that does not exist. dotenv also honours `\` as an escape inside double quotes, which is why
    docs/REFERENCE.md "Serving and exposure" and `.env.example` tell operators to use forward slashes or *single*
    backslashes.

    This takes the **raw configured text**, not `str(path)` — and pathlib collapses
    doubled separators on Windows -- `str(PureWindowsPath("C:\\root_apps\\server.crt"))` is
    `C:\root_apps\server.crt`, while `PurePosixPath` of the same string keeps them doubled -- so re-deriving the
    spelling from a `Path` made this hint unreachable on exactly the OS where the mistake is common, and only reachable
    on POSIX. The text comes from `Settings._raw_ssl_spellings` instead.
    """
    if "\\\\" not in text and "//" not in text:
        return ""

    lines = [
        "",
        "  That path contains doubled separators. In the saved file and in .env, write it with forward slashes",
        "  (C:/root_apps/mypki-data/www/server.crt) or single backslashes",
        "  (C:\\root_apps\\mypki-data\\www\\server.crt).",
    ]
    # Windows is where this matters most and where the operator can least see it: what `Path` resolved to is not what
    # they wrote, and printing only the resolved form hides the mistake that produced it.
    if resolved is not None and text != str(resolved):
        lines.append(f"  You configured it as: {text}")
    return "\n".join(lines)


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"} or host.startswith("127.")


def _startup_passphrase(args: argparse.Namespace) -> bytes | None:
    """Passphrase for an existing encrypted CA key, from the named env var or a prompt.

    Read once here and held in process memory for the lifetime of the server (page-map §6): request handlers never
    re-read
    the key file, which is both faster and a shorter window in which the passphrase has to exist anywhere.
    """
    env_name = getattr(args, "passphrase_env", None) or "MYPKI_CA_PASSPHRASE"
    from_env = os.environ.get(env_name)
    if from_env:
        return from_env.encode("utf-8")
    key_path = paths.ca_key_path(paths.resolve_data_dir(getattr(args, "data_dir", None)))
    if not key_path.exists():
        return None
    try:
        raw = key_path.read_bytes()
    except OSError:
        return None
    if b"ENCRYPTED PRIVATE KEY" not in raw:
        return None
    # The key is encrypted and no env var was supplied: prompt rather than fail, because `serve` is the command an
    # operator
    # reaches for when they are already at a terminal.
    return getpass.getpass(f"CA key passphrase ({env_name} if you prefer to set it non-interactively): ").encode(
        "utf-8"
    )


# ------------------------------------------------------------------------------------------------ info


def cmd_info(args: argparse.Namespace) -> int:
    settings = get_settings()
    root = paths.resolve_data_dir(args.data_dir, env_override=str(settings.data_dir) if settings.data_dir else None)
    # `info` takes only --data-dir per page-map §6, so the passphrase env name has to be defaulted rather than read off
    # the namespace: `args.passphrase_env` does not exist for this subcommand, and reading it is an AttributeError
    # traceback -- the exact thing this CLI promises never to print for an expected condition.
    try:
        bundle = load_ca(
            root,
            passphrase=_startup_passphrase(args),
            passphrase_env=getattr(args, "passphrase_env", None) or "MYPKI_CA_PASSPHRASE",
        )
    except (CaNotFoundError, CaPassphraseError) as exc:
        print(f"info: {exc}", file=sys.stderr)
        return EXIT_MISSING_STATE

    facts = describe_ca(bundle.cert)
    store = IssuedStore(paths.db_path(root))

    print(f"mypki {__version__}")
    print(f"  data dir           {root}")
    print(f"  config dir         {paths.config_dir(settings)}")
    print(f"  database           {paths.db_path(root)} ({store.count()} issued record(s))")
    print(f"  certificate        {bundle.cert_path}")
    print(f"  private key        {bundle.key_path} ({'present' if bundle.key_present else 'MISSING'})")
    print(f"  subject            {facts['subject']}")
    print(f"  serial             {facts['serial_hex']}")
    not_before = facts["not_before_utc"]
    not_after = facts["not_after_utc"]
    print(f"  valid (UTC)        {not_before:%Y-%m-%d %H:%M:%S}Z  ->  {not_after:%Y-%m-%d %H:%M:%S}Z")
    expired = not_after < _now_utc()
    print(f"  status             {'EXPIRED' if expired else 'valid'}")
    print(f"  sha256 fingerprint {format_fingerprint(str(facts['fingerprint_sha256']))}")
    print(f"  key                {facts['key_type']}")
    print(f"  basic constraints  {facts['basic_constraints']}")
    if expired:
        print(
            "\nThe CA certificate has expired. Re-issue it with `mypki init-ca --force` (the current pair is "
            "archived, not deleted) and re-install the new root on every client."
        )
    return EXIT_OK


def _now_utc():
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc)


# ------------------------------------------------------------------------------------------------- main


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # `serve` configures logging itself (it needs the resolved settings first); `init-ca` and `info` get it here so a
    # --log-level DEBUG actually reaches them. configure_logging is idempotent, which is what makes running it
    # twice safe.
    if args.command != "serve":
        try:
            configure_logging(settings_with_cli_overrides(args))
        except ValueError as exc:
            print(f"config error: {exc}", file=sys.stderr)
            return EXIT_USAGE
    try:
        return int(args.handler(args) or 0)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
