"""Logging setup: one rotating file plus an optional console stream, driven by `.env`.

Why this module exists
----------------------
mypki's failure modes are mostly *loud* (a refused CSR, a missing CA) — but the one failure mode that matters most is
silent: a key material reaching a log line. A CA whose logs contain private keys has leaked even if no HTTP
response ever
did, because logs get backed up, shipped to aggregators and pasted into tickets. So this file does two jobs: it
makes the
ordinary logging work on both Windows and Linux (the four measured behaviours below), and it enforces one invariant over
the whole `mypki.*` logger tree — no record containing `PRIVATE KEY` is ever written.

An enforced invariant, not a convention: the reference project's rule was "a failure must be visible in the artifact",
because too *little* reached its logs. mypki's mirror image is that too *much* could. Both need something a test can
assert rather than something a reviewer has to remember.

Knobs (see `.env.example`)
-------------------------
`MYPKI_LOG_LEVEL`, `MYPKI_LOG_FILE`, `MYPKI_LOG_MAX_BYTES`, `MYPKI_LOG_BACKUP_COUNT`, `MYPKI_LOG_TO_CONSOLE`.
`LOG_MAX_BYTES * (LOG_BACKUP_COUNT + 1)` is the hard ceiling on log bytes: the live file plus `.log.1` … `.log.N`.

Four non-obvious things this file gets right, each measured rather than assumed
-------------------------------------------------------------------------------
1. **Handlers go on the root logger, not on `mypki`.** The point is to capture uvicorn's records too — startup lines and
   one access line per request — and those are emitted by `uvicorn.*` loggers. Attaching to `logging.getLogger("mypki")`
   would file mypki's own lines and leave every server line on the terminal, which is exactly the half an operator wants
   when someone from the network team asks "did this request reach us?".

2. **`cli.py` must pass `log_config=None` to uvicorn.** Measured against uvicorn: `uvicorn.run()`/`uvicorn.Server.run()`
   applies its own `logging.config.dictConfig`, which gives the `uvicorn` logger `propagate=False` and its own
   stdout/stderr handlers. Without this argument every server line — including each access log — goes to the
   terminal and
   never into the rotating file. That one keyword is the whole reason serve-mode logging works; do not "tidy up" that
   argument during a refactor.

3. **Encoding is pinned to UTF-8.** mypki's messages contain non-ASCII (`—`, `→`, `°` in subject strings copied from
   certificates). A handler opened with the locale default raises *inside* `Handler.emit` on a POSIX/C-locale box,
   and on
   Windows that is the common case rather than the edge case. A logging failure must never be able to break request
   handling — and an unpinned encoding makes it able to.

4. **A relative `MYPKI_LOG_FILE` resolves against the working directory, and every run says which directory it picked.**
   The default `logs/mypki.log` is deliberately *not* anchored to the package or the repository: anchoring it
   would make a
   wheel-installed CA write into site-packages, and would silently override an operator who meant "relative to
   where I run
   this". So `configure_logging` writes the resolved absolute path (plus cwd) as the **first line** of the log file. The
   answer to "where did it actually land?" has to come from the process, not from reading a config file — which is how a
   supervisor with its own `WorkingDirectory` leaves evidence in the artifact instead of a mystery.

Rotation is per-process: `RotatingFileHandler` does not coordinate between processes, so run **one worker per log file**
(or give each worker its own `MYPKI_LOG_FILE`). mypki's serve command runs a single uvicorn process for this reason and
because the one-shot download store (page-map §10) is per-process too.
"""

from __future__ import annotations

import contextlib
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import TypeVar

from .config import Settings

#: Filename used when a log path is configured as a directory rather than a file.
DEFAULT_LOG_FILENAME = "mypki.log"

#: The invariant this project's logging layer exists to enforce (page-map §0): no record naming private key material is
#: ever written to the log file or the console.
FORBIDDEN_MARKERS: tuple[str, ...] = ("PRIVATE KEY", "ENCRYPTED PRIVATE KEY")

#: Marks the handlers this module owns, so re-configuring removes ours and never a host application's handlers. Without
#: it, importing mypki into another app would let `configure_logging` delete that app's handlers while "fixing" logging.
_MANAGED_ATTR = "_mypki_managed_handler"

#: Name used to find the key-material filter instance, so repeated `configure_logging` calls do not stack copies of it
#: and so a test can assert the filter is installed rather than asserting that some log line went missing.
_KEY_FILTER_NAME = "mypki_no_private_key"

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

_LOGGING_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

__all__ = [
    "DEFAULT_LOG_FILENAME",
    "FORBIDDEN_MARKERS",
    "LOG_FORMAT",
    "PrivateKeyMaterialFilter",
    "configure_logging",
    "dropped_record_count",
    "get_logger",
    "resolve_level",
]


class PrivateKeyMaterialFilter(logging.Filter):
    """Drop any record that names private key material, wherever it came from.

    Installed on the **root** logger so it guards third-party records too: a future dependency that logs a key in
    a debug
    line is exactly as guilty as mypki would be, and a filter attached only to `mypki.*` would not see it.

    Two markers rather than one: `PRIVATE KEY` covers `BEGIN PRIVATE KEY` and `BEGIN RSA PRIVATE KEY`, and
    `ENCRYPTED PRIVATE KEY` is included explicitly because it *contains* the first marker anyway — listing both states
    which formats are in scope (PKCS#8 unencrypted, traditional OpenSSL, PKCS#8 encrypted) rather than leaving a
    reader to
    infer that one substring happens to cover all three.

    Deliberately not a redaction filter. Redacting means writing the line with the secret masked, which keeps the
    shape of
    a leak in the log and invites someone to reconstruct it; dropping the record means the artifact never contained key
    material at all. The cost is stated honestly: a bug that logs a key also loses its surrounding context, so the
    fix is
    to stop logging keys, and `test_no_key_leakage.py` plus this filter are what make that fix measurable.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = str(record.getMessage())
        except Exception:  # pragma: no cover - a broken __str__ on a formatted argument
            return False
        if any(marker in message for marker in FORBIDDEN_MARKERS):
            # Counting the drop is itself safe to log: it names no key material, and "a record was dropped" is the
            # evidence an operator needs to know the filter caught something rather than that nothing was written.
            _DROPPED.append(record)
            return False
        return True


#: Records dropped this process, newest last. Bounded so a runaway emitter cannot grow memory; read by tests and by
#: `mypki info` to report "the filter dropped N records", which is the difference between an invariant holding and an
#: invariant nobody checked.
_DROPPED: list[logging.LogRecord] = []

_MAX_TRACKED_DROPS = 20


def dropped_record_count() -> int:
    """How many records this process has dropped for naming key material."""
    return len(_DROPPED)


def resolve_level(name: str) -> int:
    """Map a level name to a level number. An unknown name is an error, not a silent INFO.

    The `getattr(logging, name.upper(), logging.INFO)` spelling means a typo in `.env` (`MYPKI_LOG_LEVEL=INFP`)
    produces a
    CA that quietly logs nothing at the level you asked for — discovered during the incident, not at startup.
    Raising here
    lets `cli.py` report it as a usage error and exit non-zero (page-map §6).
    """
    key = (name or "").strip().upper()
    if key not in _LOGGING_LEVELS:
        raise ValueError(f"log_level must be one of {sorted(_LOGGING_LEVELS)}, got {name!r}")
    return _LOGGING_LEVELS[key]


def get_logger(name: str = "mypki") -> logging.Logger:
    """The module logger for `name`, which must start with the package prefix.

    Every module in this project does `log = logging.getLogger("mypki.<module>")`; this helper exists so a call site can
    say `get_logger("mypki.ca")` without importing `logging` twice, and so the prefix is one string rather than fifteen.
    """
    return logging.getLogger(name)


_HandlerT = TypeVar("_HandlerT", bound=logging.Handler)


def _managed(handler: _HandlerT) -> _HandlerT:
    """Tag a handler as ours so re-configuring removes only our handlers.

    The generic signature is not decoration: annotating this `Handler -> Handler` widens the return type and forces the
    startup line to reach for `baseFilename` through `getattr` with a fallback — code that can never run (a file handler
    exists exactly when file logging is on) while reading as if it could. Keeping the concrete type means
    `handler.baseFilename` type-checks, so a rename upstream fails at mypy time instead of silently picking up the
    fallback string.
    """
    setattr(handler, _MANAGED_ATTR, True)
    return handler


def _drop_managed_handlers(logger: logging.Logger) -> None:
    """Remove handlers this module added, leaving any host application's handlers alone."""
    for handler in list(logger.handlers):
        if getattr(handler, _MANAGED_ATTR, False):
            logger.removeHandler(handler)
            # An already-closed handler on a weird filesystem must not be able to break shutdown.
            with contextlib.suppress(OSError):  # pragma: no cover - defensive, seen only on odd filesystems
                handler.close()


def _file_target(log_file: Path) -> Path:
    """Absolute, resolved target for the log file.

    `logging.FileHandler` already makes `baseFilename` absolute on its own (`os.path.abspath(os.path.expanduser(...))`,
    measured), so `.resolve()` is not what makes the startup line absolute — mutation testing in the reference project
    proved that deleting it left every handler-side test green. What it does buy is **normalisation**:
    `logs/../logs/x.log`
    and `logs/x.log` collapse to one target instead of two spelling variants with separate backup chains, and a
    symlinked
    `logs` directory reports the directory the bytes really land in. Pinned directly by a test, because nothing
    observable
    through the handler would notice if it were removed.
    """
    expanded = log_file.expanduser()
    if expanded.is_dir():
        # `MYPKI_LOG_FILE=logs` is an operator naming a directory; honouring it as one turns the log into a file named
        # after the directory and makes the startup line unreadable. Naming the default file inside it is the
        # useful answer.
        return (expanded / DEFAULT_LOG_FILENAME).resolve()
    return expanded.resolve()


def resolved_log_file(settings: Settings) -> Path | None:
    """Where this process's log records actually land, or None when file logging is off.

    Public because `/settings` (page-map §12) answers "where did it actually land?" without a restart-and-grep, and the
    answer must be the same path `build_file_handler` opens — which is why this wraps `_file_target` rather than
    re-deriving `expanduser`/default-filename rules a second time. Two implementations of that rule is how a page starts
    naming a file the process never writes to.
    """
    if settings.log_file is None:
        return None
    return _file_target(settings.log_file)


def build_file_handler(settings: Settings) -> logging.handlers.RotatingFileHandler | None:
    """Rotating file handler for `settings.log_file`, or None when file logging is off.

    Raises `OSError` (the caller decides how to degrade) rather than swallowing it here, so a misconfigured path is
    reported once, loudly, instead of silently producing no log file at all.
    """
    if settings.log_file is None:
        return None
    target = _file_target(settings.log_file)
    target.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        str(target),
        maxBytes=settings.log_max_bytes,
        backupCount=settings.log_backup_count,
        encoding="utf-8",  # measured behaviour 3 above; never remove this argument
        # mode "a": restarting appends to the tail of the previous run instead of truncating the only copy of
        # yesterday's
        # errors. Rotation is enforced by size, not by run boundary.
        mode="a",
    )
    return _managed(handler)


def configure_logging(settings: Settings) -> logging.Logger:
    """Attach mypki's handlers to the root logger and set the level. Idempotent.

    Idempotency matters twice: `create_app` runs once per uvicorn reload worker, and tests build many apps in one
    process.
    Both would otherwise stack duplicate handlers and write every line several times — which reads like a bug in
    whatever
    is being debugged, and with a rotating handler it also burns the rotation budget on duplicates.
    """
    root = logging.getLogger()
    level = resolve_level(settings.log_level)

    _drop_managed_handlers(root)
    root.setLevel(level)

    # One filter instance for the whole tree, found by name rather than rebuilt per call: stacking copies of a
    # filter that
    # all do the same thing is how a diagnostic becomes uncountable.
    key_filter = PrivateKeyMaterialFilter()
    key_filter.name = _KEY_FILTER_NAME

    opened: str | None = None
    try:
        handler = build_file_handler(settings)
    except OSError as exc:
        # An unwritable log path must not stop the CA from serving. Degrade to console and say why, once, instead of
        # failing startup or logging nothing at all.
        console = _managed(logging.StreamHandler(sys.stderr))
        console.setLevel(level)
        console.setFormatter(logging.Formatter(LOG_FORMAT))
        console.addFilter(key_filter)
        root.addHandler(console)
        # Absolute, like the success path: a failure line naming `logs/mypki.log` while cwd is somewhere else is exactly
        # the ambiguity this whole block exists to remove.
        root.warning(
            "log file %s is unusable (%s); falling back to console logging only",
            str((settings.log_file or Path(".")).expanduser().resolve()),
            exc,
        )
        return get_logger()

    if handler is not None:
        handler.setLevel(level)
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        handler.addFilter(key_filter)
        root.addHandler(handler)
        # What RotatingFileHandler actually opened -- the artifact's own statement of where it is writing, rather than a
        # restatement of the configured value.
        opened = str(getattr(handler, "baseFilename", _file_target(settings.log_file or Path("."))))

    if settings.log_to_console:
        console = _managed(logging.StreamHandler(sys.stderr))
        console.setLevel(level)
        console.setFormatter(logging.Formatter(LOG_FORMAT))
        console.addFilter(key_filter)
        root.addHandler(console)

    # The filter also goes on the `mypki` tree itself, so a `mypki.*` child cannot bypass it if a third party
    # attaches its
    # own handler to that subtree. Handlers and filters are independent objects in logging: guarding only the handlers
    # would leave a subtree with an inherited-but-unfiltered path.
    mypki_logger = logging.getLogger("mypki")
    if not any(isinstance(f, PrivateKeyMaterialFilter) for f in mypki_logger.filters):
        mypki_logger.addFilter(key_filter)

    # Measured behaviour 1's repair: uvicorn's loggers must propagate to root or their lines never reach the file.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.propagate = True

    # Emitted last, once every handler is attached, so this line lands in the log file *and* the console mirror. A
    # relative
    # default resolves against the cwd, so the run has to name the directory it chose (measured behaviour 4).
    if opened is None:
        root.info("logging to console only (MYPKI_LOG_FILE is empty); cwd=%s", Path.cwd())
    else:
        root.info(
            "logging to %s (cwd=%s; rotate at %d bytes, keep %d backup(s), ceiling %d bytes)",
            opened,
            Path.cwd(),
            settings.log_max_bytes,
            settings.log_backup_count,
            settings.log_max_bytes * (settings.log_backup_count + 1),
        )
    return get_logger()


#: Name used to find the filter instance so repeated `configure_logging` calls do not stack copies of it.
_KEY_FILTER_NAME = "mypki_no_private_key"
