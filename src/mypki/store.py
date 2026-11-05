"""The issued-certificates record store: metadata only, in stdlib SQLite with WAL.

Why this module exists at all: an operator needs to answer "what did I sign, and when does it expire?" without opening
a browser history, and `GET /issued` (page-map §5) is that answer. The interesting decision is not the schema but what
is **excluded** from it — no private keys, no CSR bodies, no certificate bodies. A database full of PEM blobs is a
second copy of every secret this project handles, in a file that operators routinely back up, ship to log aggregators
and attach to support tickets. Serial numbers, names, types and dates answer the operational question; nothing here
answers "what is the key?".

Why stdlib `sqlite3` rather than an ORM or a JSON file: no dependency, one file, cross-platform, and WAL gives a
reader (`GET /issued`) that does not block the writer (a signing POST). An ORM would add a dependency and a migration
system for a single table; a JSON file would need its own locking story to get what WAL provides.

Why dates are stored as ISO-8601 **UTC** strings rather than SQLite's numeric or naive-text conveniences: the list page
must show times that mean the same thing on a Windows laptop and a UTC container, and `datetime.fromisoformat` of a
`+00:00`-suffixed string round-trips to an aware datetime. Storing naive local times would make "issued 14:00" mean two
different instants depending on whose machine ran the CLI (page-map §5).

Why `check_same_thread=False` plus a per-call connection rather than a shared one: uvicorn runs sync request handlers in
a threadpool, so a single connection created at startup would be used from several threads and raise. A short-lived
connection per operation is the simple correct answer for a store this small; it also means no long-lived handle to
leak when the app shuts down.

Revocation: what this table records, and what it emphatically is not
------------------------------------------------------------------------------
`/issued` now carries a **Status** column, and `revoke()` writes one narrow update: a UTC stamp plus a short reason on
an existing row. That is the whole feature at storage level -- two more columns of metadata, no PEM, no key, nothing
that a client can consume.

The honest statement of the limit: **a revoked row in this database changes nothing about a certificate that is already
installed somewhere.** X.509 clients decide trust from the certificate chain and validity dates; they consult a
Certificate Revocation List (RFC 5280 §5) or OCSP, and mypki publishes neither yet. `revoke()` therefore records the
operator's decision, makes it visible on `/issued`, and is the data source a real CRL gets built from in the next
release -- it is not a revocation a browser will act on. Saying so here matters because "there is now a revoke button"
is exactly the sentence an operator reads as "my certificates are revocable", and acting on that misreading (issuing 2-,
3- and 4-year leaves because "I can always revoke them") has a real cost.

Why the columns live in this table rather than a second `revocations` table: one certificate is one row, and a status
stored somewhere else has to be joined back on every read for a page that renders twelve rows. Two nullable columns on
an existing row are also the smallest possible migration -- see `init_schema`, which adds them in place so an older
database keeps its records.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import sqlite3
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path

from .validators import SanSet

log = logging.getLogger("mypki.store")

#: The one table. `sans_json` is a JSON array of the *validated* SANs, so what the list page displays is what was
#: issued rather than what was typed. No column here holds key or PEM material -- see module docstring, and
#: `test_store.py` asserts that by reading the schema rather than by trusting this comment.
#:
#: `revoked_at_utc` / `revocation_reason` are NULL for a certificate this CA has never revoked. A database created by
#: an older one lacks them entirely and gains them at the next `init_schema()` -- see `_ensure_revocation_columns`.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS issued_certs (
    serial_hex       TEXT PRIMARY KEY,
    cert_type        TEXT NOT NULL,
    common_name      TEXT NOT NULL,
    sans_json        TEXT NOT NULL DEFAULT '[]',
    not_before_utc   TEXT NOT NULL,
    not_after_utc    TEXT NOT NULL,
    issued_at_utc    TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    revoked_at_utc   TEXT,
    revocation_reason TEXT
)
"""

_COLUMNS = (
    "serial_hex",
    "cert_type",
    "common_name",
    "sans_json",
    "not_before_utc",
    "not_after_utc",
    "issued_at_utc",
    "fingerprint_sha256",
    "revoked_at_utc",
    "revocation_reason",
)

#: The columns an older database lacks, as name + type pairs because `ALTER TABLE ... ADD COLUMN` needs both.
#: Keeping them as a separate list is what makes the migration reviewable: adding a column to `_COLUMNS` without adding
#: it here means an existing operator's database silently lacks it and every read answers NULL for a revoked row.
_REVOCATION_COLUMNS = (("revoked_at_utc", "TEXT"), ("revocation_reason", "TEXT"))

#: `revocation_reason` is bounded so one careless note cannot break the table layout, and short enough to fit one cell.
#: It is operator prose, not a protocol field — the responder does carry protocol reason fields (OCSP carries
#: `x509.ReasonFlags`, `ocsp_responder.py`) and this column still maps onto exactly one of them:
#: `ReasonFlags.unspecified`, always. Inventing `keyCompromise` out of a sentence an operator typed would be a claim
#: about how a key was lost that this CA cannot support, and the CRL side carries no reason entry extension at all
#: (`crl.py`: an absent code means `unspecified` under RFC 5280 §5.3.1). The prose stays where it is useful -- on
#: `/issued`, for the human who reads the row next year.
MAX_REVOCATION_REASON_LENGTH = 120

__all__ = ["IssuedRecord", "IssuedStore"]


@dataclass(frozen=True)
class IssuedRecord:
    """One row of the issued list, as read back (page-map §5)."""

    serial_hex: str
    cert_type: str
    common_name: str
    sans: tuple[str, ...]
    not_before_utc: dt.datetime
    not_after_utc: dt.datetime
    issued_at_utc: dt.datetime
    fingerprint_sha256: str
    revoked_at_utc: dt.datetime | None = None
    revocation_reason: str | None = None

    @property
    def sans_display(self) -> str:
        """SANs joined for the table cell; the full value goes in `title=` so truncation never hides information."""
        return ", ".join(self.sans)

    @property
    def status(self) -> str:
        """`active` or `revoked` -- the Status column on `/issued`.

        Two states and not three. A certificate past its `not_after_utc` still reports `active`, because this CA never
        revoked it, and printing `expired` in a Status column whose other value is `revoked` would imply this host knows
        what every client currently accepts. The expiry date sits in the adjacent cell.
        """
        return "revoked" if self.revoked_at_utc is not None else "active"

    @property
    def is_expired(self) -> bool:
        """Past `not_after_utc`, judged against UTC -- the same clock every date in this store was written with."""
        return self.not_after_utc <= dt.datetime.now(dt.timezone.utc)


class IssuedStore:
    """Read/write access to `<data>/issued.db`.

    Still no DELETE (page-map §5): a record is evidence of what this CA signed, and deleting it would make a certificate
    that is valid somewhere look like it was never issued. The one UPDATE this store has ever had is `revoke()`, which
    sets the two revocation columns on an existing row and changes nothing else about it.
    """

    def __init__(self, db_file: Path) -> None:
        self.db_file = db_file

    # -------------------------------------------------------------------------------- plumbing

    def _connect(self) -> sqlite3.Connection:
        """A short-lived connection with the invariants this store depends on.

        WAL is set per connection rather than once at creation because the setting lives in the database file but is
        re-asserted harmlessly, and because a first-ever connection to a fresh file must have it applied before any
        concurrent reader shows up. `foreign_keys` is off by default in SQLite and there are no foreign keys here; the
        timeout exists so a signing POST and an `/issued` GET that overlap wait briefly instead of throwing
        "database is locked" at an operator who did nothing wrong.
        """
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.db_file), timeout=5.0, check_same_thread=False)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def init_schema(self) -> None:
        """Create the table if absent, and add the revocation columns when an older database lacks them.

        Safe to call on every startup -- which is how `create_app` calls it and how every read and write method calls
        it. The halves answer different situations: a fresh install needs the CREATE, an existing `<data>/issued.db`
        upgraded in place needs the ALTERs, with its records intact (an operator's whole reason for having this database
        is the records).
        """
        with closing(self._connect()) as connection, connection:
            connection.execute(_SCHEMA)
            _ensure_revocation_columns(connection)

    # ------------------------------------------------------------------------------------ revocation

    def revoke(
        self,
        *,
        serial_hex: str,
        reason: str | None = None,
        revoked_at_utc: dt.datetime | None = None,
    ) -> IssuedRecord | None:
        """Stamp one existing record as revoked. Returns the updated record, or None when no row carries that serial.

        Why None rather than raising for an unknown serial: `/issued` renders from a list the operator read moments ago,
        and a second tab -- or a restart onto an older database -- can make that serial stale. The handler turns None
        into "no record with that serial on this host", which is the true and useful sentence; an exception would be a
        500-shaped way of saying the same thing.

        Why re-revoking is a no-op rather than an error or a fresh stamp: `revoked_at_utc` is a fact about when the
        decision was made, so a page refresh or a double-click must not move it to "now". The stored reason is left
        alone for the same reason.

        No key material and no certificate body are read, needed or written: revocation addresses a row by its serial.
        """
        self.init_schema()
        existing = _fetch_row(self._connect(), serial_hex)
        if existing is None:
            log.info("revoke refused: no record with serial %s", serial_hex)
            return None
        current = _row_to_record(existing)
        if current.revoked_at_utc is not None:
            log.info("revoke no-op: serial %s already revoked at %s", serial_hex, current.revoked_at_utc.isoformat())
            return current

        stamp = _aware(revoked_at_utc or dt.datetime.now(dt.timezone.utc))
        note = (reason or "").strip()[:MAX_REVOCATION_REASON_LENGTH] or None
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "UPDATE issued_certs SET revoked_at_utc = ?, revocation_reason = ? WHERE serial_hex = ?",
                (_iso(stamp), note, serial_hex),
            )
        log.info("revoked record serial=%s cn=%s reason=%s", serial_hex, current.common_name, note or "(none given)")
        return replace(current, revoked_at_utc=stamp, revocation_reason=note)

    # ------------------------------------------------------------------------------------ writes

    def add_record(
        self,
        *,
        serial_hex: str,
        cert_type: str,
        common_name: str,
        sans: SanSet | tuple[str, ...],
        not_before_utc: dt.datetime,
        not_after_utc: dt.datetime,
        fingerprint_sha256: str,
        issued_at_utc: dt.datetime | None = None,
    ) -> IssuedRecord:
        """Insert one issued certificate's metadata.

        Accepts a `SanSet` (the signing path) or a plain tuple (tests and re-imports) so this module does not need to
        know which layer produced the record — it only needs names, never objects with validation logic in them.

        `INSERT OR REPLACE` on the primary key rather than a bare INSERT: `x509.random_serial_number()` makes a
        collision
        astronomically unlikely, but a re-run of a signing POST after a browser resubmit produces the *same* serial from
        the same confirmed CSR, and failing loudly there would tell an operator about an astronomically-impossible event
        instead of the ordinary thing that happened.
        """
        # Same self-initialising read path as `list_records`/`count`: the app factory already ran `init_schema` at
        # startup, but a store used on its own (an embedder, a test, a future import tool) must not answer a first write
        # with a bare `sqlite3.OperationalError: no such table`. `CREATE TABLE IF NOT EXISTS` costs one statement.
        self.init_schema()
        names = sans.all_entries() if isinstance(sans, SanSet) else tuple(sans)
        issued_at = issued_at_utc or dt.datetime.now(dt.timezone.utc)
        # The two revocation columns are written as NULL rather than left out of the statement: `INSERT OR REPLACE` on a
        # re-submitted signing POST would otherwise keep whatever stamp an earlier row for this serial carried, which
        # means a re-issued certificate could come back already revoked.
        row = (
            serial_hex,
            cert_type,
            common_name,
            json.dumps(list(names), ensure_ascii=False),
            _iso(not_before_utc),
            _iso(not_after_utc),
            _iso(issued_at),
            fingerprint_sha256,
            None,
            None,
        )
        with closing(self._connect()) as connection, connection:
            connection.execute(
                f"INSERT OR REPLACE INTO issued_certs ({', '.join(_COLUMNS)}) "
                f"VALUES ({', '.join('?' for _ in _COLUMNS)})",
                row,
            )
        log.info("recorded issued cert serial=%s type=%s cn=%s", serial_hex, cert_type, common_name)
        return IssuedRecord(
            serial_hex=serial_hex,
            cert_type=cert_type,
            common_name=common_name,
            sans=tuple(names),
            not_before_utc=_aware(not_before_utc),
            not_after_utc=_aware(not_after_utc),
            issued_at_utc=_aware(issued_at),
            fingerprint_sha256=fingerprint_sha256,
        )

    # ------------------------------------------------------------------------------------ reads

    def list_records(self, limit: int = 500) -> list[IssuedRecord]:
        """Newest-first list for `GET /issued` (page-map §5).

        Ordered by `issued_at_utc` then `serial_hex`, not by rowid: two certificates issued in the same second
        must still
        appear in a stable order, and rowid ordering makes that depend on which connection wrote first. The
        secondary key
        is what makes the page reproducible rather than merely recent.

        `limit` is a ceiling on rows rendered, not a paging feature — there is no paging here by design (page-map §5).
        """
        self.init_schema()
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM issued_certs ORDER BY issued_at_utc DESC, serial_hex DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
        return [_row_to_record(row) for row in rows]

    def count(self) -> int:
        """Number of records — used by `mypki info` and the home page footer."""
        self.init_schema()
        with closing(self._connect()) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM issued_certs").fetchone()[0])

    def count_revoked(self) -> int:
        """How many records carry a revocation stamp. The `/issued` footer and the About page counter.

        **Lifetime**, not current: this counts every row that was ever stamped, because nothing deletes them (page-map
        §5). That is exactly what `CRLNumber` needs — RFC 5280 §5.2.1 wants a number that only increases for a
        given issuer, and the CRL's *entry* count can shrink when a revoked certificate expires, so the two
        numbers are deliberately different things. `/crl` states both: entries today, revocations ever.
        """
        self.init_schema()
        with closing(self._connect()) as connection:
            return int(
                connection.execute("SELECT COUNT(*) FROM issued_certs WHERE revoked_at_utc IS NOT NULL").fetchone()[0]
            )

    def revoked_records(self) -> list[IssuedRecord]:
        """Every revoked record a CRL should carry right now: stamped, and not yet expired (page-map §14).

        Two rules in one read, both serving the derived-entry rule:

        * `revoked_at_utc IS NOT NULL` — including every stamp this table has ever held, which is the half of that
          answer an operator would otherwise have to re-do by hand;
        * **not** `is_expired` — a revoked certificate whose own validity has lapsed is left out. RFC 5280 §5.3.3 lets
          a CA remove an entry only if it asserts the certificate will no longer be considered valid, which is true here
          (it has expired anyway), but the drop must be *said* on `/crl` because "removed from the CRL" reads to a human
          as "un-revoked", and there is no un-revoke in this store.

        No `limit`, unlike `list_records` (which caps at 500 because it renders a page). A CRL is not a page: a revoked
        certificate that happens to be the 501st row would otherwise stay trusted by every client that consults the CRL,
        which is the opposite of why this file exists. `test_crl.py` proves there is no cap with a >500-row store.

        Ordered oldest-stamp-first, then by serial: a rebuilt CRL lists entries in the order the decisions were made, so
        diffing two builds shows additions at the end rather than a reshuffle. The expiry filter runs in Python against
        `IssuedRecord.is_expired` rather than in SQL against the stored ISO text, because that property is where the
        rule lives (one clock, UTC, `not_after_utc <= now`) and a lexicographic comparison of date strings would be a
        second,
        weaker copy of it.

        Read-only, so it inherits `revoke()`'s posture: no key material, no certificate body — a revocation is addressed
        by its serial number.
        """
        self.init_schema()
        columns = ", ".join(_COLUMNS)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"SELECT {columns} FROM issued_certs WHERE revoked_at_utc IS NOT NULL "
                "ORDER BY revoked_at_utc ASC, serial_hex ASC"
            ).fetchall()

        records = [_row_to_record(row) for row in rows]
        live = [record for record in records if not record.is_expired]
        dropped = len(records) - len(live)
        if dropped:
            # Loud enough that an operator reading the log can see the CRL is smaller than the ledger, and why.
            log.info(
                "CRL entry set: %d revoked row(s), %d dropped as expired (rows stay in %s; there is no un-revoke)",
                len(live),
                dropped,
                self.db_file,
            )
        return live

    def find(self, serial_hex: str) -> IssuedRecord | None:
        """One record by serial, or None when this host never signed it.

        This exists for `/issued`'s bulk revoke: the confirmation step has to name every certificate about to be
        stamped (serial **and** common name), and `revoke()` only answers after the stamp exists. A read-only
        lookup is what lets the page show "revoking these three" instead of a list of bare hex numbers.

        Read-only, so it inherits `revoke()`'s posture: no key material, no certificate body — a revocation is
        addressed by its serial number.
        """
        self.init_schema()
        row = _fetch_row(self._connect(), serial_hex)
        return None if row is None else _row_to_record(row)

    def schema_columns(self) -> list[str]:
        """Column names as SQLite reports them. Public because `test_store.py` asserts the no-key-material posture."""
        self.init_schema()
        with closing(self._connect()) as connection:
            return [str(row[1]) for row in connection.execute("PRAGMA table_info(issued_certs)").fetchall()]

    def journal_mode(self) -> str:
        """The live journal mode, so WAL is asserted rather than assumed."""
        self.init_schema()
        with closing(self._connect()) as connection:
            return str(connection.execute("PRAGMA journal_mode").fetchone()[0])


# -------------------------------------------------------------------------------------- conversions


def _iso(value: dt.datetime) -> str:
    """UTC ISO-8601 with an explicit offset.

    A naive datetime is converted rather than rejected: the values reaching here come from `cert.not_valid_before_utc`
    (aware: the UTC accessor produced it) but a hand-built record could be naive, and storing "2027-01-01"
    without an offset is how a timezone bug becomes permanent data rather than a caught exception.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat()


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _ensure_revocation_columns(connection: sqlite3.Connection) -> None:
    """Add the two revocation columns to a database that predates them.

    `PRAGMA table_info` is consulted rather than running `ALTER TABLE` and swallowing the failure, because SQLite
    reports "duplicate column name" as an error that aborts the surrounding transaction -- a startup path that depends
    on catching its own error is a startup path whose behaviour changes with the next SQLite release. Present columns
    are skipped, missing ones are added nullable, which is what makes every older row read back as `active`.

    Runs inside every `init_schema()` call, so it has to be idempotent and cheap: one PRAGMA and at most two ALTERs.
    """
    present = {str(row[1]) for row in connection.execute("PRAGMA table_info(issued_certs)").fetchall()}
    for name, sql_type in _REVOCATION_COLUMNS:
        if name not in present:
            # Both halves of this interpolation are literals from `_REVOCATION_COLUMNS`; no operator input can reach an
            # SQL identifier here. Spelled with the column list explicit so that stays readable.
            connection.execute(f"ALTER TABLE issued_certs ADD COLUMN {name} {sql_type}")
            log.info("upgraded issued.db: added column %s", name)


def _fetch_row(connection: sqlite3.Connection, serial_hex: str) -> tuple[object, ...] | None:
    """One record's row by primary key, or None. Closes the connection it was handed.

    Takes the connection rather than opening its own because `revoke()` needs the read and the write to be separate
    operations on short-lived connections (the same posture as the rest of this class), and a helper that leaked a
    connection on the not-found path would leak one per mistyped serial.
    """
    columns = ", ".join(_COLUMNS)
    try:
        cursor = connection.execute(f"SELECT {columns} FROM issued_certs WHERE serial_hex = ?", (serial_hex,))
        return cursor.fetchone()
    finally:
        connection.close()


def _row_to_record(row: tuple[object, ...]) -> IssuedRecord:
    raw_sans = row[3]
    assert isinstance(raw_sans, str)
    try:
        parsed = json.loads(raw_sans)
    except json.JSONDecodeError:  # pragma: no cover - defensive against a hand-edited database
        log.warning("sans_json for serial %s is not valid JSON; showing it empty", row[0])
        parsed = []
    # `len(row) > 8` guards the two newest columns rather than assuming them: `_COLUMNS` and the table are brought into
    # agreement by `init_schema`, but a record built from a row read out of a hand-opened connection (a future import
    # tool, or a test that selects eight columns) must not IndexError.
    revoked_raw = row[8] if len(row) > 8 else None
    reason_raw = row[9] if len(row) > 9 else None
    return IssuedRecord(
        serial_hex=str(row[0]),
        cert_type=str(row[1]),
        common_name=str(row[2]),
        sans=tuple(str(item) for item in parsed),
        not_before_utc=dt.datetime.fromisoformat(str(row[4])),
        not_after_utc=dt.datetime.fromisoformat(str(row[5])),
        issued_at_utc=dt.datetime.fromisoformat(str(row[6])),
        fingerprint_sha256=str(row[7]),
        # NULL means "this CA has never revoked it", which is also what every older row reads back as once
        # `_ensure_revocation_columns` adds the column to an existing table.
        revoked_at_utc=dt.datetime.fromisoformat(str(revoked_raw)) if revoked_raw else None,
        revocation_reason=str(reason_raw) if reason_raw else None,
    )
