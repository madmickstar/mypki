"""The issued-certificate record store: what it stores, how it orders reads, and what it refuses to store.

Why the schema is asserted rather than the docstring trusted: page-map §5 says this table holds *metadata about*
issued certificates, and the sentence that matters is "no column here holds key or PEM material". A comment saying so
is a convention; a test that reads `PRAGMA table_info` is an invariant (STYLE §8). The failure this prevents is subtle
and catastrophic -- a future "store the PEM so we can re-serve it" change would quietly turn a convenience database into
a copy of everything this CA ever signed.

Each negative case mutates one thing: a naive datetime instead of an aware one, a `SanSet` instead of a tuple, a limit
that is smaller than the row count. Hermetic via `conftest.py`'s autouse fixtures -- every database here lives under
`tmp_path`.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import inspect
import json
import sqlite3
from contextlib import closing

import pytest

from mypki import paths
from mypki.store import MAX_REVOCATION_REASON_LENGTH, IssuedRecord, IssuedStore
from mypki.validators import SanSet

# Columns page-map §5 lists. Kept as a literal here on purpose: if the schema and this list drift, that is the finding,
# and the drift is only visible against something fixed.
#
# 0.2.0 added `revoked_at_utc` + `revocation_reason`, the two halves of `/issued`'s Status column. Both are nullable,
# which
# is what makes every 0.1.0 row read back as `active` after an in-place upgrade (store._ensure_revocation_columns).
EXPECTED_COLUMNS = (
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

DAY_ONE = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
DAY_TWO = dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)


@pytest.fixture
def store(data_root) -> IssuedStore:
    """A store over `<data>/issued.db`, i.e. the same path `create_app` uses."""
    return IssuedStore(paths.db_path(data_root))


def _add(store: IssuedStore, serial: str, *, issued_at: dt.datetime, **overrides: object) -> IssuedRecord:
    """One record with everything constant except what a test explicitly changes."""
    options: dict[str, object] = {
        "serial_hex": serial,
        "cert_type": "server",
        "common_name": f"{serial}.internal",
        "sans": SanSet(dns=(f"{serial}.internal",)),
        "not_before_utc": DAY_ONE,
        "not_after_utc": DAY_TWO,
        "issued_at_utc": issued_at,
        # A plausible-looking 64-hex fingerprint derived from the serial, so a test can assert the value round-trips
        # without hard-coding a digest nobody recognises.
        "fingerprint_sha256": hashlib.sha256(serial.encode("utf-8")).hexdigest(),
    }
    options.update(overrides)
    return store.add_record(**options)  # type: ignore[arg-type]


# --------------------------------------------------------------------------------- the no-key-material posture


def test_schema_has_no_column_that_could_hold_key_or_pem_material(store: IssuedStore) -> None:
    """The invariant page-map §5 states, asserted by reading SQLite's own view of the table.

    Two halves: every column is one of the ten documented metadata columns (so an added `pem` or `key_pem` column fails
    here), and no column *name* even resembles key material. A stored PEM would also be findable by content, which
    `test_no_key_leakage.py` checks; this test is what stops it from ever being written.

    The two revocation columns pass the name check because they hold a timestamp and operator prose about a decision
    this host made — not a certificate field, and nothing a client needs in order to verify one.
    """
    columns = store.schema_columns()

    assert tuple(columns) == EXPECTED_COLUMNS, columns
    forbidden = ("pem", "key", "private", "csr", "passphrase", "secret")
    for name in columns:
        assert not any(word in name.lower() for word in forbidden), name


def test_record_values_survive_the_round_trip(store: IssuedStore) -> None:
    """What goes in comes back out, including the SAN tuple's order.

    Order matters because the table cell is a comma-joined string an operator reads: `*.internal` first and
    `a.internal` second is what they typed, and a JSON round-trip that reordered them would make the page disagree with
    the request it says it signed.
    """
    record = _add(
        store,
        "abc123",
        issued_at=DAY_ONE,
        sans=SanSet(dns=("*.internal", "a.internal"), ips=("10.0.0.7",)),
    )

    listed = store.list_records()
    assert len(listed) == 1
    stored = listed[0]
    assert stored.serial_hex == record.serial_hex == "abc123"
    assert stored.sans == ("*.internal", "a.internal", "10.0.0.7")
    assert stored.sans_display == "*.internal, a.internal, 10.0.0.7"
    assert stored.cert_type == "server"
    assert stored.fingerprint_sha256 == record.fingerprint_sha256


def test_sans_are_stored_as_json_of_names_only(store: IssuedStore) -> None:
    """`sans_json` holds a flat list of strings.

    Asserted against the raw column rather than the parsed record: a future change that serialised `SanSet` objects, or
    kept the rejected-entry diagnostics, would put validation chatter into durable storage -- and `rejected` carries
    operator-typed text, which is the wrong thing to keep forever.
    """
    _add(store, "aaa111", issued_at=DAY_ONE, sans=SanSet(dns=("a.internal",), ips=("10.0.0.7",)))

    connection = sqlite3.connect(str(store.db_file))
    try:
        raw = connection.execute("SELECT sans_json FROM issued_certs").fetchone()[0]
    finally:
        connection.close()

    assert json.loads(raw) == ["a.internal", "10.0.0.7"]
    assert "rejected" not in raw


def test_timestamps_are_stored_as_offset_aware_utc(store: IssuedStore) -> None:
    """ISO-8601 with an explicit offset, for naive and aware inputs alike.

    The naive case is the one that matters: a hand-built record or a future import path can easily carry a naive
    datetime, and storing `2027-01-01T00:00:00` with no offset makes the expiry mean something different on every
    client. Here it becomes `+00:00`, which is what "no timezone bug became permanent data" looks like.
    """
    _add(
        store,
        "naive1",
        issued_at=DAY_ONE,
        not_before_utc=dt.datetime(2026, 1, 1),
        not_after_utc=dt.datetime(2027, 1, 1),
    )

    stored = store.list_records()[0]
    assert stored.not_before_utc.tzinfo is not None
    assert stored.not_after_utc.utcoffset() == dt.timedelta(0)
    assert stored.issued_at_utc.utcoffset() == dt.timedelta(0)

    connection = sqlite3.connect(str(store.db_file))
    try:
        raw = connection.execute("SELECT not_before_utc, not_after_utc, issued_at_utc FROM issued_certs").fetchone()
    finally:
        connection.close()
    assert all(str(value).endswith("+00:00") for value in raw), raw


def test_a_non_utc_input_is_stored_converted_not_as_local_wall_time(store: IssuedStore) -> None:
    """One mutation from the previous test: an *aware* datetime with a two-hour offset.

    The instant has to survive, expressed in UTC. Storing `+02:00` verbatim would render "expires at 03:00" on one host
    and "expires at 01:00" on another, which is exactly how a rotation gets missed.
    """
    offset = dt.timezone(dt.timedelta(hours=2))
    _add(store, "tzoff1", issued_at=DAY_ONE, not_after_utc=dt.datetime(2027, 1, 1, 3, 0, tzinfo=offset))

    stored = store.list_records()[0]
    assert stored.not_after_utc == dt.datetime(2027, 1, 1, 1, 0, tzinfo=dt.timezone.utc)


def test_issued_at_defaults_to_now_when_not_supplied(store: IssuedStore) -> None:
    """The signing path does not pass `issued_at`; it must still land inside the last minute."""
    record = store.add_record(
        serial_hex="now123",
        cert_type="client",
        common_name="client.internal",
        sans=("cn.internal",),
        not_before_utc=DAY_ONE,
        not_after_utc=DAY_TWO,
        fingerprint_sha256="ab" * 32,
    )

    age = dt.datetime.now(dt.timezone.utc) - record.issued_at_utc
    assert dt.timedelta(0) <= age < dt.timedelta(minutes=1)


# --------------------------------------------------------------------------------------------- read behaviour


def test_list_is_newest_first_with_a_stable_secondary_key(store: IssuedStore) -> None:
    """`ORDER BY issued_at_utc DESC, serial_hex DESC`, not by rowid.

    The two records share one timestamp on purpose: that is the case where rowid ordering answers "which connection
    wrote first", and a page whose order depends on write races cannot be compared against a screenshot or a log. With
    the secondary key the order is reproducible from the data alone.
    """
    same_second = dt.datetime(2026, 5, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
    _add(store, "aaaa", issued_at=same_second)
    _add(store, "bbbb", issued_at=same_second)
    _add(store, "older1", issued_at=dt.datetime(2026, 4, 1, tzinfo=dt.timezone.utc))

    order = [record.serial_hex for record in store.list_records()]
    assert order == ["bbbb", "aaaa", "older1"], order


def test_limit_caps_rows_without_lying_about_the_total(store: IssuedStore) -> None:
    """`limit` is a ceiling on what is rendered, not paging (page-map §5).

    Three records exist, two are listed, and `count()` still reports three -- which is the pair of numbers the template
    prints as "2 of 3 records shown". A store that made `count()` respect the limit would make that sentence false.
    """
    for index in range(3):
        _add(store, f"serial{index}", issued_at=DAY_ONE + dt.timedelta(days=index))

    assert len(store.list_records(limit=2)) == 2
    assert store.count() == 3


def test_count_is_zero_before_anything_is_written(store: IssuedStore) -> None:
    """An empty store is a state, not an error -- the home page footer and `mypki info` both read it."""
    assert store.count() == 0
    assert store.list_records() == []


def test_init_schema_is_safe_to_call_repeatedly(store: IssuedStore) -> None:
    """Startup calls it on every boot, and a second call must not lose the first's data."""
    _add(store, "keepme1", issued_at=DAY_ONE)
    store.init_schema()
    store.init_schema()
    assert [record.serial_hex for record in store.list_records()] == ["keepme1"]


def test_journal_mode_is_wal(store: IssuedStore) -> None:
    """WAL is asserted rather than assumed (page-map §8).

    A signing POST and an `/issued` GET can overlap; without WAL the second waits on the first or fails with "database
    is locked", which reads to an operator as a broken CA rather than as ordinary concurrency.
    """
    assert store.journal_mode().lower() == "wal"


def test_the_store_has_one_narrow_update_and_no_delete(data_root) -> None:
    """`IssuedStore` exposes exactly one UPDATE — `revoke()` — and still no delete (page-map §5).

    Asserted by introspection because "the only thing this table can be changed to is revoked" is a claim about this
    project's surface, and the honest way to keep it true is to make the shape checkable rather than to assert one
    method exists. 0.1.0's version of this test forbade the word `revoke` outright; 0.2.0 narrows that to the *other*
    mutators, so a future `delete_record`/`purge_records`/`update_record` still fails here and has to be argued with
    rather than added quietly.
    """
    store = IssuedStore(paths.db_path(data_root))
    public = {name for name in dir(store) if not name.startswith("_")}

    assert {"add_record", "list_records", "count", "init_schema"} <= public
    assert "revoke" in public, "0.2.0's revocation layer is what /issued's Status column reads"
    for forbidden in ("delete", "remove", "update", "purge", "truncate", "clear"):
        assert not any(forbidden in name.lower() for name in public), sorted(public)

    # The narrowness of `revoke` is part of the claim: it takes a serial and an optional note, and has no parameter that
    # could rewrite a certificate's own fields.
    signature = inspect.signature(store.revoke)
    assert set(signature.parameters) == {"serial_hex", "reason", "revoked_at_utc"}, signature


# ------------------------------------------------------------------------------------------- revocation (0.2.0)


def test_revoking_a_record_stamps_it_without_touching_anything_else(store: IssuedStore) -> None:
    """`revoke()` sets the two revocation columns and leaves the certificate's own metadata alone.

    Asserted field by field rather than as "the row changed", because the whole point of a *record* store is that the
    evidence of what was signed survives the decision to stop trusting it: serial, names, SANs and all three timestamps
    must read back identical. `status` is asserted as the derived property `/issued` renders, not as a stored column.
    """
    _add(store, "revoke1", issued_at=DAY_ONE)
    stamp = dt.datetime(2026, 6, 1, 9, 30, tzinfo=dt.timezone.utc)

    updated = store.revoke(serial_hex="revoke1", reason="key moved off-host", revoked_at_utc=stamp)

    assert updated is not None
    assert updated.status == "revoked"
    assert updated.revoked_at_utc == stamp
    assert updated.revocation_reason == "key moved off-host"

    stored = store.list_records()[0]
    assert stored.status == "revoked"
    assert stored.revoked_at_utc == stamp
    assert stored.revocation_reason == "key moved off-host"
    # Everything that describes the certificate is untouched.
    assert stored.serial_hex == "revoke1"
    assert stored.cert_type == "server"
    assert stored.common_name == "revoke1.internal"
    assert stored.sans == ("revoke1.internal",)
    assert stored.not_before_utc == DAY_ONE
    assert stored.not_after_utc == DAY_TWO
    assert stored.issued_at_utc == DAY_ONE
    assert store.count() == 1
    assert store.count_revoked() == 1


def test_an_active_record_reports_active_and_a_null_stamp(store: IssuedStore) -> None:
    """The default state, asserted so `status` cannot become "anything not revoked is revoked by accident"."""
    _add(store, "active1", issued_at=DAY_ONE)

    stored = store.list_records()[0]
    assert stored.revoked_at_utc is None
    assert stored.revocation_reason is None
    assert stored.status == "active"
    assert store.count_revoked() == 0


def test_revoke_answers_none_for_a_serial_this_host_never_issued(store: IssuedStore) -> None:
    """An unknown serial is a *found fact*, not an exception (store.revoke docstring).

    `/issued` renders from a list the operator read moments ago, and a second tab or a restart onto an older database
    can make that serial stale. Returning None lets the handler say "no record with that serial on this host"; raising
    would be a 500-shaped way of saying the same thing. Asserted alongside `count_revoked()` staying put, because a
    refused revoke must not move a counter either.
    """
    _add(store, "real1", issued_at=DAY_ONE)

    assert store.revoke(serial_hex="not-a-serial-here") is None
    assert store.count_revoked() == 0
    assert store.list_records()[0].status == "active"


def test_revoke_is_idempotent_and_does_not_move_the_original_stamp(store: IssuedStore) -> None:
    """A double-click or a page refresh must not re-date the decision.

    `revoked_at_utc` is a fact about *when this host decided*, so the second call returns the record unchanged rather
    than stamping it "now" and quietly rewriting history. This is also the state a browser produces: an operator who
    reloads after revoking re-submits the same form.
    """
    _add(store, "twice1", issued_at=DAY_ONE)
    first = store.revoke(serial_hex="twice1", reason="decommissioned", revoked_at_utc=DAY_ONE)
    assert first is not None

    again = store.revoke(serial_hex="twice1", reason="a different note entirely")

    assert again is not None
    assert again.revoked_at_utc == DAY_ONE
    # The original note survives: re-revoking is a no-op, not an edit.
    assert again.revocation_reason == "decommissioned"
    assert store.list_records()[0].revocation_reason == "decommissioned"
    assert store.count_revoked() == 1


def test_a_revoke_without_a_reason_stores_null_rather_than_an_empty_string(store: IssuedStore) -> None:
    """The reason is optional, and "no reason given" must be distinguishable from "the reason is the empty string".

    The template renders `record.revocation_reason` truthily; storing `""` would render nothing either way, but a stored
    empty string is a value that a future CRL encoder would have to interpret. NULL is the honest spelling of absent.
    """
    _add(store, "noreason", issued_at=DAY_ONE)

    updated = store.revoke(serial_hex="noreason")

    assert updated is not None
    assert updated.revocation_reason is None
    assert updated.status == "revoked"


def test_a_long_revoke_note_is_capped_to_the_column_limit(store: IssuedStore) -> None:
    """`MAX_REVOCATION_REASON_LENGTH` truncates instead of refusing (app._revoke_reason does the same at the boundary).

    Refusing a 121-character note would mean no revocation gets recorded at all, which loses the fact while protecting
    nothing. Truncation keeps the decision and bounds the cell.
    """
    _add(store, "longnote", issued_at=DAY_ONE)
    long_reason = "r" * (MAX_REVOCATION_REASON_LENGTH + 40)

    updated = store.revoke(serial_hex="longnote", reason=long_reason)

    assert updated is not None
    assert updated.revocation_reason is not None
    assert len(updated.revocation_reason) == MAX_REVOCATION_REASON_LENGTH
    assert updated.revocation_reason == "r" * MAX_REVOCATION_REASON_LENGTH


def test_count_revoked_counts_stamped_rows_only(store: IssuedStore) -> None:
    """The footer number on `/issued`, and the `revoked_count` in every page context.

    Mixed state on purpose — revoked, active, and a revoked row that is also past its expiry — because `count_revoked()`
    answers "how many did this host mark", which is a different question from `is_expired`.
    """
    _add(store, "r1", issued_at=DAY_ONE)
    _add(store, "r2", issued_at=DAY_ONE)
    _add(store, "r3", issued_at=DAY_ONE, not_after_utc=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))
    store.revoke(serial_hex="r1", reason="one")
    store.revoke(serial_hex="r3", reason="three")

    records = {record.serial_hex: record for record in store.list_records()}
    assert store.count() == 3
    assert store.count_revoked() == 2
    assert records["r1"].status == "revoked"
    assert records["r2"].status == "active"
    # Expired *and* revoked: two independent facts about the same row.
    assert records["r3"].status == "revoked"
    assert records["r3"].is_expired is True
    assert records["r2"].is_expired is False


def test_a_record_past_not_after_is_expired_but_still_reports_active(store: IssuedStore) -> None:
    """Two states in the Status column, not three (store.IssuedRecord.status).

    A certificate this CA never revoked must not be labelled `revoked`, and labelling it `expired` in the same column as
    `revoked` would imply this host knows what every client currently accepts. The expiry fact belongs to the date cell,
    which is what `is_expired` exists for.
    """
    _add(store, "old1", issued_at=DAY_ONE, not_after_utc=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))

    stored = store.list_records()[0]
    assert stored.is_expired is True
    assert stored.status == "active"
    assert store.count_revoked() == 0


def test_a_0_1_0_database_gains_the_columns_and_keeps_every_record(data_root) -> None:
    """The in-place upgrade, tested against a hand-built 0.1.0 file rather than against a comment.

    Built the way 0.1.0 built it: the eight-column table, no revocation columns, one real record. Then 0.2.0's
    `init_schema()` runs against that same file. Two things have to be true and they are different failures — the ALTERs
    must land (otherwise every read answers NULL for a revoked row and `/issued` renders a Status column that cannot
    change), and the operator's existing records must survive (the records *are* the reason the file exists).
    """
    db_file = paths.db_path(data_root)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    legacy_schema = """
CREATE TABLE IF NOT EXISTS issued_certs (
    serial_hex       TEXT PRIMARY KEY,
    cert_type        TEXT NOT NULL,
    common_name      TEXT NOT NULL,
    sans_json        TEXT NOT NULL DEFAULT '[]',
    not_before_utc   TEXT NOT NULL,
    not_after_utc    TEXT NOT NULL,
    issued_at_utc    TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL
)
"""
    connection = sqlite3.connect(str(db_file))
    with closing(connection), connection:
        connection.execute(legacy_schema)
        connection.execute(
            "INSERT INTO issued_certs (serial_hex, cert_type, common_name, sans_json, not_before_utc, not_after_utc,"
            " issued_at_utc, fingerprint_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy01",
                "server",
                "old.internal",
                json.dumps(["old.internal"]),
                # Written with an explicit +00:00 offset, the spelling store._iso produces. The legacy file is built
                # here
                # rather than through a private helper, because "0.1.0 wrote this" must not depend on what 0.2.0's code
                # happens to do today.
                DAY_ONE.isoformat(),
                DAY_TWO.isoformat(),
                DAY_ONE.isoformat(),
                "cd" * 32,
            ),
        )
    connection = sqlite3.connect(str(db_file))
    try:
        before = {str(row[1]) for row in connection.execute("PRAGMA table_info(issued_certs)").fetchall()}
    finally:
        connection.close()
    assert "revoked_at_utc" not in before and "revocation_reason" not in before, before

    store = IssuedStore(db_file)
    store.init_schema()

    stored = store.list_records()
    assert len(stored) == 1, "an upgrade that loses a record is worse than an upgrade that fails"
    assert stored[0].serial_hex == "legacy01"
    assert stored[0].common_name == "old.internal"
    assert stored[0].sans == ("old.internal",)
    assert stored[0].not_before_utc == DAY_ONE
    # The pre-0.2.0 row reads as never-revoked, which is exactly right: this host never revoked it.
    assert stored[0].revoked_at_utc is None
    assert stored[0].status == "active"
    assert store.count_revoked() == 0

    # And the new capability works on the upgraded file, not just on a fresh one.
    assert store.revoke(serial_hex="legacy01", reason="upgraded and revoked").status == "revoked"
    assert store.list_records()[0].revocation_reason == "upgraded and revoked"


def test_the_upgrade_is_idempotent_on_a_legacy_file(data_root) -> None:
    """`init_schema()` runs on every startup, so the ALTER path must survive being run twice.

    The failure mode `store._ensure_revocation_columns` exists to avoid is spelled out there: SQLite reports a duplicate
    column as an error that aborts the surrounding transaction, so a startup that *catches* its own ALTER failure
    changes behaviour with the next SQLite release. Running the whole upgrade twice against a legacy file is how
    "present columns are skipped" gets proven rather than asserted.
    """
    db_file = paths.db_path(data_root)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_file))
    with closing(connection), connection:
        connection.execute(
            "CREATE TABLE issued_certs (serial_hex TEXT PRIMARY KEY, cert_type TEXT NOT NULL, common_name TEXT NOT "
            "NULL, sans_json TEXT NOT NULL DEFAULT '[]', not_before_utc TEXT NOT NULL, not_after_utc TEXT NOT NULL, "
            "issued_at_utc TEXT NOT NULL, fingerprint_sha256 TEXT NOT NULL)"
        )

    store = IssuedStore(db_file)
    for _ in range(3):
        store.init_schema()

    assert tuple(store.schema_columns()) == EXPECTED_COLUMNS, store.schema_columns()


# ------------------------------------------------------------------------------------------------- records


def test_a_record_is_immutable(store: IssuedStore) -> None:
    """`IssuedRecord` is frozen, so a rendered row cannot be edited by whatever renders it.

    Small, and deliberately so: the list page is built straight out of these objects, and a mutable record would let a
    template or a future formatter rewrite what was actually issued."""
    record = _add(store, "frozen1", issued_at=DAY_ONE)

    with pytest.raises(dataclasses.FrozenInstanceError):
        record.common_name = "changed"  # type: ignore[misc]


def test_a_hand_edited_sans_column_degrades_to_empty_rather_than_crashing(store: IssuedStore) -> None:
    """The defensive branch in `_row_to_record`, pinned.

    This only happens if someone edits the database with `sqlite3`, which is exactly the situation where a traceback on
    `GET /issued` is least useful: the operator was already poking at the file. The list still renders, the row shows no
    SANs, and the failure is a warning in the log rather than a 500 page.
    """
    _add(store, "broken1", issued_at=DAY_ONE)
    connection = sqlite3.connect(str(store.db_file))
    try:
        connection.execute("UPDATE issued_certs SET sans_json = '[not json' WHERE serial_hex = 'broken1'")
        connection.commit()
    finally:
        connection.close()

    records = store.list_records()
    assert len(records) == 1
    assert records[0].sans == ()
    assert records[0].serial_hex == "broken1"
