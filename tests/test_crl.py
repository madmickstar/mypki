"""The CRL as **data**: what mypki's artifact says, and the two rules that decide which serials are in it.

page-map §14 is the spec this file checks. The load-bearing claims are not "a CRL was built" but four specific ones:

1. **`CRLNumber` never decreases**, even across a rebuild whose entry set *shrank* (an expired revoked certificate was
   dropped). `len(entries)` would break this; `store.count_revoked()` cannot, because the store has no DELETE.
2. **The entry set is stamped-and-not-expired** (answer 8): historical revocations included, revoked-and-expired
   dropped,
   and the row surviving in `issued.db` either way.
3. **No `IssuingDistributionPoint`, no `DeltaCRLIndicator`.** This is a measured refusal, not a style preference: an
   IDP-scoped CRL makes openssl's `verify -crl_check` answer `error 44 … different CRL scope` for a valid leaf that has
   no CDP at all — every certificate this CA issued before 0.7.0. Asserting the absence here is what stops someone
   adding one "for completeness" in a later release.
4. **No truncation**: `list_records` caps at 500 because it renders a page; `revoked_records()` must not, or the 501st
   revoked certificate stays trusted by every client that consults the CRL.

Everything here is provable in-process: builder facts, round-trip through `load_pem_x509_crl`, signature verification
against the CA's own public key, and 159-bit serial round-trips (MEASURED: 101 of 200 real mypki serials have the top
bit set, so a hex→int path that mishandles the sign bit would silently lose entries).

What this file deliberately does **not** assert: that a real client honours the artifact. That is openssl's job, and it
is recorded as MEASURED evidence in CRL_PLAN-0.7.0.md §2 and SMOKE_TESTING.md — `error 23 … certificate revoked` against
a
mypki-shaped CRL, and `error 44 … different CRL scope` for an IDP-scoped one. pytest stays openssl-free (plan U7; the CI
job's "NO OpenSSL binary is required anywhere").

Serial fixtures: real shapes (`x509.random_serial_number()` values) plus hand-written hex, because the shortest hex a
real serial produces is 38 characters and a test that only uses `"1"` would pass against a broken leading-zero path.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from conftest import csrf_token, pem_block_count
from mypki import paths
from mypki.app import create_app
from mypki.ca import CaBundle
from mypki.config import Settings
from mypki.crl import CRL_LIFETIME, CRL_PEM_MARKER, build_crl, crl_pem, read_crl_pem, summarise_crl, write_crl_pem
from mypki.errors import MypkiError
from mypki.store import IssuedRecord, IssuedStore

DAY_ONE = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

#: A serial of the shape `x509.random_serial_number()` actually produces: 159 bits, top bit set. MEASURED on real mypki
#: serials (101 of a 200-sample carry the top bit), and the reason the hex round-trip is asserted rather than assumed.
BIG_SERIAL = 0x7F_D1_AD_BE_EF_CD_AB_90_12_34_56_78_9A_BC_DE_F0_11_22_33_44

#: The one hand-written fixture that is **not** a canonical spelling (a leading zero, which `f"{n:x}"` never produces).
#: Kept deliberately: it proves the builder does not care about the spelling's width, and it is also the reason the
#: round-trip below compares integers for this case rather than hex text — `int("0ABCDEF", 16)` is 0xabcdef and
#: `f"{0xabcdef:x}"` is "abcdef". Real issued serials cannot look like this (the shortest hex a real serial produces is
#: 38 characters), so the assertion is written to match what is actually guaranteed.
LEADING_ZERO_HEX = "0ABCDEF"


def _record(
    serial_hex: str,
    *,
    not_after_utc: dt.datetime,
    revoked_at_utc: dt.datetime | None = DAY_ONE,
    reason: str | None = None,
) -> IssuedRecord:
    """One `IssuedRecord` as the CRL builder sees it — metadata only, exactly what `issued.db` holds."""
    return IssuedRecord(
        serial_hex=serial_hex,
        cert_type="server",
        common_name=f"{serial_hex[:6]}.lab.internal",
        sans=("lab.internal",),
        not_before_utc=DAY_ONE,
        not_after_utc=not_after_utc,
        issued_at_utc=DAY_ONE,
        fingerprint_sha256="ab" * 32,
        revoked_at_utc=revoked_at_utc,
        revocation_reason=reason,
    )


@pytest.fixture
def store(data_root: Path) -> IssuedStore:
    """A store in pytest's temporary data dir, never an operator's (`isolated_data_dir` pins `MYPKI_DATA_DIR`)."""
    issued = IssuedStore(paths.db_path(data_root))
    issued.init_schema()
    return issued


def _issue_active(store: IssuedStore, serial_hex: str, *, not_after_days: int) -> None:
    """Add a live, **unrevoked** record — the state a revoke POST starts from.

    Separate from `_stamp` because the route tests must begin with an active row: `_stamp` stamps it too, and a
    POST that finds an already-stamped row reports "already revoked" and publishes nothing. That distinction is
    exactly what the publish trigger is keyed on, so a test that pre-stamped would assert the guard rather than the
    feature.
    """
    now = dt.datetime.now(dt.timezone.utc)
    store.add_record(
        serial_hex=serial_hex,
        cert_type="server",
        common_name=f"{serial_hex[:6]}.lab.internal",
        sans=("lab.internal",),
        not_before_utc=now - dt.timedelta(days=30),
        not_after_utc=now + dt.timedelta(days=not_after_days),
        fingerprint_sha256="cd" * 32,
    )


def _stamp(store: IssuedStore, serial_hex: str, *, not_after_days: int, reason: str | None = None) -> IssuedRecord:
    """Add a record valid `not_after_days` from now and revoke it, i.e. the ordinary operator path."""
    now = dt.datetime.now(dt.timezone.utc)
    store.add_record(
        serial_hex=serial_hex,
        cert_type="server",
        common_name=f"{serial_hex[:6]}.lab.internal",
        sans=("lab.internal",),
        not_before_utc=now - dt.timedelta(days=30),
        not_after_utc=now + dt.timedelta(days=not_after_days),
        fingerprint_sha256="cd" * 32,
    )
    revoked = store.revoke(serial_hex=serial_hex, reason=reason)
    assert revoked is not None
    return revoked


# ---------------------------------------------------------------------------- the builder's own facts


def test_a_zero_entry_crl_signs_and_verifies(throwaway_ca: CaBundle) -> None:
    """A CA that has never revoked anything still publishes a valid CRL (MEASURED in plan §2, re-asserted here).

    The alternative — 404 until the first revocation — would make `GET /crl.pem` a route whose behaviour changes with
    operator history, and would leave `/crl` unable to show "this CA published a CRL listing nothing". An empty
    CRL is what RFC 5280 §5.3.1 expects for that state.
    """
    crl = build_crl(bundle=throwaway_ca, records=[], crl_number=0, this_update_utc=DAY_ONE)

    assert len(list(crl)) == 0
    assert crl.is_signature_valid(throwaway_ca.cert.public_key())
    assert summarise_crl(crl).entry_count == 0


def test_dates_are_aware_utc_and_next_update_is_exactly_one_day_on(throwaway_ca: CaBundle) -> None:
    """`nextUpdate` = thisUpdate + 24 h, as a constant rather than a knob (plan U8).

    Asserted as an exact delta, not "some hours ahead": the value is a promise to clients about how often they should
    come back, and a silent change from 24 h to 7 days would be invisible in every other test in this suite.
    """
    crl = build_crl(bundle=throwaway_ca, records=[], crl_number=1, this_update_utc=DAY_ONE)

    assert crl.last_update_utc == DAY_ONE
    assert crl.last_update_utc.tzinfo is not None
    assert crl.next_update_utc == DAY_ONE + CRL_LIFETIME
    assert crl.next_update_utc.tzinfo is not None
    # Asserted on the constant itself, not only on the dates above: 24 h is a promise `/crl`, README and page-map §14
    # all repeat, and a change here has to fail somewhere that says which documents now lie.
    assert CRL_LIFETIME.total_seconds() == 24 * 3600


def test_a_naive_this_update_is_made_utc_not_rejected(throwaway_ca: CaBundle) -> None:
    """Same rule as `store._iso`: a naive datetime becomes UTC rather than being interpreted as local time.

    A CRL whose `thisUpdate` means "local" would be current on one host and stale on another, which is the exact class
    of bug `signing.py`'s UTC docstring exists to prevent for certificates.
    """
    naive = dt.datetime(2026, 1, 1, 12, 0, 0)

    crl = build_crl(bundle=throwaway_ca, records=[], crl_number=1, this_update_utc=naive)

    assert crl.last_update_utc == DAY_ONE + dt.timedelta(hours=12)
    assert crl.last_update_utc.tzinfo is not None


def test_entries_carry_the_original_revocation_stamp_not_now(throwaway_ca: CaBundle) -> None:
    """The CRL entry states **when the decision was made** — the same fact `revoke()` protects by never moving a stamp.

    Rebuilding tomorrow must not turn "revoked on 2026-01-01" into "revoked today": a client comparing the CRL against
    `/issued` would read a moved date as a new decision.
    """
    stamped_on = dt.datetime(2026, 6, 1, 9, 30, tzinfo=dt.timezone.utc)
    records = [_record("AABBCCDDEEFF", not_after_utc=DAY_ONE + dt.timedelta(days=365), revoked_at_utc=stamped_on)]

    crl = build_crl(bundle=throwaway_ca, records=records, crl_number=1, this_update_utc=DAY_ONE)
    entry = next(iter(crl))

    assert entry.serial_number == 0xAABBCCDDEEFF
    assert entry.revocation_date_utc == stamped_on


def test_the_reason_stays_operator_prose_and_no_crl_reason_extension_is_written(throwaway_ca: CaBundle) -> None:
    """No `CRLReason` entry extension (plan U6).

    RFC 5280 §5.3.1 defines an absent reason code as `unspecified`, which is the same answer mypki gives in OCSP. The
    operator's free-text note lives in `issued.db` and on `/issued`; inventing a protocol code out of prose would be a
    claim this CA cannot support, and it would have to be walked back by a CRL that can carry one.
    """
    records = [_record("1234ABCD", not_after_utc=DAY_ONE + dt.timedelta(days=365), reason="laptop was stolen")]

    crl = build_crl(bundle=throwaway_ca, records=records, crl_number=1, this_update_utc=DAY_ONE)
    entry = next(iter(crl))

    assert list(entry.extensions) == []
    # The prose survives in the record the CRL was built from — it is simply not encoded into the artifact.
    assert records[0].revocation_reason == "laptop was stolen"


def test_issuer_is_exactly_the_ca_subject(throwaway_ca: CaBundle) -> None:
    """Same rule as `signing.py`: the issuer name is the CA's own subject, byte for byte."""
    crl = build_crl(bundle=throwaway_ca, records=[], crl_number=1, this_update_utc=DAY_ONE)

    assert crl.issuer == throwaway_ca.cert.subject


# --------------------------------------------------------------------- extensions: present, and refused


def test_extensions_are_crl_number_and_aki_both_non_critical(throwaway_ca: CaBundle) -> None:
    """What the CRL *does* carry (plan §4): `CRLNumber` and a non-critical AKI, and nothing else."""
    crl = build_crl(bundle=throwaway_ca, records=[], crl_number=7, this_update_utc=DAY_ONE)

    number = crl.extensions.get_extension_for_class(x509.CRLNumber)
    aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)

    assert number.value.crl_number == 7
    assert number.critical is False
    assert aki.critical is False
    expected = x509.AuthorityKeyIdentifier.from_issuer_public_key(throwaway_ca.cert.public_key())
    assert aki.value.key_identifier == expected.key_identifier  # type: ignore[attr-defined]
    # Class names rather than OID constants: cryptography 50.0.2 has no `x509.OID_CRL_NUMBER` (MEASURED — the CRL-number
    # OID lives under `oid.CRLEntryExtensionOID`), and asserting the two value classes says the same thing without a
    # spelling that could silently resolve to nothing.
    assert [type(extension.value) for extension in crl.extensions] == [x509.CRLNumber, x509.AuthorityKeyIdentifier]


def test_no_issuing_distribution_point_and_no_delta_crl_indicator(throwaway_ca: CaBundle) -> None:
    """The measured refusal (plan §2 / P-CRL-3), asserted so it cannot be re-added quietly.

    openssl 3.5.6, MEASURED: against a CRL carrying `IssuingDistributionPoint(full_name=http://mypki.my.lab/crl.pem,
    only_contains_user_certs=True, critical)`, `openssl verify -crl_check` answers **`error 44 at 0 depth lookup:
    different CRL scope`, rc=2** for a *valid leaf with no CDP at all* — every certificate this CA issued before 0.7.0 —
    while the plain-CRL control verifies `OK` rc=0. An IDP would make `-crl_check` unusable on this CA's own history.

    Asserted as "extension not found" rather than as a comment, because the temptation to add one arrives as a
    well-meaning completeness fix in a later release, and only a failing test can argue with it.
    """
    crl = build_crl(bundle=throwaway_ca, records=[], crl_number=1, this_update_utc=DAY_ONE)

    for cls in (x509.IssuingDistributionPoint, x509.DeltaCRLIndicator):
        with pytest.raises(x509.ExtensionNotFound):
            crl.extensions.get_extension_for_class(cls)


def test_a_crl_without_a_number_extension_is_refused_by_the_reader(throwaway_ca: CaBundle) -> None:
    """The mutation check for `_crl_number`: a CRL missing its number is a failure, not a zero (STYLE §8).

    Built by hand here — `build_crl` always adds the extension — because the assertion that matters is what the reader
    does when the artifact disagrees with the spec: RFC 5280 §5.2.1 makes the number how a client detects an outdated
    copy, so answering `0` would make a broken CRL look like the very first one ever published.
    """
    hand_built = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(throwaway_ca.cert.subject)
        .last_update(DAY_ONE)
        .next_update(DAY_ONE + CRL_LIFETIME)
        .sign(private_key=throwaway_ca.key, algorithm=hashes.SHA256())  # type: ignore[arg-type]
    )

    assert list(hand_built.extensions) == []
    with pytest.raises(MypkiError, match="CRL Number"):
        summarise_crl(hand_built)


def _crl_without_next_update(crl: x509.CertificateRevocationList) -> x509.CertificateRevocationList:
    """Re-encode a built CRL with its `nextUpdate` UTCTime cut out, so the reader sees no next update.

    cryptography refuses to *build* a CRL that has no next update (`ValueError: A CRL must have a next update time`,
    MEASURED on 50.0.2), yet `CertificateRevocationList.next_update_utc` is typed `datetime | None` because DER allows
    the field to be absent (RFC 5280 §5.1.2.4). The only way to hand `summarise_crl` that object is to cut it out of the
    bytes a real build produced and repair the two length headers around the cut — which is precisely what a hand-edited
    or half-written `<data>/crl/mypki.crl.pem` amounts to, and `_published_crl` does read that file back from disk.

    Scoped to a zero-entry CRL on purpose: an entry's own `revocationDate` is also a UTCTime, so the "exactly two"
    assertion below is what keeps this helper from silently cutting the wrong field.
    """

    def _encode_length(value: int) -> bytes:
        """DER content length: single byte under 128, otherwise minimal long form."""
        if value < 0x80:
            return bytes([value])
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(raw)]) + raw

    def _read_sequence(der: bytes, offset: int) -> tuple[int, int]:
        """(size of the tag+length header, content length) for the SEQUENCE starting at `offset`."""
        assert der[offset] == 0x30, f"expected a SEQUENCE at {offset}, found {der[offset]:#04x}"
        first = der[offset + 1]
        if first & 0x80:
            count = first & 0x7F
            return 2 + count, int.from_bytes(der[offset + 2 : offset + 2 + count], "big")
        return 2, first

    der = crl.public_bytes(serialization.Encoding.DER)

    # Both headers are read **before** anything is cut, so every offset below refers to the original bytes.
    outer_header, outer_length = _read_sequence(der, 0)
    assert outer_header + outer_length == len(der), "the outer length must cover the whole file"
    tbs_header, tbs_length = _read_sequence(der, outer_header)
    # `tbs_length` is the length of the TBSCertList **content**, so the content starts one header further in than it
    # ends counting from. Getting this wrong leaves a few bytes of the signature inside the re-encoded sequence, which
    # cryptography reports as `ShortData` while parsing extensions rather than as a bad offset.
    tbs_end = outer_header + tbs_header + tbs_length
    tbs_body = der[outer_header + tbs_header : tbs_end]
    signature_and_algorithm = der[tbs_end:]

    # UTCTime is tag 0x17 with a 13-byte value (`YYMMDDHHMMSSZ`), so a whole field is 15 bytes.
    utc_times = [i for i in range(len(tbs_body)) if tbs_body[i : i + 2] == b"\x17\x0d"]
    assert len(utc_times) == 2, f"expected thisUpdate and nextUpdate only, found {utc_times}"
    cut = utc_times[1]
    assert tbs_body[cut + 2 : cut + 15].endswith(b"Z"), tbs_body[cut : cut + 15]

    shortened = tbs_body[:cut] + tbs_body[cut + 15 :]
    new_tbs = b"\x30" + _encode_length(len(shortened)) + shortened
    rebuilt = b"\x30" + _encode_length(len(new_tbs) + len(signature_and_algorithm)) + new_tbs + signature_and_algorithm

    assert len(rebuilt) == len(der) - 15, "the cut must remove exactly the one UTCTime field"
    return x509.load_der_x509_crl(rebuilt)


def test_a_crl_that_omits_nextUpdate_is_refused_rather_than_reported_as_endless(
    throwaway_ca: CaBundle,
) -> None:
    """The narrowing check for `summarise_crl`: a CRL with no nextUpdate has no freshness to publish (STYLE §8).

    `CrlFacts.lifetime_hours` subtracts `thisUpdate` from `nextUpdate`, and `/crl` prints that interval as how long the
    artifact stays current. Answering with `None` would either crash the template arithmetic or, if coerced, claim a
    CRL that never expires — the opposite of what a 24 h `nextUpdate` exists to prevent. So the reader refuses, naming
    the missing field, exactly as `_crl_number` refuses a CRL with no number.
    """
    built = build_crl(bundle=throwaway_ca, records=[], crl_number=1, this_update_utc=DAY_ONE)
    assert built.next_update_utc == DAY_ONE + CRL_LIFETIME

    mutated = _crl_without_next_update(built)
    assert mutated.next_update_utc is None
    assert mutated.last_update_utc == DAY_ONE

    with pytest.raises(MypkiError, match="nextUpdate"):
        summarise_crl(mutated)


# ------------------------------------------------------------------------------- the PEM artifact


def test_pem_armour_is_the_x509_crl_block_and_round_trips(throwaway_ca: CaBundle, tmp_path: Path) -> None:
    """PEM in, PEM out, same object (plan §2). The armour line is what `/crl` and both harnesses assert.

    `is_signature_valid` is checked on the **reloaded** object rather than the one the builder returned: what a client
    fetches
    the file, so the signature that matters is the one that survives armour.
    """
    records = [_record("DEADBEEF", not_after_utc=DAY_ONE + dt.timedelta(days=365))]
    built = build_crl(bundle=throwaway_ca, records=records, crl_number=1, this_update_utc=DAY_ONE)
    pem = crl_pem(built)

    assert pem.startswith(CRL_PEM_MARKER)
    assert pem.count("-----BEGIN X509 CRL-----") == 1
    assert pem.count("-----END X509 CRL-----") == 1

    reloaded = x509.load_pem_x509_crl(pem.encode("ascii"))
    assert reloaded == built
    assert reloaded.is_signature_valid(throwaway_ca.cert.public_key())
    assert len(list(reloaded)) == 1

    path = tmp_path / "crl" / "mypki.crl.pem"
    write_crl_pem(path, pem)
    assert read_crl_pem(path) == built


def test_write_is_atomic_and_leaves_no_temp_files(tmp_path: Path) -> None:
    """`os.replace` in the same directory, and no `.tmp` litter afterwards.

    A half-written CRL is worse than an old one: a client that fetched it mid-write sees a parse failure and cannot
    tell "the CA revoked this" from "the disk lied". The absence of leftovers is asserted because `tempfile` in the same
    directory makes that cheap, and a stray `.mypki.crl.pem.abc123.tmp` in `<data>/crl/` is exactly the kind of file an
    operator finds months later with no idea what it is.
    """
    path = tmp_path / "crl" / "mypki.crl.pem"

    write_crl_pem(path, "-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n")

    assert path.is_file()
    siblings = sorted(entry.name for entry in path.parent.iterdir())
    assert siblings == ["mypki.crl.pem"], siblings


def test_the_crl_file_is_world_readable_because_it_is_served(tmp_path: Path) -> None:
    """0644-ish, following `ca_cert_path`'s precedent and **not** `PRIVATE_FILE_MODE = 0o600`.

    This artifact is served to anyone by `GET /crl.pem`; owner-only mode would protect something that is not a secret.
    Asserted loosely (`& 0o044`) rather than exactly because umask differs between hosts and CI runners, and the claim
    worth keeping true is "readable by others", not "exactly 644". A `.key`/`.pem` CA file keeps its 0600 assertion in
    `test_ca_init.py`; this one must not inherit it.
    """
    path = tmp_path / "crl" / "mypki.crl.pem"

    write_crl_pem(path, "-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n")
    mode = path.stat().st_mode

    assert mode & 0o044, f"CRL is not group/other-readable: {oct(mode & 0o777)}"


def test_reading_a_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    """`FileNotFoundError`, so the handler can render "no CRL yet" instead of a 500.

    The distinction matters for `GET /crl.pem` on a host whose CA failed to load: the honest answer is that nothing has
    been published, and a 500 would read as a broken CA (page-map §6's posture for missing state).
    """
    with pytest.raises(FileNotFoundError):
        read_crl_pem(tmp_path / "crl" / "mypki.crl.pem")


# ---------------------------------------------------------------------------- serial round-trips


@pytest.mark.parametrize(
    "serial_hex",
    [f"{BIG_SERIAL:x}", "1", LEADING_ZERO_HEX, f"{x509.random_serial_number():x}"],
)
def test_serial_hex_survives_the_int_conversion(throwaway_ca: CaBundle, serial_hex: str) -> None:
    """`int(hex, 16)` finds the same serial back in the reloaded CRL, including 159-bit top-bit-set values.

    MEASURED on real mypki serials: `random_serial_number()` is `int.from_bytes(os.urandom(20), "big") >> 1`, so up to
    159 bits with the top bit set in about half of all issued certificates (101 of a 200 sample). A conversion that lost
    the sign bit or mishandled a leading zero would drop entries from the CRL silently — the failure would appear at a
    client as "this certificate is still valid".
    """
    records = [_record(serial_hex, not_after_utc=DAY_ONE + dt.timedelta(days=365))]

    crl = build_crl(bundle=throwaway_ca, records=records, crl_number=1, this_update_utc=DAY_ONE)
    entry = next(iter(crl))

    assert entry.serial_number == int(serial_hex, 16)
    if serial_hex != LEADING_ZERO_HEX:
        # Canonical spellings (what `f"{serial:x}"` produced when the record was written) come back identical.
        assert f"{entry.serial_number:x}" == serial_hex


def test_a_159_bit_serial_reaches_the_crl_from_the_real_store(throwaway_ca: CaBundle, store: IssuedStore) -> None:
    """The end-to-end form of the same fact: a serial minted by `random_serial_number()` is findable in the CRL.

    The test above hand-writes the hex; this one takes it through `add_record` (which formats `f"{serial:x}"`) and
    `revoked_records()`, i.e. the spelling that actually lives in `issued.db`.
    """
    minted = x509.random_serial_number()
    serial_hex = f"{minted:x}"
    _stamp(store, serial_hex, not_after_days=365)

    records = store.revoked_records()
    crl = build_crl(bundle=throwaway_ca, records=records, crl_number=store.count_revoked())

    assert next(iter(crl)).serial_number == minted


# ------------------------------------------------------------------------ CRLNumber monotonicity


def test_crl_number_never_decreases_across_a_rebuild_that_removed_an_entry(
    throwaway_ca: CaBundle, store: IssuedStore
) -> None:
    """The trap the plan calls out: entries can shrink, so `len(entries)` is the wrong number (plan §4).

    The two builds model the upgrade itself rather than a clock trick. An operator's ledger already carries one
    revoked-and-expired row and one live revoked row; a hypothetical pre-0.7 build over **all** stamped rows lists both,
    while 0.7.0's entry set lists one (answer 8 drops the expired row) and must still carry `CRLNumber` **2**.
    Publishing
    `1` there — which is exactly what `len(entries)` produces — is a number *lower* than the previous CRL's, which RFC
    5280 §5.2.1 forbids for one issuer and which a strict client may read as a retracted CRL.

    No faked clock: expiry is decided by `IssuedRecord.is_expired` against the real time, because that property is the
    only thing the rule depends on and asserting it with a lie would test the wrong thing.
    """
    _stamp(store, "AAAA0001", not_after_days=365)
    store.add_record(
        serial_hex="AAAA0002",
        cert_type="server",
        common_name="old.lab.internal",
        sans=("lab.internal",),
        not_before_utc=DAY_ONE - dt.timedelta(days=800),
        not_after_utc=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1),
        fingerprint_sha256="cd" * 32,
    )
    store.revoke(serial_hex="AAAA0002")

    all_stamped = [record for record in store.list_records() if record.revoked_at_utc is not None]
    first = build_crl(
        bundle=throwaway_ca, records=all_stamped, crl_number=store.count_revoked(), this_update_utc=DAY_ONE
    )
    second = build_crl(
        bundle=throwaway_ca,
        records=store.revoked_records(),
        crl_number=store.count_revoked(),
        this_update_utc=DAY_ONE + dt.timedelta(days=1),
    )

    assert len(list(first)) == 2
    assert len(list(second)) == 1, "the expired row was not dropped from the entry set"
    assert summarise_crl(first).crl_number == 2
    assert summarise_crl(second).crl_number == 2, "CRLNumber fell with the entry count"
    assert summarise_crl(second).crl_number >= summarise_crl(first).crl_number


def test_an_unstampable_record_is_refused_rather_than_silently_skipped(throwaway_ca: CaBundle) -> None:
    """A record with no revocation stamp in the entry set is a bug in the caller, and says so.

    `revoked_records()` filters on this column, so this arm is unreachable from the app's own path. It stays because the
    alternative — quietly dropping a row the caller handed to the builder — produces a CRL that disagrees with the
    input,
    and that disagreement is only visible at a client that keeps trusting the omitted certificate.
    """
    records = [_record("BEEF0001", not_after_utc=DAY_ONE + dt.timedelta(days=365), revoked_at_utc=None)]

    with pytest.raises(MypkiError, match="no revocation stamp"):
        build_crl(bundle=throwaway_ca, records=records, crl_number=1, this_update_utc=DAY_ONE)


def test_building_without_a_key_raises_the_same_refusal_as_signing(throwaway_ca: CaBundle) -> None:
    """A certificate on disk without its key cannot sign a CRL either (page-map §6's missing-capability answer).

    `load_ca` produces exactly this shape when the key file is absent or undecryptable, so the message has to name the
    fix (`init-ca`, or the passphrase) rather than crash inside the builder. Same refusal `issue_certificate` makes, for
    the same reason: missing capability, not invalid input.
    """
    keyless = CaBundle(
        cert=throwaway_ca.cert,
        key=None,
        cert_path=throwaway_ca.cert_path,
        key_path=throwaway_ca.key_path,
    )

    assert keyless.key_present is False
    with pytest.raises(MypkiError, match="no private key loaded"):
        build_crl(bundle=keyless, records=[], crl_number=1, this_update_utc=DAY_ONE)


# ------------------------------------------------------------------------------ the entry-set rule


def test_revoked_records_includes_historical_and_excludes_expired(store: IssuedStore) -> None:
    """Answer 8's two halves, measured against a real store rather than hand-built records.

    * stamped in an earlier release (the row was written with an old `issued_at`) → included;
    * revoked **and** expired → dropped from the CRL entry set, while `count_revoked()` still counts it and `find()`
      still returns it, because there is no un-revoke and no DELETE (page-map §5).
    """
    live = _stamp(store, "LIVE0001", not_after_days=365, reason="superseded by a new key")
    # An expired one: `add_record` accepts any dates, which is how a 0.2.0-era row looks to a 0.7.0 build.
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)
    store.add_record(
        serial_hex="EXPIRED1",
        cert_type="server",
        common_name="gone.lab.internal",
        sans=("lab.internal",),
        not_before_utc=past - dt.timedelta(days=400),
        not_after_utc=past,
        fingerprint_sha256="ef" * 32,
    )
    store.revoke(serial_hex="EXPIRED1", reason="old")
    # An active certificate must never appear in the entry set.
    store.add_record(
        serial_hex="ACTIVE01",
        cert_type="server",
        common_name="still.lab.internal",
        sans=("lab.internal",),
        not_before_utc=past,
        not_after_utc=past + dt.timedelta(days=365),
        fingerprint_sha256="ab" * 32,
    )

    serials = [record.serial_hex for record in store.revoked_records()]

    assert serials == ["LIVE0001"]
    assert live.revocation_reason == "superseded by a new key"
    # Both halves of the honest sentence: the row is still there, and it is still counted.
    assert store.find("EXPIRED1") is not None
    assert store.count_revoked() == 2


def test_revoked_records_is_ordered_by_stamp_then_serial(store: IssuedStore) -> None:
    """Oldest decision first, so two builds diff as an append rather than a reshuffle.

    Stamps are supplied explicitly and in one pass each, because `revoke()` deliberately refuses to move an existing
    stamp (a page refresh must not relocate the moment a decision was made) — stamping twice would be a no-op, not a
    re-dating. Serials run anti-alphabetically against their stamps so the timestamp decides and the tiebreak is only
    proven to exist.
    """
    now = dt.datetime.now(dt.timezone.utc)
    plan = (("ZULU0001", -3), ("MIKE0002", -2), ("ALFA0003", -1))
    for serial, _ in plan:
        _stamp(store, serial, not_after_days=365)
    for serial, offset in plan:
        store.revoke(serial_hex=serial, revoked_at_utc=now + dt.timedelta(minutes=offset))

    serials = [record.serial_hex for record in store.revoked_records()]

    assert serials == ["ZULU0001", "MIKE0002", "ALFA0003"]


def test_revoked_records_has_no_500_row_cap(store: IssuedStore) -> None:
    """>500 revoked rows: every one reaches the CRL, unlike `list_records` (page-map §14).

    `list_records` caps at 500 because it renders a page (`store.py`, and `test_store.py`'s existing limit assertions).
    A cap here would mean the 501st revoked certificate is absent from a published CRL while `/issued` still shows it as
    revoked — two answers to "is this revoked?", with the weaker one going to clients. Asserted with 520 rows so the
    boundary is crossed rather than approached, and `count_revoked()` asserted alongside it because `CRLNumber` reads
    that number.
    """
    total = 520
    for index in range(total):
        # Hex-valid fixtures: "BULK000000" is not a serial spelling (`U`, `L` and `K` are not hex digits), and this file
        # is where a non-hex serial would surface as a ValueError from the builder rather than as a finding.
        _stamp(store, f"b{index:06d}", not_after_days=365)

    assert store.count() == total
    assert len(store.list_records()) == 500, "the page cap is a rendering rule, not a storage rule"
    assert len(store.revoked_records()) == total
    assert store.count_revoked() == total
    assert all(record.serial_hex.startswith("b") for record in store.revoked_records())


def test_a_crl_built_from_the_bulk_store_carries_every_serial(throwaway_ca: CaBundle, store: IssuedStore) -> None:
    """The bulk case end to end: entry count 520, `CRLNumber` 520, and a spot-checked serial present.

    Also the size sanity check — a 520-entry CRL is a few tens of kilobytes, well inside anything a client fetches, so
    "the CRL gets huge past N entries" is not a reason to reintroduce a cap.
    """
    for index in range(520):
        _stamp(store, f"b{index:06d}", not_after_days=365)

    records = store.revoked_records()
    crl = build_crl(bundle=throwaway_ca, records=records, crl_number=store.count_revoked())
    pem = crl_pem(crl)

    assert len(list(crl)) == 520
    assert summarise_crl(crl).crl_number == 520
    present = {entry.serial_number for entry in crl}
    assert int("b000519", 16) in present
    assert len(present) == 520, "duplicate entries collapsed: a CRL is a set, so two rows with one serial would lie"
    assert len(pem) < 100_000


# ---------------------------------------------------------------------------- the knob's spelling rule


def test_crl_base_url_must_be_a_full_http_or_https_url(settings: Settings) -> None:
    """`crl_base_url` is a full URL with a scheme (plan U1), validated at startup.

    Checked here rather than only in `test_settings_save.py` because the CDP and AIA strings this value feeds are
    certificate contents: a typo like `mypki.my.lab` would be baked into every leaf issued afterwards and cannot be
    walked back without a re-issue. The failure must name the knob, at startup, before any certificate exists.
    """
    with pytest.raises(ValueError, match="crl_base_url"):
        Settings(crl_base_url="mypki.my.lab")
    with pytest.raises(ValueError, match="crl_base_url"):
        Settings(crl_base_url="ftp://mypki.my.lab")

    assert Settings(crl_base_url="https://pki.example.org").crl_base_url == "https://pki.example.org"
    assert settings.crl_base_url == "http://mypki.my.lab"


def test_a_trailing_slash_is_stripped_once_so_the_paths_cannot_double(tmp_path: Path) -> None:
    """`http://host/` and `http://host` produce the same CDP.

    The app spells paths itself (`/crl.pem`, `/ocsp`) so there is one spelling of each URL (plan §3). A trailing slash
    left in place produces `http://host//crl.pem` in a certificate — legal to encode, broken to fetch, and invisible on
    `/settings`.
    """
    assert Settings(crl_base_url="http://mypki.my.lab/").crl_base_url == "http://mypki.my.lab"
    assert Settings(crl_base_url="  http://mypki.my.lab  ").crl_base_url == "http://mypki.my.lab"


def test_the_pem_marker_is_the_one_spelling_the_page_and_harnesses_grep_for() -> None:
    """`CRL_PEM_MARKER` is the one spelling `/crl`, `test_packaging.py` and both harnesses assert.

    Asserted as a literal shape here because the harnesses grep for it in shell, where an off-by-one dash (`----BEGIN`)
    silently matches nothing and a harness that greps for nothing passes.
    """
    assert re.fullmatch(r"-{5}BEGIN X509 CRL-{5}", CRL_PEM_MARKER)
    assert CRL_PEM_MARKER == "-----BEGIN X509 CRL-----"


# ----------------------------------------------------------------------------------------------- routes (plan §5)
#
# Everything below drives the real app through `conftest`'s clients rather than calling `crl.py` directly, because these
# are the claims an operator's client actually meets: which status, which media type, which filename, which entry set
# after a revoke. The builder's own facts are asserted above; here the questions are "did startup publish", "did the
# revoke hook publish", and "what does a host with no CA say instead".


def _artifact(client: object) -> object:
    """`GET /crl.pem` parsed as a CRL, or an explicit failure naming the status.

    Raises rather than returning None so every caller of this helper is asserting a working artifact; a test that
    quietly accepted a 503 would pass against a host that publishes nothing.
    """
    response = client.get("/crl.pem")  # type: ignore[union-attr]
    if response.status_code != 200:
        raise AssertionError(f"GET /crl.pem answered {response.status_code}: {response.text[:400]}")
    return x509.load_pem_x509_crl(response.content)


def test_startup_publishes_a_zero_entry_crl(session_client, data_root: Path, throwaway_ca: CaBundle) -> None:
    """A CA + key host publishes before anyone revokes anything (plan §4's first trigger).

    Three claims at once: the file exists at the documented path, `GET /crl.pem` answers it with the headers page-map §0
    requires for a served artifact, and the zero-entry CRL verifies against this CA's own public key. The last one
    is the reason a 404-until-the-first-revoke design was rejected: an empty CRL is a valid statement, and "nothing
    has been revoked here" is worth being able to prove.
    """
    path = paths.crl_path(data_root)
    assert path.is_file(), f"startup published nothing at {path}"

    response = session_client.get("/crl.pem")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pkix-crl"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    # Literal, never `_safe_stem()`: the download name is the on-disk name and there is no operator input to filter.
    assert response.headers["content-disposition"] == 'attachment; filename="mypki.crl.pem"'

    crl = x509.load_pem_x509_crl(response.content)
    assert list(crl) == []
    assert crl.issuer == throwaway_ca.cert.subject
    assert crl.is_signature_valid(throwaway_ca.cert.public_key())
    assert summarise_crl(crl).crl_number == 0


def test_the_published_file_is_world_readable(session_client, data_root: Path) -> None:
    """The app's own write leaves the artifact readable by a second account.

    `test_the_crl_file_is_world_readable_because_it_is_served` proves the helper's mode in isolation; this proves the
    trigger that operators actually run (startup) goes through it. A CRL published at 0600 works on the box that
    wrote it and fails for every fetch proxy or collector running as its own user, which is a bug with no local
    symptom.
    """
    mode = paths.crl_path(data_root).stat().st_mode

    assert mode & 0o044, f"published CRL is not group/other-readable: {oct(mode & 0o777)}"


def test_the_page_and_the_artifact_are_one_source(session_client) -> None:
    """`/crl` renders the same bytes `GET /crl.pem` serves, because both read the file.

    The failure mode this closes is a page describing a CRL that does not exist: a build remembered in a variable, or a
    write that failed after the page's data was computed. Asserting body equality rather than "both mention a serial" is
    what makes them one implementation (page-map §1).
    """
    page = session_client.get("/crl")
    artifact = session_client.get("/crl.pem")

    assert page.status_code == 200
    assert CRL_PEM_MARKER in page.text
    pem = artifact.content.decode("ascii")
    assert pem in page.text
    assert pem_block_count(page.text, CRL_PEM_MARKER) == 1


def test_the_page_states_all_four_measured_limits(session_client) -> None:
    """The honest-limits paragraph names all four caveats, not a summary of them (plan step 5a).

    Each string is the measured wording rather than a paraphrase, because these are the sentences an operator searches
    for after hitting the failure: `error 44` is what openssl actually printed, and "before 0.7.0" is what tells an
    operator why their oldest certificates behave differently.
    """
    page = session_client.get("/crl")

    assert "error 44 at 0 depth lookup: different CRL scope" in page.text
    assert "before 0.7.0 carry no pointer" in page.text
    assert "openssl never fetches a CDP" in page.text
    assert "revoked certificate that has already expired drops out of the CRL" in page.text
    assert "UNKNOWN" in page.text
    # The advertised absolute URL, spelled from the knob rather than from the request's Host header.
    assert "http://mypki.my.lab/crl.pem" in page.text
    assert "http://mypki.my.lab/ocsp" in page.text


def test_the_page_carries_a_csrf_checked_rebuild_control(session_client) -> None:
    """The Rebuild control is a real POST form carrying this session's token.

    Asserted as markup because the button is the only way an operator can re-sign after `nextUpdate` passes with no
    revocation in between, and a form without a token would make the page's own button refuse.
    """
    page = session_client.get("/crl")

    assert '<form method="post" action="/crl/rebuild">' in page.text
    assert 'name="csrf_token" value="' in page.text
    assert "Rebuild CRL" in page.text


def test_rebuilding_without_a_token_changes_the_published_crl_nothing(session_client, data_root: Path) -> None:
    """`POST /crl/rebuild` is CSRF-checked before it signs (page-map §0), and a refusal costs no signature.

    The byte comparison is the load-bearing half: a handler that checked the token after signing would still answer 400
    while producing a fresh CRL, which is a free signing oracle for anyone who can post to this host.
    """
    before = paths.crl_path(data_root).read_bytes()

    response = session_client.post("/crl/rebuild", data={"csrf_token": "not-this-sessions-token"})

    assert response.status_code == 400
    assert "CSRF" in response.text
    assert paths.crl_path(data_root).read_bytes() == before


def test_rebuilding_with_a_token_replaces_the_artifact_and_names_what_it_says(
    session_client, data_root: Path, throwaway_ca: CaBundle
) -> None:
    """The GUI trigger answers 200 with the facts, and says plainly that it revoked nothing.

    `thisUpdate` moves and the file changes bytes; the confirmation block is what distinguishes "I rebuilt" from
    "nothing needed rebuilding", and the re-sign sentence is what stops a nervous operator reading the button as a
    revoke action (plan §4's rebuild-button paragraph).
    """
    # The published file is replaced with a CRL deliberately signed an hour ago, so "the button re-signed it" is
    # provable against a fixed older artifact instead of against a build that happened to land in the same second
    # (DER spells UTCTime to whole seconds: MEASURED identical bytes 120 ms apart).
    stale = build_crl(
        bundle=throwaway_ca,
        records=[],
        crl_number=0,
        this_update_utc=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
    )
    write_crl_pem(paths.crl_path(data_root), crl_pem(stale))
    token = csrf_token(session_client, "/crl")

    response = session_client.post("/crl/rebuild", data={"csrf_token": token})

    assert response.status_code == 200
    assert "Rebuilt" in response.text
    assert "re-sign of the same data" in response.text
    assert CRL_PEM_MARKER in response.text

    after = x509.load_pem_x509_crl(paths.crl_path(data_root).read_bytes())
    assert after.last_update_utc > stale.last_update_utc, "the button signed nothing newer than what it was given"
    assert (dt.datetime.now(dt.timezone.utc) - after.last_update_utc) < dt.timedelta(minutes=5)
    assert after.next_update_utc == after.last_update_utc + CRL_LIFETIME


def test_a_revoke_publishes_the_serial_into_the_crl(session_client, store: IssuedStore, data_root: Path) -> None:
    """The revoke hook is the second trigger, and it is the one a client depends on (answer 2).

    End to end through the web layer: a confirmed batch stamps a row **and** republishes, so the artifact a client
    fetches contains the serial within seconds of the decision. Asserted on the parsed CRL rather than on the page
    text — `/issued` could describe a build that never landed.
    """
    _issue_active(store, "cafe0001", not_after_days=365)
    token = csrf_token(session_client, "/issued")

    response = session_client.post(
        "/issued/revoke", data={"csrf_token": token, "serial_hex": ["cafe0001"], "confirm": "1"}
    )

    assert response.status_code == 200
    assert "Published a new CRL listing 1 entry (CRL Number 1)" in response.text

    crl = _artifact(session_client)
    assert [entry.serial_number for entry in crl] == [int("cafe0001", 16)]
    facts = summarise_crl(crl)
    assert facts.entry_count == 1 and facts.crl_number == 1
    record = store.find("cafe0001")
    assert record is not None and record.revoked_at_utc is not None
    # The stamp, not the moment of the build: what a CRL entry must state is when the decision was made.
    # `replace(microsecond=0)` because DER spells this field as UTCTime, which has no sub-second field at all —
    # MEASURED 03:39:22.397758 in the row read back as 03:39:22 in the CRL. Truncation is the format, not a bug.
    assert next(iter(crl)).revocation_date_utc == record.revoked_at_utc.replace(microsecond=0)


def test_a_batch_that_revoked_nothing_republishes_nothing(session_client, store: IssuedStore, data_root: Path) -> None:
    """An all-already-revoked batch changes no data, so this host signs nothing (plan §4's second trigger's guard).

    The bytes have to be identical. A rebuild that ran anyway would move `thisUpdate` and mint a signature to report
    that nothing happened — harmless-looking, and it makes "the CRL changed" useless as a signal to anyone watching
    the file.
    """
    _issue_active(store, "cafe0002", not_after_days=365)
    token = csrf_token(session_client, "/issued")
    first = session_client.post(
        "/issued/revoke", data={"csrf_token": token, "serial_hex": ["cafe0002"], "confirm": "1"}
    )
    assert "Published a new CRL" in first.text, "the first batch should have published"

    before = paths.crl_path(data_root).read_bytes()
    again = csrf_token(session_client, "/issued")

    response = session_client.post(
        "/issued/revoke", data={"csrf_token": again, "serial_hex": ["cafe0002"], "confirm": "1"}
    )

    assert response.status_code == 200
    assert "1 already revoked before this submit" in response.text
    assert "Published a new CRL" not in response.text
    assert paths.crl_path(data_root).read_bytes() == before


def test_an_unconfirmed_revoke_publishes_nothing(session_client, store: IssuedStore, data_root: Path) -> None:
    """The confirmation step publishes nothing either, which is the same rule one step earlier.

    `stamped` is empty on the confirmation response, so the hook must not fire. Asserted against the file rather than
    the page because the confirmation page *names* the serials that are about to be revoked, and a build run at that
    moment would publish revocations an operator has not confirmed.
    """
    _issue_active(store, "cafe0003", not_after_days=365)
    before = paths.crl_path(data_root).read_bytes()
    token = csrf_token(session_client, "/issued")

    response = session_client.post("/issued/revoke", data={"csrf_token": token, "serial_hex": ["cafe0003"]})

    assert response.status_code == 200
    assert '<section class="confirm-revoke">' in response.text
    assert paths.crl_path(data_root).read_bytes() == before


def test_a_host_with_no_ca_publishes_nothing_and_answers_503(client_without_ca, data_root: Path) -> None:
    """No CA means no CRL, and the answer is 503 naming the fix rather than a 500 or an empty file.

    Three halves. Startup writes **nothing** (an empty directory under `<data>` would be a promise this host cannot
    keep); `/crl` still renders its page with the no-CA notice, because every page must handle the uninitialised
    state; and `/crl.pem` answers 503 through the existing `CaNotFoundError` handler, whose hint is the command that
    fixes it.
    """
    assert not paths.crl_dir(data_root).exists(), f"a keyless host created {paths.crl_dir(data_root)}"

    page = client_without_ca.get("/crl")
    assert page.status_code == 200
    assert "Run `mypki init-ca`" in page.text

    artifact = client_without_ca.get("/crl.pem")
    assert artifact.status_code == 503
    assert "No CA found at" in artifact.text
    assert CRL_PEM_MARKER not in artifact.text


def test_a_keyless_ca_can_record_revocations_but_says_it_cannot_publish(
    settings: Settings, data_root: Path, throwaway_ca: CaBundle
) -> None:
    """A CA whose key is absent still stamps rows, and `/issued` must say that nothing was published.

    The state is real (`mypki serve` on a host whose key cannot be decrypted runs this way) and the failure is the one
    where an operator most needs to be told: the revoke *worked*, and it reached no client. Asserted with the key
    removed from a loaded bundle rather than with no CA at all, because "no CA" and "CA without a key" are different
    states that `/issued` reports differently.
    """
    from conftest import ScratchClient

    store = IssuedStore(paths.db_path(data_root))
    _issue_active(store, "cafe0004", not_after_days=365)

    # Same certificate, no key: exactly what `load_ca` hands the app when a key file is missing or undecryptable.
    # `key_present` is a property derived from `key`, so it is not passed here — which is also why this state cannot be
    # faked into "present" by a flag.
    keyless = CaBundle(
        cert=throwaway_ca.cert,
        key=None,
        cert_path=throwaway_ca.cert_path,
        key_path=throwaway_ca.key_path,
    )
    assert not keyless.key_present
    app = create_app(settings, ca_bundle=keyless, session_secret="test-session-secret-not-a-real-one")

    with ScratchClient(app, persist_cookies=True) as client:
        token = csrf_token(client, "/issued")
        response = client.post("/issued/revoke", data={"csrf_token": token, "serial_hex": ["cafe0004"], "confirm": "1"})

        assert response.status_code == 200
        assert "no CA private key loaded" in response.text
        assert "nothing is published" in response.text
        assert IssuedStore(paths.db_path(data_root)).count_revoked() == 1
    assert not paths.crl_path(data_root).exists(), "a keyless host signed a CRL it cannot sign"
