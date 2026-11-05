"""`/ocsp` as a **protocol**: DER in, DER out, HTTP 200 whatever the answer is (page-map §15).

Four claims carry this file.

1. **A failure at this endpoint is a body, not a status.** `MALFORMED_REQUEST` and `INTERNAL_ERROR` arrive inside a 200
   response (`30 03 0a 01 01` / `30 03 0a 01 02`, MEASURED), because RFC 6960 §4.2 puts the protocol status in the
   response and a client library reads that field. mypki's house rule — every rejection gets mypki's HTML page with a
   telling status — is deliberately suspended here: HTML where a client expects DER is indistinguishable from a dead
   responder. The one exception is measured and asserted below (a body over `SizeGuardMiddleware`'s limit does get
   mypki's 413 HTML), which is why the handler-side cap sits far under it.
2. **The status comes from mypki's own store**, keyed on the request's serial: GOOD for an active row, REVOKED with the
   original stamp, and UNKNOWN both for a serial this host never signed **and** for a revoked certificate that has
   already expired (U5). The second case is what keeps this host telling one story: §4's entry rule drops that serial
   from the CRL while the row stays in `issued.db`, so GOOD would contradict the artifact next door.
3. **The CertID hashes are echoed, not verified** (risk R-OCSP-1). Every assertion about them here asserts the echo —
   which is all this responder can honestly claim. What it *can* claim is that the answer is bound to a serial drawn
   from its own store: nobody can make this CA sign a statement about a certificate it knows nothing about.
4. **The root signs its own answers** (U3): `responder_id(NAME, ca_cert)`, `certificates([ca_cert])`, and the signature
   verifies against the CA's public key. The unmeasured half — whether a browser or Go client requires an
   `id-kp-OCSPSigning` EKU on the responder — is stated on `/crl`, in page-map §15 and in README, not tested here.

openssl does **not** appear in this file (plan U7; `.github/workflows/ci.yml`'s "NO OpenSSL binary is required
anywhere"). The openssl-side facts live as MEASURED evidence in CRL_PLAN-0.7.0.md §2: `Response verify OK` against a
by-hash response, and `WARNING: no nonce in response` for a responder that drops a nonce. What pytest asserts instead is
the DER openssl would have been handed, parsed with `load_der_ocsp_response` and verified against the CA's public key.

Request fixtures are built with `add_certificate_by_hash`, i.e. exactly what a client builds: hashes of the CA subject
DER and of the CA SubjectPublicKeyInfo DER. The plan's probe measured real request bodies at 73-101 B; the SHA-256 +
nonce fixture here is 139 B, which is why the handler cap is 8 KiB rather than something tighter.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import types
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import OCSPNonce
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPRequestBuilder,
    OCSPResponseStatus,
    load_der_ocsp_request,
    load_der_ocsp_response,
)

from conftest import ScratchClient, csrf_token
from mypki import paths
from mypki.app import create_app
from mypki.ca import CaBundle
from mypki.config import Settings
from mypki.ocsp_responder import (
    OCSP_LIFETIME,
    OCSP_MAX_REQUEST_BYTES,
    OCSP_REQUEST_MEDIA_TYPE,
    OCSP_RESPONSE_MEDIA_TYPE,
    answer_for,
    malformed_response_der,
    parse_ocsp_request,
    render_ocsp_response,
    serial_hex_of,
)
from mypki.store import IssuedRecord, IssuedStore

#: One whole-second instant, captured at import, used for **both** the record fixtures and `render_ocsp_response`'s
#: pinned `now_utc`. The pairing is not cosmetic: `IssuedRecord.is_expired` judges against the real clock, so a fixture
#: built around a date in the past would make every "active" row expired and every revoked row answer UNKNOWN (MEASURED:
#: this file was briefly green-looking against a 2026-03 pinned instant while the host's clock said otherwise). Pinning
#: one whole-second `now` keeps `thisUpdate`/`nextUpdate` assertable exactly **and** keeps expiry behaving as each test
#: intends. Day-scale offsets mean a test that runs minutes after import still means what it says.
FIXED_NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

#: The exact 5-byte DER of each protocol-level refusal (MEASURED; plan §2 spelling fix S1). Written as byte literals
#: rather than described in prose because these two strings are what `tools/e2e_harness.py` §11 searches
#: for in a decoded body: re-spelling either answer must break the harness, not pass a unit test that quietly moved.
MALFORMED_DER = b"\x30\x03\x0a\x01\x01"
INTERNAL_ERROR_DER = b"\x30\x03\x0a\x01\x02"

#: A serial of the shape `x509.random_serial_number()` produces (159 bits, top bit set) — the same fixture reasoning as
#: `test_crl.py`: a hex round-trip that mishandles the sign bit would silently answer UNKNOWN for a real certificate.
BIG_SERIAL = 0x7F_D1_AD_BE_EF_CD_AB_90_12_34_56_78_9A_BC_DE_F0_11_22_33_44


@pytest.fixture
def store(data_root: Path) -> IssuedStore:
    """A store in pytest's temporary data dir, never an operator's (`isolated_data_dir` pins `MYPKI_DATA_DIR`)."""
    issued = IssuedStore(paths.db_path(data_root))
    issued.init_schema()
    return issued


# ------------------------------------------------------------------------------------------- request fixtures
#
# Built the way a client builds them: hashes of the CA's subject DER and its SubjectPublicKeyInfo DER. Going through
# `add_certificate_by_hash` rather than `add_certificate(cert, issuer)` is deliberate — mypki holds no leaf certificate
# to hand a builder (the store keeps metadata only), so every request here is one a client could have made against a
# leaf it holds and mypki does not. That is the whole reason by-hash answering is possible (plan §7's lookup problem).


def _cert_id_hashes(subject: x509.Name, public_key: object, algorithm: hashes.HashAlgorithm) -> tuple[bytes, bytes]:
    """The two CertID hashes for an issuer, computed the only way they can be computed from a certificate.

    `issuer_name_hash` over the Name's DER, `issuer_key_hash` over the SubjectPublicKeyInfo DER. The probe (plan §2
    P-OCSP-2) measured that **no** other form of the key material reproduces what a real client puts in a SHA-256
    request — which is why mypki echoes the request's values instead of recomputing them (R-OCSP-1).
    """
    spki = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)  # type: ignore[union-attr]
    return (
        hashlib.new(algorithm.name, subject.public_bytes(Encoding.DER)).digest(),
        hashlib.new(algorithm.name, spki).digest(),
    )


def _request(
    bundle: CaBundle,
    serial: int,
    *,
    algorithm: hashes.HashAlgorithm | None = None,
    nonce: bytes | None = None,
) -> x509.OCSPRequest:
    """One parsed OCSP request, exactly as `load_der_ocsp_request` hands one to the responder."""
    algorithm = algorithm or hashes.SHA256()
    name_hash, key_hash = _cert_id_hashes(bundle.cert.subject, bundle.cert.public_key(), algorithm)
    builder = OCSPRequestBuilder().add_certificate_by_hash(name_hash, key_hash, serial, algorithm)
    if nonce is not None:
        builder = builder.add_extension(OCSPNonce(nonce), critical=False)
    return load_der_ocsp_request(builder.build().public_bytes(Encoding.DER))


def _foreign_request(serial: int) -> x509.OCSPRequest:
    """A request whose CertID belongs to no CA on this host — built entirely in memory.

    Used by the tests about hosts with **no** CA at all. Asking `throwaway_ca` for those hashes would be a lie in two
    directions: the fixture writes a real CA into the temporary data dir (so `create_app`'s discovery path would find
    one and the "no CA" premise would evaporate — MEASURED this session), and the hashes would describe a CA that is
    present. An ephemeral 2048-bit key plus a bare Name produces CertID bytes with no file behind them anywhere.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Absent CA (test fixture only)")])
    name_hash, key_hash = _cert_id_hashes(subject, key.public_key(), hashes.SHA256())
    builder = OCSPRequestBuilder().add_certificate_by_hash(name_hash, key_hash, serial, hashes.SHA256())
    return load_der_ocsp_request(builder.build().public_bytes(Encoding.DER))


def _post(client: ScratchClient, body: bytes):
    """`POST /ocsp` with a DER body and the media type a real client declares."""
    return client.post("/ocsp", content=body, headers={"content-type": OCSP_REQUEST_MEDIA_TYPE})


def _parsed(response) -> x509.OCSPResponse:
    """The response body parsed as DER, or an explicit failure naming the status this route is not meant to have."""
    if response.status_code != 200:
        raise AssertionError(f"POST /ocsp answered {response.status_code}: {response.text[:300]}")
    return load_der_ocsp_response(response.content)


def _answered(session_client, bundle: CaBundle, serial: int) -> x509.OCSPResponse:
    """One round trip to `/ocsp`, parsed."""
    return _parsed(_post(session_client, _request(bundle, serial).public_bytes(Encoding.DER)))


# --------------------------------------------------------------------------------------------- record fixtures


def _record(
    serial_hex: str,
    *,
    revoked_at_utc: dt.datetime | None,
    not_after_utc: dt.datetime,
    reason: str | None = None,
) -> IssuedRecord:
    """One `IssuedRecord` as the responder sees it: metadata only, exactly what `issued.db` holds."""
    return IssuedRecord(
        serial_hex=serial_hex,
        cert_type="server",
        common_name=f"{serial_hex[:6]}.lab.internal",
        sans=("lab.internal",),
        not_before_utc=FIXED_NOW - dt.timedelta(days=30),
        not_after_utc=not_after_utc,
        issued_at_utc=FIXED_NOW - dt.timedelta(days=30),
        fingerprint_sha256="ab" * 32,
        revoked_at_utc=revoked_at_utc,
        revocation_reason=reason,
    )


def _active(serial_hex: str) -> IssuedRecord:
    return _record(serial_hex, revoked_at_utc=None, not_after_utc=FIXED_NOW + dt.timedelta(days=60))


def _revoked(serial_hex: str, *, reason: str | None = None) -> IssuedRecord:
    return _record(
        serial_hex,
        revoked_at_utc=FIXED_NOW - dt.timedelta(days=3),
        not_after_utc=FIXED_NOW + dt.timedelta(days=60),
        reason=reason,
    )


def _expired_revoked(serial_hex: str) -> IssuedRecord:
    return _record(
        serial_hex,
        revoked_at_utc=FIXED_NOW - dt.timedelta(days=200),
        not_after_utc=FIXED_NOW - dt.timedelta(days=5),
    )


# --------------------------------------------------------------- the protocol rule: a failure is a body, not a status


def test_every_protocol_refusal_is_five_bytes_of_der() -> None:
    """`MALFORMED_REQUEST` and `INTERNAL_ERROR` are exact 5-byte bodies (MEASURED; plan §2 spelling fix S1).

    Asserted as whole byte strings rather than as "contains the status", because these two literals are what
    `tools/e2e_harness.py` §11 searches for in a base64-decoded body: re-spelling either answer has to
    show up as a harness failure, not as a unit test that quietly moved the goalposts.

    The builder form is part of the claim too — `OCSPResponseBuilder.build_unsuccessful(...)` is a classmethod on the
    builder and there is **no** module-level `build_unsuccessful` to import (MEASURED `ImportError`). An unsigned
    refusal carrying no response data is what RFC 6960 §4.2.1 describes, and it is also why a malformed request cannot
    be turned into free signatures.
    """
    assert malformed_response_der() == MALFORMED_DER
    assert malformed_response_der(OCSPResponseStatus.MALFORMED_REQUEST) == MALFORMED_DER
    assert malformed_response_der(OCSPResponseStatus.INTERNAL_ERROR) == INTERNAL_ERROR_DER

    parsed = load_der_ocsp_response(malformed_response_der())
    assert parsed.response_status is OCSPResponseStatus.MALFORMED_REQUEST
    # The absence of response data is proved by the length: 5 bytes is a SEQUENCE wrapping one OCSPResponseStatus enum,
    # with no room in it for a responderID, a certificate or a signature. Reading the response-data properties instead
    # would raise — cryptography refuses them on an unsuccessful response (MEASURED: "OCSP response status is not
    # successful so the property has no value"), which is the library itself agreeing that nothing was answered.
    assert len(malformed_response_der()) == 5
    with pytest.raises(ValueError, match="not successful"):
        _refused = parsed.certificate_status  # the raise is the assertion


def test_parse_ocsp_request_folds_every_parse_failure_into_none() -> None:
    """Truncated, mis-tagged and empty bodies all answer the same thing: None (and therefore `MALFORMED_REQUEST`).

    Returned rather than raised because a raised error at this endpoint becomes mypki's HTML error page — the one
    artifact an OCSP client cannot read. The three shapes are three different exceptions inside cryptography (MEASURED:
    `ParseError { kind: ShortData … }` for a truncated body, a plain ValueError for text) and the responder's answer is
    identical for all of them, so the distinction stays in the log line where it belongs rather than in the protocol.
    """
    assert parse_ocsp_request(b"not-an-ocsp-request") is None
    assert parse_ocsp_request(b"") is None
    # A DER-shaped prefix that stops mid-CertID: what a proxy that truncated a body produces.
    assert parse_ocsp_request(b"\x30\x82\x01\x00\x0a\x01\x00") is None


# -------------------------------------------------------------------------------------------- the decision table


def test_a_serial_this_host_never_signed_answers_unknown(throwaway_ca: CaBundle) -> None:
    """UNKNOWN for "no record", because both alternatives would be invented claims.

    GOOD would assert something about a certificate this CA has never seen; REVOKED would invent a decision nobody made.
    This branch is also what makes R-OCSP-1 survivable: a request carrying someone else's CertID gets an answer about
    **this host's** store, which is UNKNOWN, rather than a signed statement about another CA's serial.

    `BIG_SERIAL` (top bit set) is the fixture that proves the hex round-trip survives it — the same 159-bit shape 101 of
    200 real mypki serials have (`test_crl.py`), and a lookup path that mishandled the sign bit would answer UNKNOWN for
    every real certificate on this host.
    """
    request = _request(throwaway_ca, BIG_SERIAL)

    answer = answer_for(request, None)

    assert answer.status is OCSPCertStatus.UNKNOWN
    assert answer.status_name == "UNKNOWN"
    assert answer.record is None
    # The store's spelling of the serial, so a log line can be matched against `/issued`.
    assert answer.serial_hex == f"{BIG_SERIAL:x}"
    assert "no record" in answer.reason


def test_a_revoked_certificate_answers_revoked_and_keeps_the_original_stamp(throwaway_ca: CaBundle) -> None:
    """REVOKED carries `revoked_at_utc` as stamped, never "now" (plan §7 step 3, spelling fix S4).

    The same principle `store.revoke()` protects by refusing to move an existing stamp and `crl.py` protects by using
    the stamp for the CRL entry: a client reading both an OCSP answer and a CRL entry must be shown **one** time. Two
    times would mean this host revoked a certificate twice, once in each artifact.

    DER spells the field as UTCTime (whole seconds), so the comparison truncates microseconds — the identical rule
    `test_crl.py` asserts for a CRL entry (MEASURED: a stamp of 03:39:22.397758 reads back as 03:39:22). Truncation is
    the format, and this responder does no rounding of its own.
    """
    record = _revoked("cafe0001", reason="lab switch key leaked")
    request = _request(throwaway_ca, int("cafe0001", 16))

    answer = answer_for(request, record)
    parsed = load_der_ocsp_response(render_ocsp_response(request, answer, throwaway_ca, now_utc=FIXED_NOW))

    assert answer.status is OCSPCertStatus.REVOKED
    assert parsed.certificate_status is OCSPCertStatus.REVOKED
    assert parsed.revocation_time_utc == record.revoked_at_utc.replace(microsecond=0)
    assert parsed.this_update_utc != parsed.revocation_time_utc, "the answer must not restate the decision as 'now'"


def test_a_revoked_certificate_past_its_own_not_after_answers_unknown(throwaway_ca: CaBundle) -> None:
    """U5: revoked **and** expired is UNKNOWN, not GOOD (page-map §15 states the reason in these words).

    The disagreement this avoids is structural rather than cosmetic: §4's entry rule drops an expired revoked serial
    from the CRL (`store.revoked_records()` filters on `is_expired`) while the row stays in `issued.db` forever. A GOOD
    answer next to a CRL that does not list the serial would be one host telling two stories, and an operator holding
    both artifacts could not tell which one this CA means.

    `answer.record` is asserted non-None because UNKNOWN here is *not* "this never happened" — it is "I hold a
    revocation I can no longer show you". The reason string is what the log line says out loud to whoever is debugging
    a client that believes the certificate is fine.
    """
    record = _expired_revoked("cafe0002")
    request = _request(throwaway_ca, int("cafe0002", 16))

    answer = answer_for(request, record)

    assert answer.status is OCSPCertStatus.UNKNOWN
    assert answer.record is not None
    assert "no longer listed in the CRL" in answer.reason


def test_an_unrevoked_expired_certificate_answers_good(throwaway_ca: CaBundle) -> None:
    """GOOD for "never revoked", even past `notAfter` — OCSP reports revocation standing, not acceptance.

    The pair with the test above *is* the U5 decision, and both halves have to be asserted or the next edit collapses
    them into one branch: an expired **revoked** serial answers UNKNOWN because this host holds a revocation it cannot
    show in the CRL; an expired **never-revoked** serial answers GOOD because OCSP is not a statement about whether a
    validator would accept a certificate today. Writing both here is what keeps `decide_status`'s fourth branch from
    being "simplified" into the third.
    """
    record = _record("cafe0003", revoked_at_utc=None, not_after_utc=FIXED_NOW - dt.timedelta(days=1))
    request = _request(throwaway_ca, int("cafe0003", 16))

    answer = answer_for(request, record)

    assert answer.status is OCSPCertStatus.GOOD
    assert "notAfter" in answer.reason and "OCSP does not report" in answer.reason


def test_an_active_record_answers_good(throwaway_ca: CaBundle) -> None:
    """The one positive claim this responder makes, and it is a claim about this store only."""
    request = _request(throwaway_ca, int("cafe0004", 16))

    answer = answer_for(request, _active("cafe0004"))

    assert answer.status is OCSPCertStatus.GOOD
    assert answer.reason == "active in this host's issued list"


def test_the_reason_is_always_unspecified_and_never_the_operators_prose(throwaway_ca: CaBundle) -> None:
    """U6: `revocation_reason` in the store is prose, and prose does not become an RFC 5280 reason code.

    The row carries "lab switch key leaked". Mapping that to `keyCompromise` would invent a claim about *how* a key was
    lost, from a note typed into a text box. `unspecified` is what RFC 5280 §5.3.1 defines as "the CA did not say",
    which is exactly true here — and it matches the CRL side, where no reason entry extension is added at all
    (`crl.py`, whose absent code means the same thing).

    Asserted on the parsed DER rather than on the builder call: a future `add_extension` smuggling a real code in via
    singleExtensions would be caught here rather than reading as a correct-looking argument.
    """
    record = _revoked("cafe0005", reason="lab switch key leaked")
    request = _request(throwaway_ca, int("cafe0005", 16))

    parsed = load_der_ocsp_response(
        render_ocsp_response(request, answer_for(request, record), throwaway_ca, now_utc=FIXED_NOW)
    )

    assert parsed.revocation_reason is x509.ReasonFlags.unspecified
    assert not any(isinstance(extension.value, x509.CRLReason) for extension in parsed.single_extensions)


# ------------------------------------------------------------------ R-OCSP-1: the hashes are echoed, never verified


def test_both_cert_id_hashes_are_echoed_verbatim_from_the_request(throwaway_ca: CaBundle) -> None:
    """The response's CertID equals the request's, byte for byte, under **both** hash algorithms (plan §2 P-OCSP-2).

    This is the measured reason `add_response_by_hash` is the only usable form: mypki stores no certificate PEM, and
    cryptography cannot recompute `issuer_key_hash` for a SHA-256 request (every candidate form mismatched in the
    probe). Echoing is not a choice between two good options; it is the workable one.

    What this test deliberately does **not** claim — stated because it is the standing risk R-OCSP-1 rather than an
    oversight — is that the CertID describes *this* CA. Only the SHA-1 case could be cross-checked (its
    `issuer_key_hash` equals the CA's SubjectKeyIdentifier, MEASURED), and even that is a coincidence of form, not a
    verification. The safety of the design comes from the answer being drawn from mypki's own store: a foreign CertID
    yields UNKNOWN about a serial this host does not hold. page-map §15 carries those words.

    `hash_algorithm` is echoed as the **instance** the client asked with, so a SHA-1 client is not silently upgraded.
    """
    for algorithm in (hashes.SHA1, hashes.SHA256):
        request = _request(throwaway_ca, int("cafe0006", 16), algorithm=algorithm())
        answer = answer_for(request, _active("cafe0006"))

        parsed = load_der_ocsp_response(render_ocsp_response(request, answer, throwaway_ca, now_utc=FIXED_NOW))

        assert parsed.issuer_name_hash == request.issuer_name_hash
        assert parsed.issuer_key_hash == request.issuer_key_hash
        assert parsed.serial_number == request.serial_number
        assert parsed.hash_algorithm.name == algorithm().name


def test_the_single_response_lifetime_is_four_hours_and_is_a_constant(throwaway_ca: CaBundle) -> None:
    """`nextUpdate` = `thisUpdate` + 4 h (U8), asserted on the artifact and not only on the constant.

    Shorter than the CRL's 24 h deliberately: an OCSP answer is cheap to mint, so a client that caches one should re-ask
    within a working day, while a CRL is a signed artifact this host writes deliberately. A knob was rejected (U8) — it
    would need a §11 row, a preset and an empty-value rule for a value whose only sensible range is "often".

    `nextUpdate` is also what makes the route's `Cache-Control: no-store` meaningful rather than decorative: the field
    tells a client how long this answer may be reused, and the header stops an intermediary from deciding for itself.
    """
    request = _request(throwaway_ca, int("cafe0007", 16))

    parsed = load_der_ocsp_response(
        render_ocsp_response(request, answer_for(request, _active("cafe0007")), throwaway_ca, now_utc=FIXED_NOW)
    )

    four_hours = dt.timedelta(hours=4)
    assert four_hours == OCSP_LIFETIME
    assert parsed.next_update_utc - parsed.this_update_utc == four_hours
    assert parsed.this_update_utc == FIXED_NOW


def test_the_responder_is_the_root_certificate_itself(throwaway_ca: CaBundle) -> None:
    """U3: the root signs its own answers — responderID by Name, with itself in `certs` (page-map §15).

    No delegated responder certificate is issued and no CA re-issue is needed (`crl_sign=True` is already on the root).
    Asserted as `responder_name` equal to the CA subject plus `responder_key_hash is None`, which is the DER spelling of
    "responderID is a Name, not a key hash", and as the CA certificate being the one carried in `certs` — what lets a
    client holding only its trust anchor verify the signature without being told anything else.

    The unmeasured half stays unmeasured and is *stated* instead: openssl 3.5 accepted this root, which carries no
    `id-kp-OCSPSigning` EKU (MEASURED, plan §2), while whether a browser or Go client requires that EKU was not tested
    and cannot be tested from here. `/crl`, page-map §15 and README each say so in words. A delegated responder would
    mean issuing, storing and rotating a second key for a home-lab CA — a cost larger than the unmeasured risk.
    """
    request = _request(throwaway_ca, int("cafe0008", 16))

    parsed = load_der_ocsp_response(
        render_ocsp_response(request, answer_for(request, _active("cafe0008")), throwaway_ca, now_utc=FIXED_NOW)
    )

    assert parsed.responder_name == throwaway_ca.cert.subject
    assert parsed.responder_key_hash is None
    assert [certificate.subject for certificate in parsed.certificates] == [throwaway_ca.cert.subject]


def test_the_response_signature_verifies_against_the_cas_public_key(throwaway_ca: CaBundle) -> None:
    """The signature is real, over the bytes a client actually signs — and checking it needed nothing private.

    Verified by hand against `tbs_response_bytes` because cryptography's OCSP API has no verification helper (that is
    openssl's job, and openssl is out of the pytest gate — U7). The two halves an operator cares about: the signature
    algorithm is `sha256WithRSAEncryption` (`1.2.840.113549.1.1.11`, asserted so a change of hash algorithm cannot slip
    in silently), and verification runs against the CA's **public** key, i.e. rendering an answer exposes nothing.
    """
    request = _request(throwaway_ca, int("cafe0009", 16))

    parsed = load_der_ocsp_response(
        render_ocsp_response(request, answer_for(request, _active("cafe0009")), throwaway_ca, now_utc=FIXED_NOW)
    )

    assert parsed.signature_algorithm_oid.dotted_string == "1.2.840.113549.1.1.11"
    assert parsed.signature_hash_algorithm.name == "sha256"
    throwaway_ca.cert.public_key().verify(
        parsed.signature, parsed.tbs_response_bytes, asym_padding.PKCS1v15(), hashes.SHA256()
    )


def test_a_nonce_is_echoed_when_the_client_sent_one_and_omitted_when_it_did_not(throwaway_ca: CaBundle) -> None:
    """Nonce handling in both directions (plan §7 step 5).

    MEASURED consequence of dropping a received nonce: openssl prints `WARNING: no nonce in response`. So the echo is
    asserted as the *same bytes*, not as "an OCSPNonce extension exists" — a regenerated nonce would defeat the only
    purpose a nonce serves (letting a client tell a fresh answer from a replayed one).

    The other direction matters just as much: a client that sent no nonce gets **no** extension at all. mypki never
    invents one, because a response nonce with no request nonce is a random value carrying no meaning, and adding one
    would make two otherwise identical answers differ for no benefit.
    """
    serial = int("cafe000a", 16)

    with_nonce = _request(throwaway_ca, serial, nonce=b"client-nonce-1234")
    echoed = load_der_ocsp_response(
        render_ocsp_response(with_nonce, answer_for(with_nonce, _active("cafe000a")), throwaway_ca, now_utc=FIXED_NOW)
    )
    assert echoed.extensions.get_extension_for_class(OCSPNonce).value.nonce == b"client-nonce-1234"

    without_nonce = _request(throwaway_ca, serial)
    plain_der = render_ocsp_response(
        without_nonce, answer_for(without_nonce, _active("cafe000a")), throwaway_ca, now_utc=FIXED_NOW
    )
    plain = load_der_ocsp_response(plain_der)
    assert list(plain.extensions) == []


def test_two_answers_to_the_same_request_at_the_same_instant_are_byte_identical(throwaway_ca: CaBundle) -> None:
    """Deterministic DER, which is part of why 0.7.0 ships **no** response cache (plan §7's mitigation, declined).

    Plan §7 suggested caching signed answers per (serial, status) until `nextUpdate` to blunt the fact that `/ocsp` is a
    signing oracle reachable over HTTP. It is not implemented, and this test is part of the reasoning: with a pinned
    `thisUpdate` the same question produces identical bytes, so a cache would save one signature while storing copies of
    signatures produced for CertID hashes this responder did not verify (R-OCSP-1) — a second copy of the risk rather
    than a mitigation. The exposure is named in page-map §12 instead of half-mitigated by something unmeasured.

    `thisUpdate` is pinned deliberately: with wall-clock `now`, two builds a millisecond apart differ, and that is the
    honest cost of not caching — nothing worse than one signature per request.
    """
    request = _request(throwaway_ca, int("cafe000b", 16), nonce=b"nonce-for-determinism")
    answer = answer_for(request, _active("cafe000b"))

    first = render_ocsp_response(request, answer, throwaway_ca, now_utc=FIXED_NOW)
    second = render_ocsp_response(request, answer, throwaway_ca, now_utc=FIXED_NOW)

    assert first == second


def test_a_keyless_bundle_refuses_to_sign_rather_than_producing_an_answer(throwaway_ca: CaBundle) -> None:
    """`render_ocsp_response` refuses a keyless `CaBundle` instead of emitting something unsigned.

    Not reachable through `/ocsp` (the handler answers INTERNAL_ERROR first, asserted below), and kept as a refusal
    because this function takes a bundle: a caller that handed in a keyless one should be told. The spelling is a plain
    `ValueError` rather than `MypkiError` on purpose — at this endpoint an exception must never become mypki's HTML
    page, and the handler catches exactly this family and turns it into the protocol's own refusal.
    """
    keyless = CaBundle(
        cert=throwaway_ca.cert,
        key=None,
        cert_path=throwaway_ca.cert_path,
        key_path=throwaway_ca.key_path,
    )
    request = _request(throwaway_ca, int("cafe000c", 16))

    with pytest.raises(ValueError, match="no private key"):
        render_ocsp_response(request, answer_for(request, _active("cafe000c")), keyless, now_utc=FIXED_NOW)


def test_the_serial_conversion_matches_how_signing_writes_a_serial(throwaway_ca: CaBundle) -> None:
    """`serial_hex_of` produces the spelling `signing.py` wrote into `issued.db`: lowercase, unpadded, no `0x`.

    The lookup only works if the two spellings agree, so this is asserted against the same formatting expression
    `signing.py` uses (`f"{cert.serial_number:x}"`) rather than against a hand-written hex string. A zero-padded or
    upper-cased conversion would match nothing, every answer would be UNKNOWN, and the failure would read as "this CA
    revoked nothing" rather than as a formatting bug.

    The negative guard is asserted too, against a fabricated request object: nothing in this protocol can produce a
    negative serial (cryptography refuses to *build* one, MEASURED) but a hostile body must not become a database key
    like `-5`.
    """
    request = _request(throwaway_ca, BIG_SERIAL)

    assert serial_hex_of(request) == f"{BIG_SERIAL:x}"
    assert serial_hex_of(request) == f"{int(f'{BIG_SERIAL:x}', 16):x}"

    with pytest.raises(ValueError, match="negative serial"):
        serial_hex_of(types.SimpleNamespace(serial_number=-5))  # type: ignore[arg-type]


# ------------------------------------------------------------------------------------------------- the route


def test_the_route_answers_der_at_200_with_no_session_and_no_token(session_client) -> None:
    """`POST /ocsp` needs nothing mypki issued (page-map §0's documented CSRF exception).

    Asserted as headers rather than as "the handler does not call `require_csrf`": the observable contract is that a
    request carrying no cookie, no token and no HTML ever seen by the client gets a DER answer. `Cache-Control:
    no-store` carries weight here equal to `/crl.pem` and arguably more — an OCSP answer states whether a certificate
    is revoked **now**, and a proxy replaying a cached GOOD keeps a revoked certificate trusted for the length of that
    cache.

    No `Content-Disposition`, deliberately: this body is consumed by a library, not saved as a file, and attaching a
    filename invites an operator to download bytes they have no way to open.
    """
    bundle = session_client.app.state.ca
    assert bundle is not None

    response = _post(session_client, _request(bundle, int("cafe0010", 16)).public_bytes(Encoding.DER))

    assert response.status_code == 200
    assert response.headers["content-type"] == OCSP_RESPONSE_MEDIA_TYPE
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "content-disposition" not in response.headers

    parsed = _parsed(response)
    assert parsed.response_status is OCSPResponseStatus.SUCCESSFUL
    # The security-header set every mypki response carries still applies to a DER one.
    assert response.headers["x-frame-options"] == "DENY"


def test_a_revoked_serial_answers_revoked_over_http(session_client, store: IssuedStore) -> None:
    """End to end through the web layer: a revoke on `/issued` is answerable by OCSP seconds later.

    The whole point of 0.7.0's revocation story, asserted as one flow rather than as two unit tests: the operator stamps
    a row on the page, and the artifact a client fetches says so. Asserted on the parsed DER because `/issued` could
    describe a build that never landed — the same reasoning `test_crl.py` uses for its revoke test.

    The row is created through the store rather than through a signing POST because the responder only ever sees a
    serial number: nothing here needs a certificate body, which is the property that makes by-hash answering possible.
    """
    store.add_record(
        serial_hex="cafe0011",
        cert_type="server",
        common_name="revoked.lab.internal",
        sans=("lab.internal",),
        not_before_utc=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2),
        not_after_utc=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=300),
        fingerprint_sha256="ef" * 32,
    )
    token = csrf_token(session_client, "/issued")
    revoked = session_client.post(
        "/issued/revoke", data={"csrf_token": token, "serial_hex": ["cafe0011"], "confirm": "1"}
    )
    assert "Published a new CRL" in revoked.text, "the CRL half of the same decision must have run"

    bundle = session_client.app.state.ca
    assert bundle is not None
    parsed = _parsed(_post(session_client, _request(bundle, int("cafe0011", 16)).public_bytes(Encoding.DER)))

    record = store.find("cafe0011")
    assert record is not None and record.revoked_at_utc is not None
    assert parsed.certificate_status is OCSPCertStatus.REVOKED
    assert parsed.serial_number == int("cafe0011", 16)
    assert parsed.revocation_reason is x509.ReasonFlags.unspecified
    # One time, in both artifacts: the stamp (DER-truncated to whole seconds), not the moment of the OCSP request.
    assert parsed.revocation_time_utc == record.revoked_at_utc.replace(microsecond=0)


def test_an_active_serial_answers_good_and_an_unknown_one_answers_unknown(session_client, store: IssuedStore) -> None:
    """The two answers a client gets from a working host that has one certificate on it."""
    store.add_record(
        serial_hex="cafe0012",
        cert_type="server",
        common_name="active.lab.internal",
        sans=("lab.internal",),
        not_before_utc=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2),
        not_after_utc=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=300),
        fingerprint_sha256="cd" * 32,
    )
    bundle = session_client.app.state.ca
    assert bundle is not None

    good = _answered(session_client, bundle, int("cafe0012", 16))
    unknown = _answered(session_client, bundle, int("deadbeef99", 16))

    assert good.certificate_status is OCSPCertStatus.GOOD
    assert unknown.certificate_status is OCSPCertStatus.UNKNOWN
    # `nextUpdate` is present on every status: a client caching an UNKNOWN still knows when to ask again. Read through
    # `next(iter(...))` because cryptography's response iterator is not subscriptable (MEASURED TypeError). DER spells
    # these times as UTCTime, so the 4 h interval survives the round-trip to whole seconds.
    single = next(iter(unknown.responses))
    assert single.next_update_utc - single.this_update_utc == OCSP_LIFETIME


def test_a_revoked_and_expired_serial_answers_unknown_while_the_crl_lists_nothing(
    session_client, store: IssuedStore, data_root: Path
) -> None:
    """The two artifacts agree by answering the same way (U5), asserted as one host rather than as two modules.

    A row stamped revoked long ago whose own validity has lapsed is **absent** from the published CRL (§4's entry rule)
    and answers **UNKNOWN** over OCSP. Asserted together, in one test, on purpose: plan §12 records this coupling as
    structural, so a future change to the CRL entry rule must break a test that also names the OCSP answer. Two files
    that each tested one half separately would let one half change green-lit.

    The row is still there, which `/issued` and `/crl` both say out loud: dropping an entry is not an un-revoke.
    """
    now = dt.datetime.now(dt.timezone.utc)
    store.add_record(
        serial_hex="cafe0013",
        cert_type="server",
        common_name="old.lab.internal",
        sans=("lab.internal",),
        not_before_utc=now - dt.timedelta(days=400),
        not_after_utc=now - dt.timedelta(days=5),
        fingerprint_sha256="ab" * 32,
    )
    token = csrf_token(session_client, "/issued")
    session_client.post("/issued/revoke", data={"csrf_token": token, "serial_hex": ["cafe0013"], "confirm": "1"})

    crl = x509.load_pem_x509_crl(paths.crl_path(data_root).read_bytes())
    assert [entry.serial_number for entry in crl] == [], "an expired revoked serial must not be listed"

    bundle = session_client.app.state.ca
    assert bundle is not None
    parsed = _answered(session_client, bundle, int("cafe0013", 16))

    assert parsed.certificate_status is OCSPCertStatus.UNKNOWN
    assert store.find("cafe0013") is not None, "the row stays; there is no un-revoke in this store"


def test_a_malformed_body_is_refused_inside_the_protocol_not_as_an_http_error(session_client) -> None:
    """Garbage gets 200 + the 5-byte MALFORMED_REQUEST body (MEASURED, plan §2 "Garbage body").

    Three shapes are asserted because a client's failure is rarely the one you thought of: text, an empty body, and a
    truncated DER prefix. All three get the same answer, and none gets mypki's HTML page — which would be read as "the
    responder is down" rather than "your request was malformed", sending an operator hunting for a broken service that
    is not broken.

    The 5-byte body also means no signature was minted: a malformed request cannot be used to buy signatures.
    """
    for body in (b"curl called this wrong", b"", b"\x30\x82\x01\x00\x0a"):
        response = _post(session_client, body)

        assert response.status_code == 200, body[:16]
        assert response.content == MALFORMED_DER
        assert response.headers["content-type"] == OCSP_RESPONSE_MEDIA_TYPE
        assert load_der_ocsp_response(response.content).response_status is OCSPResponseStatus.MALFORMED_REQUEST


def test_a_body_over_the_handler_cap_is_refused_before_anything_is_signed(session_client) -> None:
    """The 8 KiB handler-side cap answers DER and mints no signature while doing it (plan §7 step 1).

    MEASURED boundary from plan §2/P-OCSP-3: a 9,000-byte body reaches the handler and gets MALFORMED_REQUEST at HTTP
    200. The load-bearing half is what does **not** happen: no OCSP response is built, so a hostile body cannot be
    turned into free signatures. Real requests are 73-101 B (MEASURED), so this cap is about malformed abuse rather
    than traffic — which is why it can be this tight and why no knob exists for it (U8).
    """
    oversized = b"\x30" + b"A" * OCSP_MAX_REQUEST_BYTES

    response = _post(session_client, oversized)

    assert response.status_code == 200
    assert len(response.content) == 5
    assert response.content == MALFORMED_DER


def test_a_body_over_the_middleware_limit_still_answers_mypkis_html_413(session_client) -> None:
    """The other side of the measured pair: above `max_csr_chars + 8192` (40,192) it is mypki's HTML 413 (plan §2).

    Asserted in the same file as the handler cap because the two limits only make sense together, and because this is
    the one place where `/ocsp` **does** answer mypki's HTML — a deliberate consequence of leaving
    `SizeGuardMiddleware` unmodified and not exempting this route. Documented out loud on `/crl` and in page-map §15 so
    an operator who hits it is not hunting for an OCSP-specific knob: the knob is `MYPKI_MAX_CSR_CHARS`, and no
    legitimate OCSP request can reach that size.

    The 413 also proves the ordering (the guard is added last so it runs first): the handler's cap never sees this body.
    """
    response = _post(session_client, b"A" * 50_000)

    assert response.status_code == 413
    assert "text/html" in response.headers["content-type"]
    assert "MYPKI_MAX_CSR_CHARS" in response.text


def test_a_keyless_host_answers_internal_error_rather_than_503_or_html(
    settings: Settings, data_root: Path, throwaway_ca: CaBundle
) -> None:
    """A host that cannot sign answers `INTERNAL_ERROR` at 200 — the protocol's word for "this responder cannot answer".

    `/crl.pem` answers 503 for the same missing state and the difference is deliberate rather than inconsistent: whoever
    fetches a CRL is a human's tool following a URL, and mypki's page with a hint helps it; an OCSP client is a library
    that can only read DER. A 503 carrying HTML would be reported as "responder unreachable", hiding the actual fact (no
    CA private key on this host), which is precisely the diagnosis an operator needs.

    Built by removing the key from a loaded bundle rather than by using no CA at all: `mypki serve` on a host whose key
    cannot be decrypted runs this way, and "no CA" and "CA without a key" are different states (the same distinction
    `test_crl.py` draws for revocation). No CRL directory is created either — the startup rule from §4 still holds.
    """
    keyless = CaBundle(
        cert=throwaway_ca.cert,
        key=None,
        cert_path=throwaway_ca.cert_path,
        key_path=throwaway_ca.key_path,
    )
    app = create_app(settings, ca_bundle=keyless, session_secret="test-session-secret-not-a-real-one")

    with ScratchClient(app, persist_cookies=True) as client:
        response = _post(client, _request(throwaway_ca, int("cafe0014", 16)).public_bytes(Encoding.DER))

        assert response.status_code == 200
        assert response.content == INTERNAL_ERROR_DER
        parsed = load_der_ocsp_response(response.content)
        assert parsed.response_status is OCSPResponseStatus.INTERNAL_ERROR
        # Five bytes means no responderID, no certificate and no signature: the answer claims nothing about this host's
        # (absent) key, which is the point of refusing rather than answering UNKNOWN.
        assert len(response.content) == 5
    assert not paths.crl_path(data_root).exists(), "a keyless host signed a CRL it cannot sign"


def test_a_host_with_no_ca_at_all_answers_internal_error_and_writes_nothing(client_without_ca, data_root: Path) -> None:
    """No CA on the host: still a DER answer, and still no `crl/` directory (the §4 startup rule holds).

    The request's CertID is built from an ephemeral in-memory key (`_foreign_request`) rather than from `throwaway_ca`,
    for two reasons: asking that fixture for hashes would write a real CA into the temporary data dir, and
    `create_app`'s discovery path would then find one — MEASURED this session, which is why "no CA" tests in this file
    do not touch the CA fixtures. The answer's shape is the point: 200 + INTERNAL_ERROR rather than a 500 from a handler
    that assumed a key was present, and no new state under `<data>`.
    """
    response = _post(client_without_ca, _foreign_request(int("cafe0015", 16)).public_bytes(Encoding.DER))

    assert response.status_code == 200
    assert response.content == INTERNAL_ERROR_DER
    assert not paths.crl_dir(data_root).exists()


def test_a_browser_form_post_to_the_route_changes_nothing_and_signs_nothing(session_client, store: IssuedStore) -> None:
    """A form-shaped POST (what a cross-site submit can produce) gets MALFORMED_REQUEST and no side effects.

    This is the assertion that makes §0's CSRF exception defensible rather than a hole: what a forged submit can achieve
    against this route is a DER refusal. No session state is touched, nothing is written, and the handler signs only
    what its own store says about a serial — so there is nothing here for a token to protect. Counted against an empty
    store rather than expressed as "the response looked fine".
    """
    before = store.count()

    response = session_client.post("/ocsp", data={"serial_hex": "cafe0016", "confirm": "1"})

    assert response.status_code == 200
    assert response.content == MALFORMED_DER
    assert store.count() == before == 0


def test_get_on_the_ocsp_route_is_not_an_ocsp_request(session_client) -> None:
    """`GET /ocsp` is 405 — the one answer on this route that is not DER (stated rather than smoothed over).

    RFC 6960 §4.1 makes OCSP a POST, and a GET carries no request body to answer; inventing a DER response for it would
    mean signing a statement about a serial nobody named. FastAPI's own 405 is left in place rather than dressed up as
    mypki's HTML page: the route is documented as POST-only in page-map §15, and a client that GETs it has a bug in its
    recipe rather than a missing feature. Recorded so the deviation from §0's "mypki's own page for every rejection" is
    at least a named and tested one.
    """
    assert session_client.get("/ocsp").status_code == 405


def test_the_route_is_in_no_page_and_no_page_links_to_it(session_client) -> None:
    """`/ocsp` appears in no nav and on no page as a control (page-map §15; U2's seven links stand).

    Asserted because the discoverability decision is a documentation decision: an operator learns the OCSP URL from a
    certificate's AIA extension or from `/crl`'s facts card, not from a menu. The URL may legitimately appear as
    **text** (the advertised pointer on `/crl`); what must not exist is a form action or a link. If a later release adds
    a "check a serial" control to `/crl`, this test changes deliberately rather than by accident.
    """
    for path in ("/", "/issued", "/ca", "/about", "/settings", "/inspect", "/crl", "/version"):
        page = session_client.get(path)

        assert page.status_code == 200, path
        assert 'action="/ocsp"' not in page.text
        assert 'href="/ocsp"' not in page.text


# ------------------------------------------------------------------- documentation agreement (plan step 9)
#
# These make page-map §14/§15 and `/crl` **checked facts** rather than prose someone hopes is still true. Two failure
# modes are worth naming: a template whose caveats were written once and drifted from the code, and a spec file that
# still describes 0.6.0. Both would stay green forever if nothing read the rendered page and the doc itself. The needles
# are the exact sentences plan §7 and §12 step 9 committed to, so rewording one is a deliberate act that fails here
# rather than an edit nobody notices. Matching is whitespace-flattened on purpose: these promises are about words, not
# about where a line happens to wrap.


def _flat(text: str) -> str:
    """Whitespace collapsed to single spaces, so a needle survives a reflow of the file it lives in."""
    return " ".join(text.split())


def test_the_crl_page_states_the_ocsp_limits_in_words(session_client) -> None:
    """`/crl` carries R-OCSP-1, the 413 boundary and the CSRF exception — asserted, not eyeballed (plan §7, §12).

    These are the three claims an operator would otherwise assume in mypki's favour: that a responder checked a
    request's CertID against its own CA, that every OCSP failure arrives as DER, and that every POST in this app is
    CSRF-checked. Each one is a limit of *this* implementation rather than of the protocol, which is why it belongs on
    the page a human reads and not only in a docstring.
    """
    page = _flat(session_client.get("/crl").text)

    # (a) R-OCSP-1, in plan §7's words: echoing is not verification, and the safety comes from the store.
    assert "The request's hashes are echoed, not verified." in page
    assert "a foreign CertID yields UNKNOWN about a serial this host does not hold" in page

    # (b) Both size limits, which one answers first, and what the far one answers with.
    assert "over 8 KiB" in page
    assert "MYPKI_MAX_CSR_CHARS + 8192" in page
    assert "40,192 bytes" in page
    assert "HTTP 413 HTML" in page

    # (c) The CSRF exception, named as an exception rather than presented as a missing check.
    assert "/ocsp</code> has no CSRF token, by design" in page
    assert "Every other POST in this app requires one" in page
