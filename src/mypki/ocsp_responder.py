"""mypki's OCSP responder: answer a DER OCSP request from the record store (page-map §15).

Why this module exists separately from `crl.py`
----------------------------------------------
Both are statements about certificates that already left this host, but they are read differently. A CRL is *fetched*
occasionally and describes the whole revoked set; an OCSP response is *asked for*, per certificate, per client, per
moment. That difference changes what has to be true of the code: it must answer a request it did not plan for, in bytes
a client will accept, without ever refusing at the HTTP layer. Putting it next to `crl.py` would invite sharing a
builder, and the two artifacts share almost nothing beyond the CA key.

The protocol rule that shapes every branch (measured, plan §2)
-------------------------------------------------------------
An OCSP responder reports its own failures **inside** the response, at HTTP 200:
`OCSPResponseBuilder.build_unsuccessful(OCSPResponseStatus.MALFORMED_REQUEST).public_bytes(Encoding.DER)` is a 5-byte
DER body (`30 03 0a 01 01`), and openssl reads it as a protocol-level status rather than an HTTP error. Returning
mypki's usual HTML 4xx for a bad OCSP request would be answered by a client as "the responder is down", not as "your
request was malformed" — so this handler has no 4xx path at all. The route is the one place in this app where an error
is a body rather than a status.

Why every response is built **by hash** (the lookup problem, solved by measurement)
-----------------------------------------------------------------------------------
An OCSP request identifies a certificate by `issuer_name_hash` + `issuer_key_hash` + `serial_number`. mypki's store keys
on `serial_hex` and deliberately keeps **no certificate PEM** (`store.py`, page-map §5), so `add_response(cert=…,
issuer=…)` has no certificate object to hand it. `add_response_by_hash` therefore answers all three statuses, taking
both hashes **verbatim from the parsed request** (GOOD/REVOKED/UNKNOWN all build, and openssl verifies a
by-hash response against its own CertID — `Response verify OK`).

**The consequence, stated rather than glossed (risk R-OCSP-1):** cryptography cannot recompute `issuer_key_hash` for a
SHA-256 request (every candidate form mismatched in the probe), so echoing is not a choice between two good options —
it is the only workable one. The practical meaning is that this responder cannot prove a request's CertID describes
*this* CA; only the SHA-1 case could be checked, via the CA's SubjectKeyIdentifier. What it *can* prove is the answer:
the response is bound to `serial_number` and drawn from mypki's own store, so a CertID that does not belong here yields
GOOD/REVOKED/UNKNOWN **about a serial this host knows nothing about** — UNKNOWN — never a statement about someone else's
certificate. page-map §15 states it in those words.

Why `UNKNOWN` and not `GOOD` for a revoked-and-expired serial (U5)
------------------------------------------------------------------
§4's entry rule drops an expired revoked certificate from the CRL, but the row stays in `issued.db` forever. Answering
GOOD would then be one host telling two stories: "not in my CRL" plus "still fine". UNKNOWN is the answer that agrees
with both facts — this responder genuinely does not know the certificate's current standing at a client that never
consulted the CRL, and it is the same answer given for a serial this CA never signed.

Why `ReasonFlags.unspecified` always (U6)
-----------------------------------------
`revocation_reason` in the store is operator prose bounded at 120 characters (`store.py`), not an RFC 5280 §5.3.1 reason
code. Mapping prose to `keyCompromise` would be inventing a claim about a certificate this CA only has a note about.
An absent/`unspecified` code is what RFC 5280 defines as "the CA did not say", which is exactly true here — and it
matches the CRL side, where no reason entry extension is added at all (`crl.py`).

Why the responder **is** the root CA (U3)
-----------------------------------------
No delegated responder certificate is issued and no CA re-issue is needed: the root already carries `crl_sign=True`
(`ca.py`). openssl verified a response signed by a root that carries **no `id-kp-OCSPSigning` EKU**.
Whether a browser or a Go client requires that EKU is **not measured**, and this module does not pretend otherwise — the
caveat is written on `/crl`, in page-map §15 and in docs/REFERENCE.md. A delegated responder would mean issuing,
storing and
rotating a second key for a home-lab CA; that cost was accepted as larger than the unmeasured risk.

What this module does **not** do: it does not read any key file (`app.py` hands in an already-loaded `CaBundle`, loaded
once at startup), it does not cache (see `OcspAnswer`'s note in `answer_for`), and it does not decide when to build a
CRL — an OCSP answer and a CRL entry are two renderings of one decision, made in `store.revoke()`.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPRequest,
    OCSPResponderEncoding,
    OCSPResponseBuilder,
    OCSPResponseStatus,
    load_der_ocsp_request,
)

from .ca import CaBundle
from .store import IssuedRecord

log = logging.getLogger("mypki.ocsp")

#: `nextUpdate` on a singleResponse: thisUpdate + this. 4 hours (U8: a constant, not a knob — no §11 row, no preset,
#: no empty-value rule for a value whose only sensible range is "often"). Shorter than the CRL's 24 h on purpose: an
#: OCSP answer is cheap to mint and a client that caches one should re-ask within a working day, while a CRL is a
#: signed artifact this host writes deliberately.
OCSP_LIFETIME = dt.timedelta(hours=4)

#: Handler-side cap on a request body (plan §7 step 1, measured in plan §2/P-OCSP-3). Real OCSP requests are 73-101 B;
#: this exists for malformed abuse, not traffic. It must sit **below** `SizeGuardMiddleware`'s limit
#: (`max_csr_chars + 8192` = 40,192 with the default knob), because a body above *that* one is answered by mypki's HTML
#: 413 page — correct for a form submission, wrong for a protocol endpoint. A client that gets HTML where it expected
#: DER cannot tell a size limit from a broken responder. The guard itself is left unmodified and `/ocsp` is not
#: exempted: both limits are real, and the smaller one answers first.
OCSP_MAX_REQUEST_BYTES = 8192

#: Media types from RFC 6960 §4.1 / IANA registrations. Only the response half appears in this module (mypki never
#: *sends* a request), but naming both keeps the pair legible to whoever writes a client recipe next.
OCSP_REQUEST_MEDIA_TYPE = "application/ocsp-request"
OCSP_RESPONSE_MEDIA_TYPE = "application/ocsp-response"

__all__ = [
    "OCSP_LIFETIME",
    "OCSP_MAX_REQUEST_BYTES",
    "OCSP_REQUEST_MEDIA_TYPE",
    "OCSP_RESPONSE_MEDIA_TYPE",
    "answer_for",
    "malformed_response_der",
    "parse_ocsp_request",
    "render_ocsp_response",
    "serial_hex_of",
]


@dataclass(frozen=True)
class OcspAnswer:
    """What this responder decided, before any signing (page-map §15).

    Carried separately from the DER for two reasons. `test_ocsp.py` asserts the *decision* (GOOD / REVOKED / UNKNOWN,
    and a preserved revocation stamp) without parsing bytes, which is where a wrong rule would hide; and `/crl` can
    state what this host would answer for a serial without minting a signature to do it. The signed artifact is the
    answer's rendering, never the answer itself.
    """

    serial_hex: str
    status: OCSPCertStatus
    record: IssuedRecord | None
    reason: str

    @property
    def status_name(self) -> str:
        """`GOOD` / `REVOKED` / `UNKNOWN` — the spelling a log line and the page both use."""
        return self.status.name


def parse_ocsp_request(body: bytes) -> OCSPRequest | None:
    """Parse a DER OCSP request, or answer None for anything that is not one.

    Returns None rather than raising because the caller's answer is a *protocol* status, not an exception: at this
    endpoint every failure is a 200 with `MALFORMED_REQUEST` inside the body (see the module docstring). A raised
    `MypkiError` would land on mypki's error handler and render HTML — precisely the artifact a client cannot read.

    Any exception from `load_der_ocsp_request` is folded into None deliberately. cryptography raises
    `ValueError`/`TypeError`/`OSError` shapes depending on whether the body is truncated, mis-tagged or empty, and the
    responder's answer is the same for all of them. Logging the type keeps the distinction available to an operator
    reading the log without making it part of the protocol.
    """
    try:
        return load_der_ocsp_request(body)
    except Exception as exc:  # broad on purpose: every parse failure is the same protocol answer
        log.info("OCSP request could not be parsed (%s: %s)", type(exc).__name__, exc)
        return None


def malformed_response_der(status: OCSPResponseStatus = OCSPResponseStatus.MALFORMED_REQUEST) -> bytes:
    """A protocol-level refusal, as DER, at HTTP 200.

    `OCSPResponseBuilder.build_unsuccessful(...)` is a **classmethod on the builder** — there is no module-level
    `build_unsuccessful` to import (importing it raises `ImportError`). The body is 5 bytes (`30 03 0a 01 01` for
    MALFORMED_REQUEST) and re-parses as `response_status=MALFORMED_REQUEST`, which is what the harness byte markers
    assert without a DER parser.

    No signature, no certificate, no response data: an unsigned refusal is what RFC 6960 §4.2.1 describes, and signing
    a refusal would put this CA's key behind a request that carries nothing to sign about.
    """
    return OCSPResponseBuilder.build_unsuccessful(status).public_bytes(serialization.Encoding.DER)


def serial_hex_of(request: OCSPRequest) -> str:
    """The store's spelling of the serial this request asks about.

    Public because `app.py` needs it **before** it can look a record up, and the lookup is what decides the status:
    `IssuedStore.find()` keys on `serial_hex`, while an OCSP request carries an integer. Doing the conversion in this
    module (rather than inline in the handler) keeps one spelling of "how mypki writes a serial" next to
    `signing.py`'s `f"{cert.serial_number:x}"`, which is the form every row was written with.

    Raises `ValueError` for a negative integer. Nothing in this protocol can produce one — cryptography refuses to
    *build* such a request, and a DER INTEGER with the sign bit set reads back as a positive 159-bit value — but a
    hostile body must not turn into a database key like `-5`, and the handler turns this ValueError into the same
    MALFORMED_REQUEST answer it gives for unparseable bytes.
    """
    if request.serial_number < 0:
        raise ValueError("OCSP request carries a negative serial number, which no certificate can have.")
    return f"{request.serial_number:x}"


def decide_status(request: OCSPRequest, record: IssuedRecord | None) -> OcspAnswer:
    """The one place this responder decides what a serial means (U5's rule lives here and nowhere else).

    Four branches, each stated because they are the four answers a client can observe:

    * **no record** → UNKNOWN. This host never signed that serial. Saying GOOD would assert something about a
      certificate this CA knows nothing about; saying REVOKED would invent a decision nobody made.
    * **stamped and not expired** → REVOKED, carrying `revoked_at_utc` **as stamped** (never "now"), for the same
      reason `crl.py` preserves it: a client comparing an OCSP answer to a CRL entry must see one time, not two.
    * **stamped and expired** → UNKNOWN, not GOOD. The serial is absent from the CRL (§4's entry rule) while the row
      remains in `issued.db`; GOOD would be this host disagreeing with its own artifact.
    * **active and not expired** → GOOD. The one status that is a positive claim, and it is a claim about this store
      only: "I signed this and I have not stamped it."

    A record whose serial does not match the request cannot reach here: `app.py` looks the record up *from* the
    request's serial number. Asserted in `test_ocsp.py` rather than assumed.
    """
    serial_hex = serial_hex_of(request)

    if record is None:
        return OcspAnswer(
            serial_hex=serial_hex,
            status=OCSPCertStatus.UNKNOWN,
            record=None,
            reason="no record with this serial exists on this host",
        )

    if record.revoked_at_utc is not None:
        if record.is_expired:
            return OcspAnswer(
                serial_hex=serial_hex,
                status=OCSPCertStatus.UNKNOWN,
                record=record,
                reason="revoked, but past its own notAfter, so it is no longer listed in the CRL",
            )
        return OcspAnswer(
            serial_hex=serial_hex,
            status=OCSPCertStatus.REVOKED,
            record=record,
            reason="stamped revoked on /issued",
        )

    if record.is_expired:
        # Never revoked, and past its validity. GOOD is still the honest answer: this CA did not revoke it, and
        # OCSP reports revocation standing rather than "would a validator accept it today". Stated in the reason so
        # the log line explains why an expired certificate answers GOOD while an expired *revoked* one answers UNKNOWN.
        return OcspAnswer(
            serial_hex=serial_hex,
            status=OCSPCertStatus.GOOD,
            record=record,
            reason="never revoked; past its own notAfter, which OCSP does not report",
        )

    return OcspAnswer(
        serial_hex=serial_hex,
        status=OCSPCertStatus.GOOD,
        record=record,
        reason="active in this host's issued list",
    )


def answer_for(request: OCSPRequest, record: IssuedRecord | None) -> OcspAnswer:
    """`decide_status` under its public name, so `app.py` reads as a question rather than a branch table."""
    return decide_status(request, record)


def render_ocsp_response(
    request: OCSPRequest,
    answer: OcspAnswer,
    bundle: CaBundle,
    *,
    now_utc: dt.datetime | None = None,
) -> bytes:
    """Sign the decision and return DER.

    `now_utc` is a parameter so a test can pin `thisUpdate`/`nextUpdate` and assert the 4 h interval exactly rather
    than "roughly four hours"; production callers pass nothing.

    **No cache, deliberately.** Plan §7 floated caching signed answers per (serial, status) until `nextUpdate` to blunt
    the fact that this is a signing oracle reachable over HTTP. It is not implemented here for two honest reasons:
    a cache keyed on a *request-supplied* CertID hash pair stores signatures produced for hashes this responder did
    not verify (R-OCSP-1 makes that worse, not better), and the store lookup plus an RSA-3072 signature is milliseconds
    on a home-lab CA whose OCSP traffic is a handful of clients. The exposure is stated in page-map §15 and §12 instead
    of being half-mitigated by a cache nobody measured.

    `algorithm=` must be an **instance** (`hashes.SHA256()`, not the class) — passing the class raises
    `ValueError: Algorithm must be SHA1, SHA224, SHA256, SHA384, or SHA512`. The same applies to
    `add_response_by_hash`'s `algorithm`, which receives the **request's own** hash algorithm object so a SHA-1 client
    gets a SHA-1 CertID echoed back rather than a silently upgraded one.
    """
    if bundle.key is None:
        # Not reachable through `/ocsp`: `app.py` answers 503 for a keyless host before this runs, exactly as it does
        # for the CRL triggers. Kept as a refusal because this function takes a `CaBundle` and a caller that handed in
        # a keyless one should be told rather than produce an unsigned or half-signed body.
        raise ValueError("This CA has no private key loaded, so it cannot sign an OCSP response.")

    now = _aware_utc(now_utc or dt.datetime.now(dt.timezone.utc))
    revoked = answer.status is OCSPCertStatus.REVOKED
    record = answer.record

    # The stamp is resolved into a local rather than inline in the call: `IssuedRecord.revoked_at_utc` is
    # `datetime | None`, and only the REVOKED branch has one. A ternary testing `revoked and record` does not tell
    # a type checker that the value handed to `_aware_utc` is non-None, so the narrowing happens here, once.
    revocation_time = None
    if revoked and record is not None and record.revoked_at_utc is not None:
        revocation_time = _aware_utc(record.revoked_at_utc)

    builder = OCSPResponseBuilder().add_response_by_hash(
        # Both hashes echoed verbatim out of the parsed request — the only workable form (R-OCSP-1, module docstring).
        request.issuer_name_hash,
        request.issuer_key_hash,
        request.serial_number,
        # The instance the client actually asked with (`request.hash_algorithm`), so the CertID round-trips.
        request.hash_algorithm,
        answer.status,
        this_update=now,
        next_update=now + OCSP_LIFETIME,
        # Preserving the stamp (U5/S4): `revocation_time_utc` is the non-deprecated spelling, and a client that reads
        # both an OCSP answer and a CRL entry must be shown the same instant.
        revocation_time=revocation_time,
        # U6: always `unspecified`, because the store's reason is prose and this CA has no code for it.
        revocation_reason=(x509.ReasonFlags.unspecified if revoked else None),
    )

    builder = builder.responder_id(OCSPResponderEncoding.NAME, bundle.cert).certificates([bundle.cert])

    nonce = _request_nonce(request)
    if nonce is not None:
        # A client that sent a nonce and got no echo prints `WARNING: no nonce in response`. The value is
        # copied verbatim; mypki never invents one, because a response nonce only has meaning against a request nonce.
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)

    response = builder.sign(bundle.key, hashes.SHA256())
    log.info(
        "OCSP answer for serial=%s status=%s (%s) this_update=%s next_update=%s",
        answer.serial_hex,
        answer.status_name,
        answer.reason,
        now.isoformat(),
        (now + OCSP_LIFETIME).isoformat(),
    )
    return response.public_bytes(serialization.Encoding.DER)


def _request_nonce(request: OCSPRequest) -> bytes | None:
    """The request's nonce bytes, or None when the client did not send one.

    `ExtensionOID` has no OCSPNonce member (only `OCSP_NO_CHECK` exists there), so the lookup goes through
    `get_extension_for_class(x509.OCSPNonce)` and its `.nonce` payload. Returning None rather than raising is what
    lets a nonce-less client get a clean response with no extensions at all instead of an empty echo.
    """
    try:
        extension = request.extensions.get_extension_for_class(x509.OCSPNonce)
    except x509.ExtensionNotFound:
        return None
    value = getattr(extension.value, "nonce", None)
    return value if isinstance(value, bytes) else None


def _aware_utc(value: dt.datetime) -> dt.datetime:
    """Naive in, UTC-aware out — the identical rule `crl.py` and `store.py` apply.

    Three modules now spell one conversion the same way on purpose: an OCSP `thisUpdate` that means local time on one
    host and UTC on another makes two clients disagree about whether a certificate is revoked *today*.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
