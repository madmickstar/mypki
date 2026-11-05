"""Step A of the sign page: every way a pasted request can be wrong, and the reason it gets for each.

page-map §3 fixes both the rules **and their order** (PEM → DER → signature → hash → key policy → CA privileges → SANs),
and the order is what makes the messages usable: a tampered *and* CA-privileged request has to be reported as the
signature failure, because "your signature is broken" is the thing the operator must fix before anything else is even
knowable. These tests assert that ordering rather than only the individual rejections.

Every negative case mutates **one** thing (STYLE §8): one byte of the DER, one added extension, one key size, one extra
PEM block. Nothing here hard-codes a version or a fixture file -- CSRs are generated per test so no test fails because a
committed key aged out.

Library facts pinned from the pinned build (cryptography 50.0.2), because they are what the code depends on:
`is_signature_valid` is a property, `signature_hash_algorithm` is `None` for algorithms cryptography does not model as a
hash, and cryptography itself refuses to sign or verify SHA-1 -- which is why a real SHA-1 request has to be built by
hand here (see `_sha1_signed_csr_pem`).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID

from mypki.csr import (
    ALLOWED_SIGNATURE_HASHES,
    CSR_PEM_BEGIN,
    CSR_PEM_END,
    CsrDetails,
    extract_single_csr_pem,
    parse_and_validate_csr,
)
from mypki.errors import CaPrivilegeRequestedError, CsrValidationError, KeyPolicyError, RequestTooLargeError

MAX_CHARS = 32000


@pytest.fixture(scope="module")
def leaf_key() -> rsa.RSAPrivateKey:
    """One RSA-2048 key for the whole module.

    Module-scoped because these tests are about *validation*, not key generation: a hundred 2048-bit keypairs would make
    this file the slowest in the suite without asserting anything extra. It is a throwaway key, never written to disk.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _csr_pem(
    key: rsa.RSAPrivateKey,
    *,
    common_name: str = "server.internal",
    sans: tuple[str, ...] = ("server.internal",),
    extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    hash_algorithm: hashes.HashAlgorithm | None = None,
) -> str:
    """A PEM CSR built exactly as an outside tool would build one.

    `sans=()` omits the SAN extension entirely rather than adding an empty one -- a client certificate with no SAN is
    legal, and "no SAN" and "an empty SAN extension" are different things to a validator.
    """
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if sans:
        names: list[x509.GeneralName] = [
            x509.IPAddress(ipaddress.ip_address(value)) if _looks_like_ip(value) else x509.DNSName(value)
            for value in sans
        ]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    signed = builder.sign(key, hash_algorithm or hashes.SHA256())
    return signed.public_bytes(Encoding.PEM).decode("ascii")


def _usage(**flags: bool) -> x509.KeyUsage:
    """A `KeyUsage` with the named bits set and every other bit clear.

    `encipher_only` / `decipher_only` stay False: they are modifiers of `key_agreement` rather than independent usages,
    and a request that sets them without `keyAgreement` is a different question from the one these tests ask.
    """
    return x509.KeyUsage(
        digital_signature=flags.get("digitalSignature", False),
        content_commitment=flags.get("contentCommitment", False),
        key_encipherment=flags.get("keyEncipherment", False),
        data_encipherment=flags.get("dataEncipherment", False),
        key_agreement=flags.get("keyAgreement", False),
        key_cert_sign=flags.get("keyCertSign", False),
        crl_sign=flags.get("crlSign", False),
        encipher_only=False,
        decipher_only=False,
    )


#: `KeyUsage`'s seven booleans, in `cryptography`'s constructor order. Used by the tests that assert every one of them
#: is named in a refusal, so "all seven" is data here rather than a count a docstring claims.
_USAGE_BITS = (
    "digitalSignature",
    "contentCommitment",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "crlSign",
)


def _der_of(pem: str) -> bytes:
    """The DER inside a PEM armour, so "the same request" can be compared as bytes rather than as text.

    Comparing PEM strings is not enough to prove byte identity: two armours of one DER can differ in line width or
    trailing newline while describing the same signed document, and comparing only the parsed objects cannot see a
    re-encoding at all (a rebuilt request parses identically). The DER is what the signature covers, so that is what
    these assertions compare.
    """
    match = re.search(rf"{CSR_PEM_BEGIN}\s*(.*?)\s*{CSR_PEM_END}", pem, re.DOTALL)
    if match is None:
        raise AssertionError("_der_of needs a PEM-armoured request")
    return base64.b64decode("".join(match.group(1).split()))


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _armour(der: bytes, kind: str = "CERTIFICATE REQUEST") -> str:
    """Wrap DER in PEM armour the way `base64.encodebytes` does it: 76-character lines."""
    body = "\n".join(base64.encodebytes(der).decode("ascii").split())
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n"


def _certification_request_info(der: bytes) -> bytes:
    """The exact DER of the `certificationRequestInfo` element -- the bytes a CSR signature covers.

    Exported as a helper because two tests here (SHA-1 and cross-key signing) must re-sign precisely those bytes, and
    getting one length byte wrong produces a request that fails to parse rather than one that fails to verify.
    """
    inner_start = 1 + (1 if der[1] < 0x80 else 1 + (der[1] & 0x7F))
    return _tlv(der, inner_start)


def _algorithm_identifier(der: bytes) -> bytes:
    """The outer `signatureAlgorithm` AlgorithmIdentifier of a DER request."""
    info = _certification_request_info(der)
    inner_start = 1 + (1 if der[1] < 0x80 else 1 + (der[1] & 0x7F))
    return _tlv(der, inner_start + len(info))


def _tlv(data: bytes, offset: int) -> bytes:
    """One complete DER TLV starting at `offset`."""
    first = data[offset + 1]
    if first < 0x80:
        length, extra = first, 0
    else:
        count = first & 0x7F
        length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
        extra = count
    return data[offset : offset + 2 + extra + length]


def _der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tamper(pem: str, offset_from_end: int = -32) -> str:
    """Flip one bit in a valid CSR's DER and re-armour it.

    One mutation, chosen inside the signature region so the request still parses as a CSR (a parse failure would prove
    the parse check rather than the signature check). Which byte is safe was measured on this build: cryptography
    accepts
    the mutated DER and `is_signature_valid` reports False.
    """
    der = bytearray(x509.load_pem_x509_csr(pem.encode("ascii")).public_bytes(Encoding.DER))
    der[offset_from_end] ^= 0x01
    return _armour(bytes(der))


def _sha1_signed_csr_pem(key: rsa.RSAPrivateKey) -> tuple[str, x509.CertificateSigningRequest]:
    """A genuinely SHA-1-signed CSR, assembled by hand.

    Needed because cryptography 50 refuses `hashes.SHA1()` for *newly signed* certificates and CSRs (MEASURED:
    `UnsupportedAlgorithm: Hash algorithm "sha1" not supported for signatures`), so the only way to feed mypki a real
    SHA-1 request -- rather than a claim about one -- is to re-sign an existing request's `certificationRequestInfo` and
    swap in the `sha1WithRSAEncryption` AlgorithmIdentifier. That is exactly what an old openssl-generated request looks
    like, which is the state this rule exists for.

    Returns the PEM **and** the parsed object so a test can assert the fixture really carries SHA-1 rather than trusting
    this helper's word for it.
    """
    original = _csr_pem(key)
    der = x509.load_pem_x509_csr(original.encode("ascii")).public_bytes(Encoding.DER)

    info = _certification_request_info(der)
    sha1_algorithm_identifier = bytes.fromhex("300d06092a864886f70d0101050500")  # sha1WithRSAEncryption + NULL
    signature = key.sign(hashlib.sha1(info).digest(), padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))
    body = info + sha1_algorithm_identifier + b"\x03" + _der_length(len(signature) + 1) + b"\x00" + signature
    sha1_der = b"\x30" + _der_length(len(body)) + body

    return _armour(sha1_der), x509.load_der_x509_csr(sha1_der)


# ------------------------------------------------------------------------------------------------ happy path


def test_a_valid_csr_is_accepted_and_described(sample_csr_pem: str) -> None:
    """The baseline everything else is a mutation of.

    `CsrDetails` is what the confirmation panel renders, so its fields are asserted against the request itself rather
    than against expected strings: subject attributes, both SAN lists, the key label, the signature hash. A page that
    described a request wrongly would be signed from that wrong description (page-map §3 step B re-parses these bytes).
    """
    details = parse_and_validate_csr(sample_csr_pem, MAX_CHARS)

    assert isinstance(details, CsrDetails)
    assert details.subject["common_name"] == "server.internal"
    assert details.subject["organization"] == "mypki tests"
    assert details.subject["country"] == "XX"
    assert details.sans.dns == ("server.internal", "*.lab.internal")
    assert details.sans.ips == ("10.0.0.7",)
    assert details.key_label == "RSA 2048"
    assert details.signature_hash == "SHA256"
    assert details.pem.startswith(CSR_PEM_BEGIN) and details.pem.endswith(f"{CSR_PEM_END}\n")


def test_clipboard_spellings_of_one_request_canonicalise_to_the_same_pem(sample_csr_pem: str) -> None:
    """CRLF endings and trailing spaces are the same request, byte for byte after re-armouring.

    These are the two things an operator's clipboard or a Windows browser actually do to a pasted PEM. `_rearmour`
    strips
    each line and rebuilds the armour, so both spellings come back identical to the original -- which is what makes "the
    bytes I validated" literally the bytes step B signs (page-map §3 step B re-reads `details.pem`, it does not trust a
    textarea round-trip).
    """
    spellings = [sample_csr_pem, sample_csr_pem.replace("\n", "\r\n"), sample_csr_pem.replace("\n", "  \n")]

    canonical = {parse_and_validate_csr(text, MAX_CHARS).pem for text in spellings}
    assert len(canonical) == 1, canonical
    assert next(iter(canonical)) == sample_csr_pem


def test_a_request_rewrapped_at_another_line_width_is_the_same_request(sample_csr_pem: str) -> None:
    """Line width is presentation; the request is its decoded content.

    `_rearmour` preserves the paste's own wrapping rather than re-wrapping to a house width, so a 40-column paste comes
    back with 40-column armour. What has to be invariant -- and what step B actually depends on -- is that the *decoded*
    bytes are the same request, and that feeding the canonical PEM back through validation yields exactly itself.
    Without that idempotence, step B's re-parse could describe a different request than step A displayed.
    """
    reparsed = parse_and_validate_csr(_rearmour_at_width(sample_csr_pem, 40), MAX_CHARS)

    original_der = x509.load_pem_x509_csr(sample_csr_pem.encode("ascii")).public_bytes(Encoding.DER)
    rewrapped_der = x509.load_pem_x509_csr(reparsed.pem.encode("ascii")).public_bytes(Encoding.DER)
    assert rewrapped_der == original_der

    again = parse_and_validate_csr(reparsed.pem, MAX_CHARS)
    assert again.pem == reparsed.pem
    assert (again.sans.dns, again.sans.ips) == (reparsed.sans.dns, reparsed.sans.ips)


def _rearmour_at_width(pem: str, width: int) -> str:
    """Re-wrap a PEM body at a different line width."""
    lines = pem.strip().splitlines()
    body = "".join(line for line in lines[1:-1])
    wrapped = "\n".join(body[index : index + width] for index in range(0, len(body), width))
    return f"{lines[0]}\n{wrapped}\n{lines[-1]}\n"


def test_a_multiline_pem_body_is_decoded_at_all(sample_csr_pem: str) -> None:
    """The regression that made every real CSR unusable, pinned (see `csr.py`'s comment).

    `base64.b64decode(..., validate=True)` refuses the newlines that PEM armour is *defined* by, so decoding the armour
    as-is rejected every generated request with "Only base64 data is allowed" while every single-line test stayed green.
    Whitespace is stripped **and** `validate=True` is kept: dropping either half breaks a different thing -- stripping
    without validating accepts arbitrary junk characters and reports them as DER parse errors.
    """
    details = parse_and_validate_csr(sample_csr_pem, MAX_CHARS)  # accepted at all is the assertion
    assert details.key_label == "RSA 2048"

    body_lines = [line for line in sample_csr_pem.splitlines() if not line.startswith("-----")]
    assert len(body_lines) > 1, "the fixture must be a genuinely line-wrapped PEM to prove this"


def test_a_body_of_junk_characters_is_still_refused_as_bad_base64(sample_csr_pem: str) -> None:
    """The other half of the previous test's mutation: `validate=True` is still doing its job.

    One line of the armour gets four non-base64 characters. The refusal must name base64 (a truncation-in-transit
    diagnosis), not the DER parse error an unvalidated decode would produce.
    """
    lines = sample_csr_pem.splitlines()
    damaged = "\n".join([lines[0], lines[1][:20] + "!!!!", *lines[2:]])

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(damaged, MAX_CHARS)
    assert "base64" in str(excinfo.value)


# --------------------------------------------------------------------------------------------- size limit (§3)


def test_an_oversized_paste_is_refused_naming_mypkis_own_knob(sample_csr_pem: str) -> None:
    """`MYPKI_MAX_CSR_CHARS`, not starlette's `1024KB`.

    Asserted on the message rather than only on the exception type: page-map §0 promises the operator sees mypki's own
    limit, and a number they cannot find in `.env` sends them looking for a framework setting that is not the knob to
    change. `RequestTooLargeError` carries `actual`/`limit` so the page can print both.
    """
    oversized = sample_csr_pem + "x" * (MAX_CHARS + 9000)

    with pytest.raises(RequestTooLargeError) as excinfo:
        parse_and_validate_csr(oversized, MAX_CHARS)

    assert "MYPKI_MAX_CSR_CHARS" in str(excinfo.value)
    assert excinfo.value.limit == MAX_CHARS
    assert excinfo.value.actual > MAX_CHARS


def test_the_size_check_runs_before_any_parsing(sample_csr_pem: str) -> None:
    """One mutation: the oversized text is also garbage.

    If parsing ran first the answer would be "no PEM block found", which sends the operator off to fix their paste
    formatting while the real problem is that the body is over the cap. Order is behaviour here, not style.
    """
    with pytest.raises(RequestTooLargeError):
        parse_and_validate_csr("complete nonsense" + "y" * (MAX_CHARS + 9000), MAX_CHARS)


def test_a_paste_exactly_at_the_limit_is_accepted(sample_csr_pem: str) -> None:
    """The boundary is inclusive.

    A limit that also rejects the largest legitimate input is a bug nobody notices until someone's 4096-bit CSR with a
    long SAN list stops working. Built by padding a valid request with trailing whitespace up to exactly the cap, which
    keeps the PEM itself valid.
    """
    exact = sample_csr_pem.rstrip("\n") + "\n"
    exact = exact + " " * (MAX_CHARS - len(exact))
    assert len(exact) == MAX_CHARS

    details = parse_and_validate_csr(exact, MAX_CHARS)
    assert details.subject["common_name"] == "server.internal"


# -------------------------------------------------------------------------------------- PEM extraction (§3 rule 1)


@pytest.mark.parametrize(
    ("paste", "marker"),
    [
        ("", "No PEM block found"),
        ("not a pem at all", "No PEM block found"),
        ("-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n", "No PEM block found"),
    ],
)
def test_a_paste_with_no_complete_block_names_the_armour_it_wants(paste: str, marker: str) -> None:
    """The message contains both armour lines, so the fix is obvious without reading a spec."""
    with pytest.raises(CsrValidationError) as excinfo:
        extract_single_csr_pem(paste, MAX_CHARS)
    assert marker in str(excinfo.value)
    assert CSR_PEM_BEGIN in str(excinfo.value)


def test_two_requests_in_one_paste_are_refused_rather_than_guessing(leaf_key: rsa.RSAPrivateKey) -> None:
    """Signing "the first one" would silently ignore the rest of what was pasted.

    A paste containing two requests is usually an operator who concatenated a leaf and a request, or pasted twice;
    picking either answer silently discards something they submitted (page-map §3).
    """
    paste = _csr_pem(leaf_key) + _csr_pem(leaf_key, common_name="other.internal")

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(paste, MAX_CHARS)
    assert "2 certificate requests" in str(excinfo.value)


@pytest.mark.parametrize(
    ("kind", "marker"),
    [("CERTIFICATE", "CERTIFICATE"), ("PRIVATE KEY", "PRIVATE KEY"), ("ENCRYPTED PRIVATE KEY", "ENCRYPTED")],
)
def test_a_paste_of_the_wrong_artifact_says_what_it_found(leaf_key: rsa.RSAPrivateKey, kind: str, marker: str) -> None:
    """Three artifacts an operator genuinely confuses, each named in its own refusal.

    "Invalid CSR" would be true and useless: a pasted certificate needs to be re-requested, a pasted private key means
    the operator has the wrong file entirely, and mypki does neither of those things (README "Naming").
    """
    if kind == "CERTIFICATE":
        now = dt.datetime.now(dt.timezone.utc)
        body = (
            (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-a-request")]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-a-request")]))
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + dt.timedelta(days=1))
                .sign(leaf_key, hashes.SHA256())
            )
            .public_bytes(Encoding.PEM)
            .decode("ascii")
        )
    else:
        encryption: NoEncryption | BestAvailableEncryption = (
            NoEncryption() if kind == "PRIVATE KEY" else BestAvailableEncryption(b"a-passphrase-not-a-real-one")
        )
        body = leaf_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption).decode("ascii")

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(body, MAX_CHARS)
    assert marker in str(excinfo.value)
    assert "not a certificate signing request" in str(excinfo.value)


def test_valid_base64_that_is_not_a_der_request_is_named_as_such(leaf_key: rsa.RSAPrivateKey) -> None:
    """The base64 is fine; the bytes inside it are not a CSR.

    A distinct diagnosis from "the base64 is broken" (tested above), because these two failures have different fixes:
    one is a truncated paste, the other is the wrong file with correct-looking armour.
    """
    paste = _armour(b"definitely not DER for a certificate request")

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(paste, MAX_CHARS)
    assert "not a DER certificate request" in str(excinfo.value)


# ------------------------------------------------------------------------------------------- signature (§3 rule 3)


def test_a_tampered_signature_is_refused_with_the_reason_an_operator_can_act_on(leaf_key: rsa.RSAPrivateKey) -> None:
    """One bit flipped in the signature region.

    The message names three possible causes (tampering, truncation in transit, a request generated with a different key)
    because all three look identical from here, and each has a different fix. page-map §0's "never 'invalid CSR'"
    rule is
    what this test exists to keep true.
    """
    tampered = _tamper(_csr_pem(leaf_key))

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(tampered, MAX_CHARS)
    assert "signature does not verify" in str(excinfo.value)


def test_a_request_signed_by_a_different_key_than_it_carries_is_refused(leaf_key: rsa.RSAPrivateKey) -> None:
    """Proof of possession, built the way it actually goes wrong.

    Assembled by hand: this request's own public key and subject, signed by a **different** private key. That is exactly
    the artifact a copy-paste between two machines produces -- a request that looks entirely well formed, parses,
    reports
    a plausible key, and whose signature belongs to nothing in it. Only `is_signature_valid` catches it; every
    other rule
    in §3 would happily accept it.
    """
    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    own_der = x509.load_pem_x509_csr(_csr_pem(leaf_key).encode("ascii")).public_bytes(Encoding.DER)
    foreign_der = x509.load_pem_x509_csr(_csr_pem(foreign_key).encode("ascii")).public_bytes(Encoding.DER)

    info = _certification_request_info(own_der)
    algorithm_identifier = _algorithm_identifier(foreign_der)
    signature = foreign_key.sign(hashlib.sha256(info).digest(), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    body = info + algorithm_identifier + b"\x03" + _der_length(len(signature) + 1) + b"\x00" + signature
    mismatched = _armour(b"\x30" + _der_length(len(body)) + body)

    parsed = x509.load_pem_x509_csr(mismatched.encode("ascii"))
    assert parsed.is_signature_valid is False  # the fixture really is the mismatch we mean to test

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(mismatched, MAX_CHARS)
    assert "signature does not verify" in str(excinfo.value)


def test_the_signature_check_is_the_first_thing_a_doubly_broken_request_gets(leaf_key: rsa.RSAPrivateKey) -> None:
    """page-map §3's order is load-bearing, and this is the case that proves it.

    One request that is **both** tampered and CA-privileged. Reporting `BasicConstraints CA:TRUE` would be
    accurate about
    one problem while hiding the one the operator must fix first -- and it would prove the pipeline inspected extensions
    on bytes it had not yet proved were genuine.
    """
    ca_like = _csr_pem(leaf_key, extensions=[(x509.BasicConstraints(ca=True, path_length=None), True)])
    doubly_broken = _tamper(ca_like)

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(doubly_broken, MAX_CHARS)
    assert "signature does not verify" in str(excinfo.value)
    assert not isinstance(excinfo.value, CaPrivilegeRequestedError)


# ------------------------------------------------------------------------------------------------ hash (§3 rule 4)


def test_the_accepted_signature_hashes_are_exactly_sha256_384_and_512() -> None:
    """The allow-list as data (page-map §3 rule 4).

    Asserted as a set rather than through three happy paths and two refusals, because the *exclusion* is the security
    claim: SHA-1 and MD5 have practical collision attacks against certificate signatures, so accepting either means this
    CA vouches for a request whose proof-of-possession someone else could forge.
    """
    assert frozenset({"sha256", "sha384", "sha512"}) == ALLOWED_SIGNATURE_HASHES
    assert "sha1" not in ALLOWED_SIGNATURE_HASHES
    assert "md5" not in ALLOWED_SIGNATURE_HASHES


def test_a_sha1_signed_request_is_refused(leaf_key: rsa.RSAPrivateKey) -> None:
    """A real SHA-1-signed CSR, not a claim about one.

    Built by hand (see `_sha1_signed_csr_pem`) because the pinned cryptography refuses to sign SHA-1 at all. Two facts
    are asserted separately so the test cannot pass on luck: the fixture really is SHA-1 (`signature_hash_algorithm`),
    and mypki refuses it. Which of §3's rules fires first depends on the library -- cryptography declines to *verify*
    SHA-1 either, so `is_signature_valid` is already False and rule 3 answers before rule 4. Either way the request is
    refused as a `CsrValidationError`, which is the behaviour this project promises.
    """
    pem, parsed = _sha1_signed_csr_pem(leaf_key)

    assert parsed.signature_hash_algorithm is not None
    assert parsed.signature_hash_algorithm.name == "sha1"

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    reason = str(excinfo.value)
    assert "SHA-1" in reason or "signature does not verify" in reason


def test_a_request_whose_hash_cryptography_does_not_model_is_refused_as_unknown() -> None:
    """Ed25519: a valid signature, `signature_hash_algorithm is None`, and no place in mypki's policy.

    Not because Ed25519 is broken -- it is not -- but because mypki's key policy (page-map §3 rule 5) issues for RSA and
    P-256/P-384 only, and the hash rule is what refuses a request whose signature scheme this CA cannot describe or
    match to an issuing hash. The message says UNKNOWN rather than inventing a hash name.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    pem = (
        (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ed.internal")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("ed.internal")]), critical=False)
            .sign(key, None)
        )
        .public_bytes(Encoding.PEM)
        .decode("ascii")
    )

    parsed = x509.load_pem_x509_csr(pem.encode("ascii"))
    assert parsed.is_signature_valid is True  # the signature is fine; the policy is what refuses it
    assert parsed.signature_hash_algorithm is None

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert "UNKNOWN" in str(excinfo.value)


def test_a_sha384_signed_request_is_accepted(leaf_key: rsa.RSAPrivateKey) -> None:
    """One mutation from the previous refusals: a hash on the allow-list that is not the common one.

    Proves the rule is an allow-list rather than "sha256 or nothing".
    """
    details = parse_and_validate_csr(_csr_pem(leaf_key, hash_algorithm=hashes.SHA384()), MAX_CHARS)
    assert details.signature_hash == "SHA384"


# ------------------------------------------------------------------------------------- key policy (§3 rule 5)


def test_a_1024_bit_rsa_request_is_refused_naming_what_was_found_and_what_is_allowed(
    leaf_key: rsa.RSAPrivateKey,
) -> None:
    """`KeyPolicyError` measured from the key, not from a spec string somebody typed.

    The message carries both halves -- "RSA-1024 is not an accepted key. Allowed: RSA 2048, RSA 3072, RSA 4096." --
    because an operator holding an openssl-generated 1024-bit request needs to know the size was the problem, and what
    to generate instead.
    """
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)

    with pytest.raises(KeyPolicyError) as excinfo:
        parse_and_validate_csr(_csr_pem(weak), MAX_CHARS)

    assert "RSA-1024" in str(excinfo.value)
    assert "Allowed" in str(excinfo.value)
    assert excinfo.value.spec == "RSA-1024"


def test_a_request_on_an_unlisted_curve_is_refused(leaf_key: rsa.RSAPrivateKey) -> None:
    """P-224 is absent from the allow-list on purpose (page-map §3 rule 5, `keys.py`'s table).

    One mutation relative to an accepted EC request: the curve. A CSR cannot sneak in a curve this CA's own generator
    refuses to issue for.
    """
    p224 = ec.generate_private_key(ec.SECP224R1())
    pem = (
        (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "p224.internal")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("p224.internal")]), critical=False)
            .sign(p224, hashes.SHA256())
        )
        .public_bytes(Encoding.PEM)
        .decode("ascii")
    )

    with pytest.raises(KeyPolicyError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert "secp224r1" in str(excinfo.value)


@pytest.mark.parametrize(("curve", "label"), [(ec.SECP256R1(), "EC P-256"), (ec.SECP384R1(), "EC P-384")])
def test_the_two_listed_curves_are_accepted_with_their_labels(curve: ec.EllipticCurve, label: str) -> None:
    """The allow-list's EC half, both entries.

    `key_label` is asserted because it is what the confirmation panel shows and what the record store keeps: a spec that
    canonicalised to `EC-256` instead of `EC P-256` would make this app refuse its own output (see `keys.py`).
    """
    key = ec.generate_private_key(curve)
    pem = (
        (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec.internal")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("ec.internal")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        .public_bytes(Encoding.PEM)
        .decode("ascii")
    )

    details = parse_and_validate_csr(pem, MAX_CHARS)
    assert details.key_label == label


# ------------------------------------------------------------------------------ the extension gate (§3 rule 6)
#
# Two categories since PLAN.md §6.3, and this file is where the split is pinned:
#
#   * **refused** — a privilege claim (`CA:TRUE`, `keyCertSign`, `crlSign`, NameConstraints, anything unrecognised).
#     Step 6 aborts with `CaPrivilegeRequestedError` naming each one; nothing reaches the confirmation panel.
#   * **ignorable with disclosure** — requests mypki would satisfy identically anyway (`CA:FALSE`, benign KeyUsage bits,
#     SKI, AKI, ExtendedKeyUsage, CertificatePolicies, CRLDistributionPoints, AuthorityInfoAccess). Step 6 accepts them
#     and `CsrDetails.ignored_extensions` carries their names, which is what the panel shows and what step B needs
#     consent for.
#
# Both halves are asserted here rather than only through the pages: a page test can pass on a build that refused
# everything (the old behaviour) or on one that accepted everything (no gate at all), and the split is exactly the thing
# that must not drift either way.

#: The privilege claims, each with the name the refusal has to print.
_REFUSED_EXTENSIONS = (
    (x509.BasicConstraints(ca=True, path_length=None), "BasicConstraints CA:TRUE"),
    (x509.NameConstraints([x509.DNSName("sub.internal")], None), "NameConstraints"),
)

#: The ignorable ones, each with the name the **disclosure** has to print. `CRLDistributionPoints` moved here from the
#: refused list for this build: it cannot reach a leaf (`signing.leaf_extensions()` takes no CSR extension), and
#: refusing it meant an operator could not sign a request their own openssl config wrote the extension into. Note what
#: 0.7.0 did **not** change (page-map §14): a leaf now does carry a CDP, but it is mypki's own
#: `<crl_base_url>/crl.pem`, added by `leaf_extensions()` — a request's URL is still dropped and disclosed, never
#: obeyed. Its name is asserted verbatim so
#: the move cannot silently drop it.
_IGNORABLE_EXTENSIONS = (
    (x509.BasicConstraints(ca=False, path_length=None), "BasicConstraints CA:FALSE"),
    (
        x509.CertificatePolicies(
            [x509.PolicyInformation(policy_identifier=x509.ObjectIdentifier("2.23.140.1.2.1"), policy_qualifiers=None)]
        ),
        "CertificatePolicies",
    ),
    (
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://crl.internal/crl.der")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]
        ),
        "CRLDistributionPoints",
    ),
    (
        x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    access_method=x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1"),
                    access_location=x509.UniformResourceIdentifier("http://ocsp.internal"),
                )
            ]
        ),
        "AuthorityInfoAccess",
    ),
)


@pytest.mark.parametrize(
    ("extension", "marker"),
    [
        *_REFUSED_EXTENSIONS,
        (_usage(digitalSignature=True, keyCertSign=True), "KeyUsage keyCertSign"),
        (_usage(crlSign=True), "KeyUsage crlSign"),
        (_usage(keyCertSign=True, crlSign=True), "KeyUsage keyCertSign; KeyUsage crlSign"),
    ],
)
def test_a_request_that_asks_for_more_than_an_end_entity_is_refused_naming_the_extension(
    leaf_key: rsa.RSAPrivateKey, extension: x509.ExtensionType, marker: str
) -> None:
    """One privilege claim per case, and the refusal names exactly that extension.

    `CaPrivilegeRequestedError.extension` exists so the operator knows which line of their request to change (page-map
    §3 rule 6). A refusal that did not name it reads like the app is broken rather than like the request was refused on
    purpose -- and this CA's entire guarantee is that it mints end-entity certificates only.

    `critical=True` on every case: a privilege claim is refused whether or not the request marked it critical, because
    criticality is a statement about *validation* ("a verifier must understand this") and not about permission.

    The list is now the refused half of rule 6 only. `CRLDistributionPoints` used to sit here and moved to
    `_IGNORABLE_EXTENSIONS` with this build: it cannot reach a leaf (a request's URL is dropped; mypki bakes its own CDP
    in from 0.7.0), and refusing it made a request that openssl's own `[v3_req]` section wrote the extension into
    unsignable. Dropping a name from *this* list
    is a gate weakening, so the cases that moved are re-asserted below as disclosures rather than deleted.
    """
    pem = _csr_pem(leaf_key, extensions=[(extension, True)])

    with pytest.raises(CaPrivilegeRequestedError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert marker in str(excinfo.value)
    assert "end-entity certificates only" in str(excinfo.value)


@pytest.mark.parametrize(
    ("extension", "marker"),
    [
        *_IGNORABLE_EXTENSIONS,
        (
            _usage(digitalSignature=True, keyEncipherment=True),
            "KeyUsage (digitalSignature, keyEncipherment)",
        ),
        (_usage(), "KeyUsage (no usages set)"),
        (
            x509.ExtendedKeyUsage(
                [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"), x509.ObjectIdentifier("1.3.6.1.5.5.7.3.2")]
            ),
            "ExtendedKeyUsage (serverAuth, clientAuth)",
        ),
    ],
)
def test_an_extension_that_asks_for_nothing_is_accepted_and_named_for_disclosure(
    leaf_key: rsa.RSAPrivateKey, extension: x509.ExtensionType, marker: str
) -> None:
    """The ignorable half of rule 6: step 6 accepts it, and `ignored_extensions` names it.

    Accepting is not the finding; **naming** is. A build that accepted these extensions and told nobody would issue a
    certificate whose extensions differ from what the operator asked for with no record of the difference anywhere,
    which is exactly the outcome PLAN.md §6.3 exists to avoid. From 0.7.0 there *is* a CRL and an OCSP answer
    (page-map §14/§15), but publishing a revocation to the clients that consult one is not a record of what the
    request originally asked for: the disclosure on the confirmation panel is that record.

    `keyEncipherment` is in the first KeyUsage case on purpose: 0.1.0 through 0.5.0 named six of the seven bits in
    `_key_usage_words`, and a request carrying only the missing one was reported as "no usages set" — a refusal an
    operator cannot act on. The marker here is the whole rendered string rather than one word, so a bit dropped from
    the table fails this case by name.
    """
    details = parse_and_validate_csr(_csr_pem(leaf_key, extensions=[(extension, False)]), MAX_CHARS)

    assert details.ignored_extensions == (marker,), details.ignored_extensions


@pytest.mark.parametrize(
    ("extension", "marker"),
    [
        *_IGNORABLE_EXTENSIONS,
        (_usage(digitalSignature=True), "KeyUsage (digitalSignature)"),
    ],
)
def test_an_ignorable_extension_is_never_stripped_from_the_request(
    leaf_key: rsa.RSAPrivateKey, extension: x509.ExtensionType, marker: str
) -> None:
    """The invariant a consent box must not be allowed to break: "ignored" means **not copied**, never deleted.

    A CSR signature covers `CertificationRequestInfo`, which includes its extension attributes (PLAN.md §6.3). Strip
    one and re-armour, and step B signs different bytes from the ones step A validated — a request mypki never saw,
    signed under a signature that verifies against it. So the staged PEM has to still carry every extension the paste
    did, and `ignored_extensions` has to be a description rather than an edit.

    Asserted three ways because each half fails independently: the parsed request still carries the extension type;
    `details.pem` re-armours the same base64 body (`_rearmour`, not a rebuild); and the re-armed PEM still verifies,
    which is what proves no byte inside the signed region moved.
    """
    pem = _csr_pem(leaf_key, extensions=[(extension, False)])
    details = parse_and_validate_csr(pem, MAX_CHARS)

    requested = [type(item.value).__name__ for item in x509.load_pem_x509_csr(pem.encode("ascii")).extensions]
    assert type(extension).__name__ in requested, "validation stripped an extension from the request"
    assert details.ignored_extensions == (marker,)

    staged = x509.load_pem_x509_csr(details.pem.encode("ascii"))
    assert [type(item.value).__name__ for item in staged.extensions] == requested
    assert staged.is_signature_valid, "the staged PEM is no longer the document the signature covers"
    assert _der_of(pem) == _der_of(details.pem), "re-armour changed the DER step B will sign"


def test_a_consent_gate_never_rewrites_the_request_it_is_deciding_about(leaf_key: rsa.RSAPrivateKey) -> None:
    """The mutation check for the invariant above (STYLE §8): a build that *did* strip would be caught here.

    Rewriting `details.pem` from a builder that drops extensions is the tempting implementation of "ignore it": it makes
    the panel's list self-consistent, and it breaks byte identity silently because the rewritten request still parses
    and still carries a valid signature over *its own* new bytes. Only comparing DER bytes sees that defect; asking
    whether the PEM looks canonical does not.
    """
    pem = _csr_pem(
        leaf_key,
        extensions=[(x509.BasicConstraints(ca=False, path_length=None), True), (_usage(digitalSignature=True), False)],
    )
    details = parse_and_validate_csr(pem, MAX_CHARS)

    stripped = (
        (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.load_pem_x509_csr(pem.encode("ascii")).subject)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("server.internal")]), critical=False)
            .sign(leaf_key, hashes.SHA256())
        )
        .public_bytes(Encoding.PEM)
        .decode("ascii")
    )

    assert details.ignored_extensions == ("BasicConstraints CA:FALSE", "KeyUsage (digitalSignature)")
    # The stripped document is well-formed and self-consistent — which is exactly why the assertion has to be about
    # bytes rather than about whether the staged PEM parses.
    assert x509.load_pem_x509_csr(stripped.encode("ascii")).is_signature_valid
    assert _der_of(stripped) != _der_of(details.pem)


def test_a_harmless_looking_keyusage_is_disclosed_and_named_rather_than_refused(
    leaf_key: rsa.RSAPrivateKey,
) -> None:
    """`digitalSignature` + `keyEncipherment` — OpenSSL's own default pair — is no longer a refusal.

    This test asserted the opposite until PLAN.md §6.3. What it still guards is unchanged and narrower: **the bits have
    to be named**. Under rule 6's first form, naming them was what made a refusal actionable; under its second form,
    naming them is what makes a disclosure actionable and what the consent box and the issued page's diff are built
    from. A build that accepted benign KeyUsage but reported `KeyUsage` with no bits would pass every signing test and
    fail this one.

    The pair is OpenSSL's, not an invention: `[v3_req]` in a distro `openssl.cnf` writes exactly
    `digitalSignature, keyEncipherment`, which is why the operator report behind this change was "a normal CSR is
    blocked". Refusing it was correct policy and unusable software at the same time.
    """
    harmless = _usage(digitalSignature=True, keyEncipherment=True)

    details = parse_and_validate_csr(_csr_pem(leaf_key, extensions=[(harmless, False)]), MAX_CHARS)

    assert details.ignored_extensions == ("KeyUsage (digitalSignature, keyEncipherment)",)
    # `key_encipherment=True` is set on the fixture above but was **not** asserted in 0.5.0 or any earlier release,
    # which is how `_key_usage_words` shipped without that bit: the test asked for the bit, checked a different one,
    # and passed. Both requested bits are named now.
    assert "digitalSignature" in details.ignored_extensions[0]
    assert "keyEncipherment" in details.ignored_extensions[0]


@pytest.mark.parametrize(
    "flags,expected_words",
    [
        *([({bit: True}, [bit]) for bit in _USAGE_BITS]),
        # The pair OpenSSL's own `[v3_req]` writes into every distro openssl.cnf, and the pair that used to be reported
        # as one word plus a dropped one.
        ({"digitalSignature": True, "keyEncipherment": True}, ["digitalSignature", "keyEncipherment"]),
        ({"keyEncipherment": True, "dataEncipherment": True}, ["keyEncipherment", "dataEncipherment"]),
    ],
)
def test_every_keyusage_bit_is_named_when_it_is_requested(
    leaf_key: rsa.RSAPrivateKey, flags: dict[str, bool], expected_words: list[str]
) -> None:
    """The disclosure is a list of what was dropped, so every bit has to appear in it.

    Asserted per bit rather than on one representative: `KeyUsage` has seven booleans and the failure mode this guards
    against is exactly one of them being missing from `_key_usage_words`' table. A single example cannot see that --
    `test_a_harmless_looking_keyusage_is_disclosed_and_named_rather_than_refused` requested two bits, named one in its
    assertion, and stayed green while the message lied about the other.

    The category per bit is asserted too, because that is the split this build introduced: five benign bits are
    disclosed, `keyCertSign` and `crlSign` are refused. A table that moved those two into the disclosed half would keep
    every word present — only the *answer* would change — so the expectation carries the category rather than just the
    wording.
    """
    privileged = flags.get("keyCertSign") or flags.get("crlSign")
    usage = _usage(**flags)

    if privileged:
        with pytest.raises(CaPrivilegeRequestedError) as excinfo:
            parse_and_validate_csr(_csr_pem(leaf_key, extensions=[(usage, False)]), MAX_CHARS)
        message = str(excinfo.value)
    else:
        message = ", ".join(
            parse_and_validate_csr(_csr_pem(leaf_key, extensions=[(usage, False)]), MAX_CHARS).ignored_extensions
        )

    for word in expected_words:
        assert word in message


def test_no_usages_set_is_said_only_when_no_usage_is_set(leaf_key: rsa.RSAPrivateKey) -> None:
    """`no usages set` must never be printed about a KeyUsage that sets something.

    The defect this guards against was that string arriving for a request carrying `keyEncipherment` alone -- the one
    sentence an operator cannot act on, because it says there is nothing to remove while the request demonstrably asks
    for something. It is now a *disclosure* rather than a refusal, which makes the misleading spelling worse rather than
    less important: an operator told "no usages set" about a request that set `keyEncipherment` would tick a consent box
    for a list they cannot check.

    Asserting both directions (an empty KeyUsage says it; every single-bit request does not) is what keeps a bit being
    left out of `_key_usage_words` from resurfacing as a misleading message.
    """
    empty = parse_and_validate_csr(_csr_pem(leaf_key, extensions=[(_usage(), False)]), MAX_CHARS)
    assert empty.ignored_extensions == ("KeyUsage (no usages set)",)

    for bit in _USAGE_BITS:
        pem = _csr_pem(leaf_key, extensions=[(_usage(**{bit: True}), False)], common_name="u.internal")
        if bit in ("keyCertSign", "crlSign"):
            # The two privileged bits are refused rather than disclosed, so their sentence comes from the exception.
            with pytest.raises(CaPrivilegeRequestedError) as excinfo:
                parse_and_validate_csr(pem, MAX_CHARS)
            message = str(excinfo.value)
        else:
            message = ", ".join(parse_and_validate_csr(pem, MAX_CHARS).ignored_extensions)
        assert "no usages set" not in message, f"{bit} was requested but not named"


def test_one_privilege_claim_refuses_a_request_that_also_carries_ignorable_extensions(
    leaf_key: rsa.RSAPrivateKey,
) -> None:
    """Both categories in one request: the refused half wins, and it does not report the ignorable half as accepted.

    A `CA:TRUE` request that also carries a benign KeyUsage is one request to fix, and an operator who was told only
    about `CA:TRUE` would resubmit without knowing the KeyUsage had been silently tolerated in the meantime. The refusal
    names every problem it found (the same collection rule as below) while still refusing — consent cannot be traded for
    a privilege claim, and no consent box is ever rendered for a request that was refused.
    """
    pem = _csr_pem(
        leaf_key,
        extensions=[
            (_usage(digitalSignature=True, keyEncipherment=True), False),
            (x509.BasicConstraints(ca=True, path_length=None), True),
        ],
    )

    with pytest.raises(CaPrivilegeRequestedError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert "BasicConstraints CA:TRUE" in str(excinfo.value)
    # The ignorable half is *not* listed on a refusal: nothing was accepted, and a message that read "we would have
    # dropped these for you" describes a signing that did not happen.
    assert "digitalSignature" not in str(excinfo.value)


def test_an_unrecognised_extension_is_treated_as_a_privilege_claim(leaf_key: rsa.RSAPrivateKey) -> None:
    """Something csr.py does not know is refused rather than waved through.

    `OtherName` (RFC 5280 §4.2.1.6, an exotic SAN general name) has no case in `_csr_extension_problems`, so it lands in
    the fallback branch. The alternative — accepting what this code cannot read — is how a gate becomes a formality:
    every extension mypki does not model would be silently "ignored", and the operator would never learn that the
    certificate they installed omitted something they asked for.
    """
    pem = _csr_pem(
        leaf_key,
        common_name="u.internal",
        extensions=[
            (
                x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.840.113549.1.9.16.1"), b"\x30\x03\x02\x01\x01"),
                False,
            )
        ],
    )

    with pytest.raises(CaPrivilegeRequestedError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert "UnrecognizedExtension" in str(excinfo.value)
    assert "end-entity certificates only" in str(excinfo.value)


def test_subject_key_identifier_and_authority_key_identifier_are_disclosed_by_name(
    leaf_key: rsa.RSAPrivateKey,
) -> None:
    """SKI and AKI, the two mypki always sets itself, are named rather than refused.

    An operator who added them (some tools copy the issuing CA's AKI into a request template) was previously told their
    request was refused, when in fact the only thing wrong was that mypki computes both from its own CA key. Naming them
    is what makes "mypki sets these" checkable against a real openssl `-text` dump.
    """
    pem = _csr_pem(
        leaf_key,
        extensions=[
            (x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False),
            (
                x509.AuthorityKeyIdentifier(
                    key_identifier=b"\x01\x02\x03", authority_cert_issuer=None, authority_cert_serial_number=None
                ),
                False,
            ),
        ],
    )

    details = parse_and_validate_csr(pem, MAX_CHARS)

    assert details.ignored_extensions == ("SubjectKeyIdentifier", "AuthorityKeyIdentifier")


def test_extended_key_usage_is_named_in_words_an_operator_pasted(
    leaf_key: rsa.RSAPrivateKey,
) -> None:
    """`extendedKeyUsage = serverAuth, clientAuth` comes back spelled the way it was typed.

    cryptography's `ObjectIdentifier` has no public name (MEASURED on 50.0.2: `shortname` is absent and `_display_name`
    is None), so a disclosure built from `str(oid)` would render the whole repr — `<ObjectIdentifier(oid=…,
    name=serverAuth)>` — on the page: technically true, useless beside a profile radio that already says `server`. An
    unnamed OID falls back to its dotted arc rather than to cryptography's own `"Unknown OID"` placeholder, so a
    disclosure can always be compared against the request it came from.
    """
    pem = _csr_pem(
        leaf_key,
        extensions=[
            (
                x509.ExtendedKeyUsage(
                    [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1"), x509.ObjectIdentifier("1.3.6.1.5.5.7.4.10")]
                ),
                False,
            )
        ],
    )

    details = parse_and_validate_csr(pem, MAX_CHARS)

    assert len(details.ignored_extensions) == 1
    name = details.ignored_extensions[0]
    assert "serverAuth" in name
    assert "1.3.6.1.5.5.7.4.10" in name  # an OID cryptography does not name still appears, as its arc
    assert "ObjectIdentifier(" not in name


def test_a_request_carrying_two_ca_powers_is_refused_naming_both(leaf_key: rsa.RSAPrivateKey) -> None:
    """Collected rather than raised on the first problem.

    `CA:TRUE` plus `keyCertSign` is one request to fix, and reporting only the first would mean two page loads to learn
    about one mistake (page-map §3 rule 6). Both names appear in one message.
    """
    pem = _csr_pem(
        leaf_key,
        extensions=[
            (x509.BasicConstraints(ca=True, path_length=0), True),
            (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
        ],
    )

    with pytest.raises(CaPrivilegeRequestedError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert "BasicConstraints CA:TRUE" in str(excinfo.value)
    assert "keyCertSign" in str(excinfo.value)
    assert "crlSign" in str(excinfo.value)


# ------------------------------------------------------------------------------------------------ SANs (§3 rule 7)


def test_a_san_that_is_an_ip_address_written_as_a_dns_name_is_named(leaf_key: rsa.RSAPrivateKey) -> None:
    """The inverse of the common openssl `-addext "subjectAltName=IP:10.0.0.1"` mistake.

    X.509 encodes it happily; a client then matches it against nothing. Naming it as an IP general name saves an
    operator
    an hour of reading RFCs (page-map §3 rule 7 re-validates foreign SANs through `validators.py`).
    """
    pem = (
        (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ip.internal")]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("10.0.0.1")]), critical=False)
            .sign(leaf_key, hashes.SHA256())
        )
        .public_bytes(Encoding.PEM)
        .decode("ascii")
    )

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert "IP address encoded as a DNS name" in str(excinfo.value)


def test_a_san_label_x509_accepts_and_mypki_refuses_is_reported_with_its_position(leaf_key: rsa.RSAPrivateKey) -> None:
    """`bad-.internal` is legal DER and an invalid RFC 1123 host.

    Position is asserted because these entries came from outside mypki, possibly as a long list: "position 0" is
    what lets
    an operator find the entry in their request (page-map §9).
    """
    pem = (
        (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "b.internal")]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("good.internal"), x509.DNSName("bad-.internal")]),
                critical=False,
            )
            .sign(leaf_key, hashes.SHA256())
        )
        .public_bytes(Encoding.PEM)
        .decode("ascii")
    )

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert "position 1" in str(excinfo.value)
    assert "hyphen" in str(excinfo.value)


def test_a_general_name_type_mypki_does_not_understand_is_refused(leaf_key: rsa.RSAPrivateKey) -> None:
    """An `email=` SAN (RFC822Name).

    mypki keeps email in the **subject** and names in the SAN (page-map §7's rationale); an unsupported general name is
    refused naming the type rather than dropped, because silently dropping one entry would sign a request whose
    names are
    not the names it displayed.
    """
    pem = (
        (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e.internal")]))
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name("ops@example.test")]), critical=False)
            .sign(leaf_key, hashes.SHA256())
        )
        .public_bytes(Encoding.PEM)
        .decode("ascii")
    )

    with pytest.raises(CsrValidationError) as excinfo:
        parse_and_validate_csr(pem, MAX_CHARS)
    assert "RFC822Name" in str(excinfo.value)


def test_repeated_names_are_signed_once(leaf_key: rsa.RSAPrivateKey) -> None:
    """Dedupe preserving first-seen order.

    A request that repeats a name is one certificate for that name, not two SAN entries -- and the order has to survive,
    because it is the order the confirmation panel displays (page-map §9).
    """
    pem = (
        (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "d.internal")]))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("zeta.internal"),
                        x509.DNSName("alpha.internal"),
                        x509.DNSName("zeta.internal"),
                        x509.IPAddress(ipaddress.ip_address("10.0.0.7")),
                    ]
                ),
                critical=False,
            )
            .sign(leaf_key, hashes.SHA256())
        )
        .public_bytes(Encoding.PEM)
        .decode("ascii")
    )

    details = parse_and_validate_csr(pem, MAX_CHARS)
    assert details.sans.dns == ("zeta.internal", "alpha.internal")
    assert details.sans.ips == ("10.0.0.7",)


def test_a_request_with_no_san_validates_because_that_is_legal(leaf_key: rsa.RSAPrivateKey) -> None:
    """`ExtensionNotFound` is not an error at validation time (page-map §3 rule 7).

    Whether SAN is *required* is `signing.py`'s per-profile decision (a server certificate without one is
    unusable), not a
    verdict about the request. Keeping the split here is what lets the confirmation panel show "no SANs" honestly and
    offer `client` rather than showing an error for a legal request.
    """
    details = parse_and_validate_csr(_csr_pem(leaf_key, sans=(), common_name="support desk"), MAX_CHARS)

    assert details.sans.empty is True
    assert details.sans.describe() == "none"


def test_a_request_with_both_dns_and_ip_sans_keeps_them_separate(leaf_key: rsa.RSAPrivateKey) -> None:
    """DNS and IP general names are different types in X.509 and stay in separate tuples.

    A single mixed list would let an ordering accident change a certificate's meaning (page-map §9), and the two lists
    are what the panel renders as two rows.
    """
    details = parse_and_validate_csr(
        _csr_pem(leaf_key, sans=("a.internal", "10.0.0.7", "*.lab.internal", "2001:db8::1")),
        MAX_CHARS,
    )

    assert details.sans.dns == ("a.internal", "*.lab.internal")
    assert details.sans.ips == ("10.0.0.7", "2001:db8::1")
    assert details.sans.all_entries() == ("a.internal", "*.lab.internal", "10.0.0.7", "2001:db8::1")
