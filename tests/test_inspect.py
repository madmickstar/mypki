"""`/inspect` (page-map §13): read a pasted PEM, describe it, refuse nothing but an oversized body.

Two halves here, and they are deliberately separated because they prove different things.

**The module half.** `mypki.inspect.describe_pem` is the only reader in this app that never raises on *content*, so
every finding — expired, self-signed, not-a-CA, SHA-1, RSA-1024, a request that asks to be a CA — has to be asserted as
a sentence the page actually carries. A finding that exists only as an internal variable is invisible to the operator
who came to look at it. The fixtures are real certificates and real requests built with `cryptography`, because
a document says" cannot be tested against a fabricated object: the whole point of the page is that it reads somebody
else's documents, including ones mypki would never have issued.

Two fixture techniques are worth naming. SHA-1 fixtures are re-assembled by hand (`_sha1_signed_cert_pem`) because
cryptography 50 refuses to *sign* SHA-1 at all (MEASURED: `UnsupportedAlgorithm: Hash algorithm "sha1" not supported for
signatures`; the same reasoning and the same DER-walking shape as `test_csr_validate._sha1_signed_csr_pem`). And the
RSA-1024 / Ed25519 fixtures exist on purpose: they are keys mypki's issuer-side policy refuses, which is exactly why
`inspect.py` does not call `ca.describe_ca` or `keys.describe_public_key` — both raise `KeyPolicyError` on them
(MEASURED), and a page whose promise is *never refuse* cannot start by calling a policy gate.

**The HTTP half.** `/inspect` echoes the paste back into the textarea, which is right for a certificate and wrong for a
key, so the redaction assertions are the load-bearing security tests in this file: a pasted key's base64 must not come
back, while the BEGIN/END lines must (the operator has to be able to see that a key *was* there). The armour pattern is
therefore asserted as **present** in the key case and **absent** in every ordinary response — `test_no_key_leakage.py`'s
zero-armour sweep covers GETs, and this file owns the POST-with-a-key case.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from conftest import csrf_token
from mypki.ca import fingerprint_hex
from mypki.config import Settings
from mypki.csr import CSR_PEM_BEGIN, CSR_PEM_END
from mypki.errors import RequestTooLargeError
from mypki.inspect import (
    KEY_BODY_REDACTED,
    MAX_BLOCKS_TO_TRY,
    PemReport,
    describe_pem,
    pem_body_sha256,
    redact_private_key_bodies,
)

#: starlette's own answer to an oversized form part (MEASURED, `max_part_size=1048576`). Its absence is the assertion:
#: if it appears, mypki's promise of an error page naming `MYPKI_MAX_CSR_CHARS` has been replaced by a framework
#: default.
STARLETTE_SIZE_MESSAGE = "Field exceeded maximum size of 1024KB."

#: Private-key armour in every spelling cryptography produces (same pattern as `test_no_key_leakage.ARMOUR_RE`).
ARMOUR_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

#: The cap used for the pure-module calls. It is written here rather than read from `Settings` so a developer's default
#: cannot silently change what an oversized test means; the HTTP half below uses the app's real setting instead.
CAP = 32_000

NOW = dt.datetime.now(dt.timezone.utc)


# ------------------------------------------------------------------------------------------- fixture helpers


def _armour(der: bytes, kind: str) -> str:
    """Canonical PEM armour for DER bytes (same shape as `test_csr_validate._armour`)."""
    body = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN {kind}-----\n{wrapped}\n-----END {kind}-----\n"


def _body_of(pem: str) -> str:
    """The base64 payload of one armour block, armour lines removed."""
    return "".join(pem.splitlines()[1:-1])


def _der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _read_der_length(der: bytes, offset: int) -> tuple[int, int]:
    first = der[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    return int.from_bytes(der[offset + 1 : offset + 1 + count], "big"), offset + 1 + count


def _outer_children(der: bytes) -> list[bytes]:
    """Each top-level child of an outer SEQUENCE, **including its own tag+length header**.

    MEASURED while building the SHA-1 fixture: dropping the header produces a body that looks right and then fails with
    `UnexpectedTag { actual: Tag { value: 0, constructed: true }, location: ["Certificate::tbs_cert"] }`, because the
    parser meets the child's *content* first (a TBS certificate opens with `[0] EXPLICIT INTEGER` for the version)
    instead of its SEQUENCE tag.
    """
    assert der[0] == 0x30, "expected an outer SEQUENCE"
    length, start = _read_der_length(der, 1)
    children: list[bytes] = []
    cursor = start
    end = start + length
    while cursor < end:
        child_length, after = _read_der_length(der, cursor + 1)
        children.append(der[cursor : after + child_length])
        cursor = after + child_length
    return children


def _certificate_pem(
    cn: str,
    issuer_cn: str | None,
    signing_key: object,
    *,
    ca: bool,
    path_length: int | None = 0,
    san: tuple[x509.GeneralName, ...] = (),
    organisation: str | None = None,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    hash_alg: object = hashes.SHA256(),
) -> str:
    subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if organisation:
        subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation))
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject_attrs))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)]))
        .public_key(signing_key.public_key())  # type: ignore[attr-defined]
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - dt.timedelta(days=30))
        .not_valid_after(not_after or NOW + dt.timedelta(days=300))
        # `path_length` must be None when `ca` is False (MEASURED: cryptography raises ValueError otherwise), which is
        # itself the reason a leaf here can never read as "CA:FALSE pathLength:0".
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(san)), critical=False)
    # cryptography 50 (MEASURED): `CertificateBuilder.sign()` returns a Certificate object, not DER bytes; and an
    # Ed25519 key must be signed with `algorithm=None` (`ValueError: Algorithm must be None when signing via ed25519 or
    # ed448`).
    return builder.sign(signing_key, hash_alg).public_bytes(Encoding.PEM).decode("ascii")  # type: ignore[arg-type]


def _request_pem(
    cn: str,
    private_key: rsa.RSAPrivateKey,
    *,
    san: tuple[x509.GeneralName, ...] = (),
    ca_request: bool = False,
) -> str:
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(san)), critical=False)
    if ca_request:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(private_key, hashes.SHA256()).public_bytes(Encoding.PEM).decode("ascii")


def _sha1_signed_cert_pem(cn: str, key: rsa.RSAPrivateKey) -> str:
    """A genuinely SHA-1-signed certificate, re-assembled by hand.

    Same reason `test_csr_validate._sha1_signed_csr_pem` exists: the pinned cryptography refuses `hashes.SHA1()` for new
    signatures, so the only way to feed `/inspect` a real SHA-1 document — rather than a claim about one — is to re-sign
    an existing certificate's TBS bytes with the `sha1WithRSAEncryption` AlgorithmIdentifier swapped in. That is
    precisely what an old openssl-issued certificate looks like, which is the state this page exists to describe.
    """
    good = _certificate_pem(cn, "root", key, ca=False, san=(x509.DNSName(cn),))
    der = x509.load_pem_x509_certificate(good.encode("ascii")).public_bytes(Encoding.DER)
    tbs = _outer_children(der)[0]
    sha1_algorithm_identifier = bytes.fromhex("300d06092a864886f70d0101050500")  # sha1WithRSAEncryption + NULL
    signature = key.sign(hashlib.sha1(tbs).digest(), padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))
    body = tbs + sha1_algorithm_identifier + b"\x03" + _der_length(len(signature) + 1) + b"\x00" + signature
    sha1_der = b"\x30" + _der_length(len(body)) + body

    parsed = x509.load_der_x509_certificate(sha1_der)
    # The fixture asserts on itself: a test that later fails to see the SHA-1 flag can check whether the *fixture* was
    # carrying SHA-1 before it blames `inspect.py`.
    assert parsed.signature_hash_algorithm is not None
    assert parsed.signature_hash_algorithm.name == "sha1"
    return _armour(sha1_der, "CERTIFICATE")


def _sha1_signed_request_pem(cn: str, key: rsa.RSAPrivateKey) -> str:
    """A genuinely SHA-1-signed request, re-assembled by hand — the CSR twin of `_sha1_signed_cert_pem`.

    Worth having separately because the two pages carry different sentences for the same hash: a certificate gets "mypki
    refuses to issue certificates signed this way" and a request gets "mypki refuses to sign a request carrying it". One
    fixture cannot assert both, and the wording is what an operator acts on.
    """
    good = _request_pem(cn, key, san=(x509.DNSName(cn),))
    der = x509.load_pem_x509_csr(good.encode("ascii")).public_bytes(Encoding.DER)
    info = _outer_children(der)[0]
    sha1_algorithm_identifier = bytes.fromhex("300d06092a864886f70d0101050500")  # sha1WithRSAEncryption + NULL
    signature = key.sign(hashlib.sha1(info).digest(), padding.PKCS1v15(), utils.Prehashed(hashes.SHA1()))
    body = info + sha1_algorithm_identifier + b"\x03" + _der_length(len(signature) + 1) + b"\x00" + signature
    sha1_der = b"\x30" + _der_length(len(body)) + body

    parsed = x509.load_der_x509_csr(sha1_der)
    assert parsed.signature_hash_algorithm is not None
    assert parsed.signature_hash_algorithm.name == "sha1"
    return _armour(sha1_der, "CERTIFICATE REQUEST")


def _tampered_request_pem(cn: str, private_key: rsa.RSAPrivateKey) -> str:
    """A request whose signature no longer verifies, mutated inside the signature region.

    One byte flipped at `[-32]` (MEASURED on this build: the request still parses as a CSR and `is_signature_valid`
    reports False; the SAN extension survives). Mutating the signature rather than an arbitrary byte is what makes the
    assertion about the *signature* row rather than about the parser.
    """
    pem = _request_pem(cn, private_key, san=(x509.DNSName(cn),))
    der = bytearray(x509.load_pem_x509_csr(pem.encode("ascii")).public_bytes(Encoding.DER))
    der[-32] ^= 0xFF
    return _armour(bytes(der), "CERTIFICATE REQUEST")


def _fact(report: PemReport, label: str) -> str:
    """One fact row by label, failing loudly when the row is absent.

    A dict lookup with a default would report `None` for a missing row and the assertion below it would read as a value
    problem rather than as "this row stopped existing".
    """
    for name, value in report.facts:
        if name == label:
            return value
    raise AssertionError(f"no {label!r} row in {[name for name, _ in report.facts]}")


def _flag_containing(reports: list[PemReport], needle: str) -> str:
    """The single flag containing `needle`, or a failure naming every flag that was present."""
    seen = [flag for report in reports for flag in report.flags]
    matches = [flag for flag in seen if needle in flag]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one flag containing {needle!r}, got {matches} (all flags: {seen})")
    return matches[0]


def _everything(report: PemReport) -> str:
    """Every word a report carries: both halves of every fact row plus every flag.

    Used where the assertion is "nothing from this input appears anywhere", which has to cover the fact rows as well as
    the prose — a base64 fragment printed in a `Type` row would otherwise slip past a flags-only search.
    """
    return " ".join(f"{label} {value}" for label, value in report.facts) + " " + " ".join(report.flags)


# -------------------------------------------------------------------------------------------------- fixtures
#
# Module-scoped on purpose: an RSA-2048 keypair costs ~100 ms and a 1024-bit one less, and every test in this half only
# reads the certificate. Function scope would spend most of the file's runtime regenerating identical documents.


@pytest.fixture(scope="module")
def rsa_2048() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa_1024() -> rsa.RSAPrivateKey:
    """A key mypki's issuer policy refuses — the fixture that proves `/inspect` is not an issuer."""
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.fixture(scope="module")
def ed25519_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _certificate_pem("leaf.example", "root", rsa_2048, ca=False, san=(x509.DNSName("leaf.example"),))


@pytest.fixture(scope="module")
def named_leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _certificate_pem(
        "named.example", "root", rsa_2048, ca=False, san=(x509.DNSName("named.example"),), organisation="Example Ops"
    )


@pytest.fixture(scope="module")
def unnamed_leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    """The same shape with no `O=` attribute, so the absence of a row is a fact about the document."""
    return _certificate_pem("plain.example", "root", rsa_2048, ca=False)


@pytest.fixture(scope="module")
def expired_leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _certificate_pem(
        "expired.example",
        "root",
        rsa_2048,
        ca=False,
        san=(x509.DNSName("expired.example"),),
        not_before=NOW - dt.timedelta(days=400),
        not_after=NOW - dt.timedelta(days=30),
    )


@pytest.fixture(scope="module")
def future_leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _certificate_pem(
        "future.example",
        "root",
        rsa_2048,
        ca=False,
        san=(x509.DNSName("future.example"),),
        not_before=NOW + dt.timedelta(days=9),
        not_after=NOW + dt.timedelta(days=400),
    )


@pytest.fixture(scope="module")
def weak_leaf_pem(rsa_1024: rsa.RSAPrivateKey) -> str:
    return _certificate_pem("weak.example", "root", rsa_1024, ca=False, san=(x509.DNSName("weak.example"),))


@pytest.fixture(scope="module")
def sha1_leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _sha1_signed_cert_pem("sha1.example", rsa_2048)


@pytest.fixture(scope="module")
def ed_leaf_pem(ed25519_key: ed25519.Ed25519PrivateKey) -> str:
    # `hash_alg=None` is required for an Ed25519 key (MEASURED); the certificate that comes out is what makes the page's
    # "not modelled" hash row a fact read off the document rather than a string written by inspect.py.
    return _certificate_pem(
        "ed.example", "root", ed25519_key, ca=False, san=(x509.DNSName("ed.example"),), hash_alg=None
    )


@pytest.fixture(scope="module")
def odd_san_leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _certificate_pem(
        "odd.example",
        "root",
        rsa_2048,
        ca=False,
        san=(
            x509.DNSName("odd.example"),
            # MEASURED on cryptography 50: the general name for an email is `RFC822Name` — there is no
            # `x509.EmailAddress`, and a test that reached for one would fail in the fixture rather than in the code.
            x509.RFC822Name("ops@example.test"),
            x509.UniformResourceIdentifier("https://example.test/x"),
        ),
    )


@pytest.fixture(scope="module")
def root_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _certificate_pem(
        "mypki Test CA",
        None,
        rsa_2048,
        ca=True,
        path_length=0,
        not_before=NOW - dt.timedelta(days=10),
        not_after=NOW + dt.timedelta(days=3650),
    )


@pytest.fixture(scope="module")
def unlimited_root_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _certificate_pem(
        "Unlimited CA",
        None,
        rsa_2048,
        ca=True,
        path_length=None,
        not_before=NOW - dt.timedelta(days=10),
        not_after=NOW + dt.timedelta(days=3650),
    )


@pytest.fixture(scope="module")
def csr_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _request_pem("csr.example", rsa_2048, san=(x509.DNSName("csr.example"),))


@pytest.fixture(scope="module")
def tampered_csr_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _tampered_request_pem("csr.example", rsa_2048)


@pytest.fixture(scope="module")
def ca_wannabe_csr_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _request_pem("ca-wannabe", rsa_2048, ca_request=True)


@pytest.fixture(scope="module")
def weak_csr_pem(rsa_1024: rsa.RSAPrivateKey) -> str:
    """A request carrying a key mypki refuses to sign for — `/inspect` still has to read it."""
    return _request_pem("weak-csr.example", rsa_1024)


@pytest.fixture(scope="module")
def odd_san_csr_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _request_pem(
        "odd-csr.example",
        rsa_2048,
        san=(x509.DNSName("odd-csr.example"), x509.RFC822Name("ops@example.test")),
    )


@pytest.fixture(scope="module")
def sha1_csr_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _sha1_signed_request_pem("sha1-csr.example", rsa_2048)


@pytest.fixture(scope="module")
def ip_san_leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return _certificate_pem(
        "ip.example",
        "root",
        rsa_2048,
        ca=False,
        san=(x509.DNSName("ip.example"), x509.IPAddress(ipaddress.ip_address("10.0.0.7"))),
    )


@pytest.fixture(scope="module")
def ec_leaf_pem() -> str:
    return _certificate_pem(
        "ec.example", "root", ec.generate_private_key(ec.SECP256R1()), ca=False, san=(x509.DNSName("ec.example"),)
    )


@pytest.fixture(scope="module")
def self_signed_leaf_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    """Subject == issuer **and** `CA:FALSE`: the odd one, and the case the root wording used to be applied to."""
    return _certificate_pem("odd-self.example", None, rsa_2048, ca=False, san=(x509.DNSName("odd-self.example"),))


@pytest.fixture(scope="module")
def plain_key_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return rsa_2048.private_bytes(Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(
        "ascii"
    )


@pytest.fixture(scope="module")
def encrypted_key_pem(rsa_2048: rsa.RSAPrivateKey) -> str:
    return rsa_2048.private_bytes(
        Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"test-passphrase")
    ).decode("ascii")


@pytest.fixture(scope="module")
def ec_key_pem() -> str:
    return (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        .decode("ascii")
    )


# ------------------------------------------------------------------------------------- a leaf, row by row


def test_a_leaf_certificate_is_described_row_by_row(leaf_pem: str) -> None:
    """Every row an operator came to read is present, with the values the certificate actually carries."""
    reports = describe_pem(leaf_pem, CAP)

    assert len(reports) == 1
    report = reports[0]
    assert report.kind == "certificate"
    assert report.armour == "CERTIFICATE"
    parsed = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
    assert _fact(report, "Type") == "end-entity certificate"
    assert _fact(report, "Subject") == "CN=leaf.example"
    assert _fact(report, "Issuer") == "CN=root"
    assert _fact(report, "Subject Alternative Names") == "leaf.example"
    assert _fact(report, "Serial (hex)") == f"{parsed.serial_number:x}"
    assert _fact(report, "Public key") == "RSA 2048"
    assert _fact(report, "BasicConstraints") == "CA:FALSE"
    assert _fact(report, "Common name") == "leaf.example"
    # The order is asserted as well as the contents: this page's whole claim is that it reads a document in an order a
    # reader can follow (what it is → whose it is → whose signature → when it is valid).
    assert [name for name, _ in report.facts] == [
        "Type",
        "Subject",
        "Issuer",
        "Subject Alternative Names",
        "Validity (UTC)",
        "Serial (hex)",
        "SHA-256 fingerprint",
        "Signature algorithm",
        "Public key",
        "BasicConstraints",
        "Common name",
    ]


def test_a_certificates_fingerprint_row_is_the_same_number_as_the_der_hash(leaf_pem: str) -> None:
    """`pem_body_sha256(body) == cert.fingerprint(SHA-256)` — MEASURED, and load-bearing for the page.

    Two rows on screen ("SHA-256 fingerprint" from `ca.fingerprint_hex`, "SHA-256 of the DER" from
    `inspect.pem_body_sha256`) are only honest because they describe the same bytes. If this equality ever breaks, the
    page shows an operator two different hashes for one document and the copy button no longer matches the table above
    it.
    """
    parsed = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
    report = describe_pem(leaf_pem, CAP)[0]

    assert pem_body_sha256(_body_of(leaf_pem)) == fingerprint_hex(parsed)
    assert report.sha256_of_der == fingerprint_hex(parsed)
    assert _fact(report, "SHA-256 fingerprint") == report.sha256_of_der


def test_the_same_certificate_pasted_from_windows_hashes_identically(leaf_pem: str) -> None:
    """CRLF versus LF changes nothing, because only the base64 payload is measured.

    The failure this guards against is the ordinary one: a certificate copied out of Notepad and the same certificate
    copied from a terminal would otherwise produce two different "SHA-256 of the DER" values, and the operator would
    conclude they were looking at two different documents.
    """
    crlf = leaf_pem.replace("\n", "\r\n")

    assert describe_pem(crlf, CAP)[0].sha256_of_der == describe_pem(leaf_pem, CAP)[0].sha256_of_der


def test_the_block_on_screen_is_the_same_bytes_as_the_block_that_was_read(leaf_pem: str) -> None:
    """The re-armoured block re-parses to the identical DER.

    `inspect._rearmour` re-wraps to 64-character lines, so what is on screen is not the sender's original text — which
    is only acceptable while the DER inside is unchanged. Asserted by comparing DER bytes rather than by comparing
    strings, because a string comparison would fail for a legitimate re-wrap and prove nothing about the bytes.
    """
    report = describe_pem(leaf_pem.replace("\n", "\r\n"), CAP)[0]

    assert report.pem is not None
    assert report.pem.startswith("-----BEGIN CERTIFICATE-----\n")
    assert report.pem.endswith("-----END CERTIFICATE-----\n")
    assert all(len(line) <= 64 for line in report.pem.splitlines()[1:-1])
    original = x509.load_pem_x509_certificate(leaf_pem.encode("ascii"))
    re_read = x509.load_pem_x509_certificate(report.pem.encode("ascii"))
    assert re_read.public_bytes(Encoding.DER) == original.public_bytes(Encoding.DER)


def test_an_organisation_row_appears_only_when_the_certificate_carries_one(
    named_leaf_pem: str, unnamed_leaf_pem: str
) -> None:
    """An attribute the document does not have is left off the table rather than rendered as an empty cell."""
    named = describe_pem(named_leaf_pem, CAP)[0]
    plain = describe_pem(unnamed_leaf_pem, CAP)[0]

    assert _fact(named, "Organisation") == "Example Ops"
    assert all(name != "Organisation" for name, _ in plain.facts)


# --------------------------------------------------------------------------------------------- time and flags


def test_an_expired_certificate_is_flagged_by_age(expired_leaf_pem: str) -> None:
    """`expired N day(s) ago`, computed from the `_utc` properties rather than from a naive datetime.

    The fixture expires exactly 30 days before `NOW`, so the count is asserted exactly. The validity row itself is
    asserted to end in `Z`: an offset-free rendering is what stops "is this expired yet?" from drifting by a machine's
    UTC offset, which is precisely the question an operator brings to this page.
    """
    report = describe_pem(expired_leaf_pem, CAP)[0]

    assert _flag_containing([report], "expired 30 day(s) ago")
    validity = _fact(report, "Validity (UTC)")
    assert validity.endswith("Z")
    assert validity.count("Z") == 2


def test_a_certificate_that_is_not_valid_yet_says_when(future_leaf_pem: str) -> None:
    """Not-yet-valid is a different sentence from expired, and both are needed.

    The day count is computed from the certificate rather than hard-coded: `inspect.py` measures whole days against
    `datetime.now(utc)`, so a fixture written as "9 days ahead" legitimately reads as 8 days some seconds later.
    Asserting the exact number here would make this test fail on wall-clock alone.
    """
    report = describe_pem(future_leaf_pem, CAP)[0]
    parsed = x509.load_pem_x509_certificate(future_leaf_pem.encode("ascii"))
    expected_days = (parsed.not_valid_before_utc - dt.datetime.now(dt.timezone.utc)).days

    flag = _flag_containing([report], "not valid until")
    assert f"{expected_days} day(s) from now" in flag
    assert parsed.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%SZ") in flag
    assert "expired" not in " ".join(report.flags)


def test_a_sha1_signed_certificate_is_written_down_rather_than_refused(sha1_leaf_pem: str) -> None:
    """SHA-1 is a finding here and a refusal on `/csr/sign` — the same fact, two postures.

    The fixture is a real SHA-1 signature (see `_sha1_signed_cert_pem`), so this asserts that `inspect.py` reads the
    AlgorithmIdentifier off the document instead of pattern-matching text, and that reading it does not raise.
    """
    reports = describe_pem(sha1_leaf_pem, CAP)

    assert len(reports) == 1
    assert _fact(reports[0], "Signature algorithm") == "Sha1Withrsaencryption / SHA1"
    assert _flag_containing(reports, "signed with SHA1")


def test_an_rsa_1024_certificate_is_reported_and_flagged_not_rejected(weak_leaf_pem: str) -> None:
    """The measured reason `ca.describe_ca` is not called.

    `keys.key_spec_for_public_key` answers RSA-1024 with `RSA-1024 is not an accepted key. Allowed: RSA 2048, RSA 3072,
    RSA 4096.` — a refusal, which is right on the signing path and useless on a reader. Here the size is *both* stated
    as a fact and named as a finding, and nothing is raised. This test is what stops a future "simplification" from
    routing `/inspect` through the issuer-side policy module.
    """
    reports = describe_pem(weak_leaf_pem, CAP)

    assert len(reports) == 1
    assert _fact(reports[0], "Public key") == "RSA 1024"
    flag = _flag_containing(reports, "RSA-1024 is not an accepted key")
    assert "mypki would not issue for this key, but it is reported here as it stands" in flag


def test_an_ed25519_certificate_is_labelled_and_its_hash_algorithm_says_not_modelled(
    ed_leaf_pem: str,
) -> None:
    """`signature_hash_algorithm` is None for Ed25519 (MEASURED), so the page says so instead of inventing a hash.

    Two measured facts in one test: the key label comes from the class name (`Ed25519`) because no table in `inspect.py`
    knows this key type, and the policy refusal is again a flag rather than an exception.
    """
    reports = describe_pem(ed_leaf_pem, CAP)

    assert _fact(reports[0], "Public key") == "Ed25519"
    assert _fact(reports[0], "Signature algorithm") == "Ed25519 / NOT MODELLED"
    assert _flag_containing(reports, "Ed25519PublicKey is not an accepted key")


def test_general_names_mypki_would_not_issue_are_surfaced_not_hidden(odd_san_leaf_pem: str) -> None:
    """An email and a URI general name survive the description.

    Re-running the paste through `validators.parse_sans` would be the tempting implementation and it is the wrong one:
    those are exactly the entries the operator came to look at, and mypki's issuer-side rules drop them. Asserted as an
    extra row so a future refactor that "reuses the validator" fails here rather than silently shrinking the table.
    """
    report = describe_pem(odd_san_leaf_pem, CAP)[0]

    assert _fact(report, "Subject Alternative Names") == "odd.example"
    odd = _fact(report, "SAN entries mypki would not issue")
    assert "RFC822Name: ops@example.test" in odd
    assert "UniformResourceIdentifier: https://example.test/x" in odd


# -------------------------------------------------------------------------------------------------- a root


def test_a_self_signed_leaf_gets_the_sentence_a_root_does_not(self_signed_leaf_pem: str, root_pem: str) -> None:
    """Two documents with identical subject and issuer, two different findings.

    This is the wording bug `/inspect` actually shipped with: every self-signed certificate got the leaf sentence, which
    accused this host's own root of not being a CA. Asserted as a pair rather than one case, because the only thing that
    makes the distinction correct is that both arms exist and neither leaks into the other.
    """
    leaf = describe_pem(self_signed_leaf_pem, CAP)[0]
    root = describe_pem(root_pem, CAP)[0]

    assert _flag_containing([leaf], "self-signed and not marked as a CA")
    assert "self-signed root" not in " ".join(leaf.flags)
    assert _flag_containing([root], "self-signed root")
    assert "not marked as a CA" not in " ".join(root.flags)


def test_an_ip_san_is_rendered_as_an_ip_not_as_a_name(ip_san_leaf_pem: str) -> None:
    """An IP general name is labelled, because `10.0.0.7` beside `ip.example` would otherwise read as a DNS entry.

    The failure this pins is the quiet one: rendering an IPAddress through the same join as the DNS names produces a
    plausible-looking SAN row that an operator cannot distinguish from a host name, and a wildcard rule they wrote for
    names then looks satisfied when it is not.
    """
    report = describe_pem(ip_san_leaf_pem, CAP)[0]

    assert _fact(report, "Subject Alternative Names") == "ip.example; IP 10.0.0.7"


def test_an_ec_certificate_is_labelled_with_its_curve_and_size(ec_leaf_pem: str) -> None:
    """`EC SECP256R1 (256 bits)` — the label cryptography reports, not a table inspect.py maintains.

    Asserted exactly because mypki's accepted specs are `ec-p256`/`ec-p384`: an operator comparing this row against
    `MYPKI_CA_KEY_SPEC` needs the curve name spelled out, and an EC certificate is the common case this page will be
    shown.
    """
    report = describe_pem(ec_leaf_pem, CAP)[0]

    assert _fact(report, "Public key") == "EC SECP256R1 (256 bits)"
    assert not [flag for flag in report.flags if "not an accepted key" in flag], "ec-p256 is accepted; no flag expected"


def test_a_certificates_facts_and_a_requests_facts_come_from_the_same_SAN_reader(
    odd_san_leaf_pem: str, odd_san_csr_pem: str
) -> None:
    """The odd-name row exists for a request too.

    `_sans_words` serves both documents only because `x509.CertificateSigningRequest` exposes `.extensions` as well
    (MEASURED). A refactor that reached for a certificate-only helper would drop this row from request pages, which is
    where an operator most often pastes an openssl request carrying an email SAN.
    """
    cert = describe_pem(odd_san_leaf_pem, CAP)[0]
    csr = describe_pem(odd_san_csr_pem, CAP)[0]

    assert "RFC822Name: ops@example.test" in _fact(cert, "SAN entries mypki would not issue")
    assert "RFC822Name: ops@example.test" in _fact(csr, "SAN entries mypki would not issue")


def test_a_request_with_an_unacceptable_key_is_flagged_as_well_as_described(weak_csr_pem: str) -> None:
    """The key policy finding is asserted on a request as well as on a certificate.

    `/csr/sign` refuses this request outright for the same reason, and the flag's wording ("mypki would not issue for
    this key") is what tells the operator that the refusal they saw was about the key rather than about the subject.
    """
    reports = describe_pem(weak_csr_pem, CAP)

    assert _fact(reports[0], "Public key") == "RSA 1024"
    assert _flag_containing(reports, "RSA-1024 is not an accepted key")
    assert _fact(reports[0], "Signature verifies against its own key") == "yes"


def test_a_sha1_signed_request_is_flagged_with_the_sign_pages_wording(sha1_csr_pem: str) -> None:
    """A request gets "refuses to sign a request carrying it", not the certificate sentence.

    The two sentences point at different actions an operator can take (re-issue the request vs. re-issue the
    certificate), which is why they are asserted as different strings rather than as one shared flag.
    """
    reports = describe_pem(sha1_csr_pem, CAP)

    assert _fact(reports[0], "Signature algorithm") == "Sha1Withrsaencryption / SHA1"
    assert _flag_containing(reports, "mypki refuses to sign a request carrying it")


def test_a_root_certificate_is_named_as_a_ca_and_flagged_as_self_signed(root_pem: str) -> None:
    """The host's own CA reads as what it is: a CA, self-issued, with nothing above it.

    The wording matters more than the data. Before this was measured, every root — including this host's own — got the
    sentence meant for a self-signed *leaf* ("self-signed and not marked as a CA"), which reads as an accusation against
    a document that is behaving exactly as a root should.
    """
    reports = describe_pem(root_pem, CAP)

    assert len(reports) == 1
    report = reports[0]
    assert _fact(report, "Type") == "CA certificate"
    assert _fact(report, "BasicConstraints") == "CA:TRUE pathLength:0"
    assert _fact(report, "Can sign other certificates") == "yes — this document claims to be a CA"
    assert _fact(report, "Self-issued") == "subject and issuer are identical"
    assert _flag_containing(reports, "self-signed root")
    assert not [flag for flag in report.flags if "not a CA" in flag]


def test_a_ca_without_a_path_length_limit_reads_as_unlimited(unlimited_root_pem: str) -> None:
    """`path_length is None` is a third state, and an empty cell is not how it should be shown."""
    report = describe_pem(unlimited_root_pem, CAP)[0]

    assert _fact(report, "BasicConstraints") == "CA:TRUE pathLength:unlimited"


def test_a_leaf_and_a_root_in_one_paste_are_distinguished_without_guessing(leaf_pem: str, root_pem: str) -> None:
    """What an operator actually pastes when a chain got copied together.

    `/csr/sign` refuses a multi-block paste because signing the wrong block is destructive. Here describing both *is*
    the feature — and this test pins the difference down so the two pages cannot drift into one implementation.
    """
    reports = describe_pem(leaf_pem + root_pem, CAP)

    assert [report.kind for report in reports] == ["certificate", "certificate"]
    assert _fact(reports[0], "Type") == "end-entity certificate"
    assert _fact(reports[1], "Type") == "CA certificate"


# --------------------------------------------------------------------------------------------- a request


def test_a_request_carries_the_rows_only_a_ca_can_give_it(csr_pem: str) -> None:
    """Validity, serial and issuer are stated as absent rather than omitted.

    A reader who finds no expiry row on a request page asks "why has this page forgotten the dates?"; the answer belongs
    on the page. Same for `.fingerprint()`, which `cryptography` does not give a request (MEASURED: AttributeError).
    """
    reports = describe_pem(csr_pem, CAP)

    assert len(reports) == 1
    report = reports[0]
    assert report.kind == "certificate request"
    assert _fact(report, "Type") == "certification request (PKCS#10) — not yet a certificate"
    assert _fact(report, "Validity (UTC)").startswith("none — a CA sets")
    assert _fact(report, "Serial (hex)").startswith("none — a CA assigns")
    assert _fact(report, "Issuer").startswith("none — a request names no issuer")
    assert "no `.fingerprint()`" in _fact(report, "SHA-256 fingerprint")
    assert _fact(report, "Signature verifies against its own key") == "yes"
    assert report.flags == []


def test_a_tampered_request_is_flagged_by_its_own_signature(tampered_csr_pem: str) -> None:
    """`is_signature_valid` is read as a property (MEASURED).

    Called as a method it would return a truthy bound method and every request would look signed — the kind of bug that
    ships as "the CA accepts anything". The tampered fixture parses as a CSR, so this asserts on the signature row
    rather than on the parser.
    """
    report = describe_pem(tampered_csr_pem, CAP)[0]

    assert _fact(report, "Signature verifies against its own key") == "no"
    assert _flag_containing([report], "signature does not verify")


def test_a_request_that_asks_to_be_a_ca_says_so_and_is_still_described(ca_wannabe_csr_pem: str) -> None:
    """`/csr/sign` refuses this request outright; `/inspect` names the ambition and keeps reading.

    Asserted as a flag *plus* a full table: a page that refused here would be useless for the operator who is trying to
    work out why their openssl-generated request was rejected.
    """
    reports = describe_pem(ca_wannabe_csr_pem, CAP)

    assert _fact(reports[0], "BasicConstraints") == "CA:TRUE pathLength:unlimited"
    flag = _flag_containing(reports, "this request asks to be a CA")
    assert "`/csr/sign` would refuse it" in flag
    assert len(reports[0].facts) > 5


# ---------------------------------------------------------------------------- unreadable and unknown input


def test_a_pem_body_that_is_not_base64_is_reported_as_unreadable() -> None:
    """A truncated paste is the most common real failure, and it gets a sentence about pasting."""
    reports = describe_pem(f"{CSR_PEM_BEGIN}\nnot!! base64@@@\n{CSR_PEM_END}\n", CAP)

    assert len(reports) == 1
    assert reports[0].kind == "unreadable"
    assert reports[0].pem is None
    assert _flag_containing(reports, "not valid base64")
    assert "the paste was probably truncated" in reports[0].flags[0]


def test_a_body_that_decodes_but_is_not_der_is_still_described() -> None:
    """A block that hashes but does not parse is a different failure from a broken base64.

    `sha256_of_der` is present here on purpose: the bytes *are* known, and an operator comparing a fingerprint against a
    client's display can still use them even though no certificate came out of the block.
    """
    reports = describe_pem("-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n", CAP)

    assert reports[0].kind == "unreadable"
    assert reports[0].sha256_of_der == hashlib.sha256(b"ABC").hexdigest()


def test_an_armour_kind_mypki_does_not_know_is_named_and_stopped_at() -> None:
    """`-----BEGIN TRUSTED CERTIFICATE-----` is OpenSSL's own extension of the format, not a mypki type.

    Guessing here would be the friendly thing to do and the dishonest one: the honest answer is "I do not know this
    block type", which is also why a private-key-looking armour never reaches a parser (see `_is_key_armour`).
    """
    reports = describe_pem("-----BEGIN TRUSTED CERTIFICATE-----\nQUJD\n-----END TRUSTED CERTIFICATE-----\n", CAP)

    assert reports[0].kind == "unrecognised"
    assert reports[0].armour == "TRUSTED CERTIFICATE"
    assert _flag_containing(reports, "does not know this block type")


@pytest.mark.parametrize("paste", ["hello world", "", "   \n  \n"])
def test_a_paste_with_no_armour_reports_itself_as_input(paste: str) -> None:
    """Not a certificate, not an error — an input with no block in it, counted in characters."""
    reports = describe_pem(paste, CAP)

    assert len(reports) == 1
    assert reports[0].kind == "nothing readable"
    assert reports[0].armour == ""
    assert _fact(reports[0], "Input") == f"{len(paste)} character(s), no `-----BEGIN … -----` block found"
    assert _flag_containing(reports, "nothing to report")


def test_pem_body_sha256_returns_none_when_there_is_no_der_to_hash(leaf_pem: str) -> None:
    """Garbage in, `None` out — not a hash of garbage.

    The second half is the one a careless implementation gets wrong: hashing the *whole* PEM (armour included) would
    make every fingerprint depend on line width and line endings.
    """
    assert pem_body_sha256("not!! base64@@@") is None
    assert pem_body_sha256(leaf_pem) is None


# --------------------------------------------------------------------------------- private keys, named only


def test_a_private_key_is_named_and_never_read(plain_key_pem: str) -> None:
    """The whole answer to a key: it is a key, nothing from it was opened, and nothing comes back.

    Asserted three ways because one assertion would not be enough. `pem is None` (the page renders no block), every fact
    and flag free of the key's base64 (no accidental echo in prose), and `sha256_of_der is None` — hashing a private key
    would put a stable identifier for it in a log line, which is its own kind of leak.
    """
    reports = describe_pem(plain_key_pem, CAP)

    assert len(reports) == 1
    report = reports[0]
    assert report.kind == "private key"
    assert report.armour == "PRIVATE KEY"
    assert report.pem is None
    assert report.sha256_of_der is None
    assert _fact(report, "Type") == "private key (`PRIVATE KEY`)"
    assert _fact(report, "Body") == "not read"
    assert _flag_containing(reports, "mypki did not open it")

    body_lines = [line for line in plain_key_pem.splitlines()[1:-1] if line]
    assert all(line not in _everything(report) for line in body_lines)


def test_an_encrypted_key_is_not_asked_for_a_passphrase(encrypted_key_pem: str) -> None:
    """MEASURED: `load_pem_private_key(..., password=None)` on an encrypted key raises TypeError.

    That TypeError is this page's one opportunity to prompt for a secret, and the naming branch means it never happens:
    no load attempt, no decrypt attempt, no passphrase field. The test asserts the absence of the exception as
    behaviour.
    """
    reports = describe_pem(encrypted_key_pem, CAP)

    assert reports[0].kind == "private key"
    assert reports[0].armour == "ENCRYPTED PRIVATE KEY"
    assert reports[0].pem is None


@pytest.mark.parametrize(
    ("fixture_name", "armour"),
    [
        ("plain_key_pem", "PRIVATE KEY"),
        ("encrypted_key_pem", "ENCRYPTED PRIVATE KEY"),
        ("ec_key_pem", "EC PRIVATE KEY"),
    ],
)
def test_every_private_key_spelling_stops_at_the_same_branch(
    request: pytest.FixtureRequest, fixture_name: str, armour: str
) -> None:
    """PKCS#8, PKCS#8-encrypted and SEC 1 all end in `PRIVATE KEY`, and the suffix rule catches them.

    The explicit set in `inspect.KEY_KINDS` documents what was measured; the suffix is what keeps the rule safe for a
    spelling this module has never seen (`DSA PRIVATE KEY`, a future one). Both are asserted because the set alone would
    pass against today's four spellings and fail quietly against tomorrow's.
    """
    pem = request.getfixturevalue(fixture_name)
    reports = describe_pem(pem, CAP)

    assert reports[0].kind == "private key"
    assert reports[0].armour == armour
    assert reports[0].pem is None
    assert reports[0].sha256_of_der is None


def test_a_key_paste_is_not_handed_to_a_parser_even_when_the_armour_is_unusual() -> None:
    """An unknown `… PRIVATE KEY` spelling is still a key, not an "unrecognised" block to be decoded.

    The failure this guards against is subtle: falling through to "unrecognised" is *safe today* because nothing is
    parsed, but it is the branch where a future "helpful" parser would be added — and that is where a key would get
    opened.
    """
    reports = describe_pem("-----BEGIN DSA PRIVATE KEY-----\nQUJDRA==\n-----END DSA PRIVATE KEY-----\n", CAP)

    assert reports[0].kind == "private key"
    assert reports[0].pem is None


# --------------------------------------------------------------------------------- how many blocks, and how big


def test_blocks_past_the_cap_are_counted_rather_than_dropped(csr_pem: str) -> None:
    """`MAX_BLOCKS_TO_TRY` bounds the rendering, not the honesty.

    A paste of ten blocks gets eight descriptions plus one row naming the two that were not parsed. Silently dropping
    them would be the quiet edit this project refuses elsewhere (see `settingsfile.preserve_unmanaged`).
    """
    paste = csr_pem * (MAX_BLOCKS_TO_TRY + 2)
    reports = describe_pem(paste, 1_000_000)

    assert len(reports) == MAX_BLOCKS_TO_TRY + 1
    assert [report.kind for report in reports[:MAX_BLOCKS_TO_TRY]] == ["certificate request"] * MAX_BLOCKS_TO_TRY
    surplus = reports[-1]
    assert surplus.kind == "not described"
    assert _fact(surplus, "Input") == "2 further block(s) in the same paste were not parsed"
    assert _flag_containing([surplus], f"beyond the first {MAX_BLOCKS_TO_TRY}")


def test_an_oversized_paste_is_the_one_thing_this_page_refuses() -> None:
    """Size is not a content judgement: it is the input this page cannot hold, and it raises before any parser runs.

    `RequestTooLargeError` names `MYPKI_MAX_CSR_CHARS` (the knob an operator can change) rather than a byte count with
    no remedy attached. Asserted on the message *and* on `exc.limit`, because the error page renders the limit.
    """
    with pytest.raises(RequestTooLargeError) as excinfo:
        describe_pem("x" * (CAP + 8_000), CAP)

    assert "MYPKI_MAX_CSR_CHARS" in str(excinfo.value)
    assert excinfo.value.limit == CAP


def test_the_size_check_runs_before_anything_is_parsed() -> None:
    """An oversized paste that also contains a valid certificate must not be described at all.

    The order is the promise: describing first and measuring afterwards would mean holding (and rendering) more bytes
    than this app says it will hold, which is what the guard exists to prevent.
    """
    with pytest.raises(RequestTooLargeError):
        describe_pem("-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n" + "y" * (CAP + 10), CAP)


# ------------------------------------------------------------------------------------------------ redaction


def test_redaction_leaves_a_certificate_exactly_as_it_was(leaf_pem: str, root_pem: str) -> None:
    """Public material is echoed untouched, and the count says so out loud.

    A certificate is already on the wire on every TLS connection; rewriting it would make the page's own fingerprint row
    impossible to line up against the text above it.
    """
    echo, count = redact_private_key_bodies(leaf_pem + root_pem)

    assert echo == leaf_pem + root_pem
    assert count == 0


def test_redaction_replaces_only_the_body_of_a_key(plain_key_pem: str) -> None:
    """Armour lines stay, base64 goes, and the marker is the module's own string.

    The BEGIN/END lines are the fact an operator needs ("your paste contained a key"); the base64 is not. Asserting the
    armour as **present** is deliberate — it is the same pattern `test_no_key_leakage.py` asserts as absent, and the two
    files cover different requests (a GET sweep here, a POST-with-a-key there).
    """
    echo, count = redact_private_key_bodies(plain_key_pem)

    assert count == 1
    assert KEY_BODY_REDACTED in echo
    assert "-----BEGIN PRIVATE KEY-----" in echo
    assert "-----END PRIVATE KEY-----" in echo
    body_lines = [line for line in plain_key_pem.splitlines()[1:-1] if len(line) > 40]
    assert body_lines, "the fixture key has no long base64 lines to check"
    assert all(line not in echo for line in body_lines)


def test_redaction_counts_every_key_in_a_mixed_paste(leaf_pem: str, plain_key_pem: str, encrypted_key_pem: str) -> None:
    """Two keys are reported as two, and the certificate beside them is untouched.

    The count is what makes the rewrite visible on the page; a redaction nobody mentions is the quiet edit again.
    """
    paste = leaf_pem + plain_key_pem + encrypted_key_pem
    echo, count = redact_private_key_bodies(paste)

    assert count == 2
    assert leaf_pem in echo
    assert echo.count(KEY_BODY_REDACTED) == 2
    # Two key blocks means two BEGIN armour lines: the regex matches BEGIN only, so this counts blocks, not lines.
    assert ARMOUR_RE.findall(echo) == ["-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----"]


def test_redaction_survives_a_paste_with_no_armour_at_all() -> None:
    """Nothing to redact is not an error, and it does not invent a marker."""
    echo, count = redact_private_key_bodies("hello world")

    assert echo == "hello world"
    assert count == 0


# --------------------------------------------------------------------------------------------- the HTTP page


def _post_paste(client, paste: str):
    """POST a paste with the client's own session token."""
    return client.post("/inspect", data={"csrf_token": csrf_token(client, "/inspect"), "pem_paste": paste})


def test_the_get_renders_an_empty_form_and_invents_no_report(session_client) -> None:
    """A GET is not evidence that anybody pasted anything.

    Same rule `settings_page` follows by refusing to claim a save on a GET: fabricating a report would put words on the
    page about a document nobody supplied. The form itself must still be there, or the page is not usable.
    """
    response = session_client.get("/inspect")

    assert response.status_code == 200
    assert "Nothing pasted yet" in response.text
    assert 'name="pem_paste"' in response.text
    assert '<th scope="row">' not in response.text
    assert "end-entity certificate" not in response.text


def test_a_pasted_certificate_comes_back_with_its_own_table(session_client, leaf_pem: str) -> None:
    """The finding and the bytes it describes are on screen together.

    The echo is the point of the design: an operator reading "expired 30 day(s) ago" has to be able to see the validity
    rows beside it. Asserted as a rendered table plus the copy affordance, because a report without a copyable block is
    a report the operator has to retype.
    """
    response = _post_paste(session_client, leaf_pem)

    assert response.status_code == 200
    assert "end-entity certificate" in response.text
    assert "CN=leaf.example" in response.text
    assert "not a CA" in response.text
    assert "RSA 2048" in response.text
    assert 'class="pem"' in response.text
    assert 'id="pem-1"' in response.text
    assert 'data-mypki-copy="pem-1"' in response.text
    assert _body_of(leaf_pem)[:64] in response.text


def test_the_pages_own_limits_are_stated_by_the_page_itself(session_client, settings: Settings) -> None:
    """The hint names the cap this process will actually apply.

    A page that promises "up to 32 000 characters" while `MYPKI_MAX_CSR_CHARS` is set to 4096 sends operators looking
    for a bug rather than at a setting. Asserted against the fixture's own settings object.
    """
    response = session_client.get("/inspect")

    assert f"Up to {settings.max_csr_chars} characters" in response.text
    assert f"{MAX_BLOCKS_TO_TRY} blocks are described" in response.text


def test_a_pasted_root_reads_back_as_a_root(session_client, root_pem: str) -> None:
    """The harness-shaped case: this host's own CA, pasted into its own reader.

    `not a CA` must be **absent** — that sentence belongs to a leaf, and a root card carrying it is the wording bug this
    page actually had before it was measured.
    """
    response = _post_paste(session_client, root_pem)

    assert response.status_code == 200
    assert "CA:TRUE pathLength:0" in response.text
    assert "self-signed root" in response.text
    # The lede names `not a CA` as an example of a finding this page reports (markup, `<em>` inside it), so the honest
    # assertion is about the rendered finding row rather than about the phrase appearing somewhere on the page.
    findings = re.search(r'<ul class="findings">(.*?)</ul>', response.text, re.DOTALL)
    assert findings is not None, "the root card rendered no findings list"
    assert "not a CA" not in findings.group(1)


def test_two_blocks_in_one_paste_render_two_tables(session_client, leaf_pem: str, csr_pem: str) -> None:
    """A certificate and a request together get two tables, each with its own copy button."""
    response = _post_paste(session_client, leaf_pem + csr_pem)

    assert response.status_code == 200
    assert 'id="pem-1"' in response.text
    assert 'id="pem-2"' in response.text
    assert "end-entity certificate" in response.text
    assert "certification request (PKCS#10)" in response.text


def test_junk_answers_200_with_a_plain_sentence(session_client) -> None:
    """Nothing readable is an answer, not a failure.

    400 here would send the operator to the error page and away from the sentence that tells them what to paste; the
    whole posture of this page is that a bad paste gets a description rather than a refusal.
    """
    response = _post_paste(session_client, "hello world")

    assert response.status_code == 200
    assert "nothing readable" in response.text
    assert "nothing to report" in response.text


def test_a_pasted_private_key_is_named_and_its_base64_does_not_come_back(session_client, plain_key_pem: str) -> None:
    """The load-bearing security assertion of this file.

    `render_inspect` echoes the paste, and a probe on this build proved that a key's base64 came back verbatim before
    `redact_private_key_bodies` existed. This test is what keeps that fixed: the marker appears, the warning names how
    many blocks were filtered, and not one base64 line of the key survives in the response body.

    The armour pattern is asserted as **present** here on purpose — the redaction deliberately keeps BEGIN/END so the
    operator can see a key was in the paste. `test_no_key_leakage.py` asserts zero armour across ordinary GETs; this
    file owns the case where an operator pastes a key, and there the honest check is the base64, not the armour line.
    """
    response = _post_paste(session_client, plain_key_pem)

    assert response.status_code == 200
    assert KEY_BODY_REDACTED in response.text
    assert "private-key block(s) were in your paste" in response.text
    assert "private key" in response.text
    body_lines = [line for line in plain_key_pem.splitlines()[1:-1] if len(line) > 40]
    assert body_lines, "the fixture key has no long base64 lines to check"
    assert all(line not in response.text for line in body_lines)
    assert ARMOUR_RE.search(response.text) is not None


def test_an_ordinary_response_carries_no_private_key_armour(session_client, leaf_pem: str, csr_pem: str) -> None:
    """Certificates and requests echo whole; neither brings armour with it.

    Pairs with the test above so the two halves of the rule are both pinned: keys are filtered, public blocks are not,
    and a page that leaks `-----BEGIN … PRIVATE KEY` in an ordinary paste fails here rather than in review.
    """
    for paste in (leaf_pem, csr_pem, leaf_pem + csr_pem):
        response = _post_paste(session_client, paste)

        assert response.status_code == 200
        assert ARMOUR_RE.findall(response.text) == []


def test_an_oversized_paste_names_mypkis_own_knob_and_not_starlettes(session_client, settings: Settings) -> None:
    """413 naming `MYPKI_MAX_CSR_CHARS`, with starlette's bare JSON message absent.

    The margin is `+ 9000` characters rather than `+ 1` because the limit is inclusive (measured in
    `test_csr_validate.py`) and a legitimate knob value must not turn this test into a passing-by-accident case.
    """
    paste = f"{CSR_PEM_BEGIN}\n{'A' * 4000}\n{CSR_PEM_END}\n" + "y" * settings.max_csr_chars

    response = _post_paste(session_client, paste)

    assert response.status_code == 413
    assert "MYPKI_MAX_CSR_CHARS" in response.text
    assert STARLETTE_SIZE_MESSAGE not in response.text


def test_a_post_without_a_token_is_refused_before_the_paste_is_read(client) -> None:
    """CSRF first, even on a page that writes nothing.

    Asserted two ways: the refusal names CSRF, and the paste is **not** echoed — proof that `require_csrf` runs before
    `describe_pem`, which is what keeps this route from becoming a free PEM oracle for an attacker who can only make a
    victim's browser send a form.
    """
    pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"
    response = client.post("/inspect", data={"pem_paste": pem})

    assert response.status_code == 400
    assert "CSRF" in response.text
    assert "nothing readable" not in response.text


def test_the_rejections_carry_the_same_security_headers_as_the_successes(session_client, settings: Settings) -> None:
    """An error page is still a page (`/inspect`'s 413 and 400 are rendered by the same handlers as its 200).

    `test_views.py` covers the GET headers for every page in `PAGES`; this covers the two paths that only `/inspect`
    produces from a paste, because header lists duplicated between an exception handler and a middleware are exactly the
    lists that drift.
    """
    oversized = _post_paste(session_client, "y" * (settings.max_csr_chars + 8192 + 10_000))
    no_token = session_client.post(
        "/inspect",
        data={"pem_paste": "hello"},
        headers={"cookie": ""},
    )

    for response in (oversized, no_token):
        assert response.status_code in (400, 413)
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "unsafe-inline" not in response.headers["content-security-policy"]


def test_the_page_states_what_it_cannot_tell_you(session_client) -> None:
    """No chain verification, no revocation, findings that are not gates, keys that are not opened.

    These four sentences are the page's honesty contract, and they are asserted as rendered text rather than as a
    docstring because a reader only ever sees the page. If any of them is removed, an operator is left to infer a
    guarantee this app does not provide. From 0.7.0 this host *does* publish a CRL and answer OCSP — but `/inspect`
    consults neither: it reads the pasted document and nothing else, so "valid" here still means only "not expired,
    according to this document", including for a certificate this very host revoked.
    """
    text = session_client.get("/inspect").text

    assert "It does not verify a chain" in text
    assert "It does not know about revocation" in text
    assert "Its findings are not gates" in text
    assert "A private key is named and not opened" in text


def test_the_findings_are_rendered_as_findings_not_as_form_errors(session_client, expired_leaf_pem: str) -> None:
    """`.finding` rows under a table, not the amber "fix this and submit again" block.

    `.form-errors` promises nothing was written and asks for another submission; a finding says something about a
    document and asks for nothing. The distinction is a CSS-class fact with a real consequence, so it is asserted as
    markup.
    """
    response = _post_paste(session_client, expired_leaf_pem)

    assert response.status_code == 200
    assert 'class="findings"' in response.text
    assert 'class="finding"' in response.text
    assert "form-errors" not in response.text
    assert "expired 30 day(s) ago" in response.text


def test_a_clean_certificate_says_so_without_claiming_it_is_trusted(session_client, csr_pem: str) -> None:
    """The no-findings arm exists, and its wording stops short of a guarantee.

    A CSR with an accepted key and a valid signature has nothing to flag; the sentence that fills the gap must not read
    as "verified", because nothing on this page verified anything.
    """
    response = _post_paste(session_client, csr_pem)

    assert response.status_code == 200
    assert "No findings" in response.text
    assert "not a statement that it is trusted" in response.text


def test_the_inspect_page_needs_no_ca(client_without_ca) -> None:
    """`/inspect` works on a host that has never run `mypki init-ca`.

    It describes text, not this server's state, so it is the page an operator reaches for *before* they have a CA — and
    the one page whose usefulness must not depend on the app having a key to lose.
    """
    response = client_without_ca.post(
        "/inspect",
        data={"csrf_token": csrf_token(client_without_ca, "/inspect"), "pem_paste": "hello world"},
    )

    assert response.status_code == 200
    assert "nothing readable" in response.text
    assert "Run `mypki init-ca`" not in response.text


# ----------------------------------------------------------------------------- the page's own furniture


def test_the_paste_card_has_the_blue_settings_style_title_and_the_page_has_no_lede(session_client) -> None:
    """`Paste PEM` is a `.section-heading` above the paste card, as on /settings; only the form sits under the title."""
    page = session_client.get("/inspect").text

    assert "<h1>Inspect a PEM</h1>" in page
    assert 'class="lede"' not in page
    assert '<h2 class="section-heading" id="pem_paste_title">Paste PEM</h2>' in page
    assert page.count(">Paste PEM<") == 1
    assert 'aria-labelledby="pem_paste_title"' in page
    assert page.index("Paste PEM") < page.index('name="pem_paste"') < page.index("It does not verify a chain.")
