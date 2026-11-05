"""The chain mypki hands back: leaf first, then the CA, and a signature only the real CA key can produce.

page-map §3 step B promises two artifacts — the leaf PEM and a `chain_pem` an operator can install from one file. Both
halves are worth pinning because both break quietly:

* **Order.** Leaf then CA, in that order (page-map §3): a client importing the file expects the certificate it
  authenticates first, and reversing the two yields a chain most TLS stacks reject with an error about the trust anchor
  rather than about the ordering. So "exactly two certificates, leaf first" is asserted after parsing, not by
  reading the
  concatenation.
* **Identity.** The CA entry must be *this* CA's certificate byte-for-byte. Appending a re-encoded copy, a different
  root, or an old archived root all produce a file that looks right and fails on a client.

`verify_directly_issued_by` ties the two together: it checks issuer-name equality **and** that the signature over the
leaf's DER was made by that certificate's key. MEASURED on cryptography 50.0.2, and pinned here because the spelling
differs per failure and a test should encode which one it saw:

  * genuine leaf → returns `None` (it does not return True; asserting truthiness would pass on any object);
  * wrong signing key, correct issuer name → raises `InvalidSignature`;
  * correct signing key, one byte of signed content changed → raises `InvalidSignature`;
  * correct key, different issuer name → raises `ValueError: Issuer certificate subject does not match certificate
    issuer.`

CSRs and certificates are built once per module (throwaway keys, pytest temporary directories) because these tests
assert X.509 relationships; a fresh CA per test would buy nothing and cost a third of a second each.
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mypki.ca import CaBundle, init_ca, load_ca
from mypki.csr import CsrFields, build_csr, parse_and_validate_csr
from mypki.keys import KeySpec
from mypki.signing import issue_certificate
from mypki.validators import SanSet

# Split rather than one flat list: `build_csr` classifies through `validators.py`, which refuses a bare address typed
# as a DNS entry (`'10.0.0.9' is an IP address encoded as a DNS name`) — so the SAN set has to be stated the way the
# validator splits it, exactly as `test_signing.py` does.
SAN_SET = SanSet(dns=("chain.internal",), ips=("10.0.0.9",))

#: The base baked into this file's one shared leaf (0.7.0). A name that is not the shipped default, so an
#: assertion that the CDP/AIA carry it cannot be satisfied by a default somewhere else.
CRL_BASE = "http://chain-tests.internal"


@pytest.fixture(scope="module")
def chain_ca(tmp_path_factory: pytest.TempPathFactory) -> CaBundle:
    """The issuing CA, in pytest's temporary storage — never an operator's data dir."""
    root = tmp_path_factory.mktemp("chain-ca")
    init_ca(
        root,
        common_name="mypki Chain Test CA",
        organization="mypki tests",
        country="XX",
        spec=KeySpec.from_string("rsa-2048"),
        days=3650,
    )
    return load_ca(root)


@pytest.fixture(scope="module")
def other_ca(tmp_path_factory: pytest.TempPathFactory) -> CaBundle:
    """A second, unrelated root — the archived-or-second-root state a real host ends up with."""
    root = tmp_path_factory.mktemp("chain-ca-other")
    init_ca(
        root,
        common_name="mypki Other Test CA",
        organization="mypki tests",
        country="XX",
        spec=KeySpec.from_string("rsa-2048"),
        days=3650,
    )
    return load_ca(root)


@pytest.fixture(scope="module")
def leaf_key() -> rsa.RSAPrivateKey:
    """The leaf's own private key, kept so a test can re-sign the leaf with it.

    The mutation `test_a_re_signed_copy_of_the_same_leaf_fails_verification` needs exactly this key: a copy signed
    by the
    subject's own key is the classic forged-leaf shape, and no other key produces it.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def issued(chain_ca: CaBundle, leaf_key: rsa.RSAPrivateKey):
    """One real leaf issued by `chain_ca`, shared by every test in this file.

    Module-scoped so each mutation starts from the *same* certificate: a fresh leaf per test would let a bug hide behind
    "this particular leaf happened to verify".
    """
    fields = CsrFields(common_name="chain.internal", sans=SAN_SET, organization="mypki tests", country="XX")
    details = parse_and_validate_csr(build_csr(fields, leaf_key), 32000)
    return issue_certificate(
        chain_ca, details, cert_type="server", validity_days=90, max_sans=100, crl_base_url=CRL_BASE
    )


# ---------------------------------------------------------------------------- verify_directly_issued_by


def test_the_issued_leaf_verifies_against_the_ca_that_signed_it(chain_ca: CaBundle, issued) -> None:
    """The happy path, asserted as the library's actual answer rather than as "the PEM looks plausible".

    `verify_directly_issued_by` returns **None** on success (MEASURED) — it raises on failure. Asserting `is None` is
    deliberate: asserting truthiness would pass against any object that merely failed to raise, including a check that
    never looked at the signature at all.
    """
    assert issued.cert.verify_directly_issued_by(chain_ca.cert) is None


def test_a_re_signed_copy_of_the_same_leaf_fails_verification(
    chain_ca: CaBundle, issued, leaf_key: rsa.RSAPrivateKey
) -> None:
    """Same subject, issuer, public key, serial and extensions — signed by the **leaf's own** key.

    This is the mutation that proves the check is cryptographic rather than cosmetic. The copy carries a perfectly valid
    signature (proof of possession by the subject it names); it simply is not this CA's. Anything that accepted it — a
    name comparison, a subject-string match, an issuer DN check — would report a forged leaf as trusted while `/ca` went
    on showing the correct root beside it.

    MEASURED: `InvalidSignature`, not False — cryptography raises rather than answering, so a test written as
    `assert not cert.verify_directly_issued_by(...)` would error out instead of passing.
    """
    copy = _rebuild(issued.cert, signer=leaf_key)

    assert copy.subject == issued.cert.subject
    assert copy.issuer == issued.cert.issuer
    assert copy.serial_number == issued.cert.serial_number
    assert copy.public_bytes(Encoding.DER) != issued.cert.public_bytes(Encoding.DER)
    # The issuer name still matches perfectly; only the signature differs.
    assert copy.issuer == chain_ca.cert.subject

    with pytest.raises(InvalidSignature):
        copy.verify_directly_issued_by(chain_ca.cert)


def test_a_single_byte_change_anywhere_in_the_signed_region_fails(chain_ca: CaBundle, issued) -> None:
    """The signature covers the leaf's DER, not a summary of it.

    One bit flipped inside the signed content (offset -32 from the end of the DER, i.e. inside the certificate body
    rather than in the trailing signature bytes): the result still parses as a well-formed certificate and then fails
    verification. Asserted at one offset with the mutation *measured* to change nothing structural — offsets that break
    the ASN.1 parse test the parser, not the signature check, and would stay green if the signature were never verified.
    """
    der = bytearray(issued.cert.public_bytes(Encoding.DER))
    original = bytes(der)
    der[-32] ^= 0x01

    tampered = x509.load_der_x509_certificate(bytes(der))

    assert bytes(der) != original
    assert tampered.subject == issued.cert.subject
    with pytest.raises(InvalidSignature):
        tampered.verify_directly_issued_by(chain_ca.cert)


def test_a_leaf_re_signed_by_the_real_ca_key_verifies_because_verification_knows_no_ledger(
    chain_ca: CaBundle, issued
) -> None:
    """The honest limit of `verify_directly_issued_by`: it checks a signature, not an issuance record.

    Re-signed by this CA's own key with a different serial, the copy **verifies** — because it is, cryptographically,
    a certificate this CA issued. Nothing in X.509 verification knows which serials mypki actually wrote to
    `issued.db`. From 0.7.0 this host publishes a CRL and answers OCSP (page-map §14/§15), and neither changes this
    result: the copy carries a serial this CA never wrote, so it is absent from the CRL by construction and OCSP answers
    UNKNOWN for it — which is not the same as a client being told "this certificate is fine". Stated as a passing
    assertion rather than left untested, because the tempting-but-false belief is that a CA can tell a client "I never
    signed that serial": it cannot, which is exactly why `MYPKI_VALIDITY_MAX_DAYS` is refused rather than clamped
    and why
    the record store is described as a convenience rather than an audit trail.

    Contrast with the two tests above: content changed *without* a matching signature fails; a signature made by the
    wrong key fails. A signature made by the right key over any content succeeds — that is what a signature means.
    """
    re_signed = _rebuild(issued.cert, signer=chain_ca.key, serial=issued.cert.serial_number + 1)

    assert re_signed.serial_number != issued.cert.serial_number
    assert re_signed.verify_directly_issued_by(chain_ca.cert) is None

    # …and the record store knows nothing about it: `verify` is not a lookup.
    # The copy verifies exactly as well as the certificate mypki recorded. Signature verification never consults
    # a ledger, and on 0.6.0 there was nothing else on this host to consult either. From 0.7.0 there IS a published CRL
    # and an OCSP responder (page-map §14/§15), but `verify_directly_issued_by` still does not consult them: revocation
    # checking is openssl's `-crl_check`, and plan §2/P-CRL-4 measured that openssl fetches nothing on its own.
    assert issued.cert.verify_directly_issued_by(chain_ca.cert) is None


def test_a_leaf_issued_by_a_different_ca_does_not_verify_against_this_one(
    chain_ca: CaBundle, other_ca: CaBundle, issued
) -> None:
    """Two real roots on one host; only the one that signed the leaf verifies it.

    The realistic state this models is a host with an archived or second root installed (page-map §6 archives rather
    than deletes). A client — or an operator reading `/ca` — must not be able to substitute either one, and the failure
    has to be loud: MEASURED as `ValueError: Issuer certificate subject does not match certificate issuer`, which is a
    *different* exception from the wrong-key case above. Asserting the message rather than catching broadly is what
    keeps the two distinct failures distinct in the test record.
    """
    assert issued.cert.verify_directly_issued_by(chain_ca.cert) is None

    with pytest.raises(ValueError, match="subject does not match"):
        issued.cert.verify_directly_issued_by(other_ca.cert)


def test_a_leaf_signed_with_the_wrong_key_but_the_right_issuer_name_fails_loudly(
    chain_ca: CaBundle, other_ca: CaBundle, issued
) -> None:
    """The issuer name is *not* enough, and that failure is `InvalidSignature` rather than a name mismatch.

    A leaf carrying this CA's exact subject string but signed by another root's private key is the shape of a
    mis-issued or spoofed certificate. Distinguishing it from the previous test proves both checks exist: name equality
    and signature validity are separate conditions, each with its own error.
    """
    forged = _rebuild(issued.cert, signer=other_ca.key)

    assert forged.issuer == chain_ca.cert.subject
    with pytest.raises(InvalidSignature):
        forged.verify_directly_issued_by(chain_ca.cert)


# --------------------------------------------------------------------------------- the chain_pem artifact


def test_chain_pem_parses_as_exactly_two_certificates_leaf_then_ca(chain_ca: CaBundle, issued) -> None:
    """Parsed as a client parses it, not string-matched (STYLE §9).

    `x509.load_pem_x509_certificates` is what a TLS stack does with the file. Asserting two certificates in
    leaf→CA order
    catches the reversed chain, an accidental third certificate (a stale archived root appended), and a body that holds
    one certificate with the other merely mentioned in text.
    """
    certs = list(x509.load_pem_x509_certificates(issued.chain_pem.encode("ascii")))

    assert len(certs) == 2, [cert.subject.rfc4514_string() for cert in certs]
    assert certs[0].subject == issued.cert.subject
    assert certs[0].serial_number == issued.cert.serial_number
    assert certs[1].subject == chain_ca.cert.subject


def test_the_ca_entry_in_the_chain_is_byte_equal_to_the_bundle_certificate(chain_ca: CaBundle, issued) -> None:
    """The second block is *this* CA's certificate byte for byte — not an equivalent re-encoding.

    Compared as DER rather than PEM text on purpose: two spellings of one certificate can differ in armour line width
    while the bytes are identical (see `_rearmour`'s measured behaviour in `csr.py`), and conversely a visually similar
    file whose DER differs is exactly the archive/restore mix-up `key_matches_certificate` exists to catch (README
    gotcha
    1). This is what makes "install the chain" mean installing one specific root.
    """
    certs = list(x509.load_pem_x509_certificates(issued.chain_pem.encode("ascii")))

    assert certs[1].public_bytes(Encoding.DER) == chain_ca.cert.public_bytes(Encoding.DER)
    assert certs[1].public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ) == chain_ca.cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    # `chain_pem` is literally `pem + <CA PEM>` (signing.py), so the tail assertion pins the concatenation itself.
    assert issued.chain_pem.endswith(chain_ca.cert.public_bytes(Encoding.PEM).decode("ascii"))


def test_the_leaf_pem_holds_one_certificate_and_the_chain_pem_holds_two(issued) -> None:
    """Armour **occurrences**, not lines.

    `text.count(marker)` is the honest form (see `conftest.pem_block_count`): a line-counting version answers 1 for two
    blocks placed on one line and cannot tell a chain from a single certificate at all. Asserted on both artifacts
    because the pair is the promise — `/download/<id>` serves one certificate, `<stem>-chain.pem` serves two.
    """
    assert issued.pem.count("-----BEGIN CERTIFICATE-----") == 1
    assert issued.pem.count("-----END CERTIFICATE-----") == 1
    assert issued.chain_pem.count("-----BEGIN CERTIFICATE-----") == 2
    assert issued.chain_pem.count("-----END CERTIFICATE-----") == 2
    assert issued.chain_pem.startswith(issued.pem)


def test_the_chain_contains_a_leaf_and_a_root_and_the_leaf_is_not_an_issuer(chain_ca: CaBundle, issued) -> None:
    """A guard against the profile bug rather than the parsing bug.

    If `BasicConstraints CA:TRUE` ever reached a leaf, this file would still parse as two certificates and every
    ordering
    test above would stay green while the issued certificate became a signing authority. Asserted here because this is
    where a reader looks at the chain as a whole rather than at one extension table.
    """
    certs = list(x509.load_pem_x509_certificates(issued.chain_pem.encode("ascii")))

    leaf_basic = certs[0].extensions.get_extension_for_class(x509.BasicConstraints).value
    root_basic = certs[1].extensions.get_extension_for_class(x509.BasicConstraints).value

    assert leaf_basic.ca is False
    assert leaf_basic.path_length is None
    assert root_basic.ca is True
    assert root_basic.path_length == 0


def test_the_chain_survives_being_written_out_and_read_back(
    chain_ca: CaBundle, issued, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """What an operator saves from `/download/<id>` is the same two certificates this file parsed.

    The download route serves `issued.chain_pem` unchanged (page-map §10), so writing it out and re-reading it is a
    round trip through the filesystem: newline translation on Windows, or an encoding assumption in a browser
    save, would
    show up here as a chain that no longer parses to two certificates. Written under pytest's temporary directory —
    mypki itself never writes a certificate anywhere (page-map §2).
    """
    target = tmp_path_factory.mktemp("chain-file") / "mypki-chain.pem"
    target.write_text(issued.chain_pem, encoding="ascii", newline="\n")

    reloaded = list(x509.load_pem_x509_certificates(target.read_bytes()))

    assert len(reloaded) == 2
    assert reloaded[0].serial_number == issued.cert.serial_number
    assert reloaded[1].public_bytes(Encoding.DER) == chain_ca.cert.public_bytes(Encoding.DER)


def test_the_leaf_is_not_valid_for_ever_and_the_root_outlives_it(chain_ca: CaBundle, issued) -> None:
    """Validity is the bound mypki has on a mistake that every client honours, asserted on both chain members.

    0.7.0 added a CRL and OCSP, so validity is no longer the *only* bound — but it remains the only one that needs no
    cooperation from the client: a CRL entry or an OCSP answer counts only for a client that consults one, and leaves
    issued before 0.7.0 carry no pointer to either (page-map §14).

    If the chain ever carried a CA whose `not_after` fell *before* the leaf's, the chain would be unusable while every
    per-certificate test stayed green: a leaf cannot outlive the root that vouches for it.
    """
    now = dt.datetime.now(dt.timezone.utc)

    assert issued.cert.not_valid_before_utc <= now < issued.cert.not_valid_after_utc
    assert chain_ca.cert.not_valid_after_utc > issued.cert.not_valid_after_utc


# ------------------------------------------------------------------------------------------------- helpers


def _rebuild(
    cert: x509.Certificate,
    *,
    signer: object,
    serial: int | None = None,
    issuer: x509.Name | None = None,
) -> x509.Certificate:
    """Copy a certificate's content field-for-field and sign it with a chosen key.

    Extensions are re-added with their original critical flags rather than dropped, so the copy differs from the
    original
    in exactly one way (STYLE §8): who signed it, and optionally which serial it carries. A `signer` that is a
    public key
    raises at build time, which is informative in its own right — but every call site here passes a private key.
    """
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(issuer or cert.issuer)
        .public_key(cert.public_key())
        .serial_number(cert.serial_number if serial is None else serial)
        .not_valid_before(cert.not_valid_before_utc)
        .not_valid_after(cert.not_valid_after_utc)
    )
    for extension in cert.extensions:
        builder = builder.add_extension(extension.value, critical=extension.critical)
    return builder.sign(private_key=signer, algorithm=hashes.SHA256())  # type: ignore[arg-type]
