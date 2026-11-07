"""The leaf profile as **data**: which extensions mypki puts on a certificate, and what it refuses to issue.

page-map §7 is the shortest and most load-bearing section in the spec: three hard-coded profiles (`server`, `client`,
`both`), CA-set extensions only, and **SAN as the single value copied from the request**. That last rule is the whole
reason this module exists — a CSR that could carry its own KeyUsage or ExtendedKeyUsage is a request that decides what
this CA certified, and `CA:TRUE` walking out of a leaf certificate is how a mini-CA becomes an open signing oracle.

So the profile is asserted through `leaf_extensions()`, which returns `(extension, critical)` pairs without a CA, a
keypair or a signature. An extension table is exactly the kind of claim that should be checkable without a cryptographic
side effect: if the profile ever drifts, it fails here as data rather than at a client that rejects the certificate.

Each negative case mutates **one** thing (STYLE §8): one cert_type string, one empty SAN set, one `max_sans`, one
`validity_days`, one `bundle.key`. Nothing hard-codes the version or the limits — the bounds come from `Settings` and
the refusal text is matched against the knob names an operator would actually go and change.

Two fixtures here are module-scoped on purpose (RSA-2048 CA, one keypair per algorithm): these tests assert X.509
semantics, and paying a third of a second per test for a CA nobody inspects would make this the slowest file in the
suite without asserting anything extra. They are still `tmp_path_factory` directories, so nothing lands in an operator's
data dir (STYLE §8).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import functools
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

from mypki import paths
from mypki.ca import CaBundle, init_ca, load_ca
from mypki.config import Settings
from mypki.csr import CsrDetails, CsrFields, build_csr, parse_and_validate_csr
from mypki.errors import CsrValidationError, MypkiError
from mypki.keys import KeySpec
from mypki.signing import CERT_TYPES, issue_certificate, leaf_extensions, signing_hash
from mypki.validators import SanSet, validity_days

DNS_SAN = SanSet(dns=("server.internal", "*.lab.internal"), ips=("10.0.0.7",))
NO_SAN = SanSet()

#: The base every leaf in this file is issued with (0.7.0). Deliberately **not** the shipped default: a distinct host
#: name is what makes `test_cdp_and_aia_point_at_the_configured_base` able to tell "the value came from the parameter"
#: apart from "the module fell back to its own default", which an assertion against `http://mypki.my.lab` cannot do.
CRL_BASE = "http://signing-tests.internal"


# ------------------------------------------------------------------------------------ module-scoped throwaways
# A CA and a leaf keypair are generated once per module rather than once per test: the assertions below are about
# extension semantics, and a real CA is needed only so AKI can be compared against the issuer's actual key.


@pytest.fixture(scope="module")
def signing_ca(tmp_path_factory: pytest.TempPathFactory) -> CaBundle:
    """A throwaway RSA-2048 root in pytest's temporary storage — never an operator's data dir."""
    root = tmp_path_factory.mktemp("signing-ca")
    init_ca(
        root,
        common_name="mypki Signing Test CA",
        organization="mypki tests",
        country="XX",
        spec=KeySpec.from_string("rsa-2048"),
        days=3650,
    )
    return load_ca(root)


@pytest.fixture(scope="module")
def rsa_leaf() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_p256_leaf() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def ec_p384_leaf() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


# --------------------------------------------------------------------------------------------- helpers


def _details(key: object, sans: SanSet = DNS_SAN) -> CsrDetails:
    """A validated `CsrDetails` for a key and SAN set, built the way the sign page builds one.

    Round-tripping through `build_csr` + `parse_and_validate_csr` rather than fabricating the dataclass: step B signs
    from a real parsed request, so a test that hand-rolled `CsrDetails` could pass against a shape the app never
    actually produces.
    """
    fields = CsrFields(common_name="server.internal", sans=sans, organization="mypki tests", country="XX")
    return parse_and_validate_csr(build_csr(fields, key), 32000)  # type: ignore[arg-type]


@functools.lru_cache(maxsize=1)
def _standin_public_key() -> rsa.RSAPublicKey:
    """One throwaway public key for profile-only assertions.

    Cached rather than generated per call because the extension table does not care *which* key it is derived from, and
    generating one RSA-2048 keypair per parametrised case would make this file cost more in key generation than in
    assertions. `leaf_extensions` is called directly here — no CA, no signature — which is exactly why it is exposed.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()


def _profile(
    cert_type: str,
    spec: KeySpec,
    sans: SanSet = DNS_SAN,
    leaf_key: object = None,
    ca: CaBundle | None = None,
    crl_base_url: str = CRL_BASE,
) -> list[tuple[x509.ExtensionType, bool]]:
    """`leaf_extensions` for one profile, as the pairs it really returns."""
    leaf_public = leaf_key.public_key() if leaf_key is not None else _standin_public_key()
    ca_public = ca.cert.public_key() if ca is not None else leaf_public
    return leaf_extensions(cert_type, spec, sans, leaf_public, ca_public, crl_base_url)  # type: ignore[arg-type]


def _usage_flags(usage: x509.KeyUsage) -> dict[str, object]:
    """A KeyUsage as a comparable mapping, with the keyAgreement-only bits marked when they are undefined.

    See `test_client_profile_is_digital_signature_only` for why reading `.encipher_only` unconditionally is not an
    option: cryptography raises instead of returning False. Marking those two as "undefined" keeps the whole flag
    profile assertable in one dict comparison, and keeps a future keyAgreement change visible.
    """
    flags: dict[str, object] = {
        name: getattr(usage, name)
        for name in (
            "digital_signature",
            "content_commitment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "key_encipherment",
        )
    }
    for name in ("encipher_only", "decipher_only"):
        flags[name] = getattr(usage, name) if usage.key_agreement else "undefined"
    return flags


def _whole_seconds(value: dt.datetime) -> dt.datetime:
    """Truncate to whole seconds — the precision X.509 validity fields actually carry.

    `not_valid_before` is encoded as UTCTime/GeneralizedTime, which has no sub-second component, so cryptography
    truncates on write (MEASURED: a `now()` carrying microseconds comes back with `microsecond == 0`). A test that
    compares an untruncated `now()` against the certificate is asserting a precision the format does not have.
    """
    return value.replace(microsecond=0)


def _from_cert(cert: x509.Certificate, cls: type) -> x509.ExtensionType | None:
    """One extension value read back out of an issued certificate, or None when absent.

    `cert.extensions` yields `Extension` wrappers rather than values, so the profile helper and the certificate need
    different lookups. Absent is reported as None for the same reason as in `_one`: it is a fact about the certificate.
    """
    with contextlib.suppress(x509.ExtensionNotFound):
        return cert.extensions.get_extension_for_class(cls).value
    return None


def _one(extensions: list[tuple[x509.ExtensionType, bool]], cls: type) -> tuple[x509.ExtensionType | None, bool | None]:
    """The `(value, critical)` pair for one extension class, or `(None, None)` when it is absent.

    Absent is a value here, not an error: "no SAN extension at all" and "an empty SAN extension" are different
    certificates, and a helper that raised would hide the first.
    """
    for value, critical in extensions:
        if isinstance(value, cls):
            return value, critical
    return None, None


# ---------------------------------------------------------------------------------- ExtendedKeyUsage as data


@pytest.mark.parametrize(
    ("cert_type", "expected"),
    [
        ("server", [ExtendedKeyUsageOID.SERVER_AUTH]),
        ("client", [ExtendedKeyUsageOID.CLIENT_AUTH]),
        ("both", [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
    ],
)
def test_extended_key_usage_is_exactly_the_profile(cert_type: str, expected: list[object]) -> None:
    """The EKU set is asserted as a list of OIDs in order, not as "the page says server".

    Order matters to some validators, and `both` carrying exactly two entries (not one, not three) is the difference
    between a dual-use certificate and an accident. Non-critical is RFC 5280 §4.2.2.9: a critical EKU makes a client
    that cannot parse the extension reject a certificate it could otherwise honour.
    """
    eku, critical = _one(_profile(cert_type, KeySpec.from_string("rsa-2048")), x509.ExtendedKeyUsage)

    assert eku is not None
    assert list(eku) == expected  # type: ignore[arg-type]
    assert critical is False


# --------------------------------------------------------------------------------------- BasicConstraints: leaf


@pytest.mark.parametrize("cert_type", CERT_TYPES)
def test_basic_constraints_declare_a_leaf_and_are_critical(cert_type: str) -> None:
    """`CA:FALSE`, `path_length=None`, critical.

    `ca is False` and `path_length is None` are asserted with `is`, not truthiness: `0` is falsy and a leaf carrying
    `pathLength:0` would read as "no certificates may follow this one" — true of a leaf but not the spelling clients
    expect (RFC 5280 §4.2.1.9). Critical because a non-critical BasicConstraints can be ignored by a client that
    would otherwise honour it, which is how a leaf gets used as an issuer.
    """
    basic, critical = _one(_profile(cert_type, KeySpec.from_string("rsa-2048")), x509.BasicConstraints)

    assert basic is not None
    assert basic.ca is False  # type: ignore[attr-defined]
    assert basic.path_length is None  # type: ignore[attr-defined]
    assert critical is True


def test_no_leaf_profile_ever_carries_cert_signing_or_crl_signing() -> None:
    """Every profile, every accepted key spec: `keyCertSign` and `crlSign` are both False.

    This is the assertion that makes "mypki signs end-entity certificates only" true on the issuing side as well as on
    the validation side (page-map §3 rule 6 refuses a CSR that *asks*). A leaf with keyCertSign can mint certificates,
    so one profile slipping through here turns this CA into an unbounded signing tree.

    Collected into a list of problems rather than raising on the first failure, because a regression usually hits two
    profiles at once and the diff should name both.
    """
    problems: list[str] = []
    for cert_type in CERT_TYPES:
        for spec_name in ("rsa-2048", "ec-p256"):
            usage, critical = _one(_profile(cert_type, KeySpec.from_string(spec_name)), x509.KeyUsage)
            if usage is None:
                problems.append(f"{cert_type}/{spec_name}: no KeyUsage extension at all")
                continue
            if usage.key_cert_sign:  # type: ignore[attr-defined]
                problems.append(f"{cert_type}/{spec_name}: keyCertSign is True")
            if usage.crl_sign:  # type: ignore[attr-defined]
                problems.append(f"{cert_type}/{spec_name}: crlSign is True")
            if critical is not True:
                problems.append(f"{cert_type}/{spec_name}: KeyUsage is not critical")

    assert problems == [], problems


@pytest.mark.parametrize(
    ("cert_type", "spec_name", "expected"),
    [
        ("server", "rsa-2048", True),
        ("both", "rsa-3072", True),
        ("client", "rsa-2048", False),
        ("server", "ec-p256", False),
        ("both", "ec-p384", False),
        ("client", "ec-p384", False),
    ],
)
def test_key_encipherment_only_where_the_key_can_actually_do_it(cert_type: str, spec_name: str, expected: bool) -> None:
    """True for RSA `server`/`both`, False for every EC leaf and for every `client`.

    `keyEncipherment` authorises the key to *wrap other keys*, which only RSA key-transport actually does; an EC
    public key cannot, so setting it certifies a capability the key does not have and profile-strict validators call
    that an error (RFC 5280 §4.2.1.3). Asserting both halves — True for RSA and False for EC — is what "we handled EC"
    means as a fact rather than as a claim.
    """
    usage, _ = _one(_profile(cert_type, KeySpec.from_string(spec_name)), x509.KeyUsage)

    assert usage is not None
    assert usage.key_encipherment is expected  # type: ignore[attr-defined]


def test_client_profile_is_digital_signature_only() -> None:
    """A client certificate authenticates its holder; it does not encipher traffic.

    Asking for anything else is how a smartcard certificate starts looking like a TLS-server certificate to every
    policy checker in the chain. Asserted as the full flag pattern rather than as "keyEncipherment is False", because
    the other flags are the same class of mistake.

    MEASURED on cryptography 50.0.2: `KeyUsage.encipher_only` and `.decipher_only` **raise** `ValueError: encipher_only
    is undefined unless key_agreement is true`. That is not a quirk to work around silently — it is RFC 5280's rule that
    those two bits only mean anything alongside keyAgreement, so `_usage_flags` reads them only when defined and records
    `"undefined"` otherwise. A profile that started setting keyAgreement would therefore show up here as a changed flag
    rather than as an exception.
    """
    usage, _ = _one(_profile("client", KeySpec.from_string("rsa-2048")), x509.KeyUsage)

    assert usage is not None
    flags = _usage_flags(usage)  # type: ignore[arg-type]
    expected = {
        "digital_signature": True,
        "content_commitment": False,
        "data_encipherment": False,
        "key_agreement": False,
        "key_cert_sign": False,
        "crl_sign": False,
        "key_encipherment": False,
        # Undefined unless keyAgreement is set, and this profile does not set it.
        "encipher_only": "undefined",
        "decipher_only": "undefined",
    }
    assert flags == expected


# ---------------------------------------------------------------------------- SAN copied; SKI/AKI; nothing else


def test_the_san_set_is_copied_verbatim_including_order_and_ip_general_names(signing_ca: CaBundle) -> None:
    """DNS names, the bare address and the wildcard arrive exactly as validated.

    A SAN list that passes validation but lands in a certificate differently from the one the operator typed is a
    mis-issuance, and this CA has no revocation to undo it (see `validators.py`). Order is asserted too: reordering a
    SAN set changes which name a strict client treats as primary.
    """
    extensions = _profile("server", KeySpec.from_string("rsa-2048"), DNS_SAN, ca=signing_ca)
    san, critical = _one(extensions, x509.SubjectAlternativeName)

    assert san is not None
    names = list(san)  # type: ignore[arg-type]
    dns = [name.value for name in names if isinstance(name, x509.DNSName)]
    ips = [str(name.value) for name in names if isinstance(name, x509.IPAddress)]

    assert dns == ["server.internal", "*.lab.internal"]
    assert ips == ["10.0.0.7"]
    assert critical is False


def test_no_san_means_no_san_extension_at_all() -> None:
    """An empty SAN set omits the extension rather than emitting an empty one.

    A client certificate may legitimately have no SAN (page-map §7), and an *empty* SubjectAlternativeName is not the
    same object as none: some validators reject a zero-length general-name sequence outright.
    """
    san, _ = _one(_profile("client", KeySpec.from_string("rsa-2048"), NO_SAN), x509.SubjectAlternativeName)

    assert san is None


def test_ski_and_aki_are_present_and_not_critical(signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey) -> None:
    """Both identifiers present, both non-critical, and AKI derived from the **issuer's** key.

    AKI comes from `bundle.cert.public_key()` rather than the leaf's — that is what lets a client pick the right anchor
    when several roots are installed (RFC 5280 §4.2.1.1). Asserted against freshly computed identifiers so a swap of
    leaf and CA key would fail here rather than at a client that cannot build a chain.
    """
    extensions = _profile("server", KeySpec.from_string("rsa-2048"), DNS_SAN, leaf_key=rsa_leaf, ca=signing_ca)

    ski, ski_critical = _one(extensions, x509.SubjectKeyIdentifier)
    aki, aki_critical = _one(extensions, x509.AuthorityKeyIdentifier)

    assert ski == x509.SubjectKeyIdentifier.from_public_key(rsa_leaf.public_key())
    assert ski_critical is False
    assert aki is not None
    expected_aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_ca.cert.public_key())
    assert aki.key_identifier == expected_aki.key_identifier  # type: ignore[attr-defined]
    assert aki_critical is False


def test_the_leaf_extension_set_is_exactly_the_documented_eight() -> None:
    """The full ordered table for a SAN-bearing profile: eight extensions, nothing else.

    `leaf_extensions` is the only place a leaf's extensions are decided, so "only what mypki decides" is enforced by
    construction rather than by a filter someone has to remember downstream. Asserting the exact class set **in order**
    is what catches the day someone adds one more extension and calls it harmless.

    Through 0.6.0 this list had six entries and its docstring said "no CRLDP or AIA". From 0.7.0 the last two entries
    are the CRL pointer and the OCSP pointer (answer 6 + U4), so the sentence is now false and the list has grown —
    which is exactly the failure mode this test exists to make loud: a profile change shows up here as data, in the
    order the builder actually appends them, rather than at a client that rejects the certificate.
    """
    extensions = _profile("both", KeySpec.from_string("rsa-3072"))

    assert [type(value) for value, _ in extensions] == [
        x509.BasicConstraints,
        x509.KeyUsage,
        x509.ExtendedKeyUsage,
        x509.SubjectAlternativeName,
        x509.SubjectKeyIdentifier,
        x509.AuthorityKeyIdentifier,
        x509.CRLDistributionPoints,
        x509.AuthorityInformationAccess,
    ]


def test_the_two_pointers_are_never_critical() -> None:
    """CDP and AIA both arrive non-critical, for the same reason EKU does.

    A critical extension makes a client that cannot parse it reject a certificate it could otherwise honour. The CDP
    and AIA are conveniences — a pointer to where revocation information happens to live — so making them critical
    would turn "this deployment publishes a CRL" into a hard validity requirement on every relying party.
    """
    extensions = _profile("server", KeySpec.from_string("rsa-2048"), DNS_SAN)

    _, cdp_critical = _one(extensions, x509.CRLDistributionPoints)
    _, aia_critical = _one(extensions, x509.AuthorityInformationAccess)

    assert cdp_critical is False
    assert aia_critical is False


def test_cdp_and_aia_point_at_the_configured_base() -> None:
    """Both URLs are the one configured base plus the suffix this app actually serves (plan §3, §6).

    Asserted against `CRL_BASE` rather than the shipped default: a distinct host name is the only way to tell "the
    value came from the parameter" apart from "the module fell back to its own default", which an assertion against
    `http://mypki.my.lab` cannot do. Both suffixes are spelled out here as literals because they are the routes
    `app.py` registers — if a route moves and this pointer does not, this test is where that shows up.
    """
    extensions = _profile("server", KeySpec.from_string("rsa-2048"), DNS_SAN)

    cdp, _ = _one(extensions, x509.CRLDistributionPoints)
    aia, _ = _one(extensions, x509.AuthorityInformationAccess)

    assert cdp is not None and aia is not None

    points = list(cdp)  # type: ignore[arg-type]
    assert len(points) == 1
    point = points[0]
    assert point.full_name is not None
    # `.value`, not `.uri`: cryptography 50 spells every GeneralName's payload as `value`.
    assert [name.value for name in point.full_name] == [f"{CRL_BASE}/crl.pem"]
    # `reasons=None` and `crl_issuer=None`: the whole-CRL form. A scoped point would be a second claim this app does
    # not make, and §4 of the plan is explicit that no IssuingDistributionPoint accompanies it either.
    assert point.crl_issuer is None
    assert point.reasons is None

    descriptions = list(aia)  # type: ignore[arg-type]
    assert len(descriptions) == 1
    assert descriptions[0].access_method == AuthorityInformationAccessOID.OCSP
    assert isinstance(descriptions[0].access_location, x509.UniformResourceIdentifier)
    assert descriptions[0].access_location.value == f"{CRL_BASE}/ocsp"


def test_a_client_leaf_without_sans_still_carries_both_pointers(
    signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey
) -> None:
    """Seven extensions instead of eight: the SAN drops out, the pointers do not.

    The two new extensions are appended after the identifiers, outside the `if not sans.empty` branch, so a client
    certificate with no SAN still says where this CA's revocation information lives. Asserted on a **real issued**
    certificate rather than the profile table alone: "the builder appends it" and "the signed artifact carries it"
    are different claims, and only the second one is what a client reads.
    """
    issued = issue_certificate(
        signing_ca,
        _details(rsa_leaf, NO_SAN),
        cert_type="client",
        validity_days=30,
        max_sans=100,
        crl_base_url=CRL_BASE,
    )

    assert _from_cert(issued.cert, x509.SubjectAlternativeName) is None

    cdp = _from_cert(issued.cert, x509.CRLDistributionPoints)
    aia = _from_cert(issued.cert, x509.AuthorityInformationAccess)

    assert cdp is not None and aia is not None
    assert [name.value for name in cdp[0].full_name] == [f"{CRL_BASE}/crl.pem"]  # type: ignore[index]
    assert aia[0].access_location.value == f"{CRL_BASE}/ocsp"  # type: ignore[attr-defined]

    critical = {
        extension.oid: extension.critical
        for extension in issued.cert.extensions  # type: ignore[attr-defined]
    }
    assert critical[x509.ExtensionOID.CRL_DISTRIBUTION_POINTS] is False
    assert critical[x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS] is False


# ------------------------------------------------------------------------------------------- issuing a leaf


def test_two_signings_of_the_same_csr_yield_different_serials(
    signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey
) -> None:
    """Random serials, not a counter (RFC 5280 §7.1: "do not do this").

    Sequential serials let anyone who sees one certificate predict the next, which turns this CA's issue rate into
    observable information. Two signings of the *same* request are the sharpest form of the test: everything else in
    the output is deliberately identical, so a counter would show up immediately here and nowhere else.
    """
    details = _details(rsa_leaf)

    first = issue_certificate(
        signing_ca, details, cert_type="server", validity_days=30, max_sans=100, crl_base_url=CRL_BASE
    )
    second = issue_certificate(
        signing_ca, details, cert_type="server", validity_days=30, max_sans=100, crl_base_url=CRL_BASE
    )

    assert first.serial_hex != second.serial_hex
    assert first.pem != second.pem
    assert first.fingerprint_sha256 != second.fingerprint_sha256
    # Everything the profile fixes stays identical: only the serial (and therefore the signature) differs.
    assert first.cert.subject == second.cert.subject == details.subject_name
    assert first.sans == second.sans == details.sans


def test_issuer_is_exactly_the_ca_subject(signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey) -> None:
    """`issuer_name(bundle.cert.subject)` — the same `Name` object, not a re-rendered copy.

    A subject/issuer mismatch is invisible in a browser and fatal to chain building. Comparing the two `x509.Name`
    objects is the assertion; comparing their RFC 4514 strings would let an attribute-order change pass.
    """
    issued = issue_certificate(
        signing_ca, _details(rsa_leaf), cert_type="server", validity_days=30, max_sans=100, crl_base_url=CRL_BASE
    )

    assert issued.cert.issuer == signing_ca.cert.subject
    assert issued.cert.subject.rfc4514_string() == "C=XX,O=mypki tests,CN=server.internal"


def test_validity_is_tz_aware_utc_and_exactly_the_requested_span(
    signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey
) -> None:
    """Validity computed and stored as aware UTC (page-map §7).

    The naive accessors read and write *local* time, so a CA started in a mis-set container timezone would issue
    certificates whose expiry means something different on every client. Asserted on the tz-aware accessors, with the
    span compared as an exact `timedelta` — "about 30 days" is what a local-time bug looks like.
    """
    before = _whole_seconds(dt.datetime.now(dt.timezone.utc))
    issued = issue_certificate(
        signing_ca, _details(rsa_leaf), cert_type="server", validity_days=30, max_sans=100, crl_base_url=CRL_BASE
    )
    after = dt.datetime.now(dt.timezone.utc)

    assert issued.not_before_utc.tzinfo is not None
    assert issued.not_before_utc.utcoffset() == dt.timedelta(0)
    assert issued.not_after_utc.utcoffset() == dt.timedelta(0)
    assert before <= issued.not_before_utc <= after
    assert issued.not_after_utc - issued.not_before_utc == dt.timedelta(days=30)
    # The certificate itself, not just the dataclass wrapper: what a client reads.
    assert issued.cert.not_valid_before_utc == issued.not_before_utc
    assert issued.cert.not_valid_after_utc == issued.not_after_utc


def test_signing_hash_follows_the_leaf_key_size(signing_ca: CaBundle, ec_p384_leaf: ec.EllipticCurvePrivateKey) -> None:
    """SHA-384 for a P-384 leaf, SHA-256 otherwise — and the issued certificate agrees.

    Matching the hash to the curve rather than always reaching for the strongest available: a P-256 leaf signed with
    SHA-384 buys nothing and confuses auditors who read hash strength as a policy statement (page-map §7). Asserted on
    both the helper and the real signature algorithm inside the certificate, because a builder that silently used
    something else would pass the helper test.
    """
    assert isinstance(signing_hash(ec_p384_leaf.public_key()), hashes.SHA384)

    issued = issue_certificate(
        signing_ca, _details(ec_p384_leaf), cert_type="server", validity_days=30, max_sans=100, crl_base_url=CRL_BASE
    )
    assert issued.cert.signature_hash_algorithm is not None
    assert issued.cert.signature_hash_algorithm.name == "sha384"


# --------------------------------------------------------------------------------------------- validity rules


def test_validity_days_honours_minimum_default_and_maximum(settings: Settings) -> None:
    """The three bounds, read from `Settings` rather than written out here.

    `None`/empty resolves to the default; the minimum and maximum are accepted inclusive. Nothing in this test states
    what the numbers are — a knob change should move the test's expectations, not require editing a test.
    """
    minimum = 1
    default = settings.validity_default_days
    maximum = settings.validity_max_days

    assert validity_days(None, default, minimum, maximum) == default
    assert validity_days("", default, minimum, maximum) == default
    assert validity_days("   ", default, minimum, maximum) == default
    assert validity_days(minimum, default, minimum, maximum) == minimum
    assert validity_days(maximum, default, minimum, maximum) == maximum
    assert validity_days(str(maximum), default, minimum, maximum) == maximum


def test_over_max_validity_is_refused_naming_the_knob_and_is_never_clamped(settings: Settings) -> None:
    """1000 days against a ceiling of `MYPKI_VALIDITY_MAX_DAYS` is refused, not shortened.

    Clamping is the tempting implementation and it is the wrong one: an operator who asked for 1000 days and silently
    received 825 believes they have a certificate valid until a date nobody wrote down. Validity is also the one
    bound on a wrong certificate that needs no cooperation from the client: this host publishes a CRL and answers
    OCSP from 0.7.0, but those count only for a client that consults one, and pre-0.7 leaves carry no pointer
    (docs/REFERENCE.md gotcha 2). The
    message names the knob so the next request goes through `.env` rather than through guesswork.
    """
    maximum = settings.validity_max_days

    with pytest.raises(CsrValidationError) as caught:
        validity_days(maximum + 175, settings.validity_default_days, 1, maximum)

    assert "MYPKI_VALIDITY_MAX_DAYS" in caught.value.reason
    assert str(maximum) in caught.value.reason
    assert caught.value.field == "validity_days"
    # The refusal is the answer; there is no quietly-shortened value to compare against.
    with pytest.raises(CsrValidationError):
        validity_days(10_000, settings.validity_default_days, 1, maximum)


def test_below_minimum_validity_is_refused_with_the_bound(settings: Settings) -> None:
    """Zero and negative are rejections naming the bound, not "invalid number".

    A zero-day certificate is expired before it is installed; refusing it with the bound in the message is what makes
    the page usable.
    """
    for value in (0, -1):
        with pytest.raises(CsrValidationError) as caught:
            validity_days(value, settings.validity_default_days, 1, settings.validity_max_days)
        assert "at least 1" in caught.value.reason
        assert str(value) in caught.value.reason


def test_a_non_numeric_validity_is_refused_without_a_traceback(settings: Settings) -> None:
    """`validity_days=30d` is a form value, and the page has to say so.

    The `from None` on the re-raise matters as much as the message: an operator should see "must be a whole number of
    days (got '30d')", not a chained `ValueError` from `int()`.
    """
    with pytest.raises(CsrValidationError) as caught:
        validity_days("30d", settings.validity_default_days, 1, settings.validity_max_days)

    assert "whole number of days" in caught.value.reason
    assert "30d" in caught.value.reason


# ------------------------------------------------------------------------------- per-profile refusals


@pytest.mark.parametrize("cert_type", ("server", "both"))
def test_a_server_or_both_certificate_without_sans_is_refused_offering_client(
    signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey, cert_type: str
) -> None:
    """No SAN + `server`/`both` is a refusal that names the alternative.

    A TLS server certificate with no SAN is rejected by every current browser (name matching ignores CN), so issuing
    one would produce a certificate usable for nothing. The message offers `client`, because "no SAN at all" is legal
    for a client certificate and the operator usually means one of the two.
    """
    with pytest.raises(CsrValidationError) as caught:
        issue_certificate(
            signing_ca,
            _details(rsa_leaf, NO_SAN),
            cert_type=cert_type,
            validity_days=30,
            max_sans=100,
            crl_base_url=CRL_BASE,
        )

    assert "requires at least one SAN" in caught.value.reason
    assert "issue it as `client`" in caught.value.reason
    assert caught.value.field == "sans"


def test_a_client_certificate_may_have_no_sans(signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey) -> None:
    """The same request under the third profile issues fine.

    This is the half that proves the refusal above is a **profile rule** rather than a blanket "SANs are mandatory":
    identical input, one field changed, opposite outcome.
    """
    issued = issue_certificate(
        signing_ca,
        _details(rsa_leaf, NO_SAN),
        cert_type="client",
        validity_days=30,
        max_sans=100,
        crl_base_url=CRL_BASE,
    )

    assert issued.sans.empty
    assert _from_cert(issued.cert, x509.SubjectAlternativeName) is None


def test_exceeding_max_sans_is_refused_naming_the_knob(signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey) -> None:
    """`MYPKI_MAX_SANS` on the page, with both counts in the message.

    Each SAN is a name this CA is being asked to vouch for, so the cap bounds one request's blast radius. Naming the
    found count and the limit is what lets an operator trim the list instead of guessing how far over they are.
    """
    sans = SanSet(dns=("a.internal", "b.internal", "c.internal"))

    with pytest.raises(CsrValidationError) as caught:
        issue_certificate(
            signing_ca,
            _details(rsa_leaf, sans),
            cert_type="server",
            validity_days=30,
            max_sans=2,
            crl_base_url=CRL_BASE,
        )

    assert "carries 3 SANs" in caught.value.reason
    assert "limit is 2" in caught.value.reason
    assert "MYPKI_MAX_SANS" in caught.value.reason


def test_an_unknown_cert_type_is_refused_naming_the_three_profiles(
    signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey
) -> None:
    """`cert_type=root` is refused rather than defaulted to `server`.

    Defaulting would issue a TLS-server certificate for a request that asked for something else — and the three names
    in the message are what makes the page self-explanatory. Asserted against `CERT_TYPES` so adding a fourth profile
    updates this test instead of breaking it.
    """
    with pytest.raises(CsrValidationError) as caught:
        issue_certificate(
            signing_ca, _details(rsa_leaf), cert_type="root", validity_days=30, max_sans=100, crl_base_url=CRL_BASE
        )

    for name in CERT_TYPES:
        assert name in caught.value.reason
    assert "root" in caught.value.reason
    assert caught.value.field == "cert_type"


def test_a_bundle_without_a_private_key_raises_mypki_error_not_a_validation_failure(
    signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey
) -> None:
    """`bundle.key is None` is missing capability, not invalid input.

    A host can hold the public certificate (so `/` and `/ca/certificate` answer) while the private key is absent or
    undecryptable — page-map §1 models that as a boolean rather than as a crash. The distinction in type matters: a
    `MypkiError` says "this host cannot sign", a `CsrValidationError` would say "your request is wrong", and only one
    of them is true here.
    """
    from mypki.ca import CaBundle as BundleType

    keyless = BundleType(
        cert=signing_ca.cert,
        key=None,
        cert_path=signing_ca.cert_path,
        key_path=signing_ca.key_path,
    )
    assert keyless.key_present is False

    with pytest.raises(MypkiError) as caught:
        issue_certificate(
            keyless, _details(rsa_leaf), cert_type="server", validity_days=30, max_sans=100, crl_base_url=CRL_BASE
        )

    assert "no private key loaded" in str(caught.value)
    assert not isinstance(caught.value, CsrValidationError)


def test_the_summary_line_carries_no_pem_body(signing_ca: CaBundle, rsa_leaf: rsa.RSAPrivateKey) -> None:
    """`IssuedCert.summary` is what reaches the log (page-map §0): identity and expiry only.

    A PEM body in a log line is a copy of the certificate in an artifact that gets backed up and shipped to log
    aggregators. Asserted on the shape rather than on absence-of-a-marker, because the interesting failure is a summary
    that grows.
    """
    issued = issue_certificate(
        signing_ca, _details(rsa_leaf), cert_type="server", validity_days=30, max_sans=100, crl_base_url=CRL_BASE
    )
    summary = issued.summary

    assert "-----BEGIN" not in summary
    assert issued.serial_hex in summary
    assert "type=server" in summary
    assert "cn=server.internal" in summary
    assert "dns=2, ip=1" in summary


def test_a_keyless_ca_directory_is_still_loadable_for_public_pages(
    data_root: Path, settings: Settings, rsa_leaf: rsa.RSAPrivateKey
) -> None:
    """The `key is None` state the web layer depends on, produced the way an operator produces it.

    Deleting `ca_key.pem` next to a real `ca_cert.pem` is an ordinary restore accident. `load_ca` must report it as a
    usable public bundle rather than crash, because `/` and `/ca/certificate` are exactly the pages that answer "what
    did this host issue from?" — and the previous test's refusal is only meaningful if this state is reachable.
    """
    init_ca(
        data_root,
        common_name="mypki Keyless Test CA",
        spec=KeySpec.from_string("rsa-2048"),
        days=365,
    )
    paths.ca_key_path(data_root).unlink()

    bundle = load_ca(data_root)

    assert bundle.key is None
    assert bundle.key_present is False
    assert bundle.cert.subject.rfc4514_string() == "CN=mypki Keyless Test CA"

    with pytest.raises(MypkiError):
        issue_certificate(
            bundle,
            _details(rsa_leaf),
            cert_type="server",
            validity_days=settings.validity_default_days,
            max_sans=settings.max_sans,
            crl_base_url=CRL_BASE,
        )
