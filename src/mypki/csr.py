"""Building and validating certificate signing requests — the two directions of the same object.

Why this module exists: a CSR is the one artifact in this project that arrives from outside (pasted into a textarea)
and then becomes an authoritative statement about who a certificate is for. So the code splits into exactly two jobs,
and the split *is* the security boundary: `build_csr` constructs a request mypki controls from validated fields, and
`parse_and_validate_csr` interrogates a request somebody else wrote. Sharing one SAN validator between both
(`validators.py`) is what guarantees that the CSR this app generates would pass the checks this app applies to a
foreign one — if those two ever drift, mypki starts refusing its own output, which is how a CA quietly stops working.

Why validation is ordered rather than collected: page-map §3 step A fixes the order PEM → parse → signature → hash →
key policy → CA privileges → SANs. Two reasons it is written as sequential raises instead of "run everything and
report all failures": a garbage PEM has no public key to inspect, so the later checks cannot run at all; and telling an
operator about a broken signature before their key size matters because the first thing they should learn about a
tampered request is that it was tampered with.

Rejected alternatives: accepting bare base64 DER without PEM armour (invites truncated input that parses as something
other than what was intended), and copying extensions from the CSR into the issued certificate — page-map §7 copies SAN
and nothing else, because "the CSR asked for it" is precisely how a request tries to mint a CA.

As of this build, step 6 answers in two categories rather than one (page-map §3 rule 6, PLAN.md §6.3): a privilege claim
refuses the request outright, and a non-SAN extension that asks for nothing mypki would have set itself is listed on the
confirmation panel and dropped **only** with the operator's explicit consent. Neither category rewrites the request —
"ignored" here means "not copied", never "deleted from the PEM", because a CSR signature covers its own extension
attributes.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from .errors import CaPrivilegeRequestedError, CsrValidationError, RequestTooLargeError
from .keys import KeySpec, describe_public_key, key_spec_for_public_key
from .validators import (
    SanSet,
    parse_sans,
    validate_common_name,
    validate_country,
    validate_email,
    validate_printable_field,
    validate_san_entry,
)

log = logging.getLogger("mypki.csr")

# mypki emits **PEM only** (PLAN §2 assumption 4): no DER, PKCS#12 or JKS output anywhere in the project. `Encoding.PEM`
# therefore appears exactly once in this module -- at the end of `build_csr` -- and nowhere else: a CSR that left this
# function in DER would not survive the paste-into-a-textarea step it is designed for, and offering a second format here
# would be the first crack in the "one output medium" rule the rest of the app assumes.

#: The armour mypki accepts. Anything else (a certificate, a private key, a CRL) is named specifically on the page,
#: because "invalid CSR" wastes an operator's time when the useful answer is "you pasted a certificate".
CSR_PEM_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----"
CSR_PEM_END = "-----END CERTIFICATE REQUEST-----"

_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)

#: Hashes mypki will honour in a CSR signature. SHA-1 and MD5 are excluded (page-map §3 rule 4): both have practical
#: collision attacks against certificate signatures, so accepting one here means this CA vouches for a request whose
#: proof-of-possession is forgeable by someone else.
ALLOWED_SIGNATURE_HASHES = frozenset({"sha256", "sha384", "sha512"})

#: Hard floor for an optional key passphrase (page-map §2).
#:
#: Enforcing one number here and enforcing it again independently in `cli.py` made a rule into two copies of a rule.
#: Both surfaces now accept 8 or more and both say out loud that 12 is the better number — see
#: `PASSPHRASE_RECOMMENDED_LENGTH` and `passphrase_advisory`. Lowering the floor does not lower the recommendation: it
#: moves the decision from "the tool refuses your passphrase" to "the tool tells you what it thinks of it".
#:
#: 8 is still a floor rather than an endorsement. `keys.private_key_pem` encrypts with `BestAvailableEncryption`, which
#: derives its encryption key from the passphrase, so an 8-character one is guessable offline once the file is in
#: someone's
#: hands. The floor exists to refuse the 3-4 character cases that make encryption decorative.
PASSPHRASE_MIN_LENGTH = 8

#: The length both the web form and `mypki init-ca` recommend, as opposed to enforce.
PASSPHRASE_RECOMMENDED_LENGTH = 12

__all__ = [
    "ALLOWED_SIGNATURE_HASHES",
    "CSR_PEM_BEGIN",
    "CSR_PEM_END",
    "PASSPHRASE_MIN_LENGTH",
    "PASSPHRASE_RECOMMENDED_LENGTH",
    "CsrDetails",
    "CsrFields",
    "build_csr",
    "extract_single_csr_pem",
    "parse_and_validate_csr",
    "passphrase_advisory",
    "subject_from_fields",
    "validate_generate_fields",
]


class CsrFields:
    """Validated subject fields for a CSR, as produced from form input (page-map §2)."""

    __slots__ = (
        "common_name",
        "country",
        "email",
        "locality",
        "organization",
        "organizational_unit",
        "sans",
        "state",
    )

    def __init__(
        self,
        common_name: str,
        sans: SanSet,
        organization: str | None = None,
        organizational_unit: str | None = None,
        country: str | None = None,
        state: str | None = None,
        locality: str | None = None,
        email: str | None = None,
    ) -> None:
        self.common_name = common_name
        self.sans = sans
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.country = country
        self.state = state
        self.locality = locality
        self.email = email


class CsrDetails:
    """What a validated CSR actually says — the confirmation panel on `/csr/sign` (page-map §3 step A).

    Carries `pem` and `sans` so step B can sign without re-parsing. It carries **no** record of *refused* extensions:
    a CSR carrying one never reaches this class, because `_csr_extension_problems` aborts at step 6 with
    `CaPrivilegeRequestedError`, whose `.extension` is what the operator reads (page-map §3).

    `ignored_extensions` is the other half — the non-SAN extensions that survived step 6 because they ask for nothing
    this CA would not have set itself (PLAN.md §6.3). It is a **description of the request**, not a modification of it:
    `pem` here still carries every extension the operator pasted, byte for byte, because a CSR signature covers the
    extension attributes and re-encoding without them would make step B sign different bytes from the ones step A
    validated. Nothing on this class can delete anything.
    """

    __slots__ = (
        "ignored_extensions",
        "key_label",
        "pem",
        "public_key",
        "sans",
        "signature_algorithm",
        "signature_hash",
        "subject",
        "subject_name",
    )

    def __init__(
        self,
        pem: str,
        subject: dict[str, str | None],
        sans: SanSet,
        key_label: str,
        signature_algorithm: str,
        signature_hash: str,
        public_key: object,
        subject_name: x509.Name,
        ignored_extensions: tuple[str, ...] = (),
    ) -> None:
        self.pem = pem
        self.subject = subject
        self.sans = sans
        self.key_label = key_label
        self.signature_algorithm = signature_algorithm
        self.signature_hash = signature_hash
        # The parsed objects, not just their descriptions: step B signs from these rather than re-parsing the PEM, so
        # "what was validated" and "what was signed" are the same bytes by construction rather than by discipline.
        self.public_key = public_key
        self.subject_name = subject_name
        # Names only — `BasicConstraints CA:FALSE`, `KeyUsage (digitalSignature)`, ... — derived from this request by
        # `_csr_extension_problems` and nothing else. A client cannot put anything in this tuple: it is rebuilt from the
        # staged bytes at step B rather than read back from the form, which is what stops a POST from consenting to an
        # extension the page never showed (page-map §3 rule 6).
        self.ignored_extensions = tuple(ignored_extensions)

    @property
    def summary(self) -> str:
        """One line for the log: names and counts only, never PEM bodies (page-map §0)."""
        return f"subject={self.subject.get('common_name')} {self.sans.describe()} key={self.key_label}"


def subject_from_fields(fields: CsrFields) -> x509.Name:
    """Map validated fields onto NameOIDs.

    Only present attributes are added: an empty `O=` or `C=` is copied into every client's certificate viewer, and some
    validators treat a zero-length attribute as malformed rather than as absent. EMAIL_ADDRESS is a general name in
    X.509 (RFC 5280 §4.1.2.1), so an email belongs in the subject and not in a SAN — mypki keeps them separate on
    purpose: `sans` says what a certificate may be used *for*, the subject says whose it is.
    """
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, fields.common_name)]
    for oid, value in (
        (NameOID.ORGANIZATION_NAME, fields.organization),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, fields.organizational_unit),
        (NameOID.COUNTRY_NAME, fields.country),
        (NameOID.STATE_OR_PROVINCE_NAME, fields.state),
        (NameOID.LOCALITY_NAME, fields.locality),
        (NameOID.EMAIL_ADDRESS, fields.email),
    ):
        if value:
            attributes.append(x509.NameAttribute(oid, value))
    return x509.Name(attributes)


def _signature_hash(key: object) -> hashes.SHA256 | hashes.SHA384:
    """SHA-384 for a P-384 key, SHA-256 otherwise (page-map §7).

    Matching the hash to the curve rather than always reaching for the strongest available: a P-256 leaf signed with
    SHA-384 buys nothing and confuses auditors who read hash strength as a policy statement.

    The return type names those two concrete classes rather than `hashes.HashAlgorithm`: cryptography's own builders
    take `_AllowedHashTypes`, a union of eight concrete hashes, and the abstract base is not a member of it — an
    annotation of `HashAlgorithm` here makes every call site (`builder.sign(key, _signature_hash(key))`) an arg-type
    error even though both values are exactly what the builder accepts.
    """
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.key_size >= 384:
        return hashes.SHA384()
    return hashes.SHA256()


def build_csr(fields: CsrFields, key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    """Build a PEM CSR for already-validated fields with a key that exists only in this call.

    The only extension added is SAN, and it is omitted entirely when there are none — a client certificate may
    legitimately have no SAN (page-map §7). No `ExtensionRequest` beyond that, which is what makes the sign page's
    "no non-SAN extensions" rule hold for this app's own output as well as for somebody else's.

    Returns a PEM **string**: it goes into a `<pre>`, into a download body and back through the sign page unchanged, and
    one canonical text form is what keeps those three copies byte-identical.
    """
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject_from_fields(fields))
    if not fields.sans.empty:
        names: list[x509.GeneralName] = [x509.DNSName(name) for name in fields.sans.dns]
        names += [x509.IPAddress(ipaddress.ip_address(value)) for value in fields.sans.ips]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)

    csr = builder.sign(key, _signature_hash(key))
    log.info("built CSR %s (%s SANs)", fields.common_name, fields.sans.describe())
    return csr.public_bytes(Encoding.PEM).decode("ascii")


def extract_single_csr_pem(paste: str, max_chars: int) -> str:
    """Extract exactly one `CERTIFICATE REQUEST` block from a paste, enforcing mypki's own size cap.

    Three failures are named separately because they have three different fixes (page-map §3):

      * oversized input → mypki's error page naming `MYPKI_MAX_CSR_CHARS`, raised **before** parsing so starlette's own
        1 MiB part limit cannot answer first with a bare JSON `Field exceeded maximum size of 1024KB.`;
      * zero blocks, or a block of another type → "that is a certificate/key, not a CSR";
      * two or more blocks → refused outright. Signing "the first one" would silently ignore the rest of what was
        pasted, and a paste containing both a leaf and a request is exactly the case where picking either is wrong.
    """
    text = paste or ""
    if len(text) > max_chars:
        raise RequestTooLargeError(len(text), max_chars, "MYPKI_MAX_CSR_CHARS")

    blocks = _BLOCK_RE.findall(text)
    if not blocks:
        raise CsrValidationError(
            f"No PEM block found. Paste a certificate signing request between {CSR_PEM_BEGIN} and {CSR_PEM_END}.",
            "csr_pem",
        )

    kinds = sorted({kind.strip() for kind, _ in blocks})
    csr_blocks = [body for kind, body in blocks if kind.strip() == "CERTIFICATE REQUEST"]
    if not csr_blocks:
        raise CsrValidationError(
            f"That is a {' / '.join(kinds)}, not a certificate signing request. mypki signs CSRs; it does not "
            "re-sign certificates and it does not accept private keys.",
            "csr_pem",
        )
    if len(csr_blocks) > 1:
        raise CsrValidationError(
            f"Found {len(csr_blocks)} certificate requests. Paste exactly one — mypki will not guess which.",
            "csr_pem",
        )
    return csr_blocks[0]


def parse_and_validate_csr(paste: str, max_chars: int) -> CsrDetails:
    """Validate a pasted CSR in page-map §3 order and describe what it asks for.

    The order is load-bearing (module docstring): PEM → DER parse → signature → hash → key policy → CA privileges →
    SANs. Every failure raises a mypki error whose message already contains the operator's next step.
    """
    body = extract_single_csr_pem(paste, max_chars)

    # Base64 first, with its reason kept separate from the parse failure: "the base64 is broken" and "that decodes to
    # something that is not a CSR" are different diagnoses of what looks like the same paste.
    #
    # Whitespace is removed before decoding, and `validate=True` is kept. Both halves matter, and dropping either one
    # breaks something different: PEM armour is line-wrapped by definition (64 characters per line in this
    # app's own generated output), and `b64decode(..., validate=True)` refuses a body containing the newlines that make
    # it valid PEM -- so decoding the armour as-is rejects every real CSR with "Only base64 data is allowed". Stripping
    # without validating instead accepts any character an attacker puts in the block and reports it as a DER parse
    # error.
    cleaned = "".join(body.split())
    try:
        der = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CsrValidationError(
            f"The PEM body is not valid base64 ({exc}); the request was probably truncated while pasting.",
            "csr_pem",
        ) from None

    # `load_der_x509_csr`, and `load_pem_x509_csr` for the armour form: the longer, obvious name
    # (`load_pem_x509_certificate_signing_request`) does not exist in the pinned version at all. The obvious
    # spelling is a trap, so this is where it gets written down.
    try:
        csr = x509.load_der_x509_csr(der)
    except ValueError as exc:
        raise CsrValidationError(
            f"The bytes inside the PEM block are not a DER certificate request ({exc}).",
            "csr_pem",
        ) from None

    # Step 3: proof of possession. `is_signature_valid` is a boolean property, not a method -- calling it
    # would validate nothing and always be truthy, which is the kind of bug that ships as "the CA accepts anything".
    if not csr.is_signature_valid:
        raise CsrValidationError(
            "CSR signature does not verify — the request was tampered with, truncated in transit, or generated with a "
            "different key than it claims.",
            "csr_pem",
        )

    # Step 4: hash policy. `signature_hash_algorithm` is None for algorithms cryptography does not model as a hash.
    hash_name = getattr(csr.signature_hash_algorithm, "name", None) or "unknown"
    if hash_name not in ALLOWED_SIGNATURE_HASHES:
        raise CsrValidationError(
            f"This CSR is signed with {hash_name.upper()}. mypki accepts SHA-256, SHA-384 or SHA-512 only; SHA-1 and "
            "MD5 requests are refused because their collision resistance is broken.",
            "signature_hash",
        )

    # Step 5: key policy, applied to the key *inside* the request rather than to a spec string somebody typed.
    public_key = csr.public_key()
    spec = key_spec_for_public_key(public_key)  # raises KeyPolicyError naming the rejected spec

    # Step 6: CA privileges and non-SAN extensions. One pass produces both halves (page-map §3 rule 6): `refused` is
    # what aborts here, `ignorable` is what the panel has to disclose and what step B needs consent for. The request is
    # **not** rewritten either way — see `_csr_extension_problems`.
    refused, ignorable = _csr_extension_problems(csr)
    if refused:
        raise CaPrivilegeRequestedError("; ".join(refused))

    # Step 7: SANs, through the same validator that built this app's own CSRs.
    sans = _sans_from_csr(csr)

    subject = _subject_dict(csr.subject)
    algorithm_name = getattr(getattr(csr, "signature_algorithm_oid", None), "_name", "unknown")
    details = CsrDetails(
        pem=_rearmour(body),
        subject=subject,
        sans=sans,
        key_label=describe_public_key(public_key),
        signature_algorithm=algorithm_name.replace("-", " ").title(),
        signature_hash=hash_name.upper(),
        public_key=public_key,
        subject_name=csr.subject,
        ignored_extensions=tuple(ignorable),
    )
    if ignorable:
        # Names only, never PEM bodies and never the extension values (page-map §0). The sentence an operator reads on
        # the page is "these are not copied"; this line is what a log carries for the same fact.
        log.info(
            "CSR %s requests %d extension(s) mypki will not copy: %s",
            details.subject.get("common_name"),
            len(ignorable),
            ", ".join(ignorable),
        )
    log.info("validated CSR %s (key=%s)", details.subject.get("common_name"), spec.label)
    return details


def _rearmour(base64_body: str) -> str:
    """Rebuild canonical PEM armour from the captured base64 body.

    Canonicalising here is what makes "the bytes I validated" and "the bytes I sign" identical even when the paste used
    CRLF endings, trailing spaces or a different line width — three spellings of one request that would otherwise
    produce three different-looking confirmations.
    """
    lines = [line.strip() for line in base64_body.strip().splitlines() if line.strip()]
    return f"{CSR_PEM_BEGIN}\n" + "\n".join(lines) + f"\n{CSR_PEM_END}\n"


def _csr_extension_problems(csr: x509.CertificateSigningRequest) -> tuple[list[str], list[str]]:
    """Split a CSR's non-SAN extensions into **(refused, ignorable)**, in request order (page-map §3 rule 6).

    Two categories, decided by what the extension *asks for* rather than by whether it is dangerous (PLAN.md §6.3):

      * **refused** — a privilege claim: `BasicConstraints CA:TRUE`, `keyCertSign`, `crlSign`, NameConstraints, and any
        extension this function does not recognise. These abort step 6 with `CaPrivilegeRequestedError` naming each one.
        They are refused even though they cannot reach a leaf either — `signing.leaf_extensions()` takes no CSR
        extension at all — because the cost of accepting them is expectational, not cryptographic: an operator who asks
        for a CA and quietly receives `CA:FALSE` deploys something that does not do what they asked. This CA now
        does publish a CRL (page-map §14), but revoking a mis-issued leaf only reaches clients that consult it, and the
        disclosure on the confirmation page remains the cheaper defence.
      * **ignorable** — requests mypki would satisfy identically anyway: `BasicConstraints CA:FALSE`, benign KeyUsage
        bits, SKI, AKI, ExtendedKeyUsage, CertificatePolicies, CRLDistributionPoints, AuthorityInfoAccess. These reach
        the confirmation panel, where they are named and dropped **only** behind an explicit consent box (default OFF).

    "Ignorable" means *not copied*, never *deleted*: nothing here touches the request's bytes. A CSR signature covers
    `CertificationRequestInfo`, which includes its extension attributes, so a re-encoded request is a different document
    and step B would sign something other than what step A validated.

    Both lists are collected rather than raised on the first finding: a request carrying both `CA:TRUE` and
    `keyCertSign` is one mistake to fix, not two page loads — and a request carrying a privilege claim **and** a benign
    KeyUsage must not train the operator to think the second half was accepted.
    """
    refused: list[str] = []
    ignorable: list[str] = []
    for extension in csr.extensions:
        value = extension.value
        if isinstance(value, x509.SubjectAlternativeName):
            continue
        if isinstance(value, x509.BasicConstraints):
            if value.ca:
                refused.append("BasicConstraints CA:TRUE")
            else:
                ignorable.append("BasicConstraints CA:FALSE")
        elif isinstance(value, x509.KeyUsage):
            if value.key_cert_sign:
                refused.append("KeyUsage keyCertSign")
            if value.crl_sign:
                refused.append("KeyUsage crlSign")
            if not value.key_cert_sign and not value.crl_sign:
                ignorable.append(f"KeyUsage ({_key_usage_words(value)})")
        elif isinstance(value, x509.NameConstraints):
            refused.append("NameConstraints")
        elif isinstance(value, x509.SubjectKeyIdentifier):
            ignorable.append("SubjectKeyIdentifier")
        elif isinstance(value, x509.AuthorityKeyIdentifier):
            ignorable.append("AuthorityKeyIdentifier")
        elif isinstance(value, x509.ExtendedKeyUsage):
            ignorable.append(f"ExtendedKeyUsage ({_extended_key_usage_words(value)})")
        elif isinstance(value, x509.CertificatePolicies):
            ignorable.append("CertificatePolicies")
        elif isinstance(value, x509.CRLDistributionPoints):
            ignorable.append("CRLDistributionPoints")
        elif isinstance(value, x509.AuthorityInformationAccess):
            ignorable.append("AuthorityInfoAccess")
        else:
            # Unrecognised is treated as a privilege claim rather than as noise: the alternative is that a mypki that
            # does not know what an extension means silently accepts it.
            refused.append(type(value).__name__)
    return refused, ignorable


def _extended_key_usage_words(usage: x509.ExtendedKeyUsage) -> str:
    """Render an ExtendedKeyUsage's OIDs as the words an operator recognises (`serverAuth`, `clientAuth`).

    Names rather than dotted arcs where cryptography has one: this string sits next to the profile radios on the panel,
    and a reader who pasted `extendedKeyUsage = serverAuth` into an openssl config should see their own spelling back.

    cryptography's `ObjectIdentifier` has **no public name attribute** — `shortname` is absent and `_display_name` is
    None on the pinned version, and `str(oid)` renders the whole repr, `<ObjectIdentifier(oid=1.3.6.1.5.5.7.3.1,
    name=serverAuth)>`, which is unusable in a sentence. So the label comes from the private `oid._name` — reached for
    display only, never for a decision: an unknown extension is refused above however well this function can spell it.

    An unnamed OID gets its dotted arc rather than cryptography's own placeholder (`_name` is the literal
    string `"Unknown OID"` for anything outside its table). "Unknown OID" twice on one line cannot be compared against a
    request, and an arc can be looked up; that is the difference between a disclosure and a shrug.
    """
    words: list[str] = []
    for oid in usage:
        name = getattr(oid, "_name", None)
        spelling = str(name) if name and str(name) != "Unknown OID" else oid.dotted_string
        words.append(spelling)
    return ", ".join(words) or "no usages set"


def _key_usage_words(usage: x509.KeyUsage) -> str:
    """Render a KeyUsage's requested bits as words, so mypki can say which of them it is dropping.

    Used by both halves of rule 6 (page-map §3): the disclosure string for a benign usage, and — via the two named
    privilege bits beside it — part of what a refusal lists. "Which of them" is the whole point in either case: the
    words are compared against `openssl req -text`, so a bit missing from this table is a difference nobody can see.

    All seven booleans are listed, in `cryptography`'s own constructor order rather than an alphabetical or severity
    order: a reader comparing this string against `openssl req -text` should see the same bits in the same sequence.
    `keyEncipherment` was missing from this table for a long stretch (each shipped archive's `csr.py` mentions it zero
    times), which made a request carrying *only* that bit read as "no usages set" — the one sentence an operator cannot
    act on, since it says there is nothing to remove while the request demonstrably asks for something. That is why this
    table is asserted bit-by-bit in `test_csr_validate.py` rather than spot-checked on one example: a single
    representative cannot see a missing row.
    """
    requested = [
        word
        for word, flag in (
            ("digitalSignature", usage.digital_signature),
            ("contentCommitment", usage.content_commitment),
            ("keyEncipherment", usage.key_encipherment),
            ("dataEncipherment", usage.data_encipherment),
            ("keyAgreement", usage.key_agreement),
            ("keyCertSign", usage.key_cert_sign),
            ("crlSign", usage.crl_sign),
        )
        if flag
    ]
    return ", ".join(requested) or "no usages set"


def _sans_from_csr(csr: x509.CertificateSigningRequest) -> SanSet:
    """Read SANs out of a CSR and re-validate them through `validators.py`.

    Re-validation rather than trust is the point: these entries came from outside mypki, and something X.509's own
    encoder accepted (an IP encoded as a DNS name, a 70-character label) still has to satisfy the rules this CA states
    on its page (page-map §9).

    `ExtensionNotFound` is not an error — a client certificate with no SAN is legal. Whether SAN is *required* is
    `signing.py`'s per-type decision (page-map §7), not a validation verdict, and keeping that split here means the
    confirmation panel can show "no SANs" honestly instead of showing an error for a legal request.
    """
    try:
        extension = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return SanSet()

    dns: list[str] = []
    ips: list[str] = []
    rejected: list[tuple[int, str]] = []

    for index, name in enumerate(extension.value):
        if isinstance(name, x509.DNSName):
            # An IP written as a DNS string is the inverse of the usual openssl `-addext subjectAltName` mistake in
            # its inverse form; naming it saves an operator an hour of reading RFCs.
            try:
                literal = ipaddress.ip_address(name.value)
            except ValueError:
                literal = None
            if literal is not None:
                rejected.append(
                    (index, f"{name.value!r} is an IP address encoded as a DNS name; issue it as an IP general name")
                )
                continue
            dns.append(name.value)
        elif isinstance(name, x509.IPAddress):
            ips.append(str(name.value))
        else:
            rejected.append((index, f"unsupported SAN general name {type(name).__name__}"))

    # Positional re-validation of the DNS entries: same rules and same messages as the generate form.
    # `validators.py` imports only `errors.py`, so importing it up top creates no cycle even though both modules sit
    # in the same layer.
    revalidated: list[str] = []
    for index, value in enumerate(dns):
        try:
            kind, clean = validate_san_entry(value, index)
        except CsrValidationError as exc:
            rejected.append((index, exc.reason))
            continue
        if kind != "dns":
            rejected.append((index, f"{value!r} classified as {kind} while reading the CSR"))
            continue
        revalidated.append(clean)

    if rejected:
        rejected.sort(key=lambda item: item[0])
        listed = "; ".join(f"position {index}: {reason}" for index, reason in rejected)
        raise CsrValidationError(f"The CSR contains SAN entries mypki will not sign — {listed}", "csr_pem")

    # Dedupe preserving first-seen order: a CSR that repeats one name is signed once, not twice.
    return SanSet(tuple(dict.fromkeys(revalidated)), tuple(dict.fromkeys(ips)))


def _subject_dict(name: x509.Name) -> dict[str, str | None]:
    """Subject as a plain mapping for the confirmation panel."""
    out: dict[str, str | None] = {}
    for oid, key in (
        (NameOID.COMMON_NAME, "common_name"),
        (NameOID.ORGANIZATION_NAME, "organization"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "organizational_unit"),
        (NameOID.COUNTRY_NAME, "country"),
        (NameOID.STATE_OR_PROVINCE_NAME, "state"),
        (NameOID.LOCALITY_NAME, "locality"),
        (NameOID.EMAIL_ADDRESS, "email"),
    ):
        attributes = name.get_attributes_for_oid(oid)
        if not attributes:
            out[key] = None
            continue
        # cryptography types `NameAttribute.value` as `str | bytes`, because the ASN.1 string type behind an attribute
        # varies by OID (UTF8String for `CN=`, PrintableString for `C=`, OCTET/BIT STRING for the rarer ones). The
        # confirmation panel renders these into a template, and a `bytes` value would print as `b'...'` to an operator,
        # so text is coerced rather than passed through.
        value = attributes[0].value
        out[key] = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    return out


def validate_generate_fields(
    *,
    common_name: str | None,
    sans_raw: str | None,
    organization: str | None,
    organizational_unit: str | None,
    country: str | None,
    state: str | None,
    locality: str | None,
    email: str | None,
    key_type: str | None,
    passphrase: str | None,
    confirm: str | None,
    max_sans: int,
) -> tuple[CsrFields, KeySpec, bytes | None]:
    """Validate the whole generate-CSR form in one place (page-map §2).

    Returns `(fields, key_spec, passphrase_or_None)`. Raises `CsrValidationError` / `KeyPolicyError` with page-ready
    messages and produces nothing partial: a rejected form generates no key.

    Field validation runs **before** `KeySpec.from_string` only in the sense that both precede any key generation --
    key generation is the expensive step of `/csr/generate`, and doing it before validating the words that describe the
    certificate would let a malformed form spend CPU for nothing.
    """
    fields = CsrFields(
        common_name=validate_common_name(common_name),
        sans=parse_sans(sans_raw, max_sans),
        organization=validate_printable_field(organization, "organization"),
        organizational_unit=validate_printable_field(organizational_unit, "organizational_unit"),
        country=validate_country(country),
        state=validate_printable_field(state, "state"),
        locality=validate_printable_field(locality, "locality"),
        email=validate_email(email),
    )
    spec = KeySpec.from_string(key_type or "rsa-3072")
    return fields, spec, _validated_passphrase(passphrase, confirm)


def passphrase_advisory(passphrase: str | None) -> str | None:
    """The "12 or more is better" sentence for a legal-but-short passphrase, or None when there is nothing to say.

    Advisory rather than an exception, and rendered by the caller on the page that already succeeded: somebody who chose
    an 8-character passphrase made a choice, and refusing it is the tool deciding for them while warning is the tool
    informing them. Returning `None` for blank/absent/long-enough values is what lets both surfaces call it
    unconditionally instead of re-implementing the length comparison in a template or in a print statement.

    Like `_validated_passphrase`, this function must never quote the passphrase — its message describes the *length*.
    """
    length = len(passphrase or "")
    if length == 0 or length >= PASSPHRASE_RECOMMENDED_LENGTH:
        return None
    return (
        f"A {length}-character passphrase is accepted, but {PASSPHRASE_RECOMMENDED_LENGTH} or more is better: an "
        "encrypted key is only as hard to guess as the passphrase that encrypted it."
    )


def _validated_passphrase(passphrase: str | None, confirm: str | None) -> bytes | None:
    """Optional passphrase pair: both blank, or both present, matching and ≥8 characters (page-map §2).

    The floor is 8 and the recommendation is 12 (`PASSPHRASE_RECOMMENDED_LENGTH` plus
    `passphrase_advisory`), which is also what `cli._passphrase_for_init` does so one rule is not two rules. Refusing
    below 8 still exists because PKCS#8 encryption is only as strong as the passphrase — a 3- or 4-character one makes
    an encrypted key barely harder to guess than an unencrypted file. Returning bytes is what `BestAvailableEncryption`
    wants, and it keeps the encoding decision in one place instead of at each call site.

    What this function must never do: log either field, or quote either value in a message. A mismatch says *which*
    field failed, not what was typed.
    """
    left = passphrase or ""
    right = confirm or ""
    if not left and not right:
        return None
    if len(left) < PASSPHRASE_MIN_LENGTH:
        raise CsrValidationError(
            f"A passphrase must be at least {PASSPHRASE_MIN_LENGTH} characters — a shorter one makes an encrypted key "
            f"barely harder to guess than an unencrypted file; {PASSPHRASE_RECOMMENDED_LENGTH} or more is better.",
            "passphrase",
        )
    if left != right:
        # Names the field, never the values: this message is rendered straight into HTML.
        raise CsrValidationError("passphrase and confirm do not match", "confirm")
    return left.encode("utf-8")
