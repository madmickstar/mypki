"""Read one pasted PEM block and say what it is — without ever refusing it (page-map §13).

Why this module exists at all: the sign page already parses a PEM, but it parses it **in order to sign it**, and that
order is a policy (`csr.parse_and_validate_csr`: PEM → DER → signature → hash policy → key policy → CA privileges →
SANs, each step raising). An operator who is *diagnosing* — "is this the expired one?", "is this the root or the leaf?",
"why does my client reject this?" — needs the opposite posture. A weak, expired, SHA-1-signed, self-signed certificate
that mypki would never issue is still a certificate that exists on some host they are responsible for, and the useful
answer is "here is what it says", not a refusal. So nothing in this module raises on content: every finding becomes a
sentence on the page.

What that posture deliberately does **not** include, stated because a reader will otherwise assume it:

  * **No chain verification.** There is no trust store here and no issuer certificate to check against; `/inspect` can
    say "issuer CN=…", it cannot say "and that issuer is trusted by anybody". The only CA-shaped fact it reports is the
    one carried inside the certificate itself (`BasicConstraints CA:TRUE`).
  * **No revocation lookup.** This host now publishes a CRL and answers OCSP (`crl.py`, `ocsp_responder.py`,
    page-map §14/§15), but **this module consults neither**: `describe_pem` reads the bytes it was handed and nothing
    else, so a certificate reported valid here may have been revoked by whoever issued it — including by this very host,
    whose CRL lives on `/revoke.crl` rather than in this function. That is a deliberate limit rather than an oversight:
    `/inspect` accepts arbitrary PEM from arbitrary CAs, and answering "revoked?" for a certificate from a CA this host
    has no relationship with would be a claim it cannot support. `/issued`'s status column is where this CA's own
    revocations are visible.
  * **No policy enforcement.** The hash and key-size findings are words, not gates: `KeyPolicyError` and
    `ALLOWED_SIGNATURE_HASHES` belong to the signing path, and a certificate that violates them here is described rather
    than rejected.

Why `ca.describe_ca` is NOT called here, and why that has to be spelled out: it ends with
`key_spec_for_public_key(cert.public_key())`, which raises `KeyPolicyError` for anything mypki would not issue —
RSA-1024 answers "RSA-1024 is not an accepted key. Allowed: RSA 2048, RSA 3072, RSA 4096." and an Ed25519 certificate
answers "Ed25519PublicKey is not an accepted key". A function whose whole promise is *never refuse* cannot call a
policy gate, so this module reads the same public facts straight off the certificate (`subject`, `serial_number`,
`not_valid_*_utc`, `extensions`) and reuses only `ca.fingerprint_hex`, which performs no policy. The key label is built
here from what cryptography reports about the key (`key_size`, `curve.name`, the class name), and the *policy* question
is asked separately, in a handler that turns the refusal into a sentence.

Why the private-key case is handled by naming rather than loading: a PEM private key is the one input an operator may
paste by accident, and the safe answer is to refuse to touch it — no `load_pem_private_key`, no decrypt attempt, no
parse, and nothing from the block rendered back. The armour line alone identifies it, so this branch never reads the
body (see `tests/test_inspect.py`, which pastes a real key and asserts that none of its bytes come back).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import datetime as dt
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .ca import fingerprint_hex
from .errors import RequestTooLargeError

log = logging.getLogger("mypki.inspect")

KEY_BODY_REDACTED = "[redacted by mypki - this page does not display private keys]"

__all__ = [
    "KEY_BODY_REDACTED",
    "MAX_BLOCKS_TO_TRY",
    "PemReport",
    "describe_pem",
    "pem_body_sha256",
    "redact_private_key_bodies",
]

#: How many blocks `/inspect` parses out of a paste. One is what an operator pastes; two is what happens when a leaf and
#: its root got copied together, and the honest answer to that is "you pasted N blocks, here is each of them" rather
#: than the sign page's "I will not guess which" (that refusal exists because *signing* the wrong one is destructive;
#: here describing both is the point). The cap exists so a paste of a hundred blocks cannot make this page render a
#: hundred tables — `MYPKI_MAX_CSR_CHARS` already bounds the bytes, and 8 parsed objects is generous against a chain an
#: operator would actually copy. Surplus blocks are counted and named, never silently dropped.
MAX_BLOCKS_TO_TRY = 8

#: Armour kinds this module recognises. Anything else gets "unrecognised" plus its armour line, rather than a guess:
#: `-----BEGIN TRUSTED CERTIFICATE-----` (OpenSSL's own extension of the format), a GPG block and a truncated header all
#: deserve the same honest sentence.
CSR_KINDS = frozenset({"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"})
CERTIFICATE_KINDS = frozenset({"CERTIFICATE"})
KEY_KINDS = frozenset(
    {
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "EC PRIVATE KEY",
        "RSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    }
)

_BLOCK_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)


@dataclass(frozen=True)
class PemReport:
    """What one pasted PEM block says, plus the sentences an operator has to read before believing it.

    `facts` is a list of `(label, value)` pairs rather than a dict so the page renders them in the order this module
    decided matters (what it is → whose it is → whose signature is on it → when it is valid) instead of in whatever
    order a mapping iterates. `flags` is the "show + flag" half: findings, not verdicts — expired, self-signed,
    not-a-CA, SHA-1, a key mypki would not issue for. Both lists are allowed to be empty and so is `facts`: a report
    that says only "I could not read this" is still the page this module exists to produce.

    `pem` is the re-armoured block, present only when the content parsed. It is deliberately **None** for a private key:
    echoing a key back into a rendered page is how it lands in a browser's form cache and in a screenshot of a support
    ticket, and this module's whole answer to a key is "I did not open it".
    """

    kind: str
    armour: str
    pem: str | None
    sha256_of_der: str | None
    facts: list[tuple[str, str]] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        """One line for the log: kind, counts and flags only — never a PEM body or a base64 fragment (page-map §0)."""
        flags = "; ".join(self.flags) or "none"
        return f"kind={self.kind} armour={self.armour or 'none'} facts={len(self.facts)} flags={flags}"


def _flag(text: str) -> str:
    """A finding, worded as a fact about the certificate rather than as a verdict on it."""
    return text


def _signature_words(obj: Any) -> tuple[str, str]:
    """`(algorithm, hash)` as display text for a certificate or a request.

    Both halves come from the object rather than from a table of OIDs. `signature_algorithm_oid._name` is what
    cryptography reports (`sha256WithRSAEncryption`, `ed25519`) and `signature_hash_algorithm` is **None** for
    algorithms it does not model as a hash (Ed25519), so the fallback says "not modelled" instead of
    inventing one.
    """
    algorithm = getattr(getattr(obj, "signature_algorithm_oid", None), "_name", None) or "unknown"
    hash_name = getattr(getattr(obj, "signature_hash_algorithm", None), "name", None)
    return algorithm.replace("-", " ").title(), (hash_name or "not modelled").upper()


def _sans_words(obj: Any) -> tuple[str, list[str]]:
    """The SAN line of a certificate *or* a request as display text, plus the entries that are not host names.

    Read straight off the extension rather than through `validators.parse_sans`: this page describes what a document
    **says**, and re-running it through mypki's issuer-side rules would silently drop exactly the entries an operator
    came to look at (an email or URI general name, an `otherName`, an address mypki would refuse). Those go in the
    returned `odd` list, which the page shows instead of hiding.

    Both `x509.Certificate` and `x509.CertificateSigningRequest` expose `.extensions.get_extension_for_class`, which is
    why one function serves both here.
    """
    try:
        san = obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return "none present", []

    dns: list[str] = []
    ips: list[str] = []
    odd: list[str] = []
    for entry in san.value:
        if isinstance(entry, x509.DNSName):
            dns.append(str(entry.value))
        elif isinstance(entry, x509.IPAddress):
            ips.append(str(entry.value))
        else:
            odd.append(f"{type(entry).__name__}: {entry.value}")

    parts = []
    if dns:
        parts.append(", ".join(dns))
    if ips:
        parts.append("IP " + ", ".join(ips))
    return ("; ".join(parts) if parts else "present but empty"), odd


def _basic_constraints(obj: Any) -> x509.BasicConstraints | None:
    """The certificate's `BasicConstraints`, or None when it has none.

    `contextlib.suppress` rather than a try/except that re-raises: for this page "absent" is the answer, not an error.
    A request can also carry one (that is what `CaPrivilegeRequestedError` exists to refuse on the sign page), and here
    it is simply reported.
    """
    with contextlib.suppress(x509.ExtensionNotFound):
        return obj.extensions.get_extension_for_class(x509.BasicConstraints).value
    return None


def _key_words(obj: Any) -> tuple[str, str | None]:
    """The public key's label as text, plus a policy sentence if mypki would not issue for that key.

    The label is built here rather than taken from `keys.describe_public_key` because that function shares the
    policy gate and raises `KeyPolicyError` on RSA-1024. An operator looking at somebody else's certificate needs "RSA
    1024" even when mypki dislikes it, so the label comes from what cryptography reports about the key and the *policy*
    question is asked separately, with its refusal caught and turned into a flag.
    """
    public_key = obj.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        label = f"RSA {public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        label = f"EC {public_key.curve.name.upper()} ({public_key.curve.key_size} bits)"
    else:
        # Ed25519 / Ed448 / DSA and anything a future cryptography adds: the class name is the honest label, because a
        # table of algorithms here would be a second answer that goes stale.
        label = type(public_key).__name__.replace("PublicKey", "")

    # Imported here rather than at module level — see the note below. (No `noqa` marker: ruff's import-position rule is
    # not enabled in this project, so a directive would only earn an unused-noqa warning.)
    from .keys import key_spec_for_public_key

    # Imported inside the function for the same reason `config.get_settings` imports `settingsfile`: `keys.py` is the
    # issuer-side policy module, and this module's promise is not to be an issuer. Importing it at module level would
    # put the gate in the import path of every caller of `describe_pem`, including a future CLI `inspect` command that
    # must never inherit signing behaviour by accident.
    try:
        key_spec_for_public_key(public_key)
    except Exception as exc:  # KeyPolicyError today; any future policy type is still "a finding, not a refusal"
        return label, _flag(f"{exc} — mypki would not issue for this key, but it is reported here as it stands")
    return label, None


def _validity_words(cert: x509.Certificate, now: dt.datetime) -> tuple[str, list[str]]:
    """Validity as text plus the two time flags: expired, and not-yet-valid.

    The `_utc` properties, not the deprecated naive ones: they are timezone-aware, so "is this expired yet?" cannot
    drift by a machine's UTC offset — which is precisely the bug this page exists to answer.
    """
    start = cert.not_valid_before_utc
    end = cert.not_valid_after_utc
    text = f"{start.strftime('%Y-%m-%d %H:%M:%S')}Z \u2192 {end.strftime('%Y-%m-%d %H:%M:%S')}Z"
    flags: list[str] = []
    if end < now:
        flags.append(_flag(f"expired {(now - end).days} day(s) ago — no client should still trust this one"))
    elif start > now:
        flags.append(
            _flag(f"not valid until {start.strftime('%Y-%m-%d %H:%M:%S')}Z ({(start - now).days} day(s) from now)")
        )
    return text, flags


def _basic_constraints_words(basic: x509.BasicConstraints | None) -> str:
    """`BasicConstraints` as the text mypki itself writes on its own root (page-map §4): `CA:TRUE pathLength:0`.

    Three states are distinguished because they mean three different things to a reader: no extension at all, a CA with
    no path-length limit (`path_length is None`, which reads as "unlimited" rather than as an empty cell), and a CA
    that may sign only up to N levels down.
    """
    if basic is None:
        return "not present"
    if not basic.ca:
        return "CA:FALSE"
    return f"CA:TRUE pathLength:{basic.path_length if basic.path_length is not None else 'unlimited'}"


def _one_name(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    """One subject/issuer attribute as text, or None when the document was created without it.

    The bytes arm exists because cryptography types `NameAttribute.value` as `str | bytes`: the ASN.1 string type
    varies by OID, and a template rendering a `bytes` prints `b'...'` to an operator. Same reasoning as `ca._one`.
    """
    attributes = name.get_attributes_for_oid(oid)
    if not attributes:
        return None
    value = attributes[0].value
    if isinstance(value, bytes):  # pragma: no cover - defensive; a foreign certificate may encode an attribute as bytes
        return value.decode("utf-8", "replace")
    return str(value)


def _certificate_facts(cert: x509.Certificate, now: dt.datetime) -> tuple[list[tuple[str, str]], list[str]]:
    """Facts and flags for one parsed X.509 certificate — leaf or root, trusted or not."""
    facts: list[tuple[str, str]] = []
    flags: list[str] = []

    algorithm, hash_name = _signature_words(cert)
    sans_text, odd_sans = _sans_words(cert)
    validity, validity_flags = _validity_words(cert, now)
    key_label, key_flag = _key_words(cert)
    basic = _basic_constraints(cert)
    is_ca = basic is not None and basic.ca

    facts.append(("Type", "CA certificate" if is_ca else "end-entity certificate"))
    facts.append(("Subject", cert.subject.rfc4514_string()))
    facts.append(("Issuer", cert.issuer.rfc4514_string()))
    facts.append(("Subject Alternative Names", sans_text))
    facts.append(("Validity (UTC)", validity))
    facts.append(("Serial (hex)", f"{cert.serial_number:x}"))
    facts.append(("SHA-256 fingerprint", fingerprint_hex(cert)))
    facts.append(("Signature algorithm", f"{algorithm} / {hash_name}"))
    facts.append(("Public key", key_label))
    facts.append(("BasicConstraints", _basic_constraints_words(basic)))

    common_name = _one_name(cert.subject, NameOID.COMMON_NAME)
    if common_name:
        facts.append(("Common name", common_name))
    organisation = _one_name(cert.subject, NameOID.ORGANIZATION_NAME)
    if organisation:
        facts.append(("Organisation", organisation))

    if is_ca:
        facts.append(("Can sign other certificates", "yes — this document claims to be a CA"))
    else:
        flags.append(_flag("not a CA — no `BasicConstraints CA:TRUE`, so this certificate cannot sign another one"))

    if cert.subject == cert.issuer:
        facts.append(("Self-issued", "subject and issuer are identical"))
        # Two different readings of the same equality, and both belong on screen: a self-signed *root* is what every CA
        # is, including this host's own — expected, but nothing above it can vouch for it, so trust has to be installed
        # out of band. A self-signed certificate that is NOT marked as a CA is the odd one: it claims to sign itself and
        # claims no power to sign anything else.
        if is_ca:
            flags.append(
                _flag("self-signed root — nothing above this document can vouch for it; trust is installed out of band")
            )
        else:
            flags.append(_flag("self-signed and not marked as a CA — nothing in this document points at an issuer"))
    if odd_sans:
        facts.append(("SAN entries mypki would not issue", ", ".join(odd_sans)))
    flags.extend(validity_flags)
    if key_flag:
        flags.append(key_flag)
    if hash_name in {"SHA1", "MD5"}:
        flags.append(_flag(f"signed with {hash_name} — mypki refuses to issue certificates signed this way"))

    return facts, flags


def _request_facts(csr: x509.CertificateSigningRequest) -> tuple[list[tuple[str, str]], list[str]]:
    """Facts and flags for one parsed certification request.

    A request has no validity period, no serial and no issuer — those are what a CA *adds* — so their absence is stated
    as a row rather than left out, because "why has this page forgotten the expiry date?" is otherwise unanswerable.
    `is_signature_valid` is a boolean **property** (calling it as a method would validate nothing and always
    be truthy — the kind of bug that ships as "the CA accepts anything"), so proof of possession is read and reported
    here rather than used as a gate.
    """
    facts: list[tuple[str, str]] = []
    flags: list[str] = []

    algorithm, hash_name = _signature_words(csr)
    sans_text, odd_sans = _sans_words(csr)
    key_label, key_flag = _key_words(csr)
    basic = _basic_constraints(csr)

    facts.append(("Type", "certification request (PKCS#10) — not yet a certificate"))
    facts.append(("Subject", csr.subject.rfc4514_string()))
    facts.append(("Subject Alternative Names", sans_text))
    facts.append(("Validity (UTC)", "none — a CA sets the validity dates when it signs"))
    facts.append(("Serial (hex)", "none — a CA assigns the serial when it signs"))
    facts.append(
        (
            "Issuer",
            "none — a request names no issuer; this is not a signature check, it is what PKCS#10 carries",
        )
    )
    facts.append(
        (
            "SHA-256 fingerprint",
            "not available — `cryptography` gives a request no `.fingerprint()` (MEASURED)",
        )
    )
    facts.append(("Signature algorithm", f"{algorithm} / {hash_name}"))
    facts.append(("Public key", key_label))
    facts.append(("BasicConstraints", _basic_constraints_words(basic)))

    common_name = _one_name(csr.subject, NameOID.COMMON_NAME)
    if common_name:
        facts.append(("Common name", common_name))

    facts.append(("Signature verifies against its own key", "yes" if csr.is_signature_valid else "no"))

    if basic is not None and basic.ca:
        flags.append(
            _flag(
                "this request asks to be a CA — `mypki` signs end-entity certificates only, "
                "so `/csr/sign` would refuse it"
            )
        )
    if odd_sans:
        facts.append(("SAN entries mypki would not issue", ", ".join(odd_sans)))
    if not csr.is_signature_valid:
        flags.append(_flag("signature does not verify — the request was tampered with or truncated while pasting"))
    if key_flag:
        flags.append(key_flag)
    if hash_name in {"SHA1", "MD5"}:
        flags.append(_flag(f"signed with {hash_name} — mypki refuses to sign a request carrying it"))

    return facts, flags


def pem_body_sha256(body: str) -> str | None:
    """SHA-256 of the **DER** inside one PEM block, hex, or None when the base64 is unreadable.

    Hashing the DER rather than the armour text is what makes this comparable with a fingerprint row and stable across
    copies: a certificate pasted from Notepad (CRLF) and the same one pasted from a terminal hash identically, because
    only the base64 payload is measured. A block whose base64 is broken has no DER to hash, so None is returned rather
    than hashing garbage.

    `validate=True` after stripping whitespace, exactly as `csr.extract_single_csr_pem` does: PEM armour is
    line-wrapped by definition, and decoding it as-is with `validate=True` rejects every real certificate with "Only
    base64 data is allowed" (recorded in `csr.py`). Stripping without validating instead accepts any
    character put inside the block and reports the damage as a parse error.
    """
    cleaned = "".join(body.split())
    try:
        der = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None
    return hashlib.sha256(der).hexdigest()


def _rearmour(armour: str, body: str) -> str:
    """Canonical armour for a block that parsed: the captured base64 lines, one BEGIN, one END, trailing newline.

    The page has to show something copyable, and re-wrapping is what makes the displayed block hash the same as the
    bytes the fingerprint row names, whatever line width or line ending the paste used. Same reasoning as
    `csr._rearmour`, which exists so "what was validated" and "what was signed" are the same bytes; here it is so "what
    is on screen" and "what the fingerprint describes" are the same bytes. It is **not** a claim that these are the
    sender's original bytes — the DER inside is the only thing carried across, and for a certificate that DER is what
    every fingerprint and every signature covers.
    """
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    return f"-----BEGIN {armour}-----\n" + "\n".join(lines) + f"\n-----END {armour}-----\n"


def _der(body: str) -> bytes:
    """Base64-decode one armour body into DER, raising `ValueError` whose text is already the operator's next step.

    Kept separate from the two loaders so "the base64 is broken" and "that decodes to something that is not a
    certificate" stay two different sentences on the page — the same split `csr.parse_and_validate_csr` makes, for the
    same reason: they have different fixes.
    """
    cleaned = "".join(body.split())
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"the PEM body is not valid base64 ({exc}); the paste was probably truncated") from None


def _unreadable(kind: str, reason: str, sha256: str | None) -> PemReport:
    """A block with armour but no readable content: reported, not refused."""
    return PemReport(
        kind="unreadable",
        armour=kind or "(no name)",
        pem=None,
        sha256_of_der=sha256,
        facts=[
            ("Type", f"PEM block named `{kind}`" if kind else "PEM block with no name"),
            ("Body", "could not be parsed"),
        ],
        flags=[_flag(reason)],
    )


def _describe_one(kind: str, body: str) -> PemReport:
    """One `-----BEGIN kind -----` block described, whatever it turns out to be."""
    sha256 = pem_body_sha256(body)

    if _is_key_armour(kind):
        # Named and stopped at. No `load_pem_private_key`, so an encrypted key is not even asked for a passphrase (which
        # would otherwise be this page's one opportunity to prompt for a secret), and no byte of the body is echoed
        # back.
        return PemReport(
            kind="private key",
            armour=kind,
            pem=None,
            sha256_of_der=None,
            facts=[("Type", f"private key (`{kind}`)"), ("Body", "not read")],
            flags=[
                _flag(
                    "this is a private key. mypki did not open it and will not display it — paste certificates and "
                    "requests here; keys belong in the data dir or in a password manager"
                )
            ],
        )

    if kind in CERTIFICATE_KINDS:
        try:
            cert = x509.load_der_x509_certificate(_der(body))
        except (ValueError, TypeError) as exc:
            return _unreadable(kind, str(exc), sha256)
        facts, flags = _certificate_facts(cert, dt.datetime.now(dt.timezone.utc))
        return PemReport(
            kind="certificate", armour=kind, pem=_rearmour(kind, body), sha256_of_der=sha256, facts=facts, flags=flags
        )

    if kind in CSR_KINDS:
        try:
            csr = x509.load_der_x509_csr(_der(body))
        except (ValueError, TypeError) as exc:
            return _unreadable(kind, str(exc), sha256)
        facts, flags = _request_facts(csr)
        return PemReport(
            kind="certificate request",
            armour=kind,
            pem=_rearmour(kind, body),
            sha256_of_der=sha256,
            facts=facts,
            flags=flags,
        )

    return PemReport(
        kind="unrecognised",
        armour=kind or "(no name)",
        pem=None,
        sha256_of_der=sha256,
        facts=[("Type", f"PEM block named `{kind}`" if kind else "PEM block with no name"), ("Body", "not parsed")],
        flags=[_flag("mypki does not know this block type, so it reports the armour line and stops there")],
    )


def _is_key_armour(kind: str) -> bool:
    """Whether one armour kind names a private key.

    The suffix test as well as the explicit set: `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `EC PRIVATE KEY`, `RSA PRIVATE
    KEY` and `OPENSSH PRIVATE KEY` all end the same way, and an armour kind this module has never seen (`DSA PRIVATE
    KEY`, a future one) still matches instead of falling through to "unrecognised" and being handed to a parser. The
    set is kept as documentation of what was measured; the suffix is what makes the rule safe for the next spelling.
    """
    return kind in KEY_KINDS or kind.endswith("PRIVATE KEY")


def redact_private_key_bodies(paste: str) -> tuple[str, int]:
    """`paste` with every private-key block's base64 replaced by a marker line, plus how many blocks were redacted.

    This exists because `/inspect` re-renders what the operator pasted so that an expired certificate can be read next
    to the sentence describing it (see `app.render_inspect`). Re-rendering is right for a certificate — public
    material, already on the wire on every TLS connection — and wrong for a key: echoing a key into a rendered page is
    how it lands in a browser's back-forward cache, a support screenshot and a "save page" copy. So the echo is
    filtered here rather than left to a template to remember.

    Only the body is replaced; the armour lines stay, because "your paste contained a key" is the fact an operator
    needs and the base64 is not. The count comes back so the page can say out loud how many blocks were filtered:
    rewriting what somebody pasted, with nothing on screen telling them, is the quiet edit this project refuses
    elsewhere (see `settingsfile.preserve_unmanaged`).
    """
    count = 0

    def redact(match: re.Match[str]) -> str:
        nonlocal count
        kind = match.group(1).strip()
        if not _is_key_armour(kind):
            return match.group(0)
        count += 1
        return f"-----BEGIN {kind}-----\n{KEY_BODY_REDACTED}\n-----END {kind}-----"

    return _BLOCK_RE.sub(redact, paste or ""), count


def describe_pem(paste: str, max_chars: int) -> list[PemReport]:
    """Describe every PEM block in a paste. Refuses nothing except an oversized body.

    The size check is first and identical to the sign page's (`RequestTooLargeError` naming `MYPKI_MAX_CSR_CHARS`,
    raised **before** any parser so starlette's own 1 MiB part limit cannot answer with a bare JSON message first,
    see `SizeGuardMiddleware`). Size is not a *content* judgement: it is the one input this page cannot describe
    usefully, because describing it would mean holding and rendering more bytes than this app promises to hold.

    Everything else is described: an unrecognised armour kind, a block whose base64 is broken, a block that decodes but
    is not DER, a private key (named, never read), a request, a leaf, a root, an expired leaf, a not-yet-valid leaf, a
    SHA-1 leaf, an RSA-1024 leaf. A parse failure becomes a `PemReport` whose facts say what could not be read.
    """
    text = paste or ""
    if len(text) > max_chars:
        raise RequestTooLargeError(len(text), max_chars, "MYPKI_MAX_CSR_CHARS")

    blocks = _BLOCK_RE.findall(text)
    if not blocks:
        return [
            PemReport(
                kind="nothing readable",
                armour="",
                pem=None,
                sha256_of_der=None,
                facts=[("Input", f"{len(text)} character(s), no `-----BEGIN … -----` block found")],
                flags=[_flag("nothing to report — paste a certificate or a request between its BEGIN and END lines")],
            )
        ]

    reports = [_describe_one(kind.strip(), body) for kind, body in blocks[:MAX_BLOCKS_TO_TRY]]
    surplus = len(blocks) - MAX_BLOCKS_TO_TRY
    if surplus > 0:
        reports.append(
            PemReport(
                kind="not described",
                armour="",
                pem=None,
                sha256_of_der=None,
                facts=[("Input", f"{surplus} further block(s) in the same paste were not parsed")],
                flags=[_flag(f"{surplus} block(s) beyond the first {MAX_BLOCKS_TO_TRY}: paste fewer at a time")],
            )
        )
    log.info("inspected %d PEM block(s): %s", len(reports), "; ".join(report.summary for report in reports))
    return reports
